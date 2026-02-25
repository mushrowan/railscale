//! user endpoints for api v1 (headscale-compatible).

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};

use super::nodes::PaginationParams;

use tracing::{debug, info, warn};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext, JsonBody};
use railscale_db::Database;
use railscale_types::{Email, User, UserId, Username};

/// response wrapper for list users endpoint.
#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<UserResponse>,
}

/// user representation in api responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pic_url: Option<String>,
    /// oidc group memberships synced from identity provider.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub oidc_groups: Vec<String>,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.0.to_string(),
            name: user.name,
            display_name: user.display_name,
            email: user.email,
            provider: user.provider,
            profile_pic_url: user.profile_pic_url,
            oidc_groups: user.oidc_groups,
            created_at: user.created_at.to_rfc3339(),
        }
    }
}

/// request body for creating a user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: Username,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<Email>,
}

/// response for create user endpoint.
#[derive(Debug, Serialize)]
pub struct CreateUserResponse {
    pub user: UserResponse,
}

/// response for delete user endpoint.
#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {}

/// response for rename user endpoint.
#[derive(Debug, Serialize)]
pub struct RenameUserResponse {
    pub user: UserResponse,
}

/// create the users router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/{id}", delete(delete_user))
        .route("/{old_id}/rename/{new_name}", post(rename_user))
}

/// list all users.
///
/// `GET /api/v1/user`
///
/// supports optional pagination: `?limit=100&offset=0`
async fn list_users(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<ListUsersResponse>, ApiError> {
    let users = state.db.list_users().await.map_err(ApiError::internal)?;

    debug!(count = users.len(), "listing users");
    let users: Vec<UserResponse> = pagination
        .apply(users)
        .into_iter()
        .map(UserResponse::from)
        .collect();

    Ok(Json(ListUsersResponse { users }))
}

/// maximum length for display name (characters).
const MAX_DISPLAY_NAME_LEN: usize = 255;

/// create a new user.
///
/// `POST /api/v1/user`
async fn create_user(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<CreateUserRequest>,
) -> Result<(StatusCode, Json<CreateUserResponse>), ApiError> {
    if let Some(ref display_name) = req.display_name
        && display_name.chars().count() > MAX_DISPLAY_NAME_LEN
    {
        return Err(ApiError::bad_request(format!(
            "display_name exceeds maximum length of {} characters",
            MAX_DISPLAY_NAME_LEN
        )));
    }

    let name = req.name.into_inner();

    if state
        .db
        .get_user_by_name(&name)
        .await
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict(format!(
            "user '{}' already exists",
            name
        )));
    }

    let mut user = User::new(UserId(0), name);
    user.display_name = req.display_name;
    user.email = req.email.map(|e| e.into_inner());

    let user = state
        .db
        .create_user(&user)
        .await
        .map_err(ApiError::internal)?;

    info!(user_id = user.id.0, name = %user.name, "user created");
    Ok((
        StatusCode::CREATED,
        Json(CreateUserResponse {
            user: UserResponse::from(user),
        }),
    ))
}

/// delete a user.
///
/// `DELETE /api/v1/user/{id}`
async fn delete_user(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<DeleteUserResponse>, ApiError> {
    let user_id = UserId(id);

    if state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("user {} not found", id)));
    }

    let user_nodes = state
        .db
        .list_nodes_for_user(user_id)
        .await
        .map_err(ApiError::internal)?;

    state
        .db
        .delete_nodes_for_user(user_id)
        .await
        .map_err(ApiError::internal)?;

    {
        let mut allocator = state.ip_allocator.lock().await;
        for node in &user_nodes {
            if let Some(v4) = node.ipv4 {
                allocator.release(v4);
            }
            if let Some(v6) = node.ipv6 {
                allocator.release(v6);
            }
        }
    }

    state
        .db
        .delete_preauth_keys_for_user(user_id)
        .await
        .map_err(ApiError::internal)?;

    state
        .db
        .delete_user(user_id)
        .await
        .map_err(ApiError::internal)?;

    warn!(
        user_id = id,
        nodes_deleted = user_nodes.len(),
        "user deleted"
    );
    Ok(Json(DeleteUserResponse {}))
}

/// rename a user.
///
/// `POST /api/v1/user/{old_id}/rename/{new_name}`
async fn rename_user(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path((old_id, new_name)): Path<(u64, String)>,
) -> Result<Json<RenameUserResponse>, ApiError> {
    let new_name = Username::new(&new_name).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let user_id = UserId(old_id);

    let mut user = state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("user {} not found", old_id)))?;

    if let Some(existing) = state
        .db
        .get_user_by_name(new_name.as_str())
        .await
        .map_err(ApiError::internal)?
        && existing.id != user_id
    {
        return Err(ApiError::conflict(format!(
            "user '{}' already exists",
            new_name
        )));
    }

    let old_name = user.name.clone();
    user.name = new_name.into_inner();
    let user = state
        .db
        .update_user(&user)
        .await
        .map_err(ApiError::internal)?;

    info!(user_id = old_id, old_name = %old_name, new_name = %user.name, "user renamed");
    Ok(Json(RenameUserResponse {
        user: UserResponse::from(user),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_response_from_user() {
        let user = User::new(UserId(42), "alicja".to_string());
        let response = UserResponse::from(user);

        assert_eq!(response.id, "42");
        assert_eq!(response.name, "alicja");
        assert!(response.display_name.is_none());
        assert!(response.email.is_none());
        assert!(response.oidc_groups.is_empty());
    }

    #[test]
    fn test_user_response_with_oidc_groups() {
        let mut user = User::new(UserId(42), "alicja".to_string());
        user.oidc_groups = vec!["engineering".to_string(), "devops".to_string()];

        let response = UserResponse::from(user);
        assert_eq!(response.oidc_groups, vec!["engineering", "devops"]);

        // verify serialization includes oidc_groups
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"oidc_groups\""));
        assert!(json.contains("engineering"));
    }

    #[test]
    fn test_user_response_serialization() {
        let response = UserResponse {
            id: "1".to_string(),
            name: "alicja".to_string(),
            display_name: Some("Alicja Smith".to_string()),
            email: Some("alicja@example.com".to_string()),
            provider: None,
            profile_pic_url: None,
            oidc_groups: vec![],
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();

        // verify snake_case field names
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"display_name\""));
        assert!(json.contains("\"created_at\""));

        // verify none/empty fields are skipped
        assert!(!json.contains("\"provider\""));
        assert!(!json.contains("\"profile_pic_url\""));
        assert!(!json.contains("\"oidc_groups\"")); // empty vec skipped
    }

    #[test]
    fn test_list_users_response_serialization() {
        let response = ListUsersResponse {
            users: vec![UserResponse {
                id: "1".to_string(),
                name: "alicja".to_string(),
                display_name: None,
                email: None,
                provider: None,
                profile_pic_url: None,
                oidc_groups: vec![],
                created_at: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"users\""));
    }

    #[test]
    fn test_create_user_request_deserialization() {
        let json = r#"{"name": "ro"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "ro");
        assert!(req.display_name.is_none());
        assert!(req.email.is_none());

        let json = r#"{"name": "ro", "display_name": "Ro Smith", "email": "ro@example.com"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "ro");
        assert_eq!(req.display_name.as_deref(), Some("Ro Smith"));
        assert_eq!(
            req.email.as_ref().map(|e| e.as_str()),
            Some("ro@example.com")
        );
    }

    #[test]
    fn test_create_user_request_rejects_invalid_email() {
        let json = r#"{"name": "ro", "email": "not-an-email"}"#;
        let result: Result<CreateUserRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid email format"));
    }
}
