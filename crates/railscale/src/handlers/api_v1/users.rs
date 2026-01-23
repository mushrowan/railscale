//! user endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `GET /api/v1/user` - list all users
//! - `POST /api/v1/user` - create a user
//! - `DELETE /api/v1/user/{id}` - delete a user
//! - `POST /api/v1/user/{old_id}/rename/{new_name}` - rename a user

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext};
use railscale_db::Database;
use railscale_types::{Email, User, UserId, Username};

/// response wrapper for list users endpoint.
#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<UserResponse>,
}

/// user representation in api responses.
/// uses snake_case to match headscale's json format.
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
            created_at: user.created_at.to_rfc3339(),
        }
    }
}

/// request body for creating a user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    /// username must be 1-63 lowercase alphanumeric chars with hyphens.
    /// validated automatically via serde deserialization.
    pub name: Username,
    #[serde(default)]
    pub display_name: Option<String>,
    /// email address (validated automatically via serde deserialization).
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
async fn list_users(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<ListUsersResponse>, ApiError> {
    let users = state.db.list_users().await.map_err(ApiError::internal)?;

    let users: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(ListUsersResponse { users }))
}

/// create a new user.
///
/// `POST /api/v1/user`
async fn create_user(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<CreateUserResponse>), ApiError> {
    // username is already validated by serde deserialization
    let name = req.name.into_inner();

    // check if user already exists
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

    // check user exists
    if state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("user {} not found", id)));
    }

    state
        .db
        .delete_user(user_id)
        .await
        .map_err(ApiError::internal)?;

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
    // validate new username
    let new_name = Username::new(&new_name).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let user_id = UserId(old_id);

    // get existing user
    let mut user = state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("user {} not found", old_id)))?;

    // check new name doesn't conflict
    if let Some(existing) = state
        .db
        .get_user_by_name(new_name.as_str())
        .await
        .map_err(ApiError::internal)?
    {
        if existing.id != user_id {
            return Err(ApiError::conflict(format!(
                "user '{}' already exists",
                new_name
            )));
        }
    }

    // update name
    user.name = new_name.into_inner();
    let user = state
        .db
        .update_user(&user)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RenameUserResponse {
        user: UserResponse::from(user),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_response_from_user() {
        let user = User::new(UserId(42), "alice".to_string());
        let response = UserResponse::from(user);

        assert_eq!(response.id, "42");
        assert_eq!(response.name, "alice");
        assert!(response.display_name.is_none());
        assert!(response.email.is_none());
    }

    #[test]
    fn test_user_response_serialization() {
        let response = UserResponse {
            id: "1".to_string(),
            name: "alice".to_string(),
            display_name: Some("Alice Smith".to_string()),
            email: Some("alice@example.com".to_string()),
            provider: None,
            profile_pic_url: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();

        // verify snake_case field names
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"display_name\""));
        assert!(json.contains("\"created_at\""));

        // verify none fields are skipped
        assert!(!json.contains("\"provider\""));
        assert!(!json.contains("\"profile_pic_url\""));
    }

    #[test]
    fn test_list_users_response_serialization() {
        let response = ListUsersResponse {
            users: vec![UserResponse {
                id: "1".to_string(),
                name: "alice".to_string(),
                display_name: None,
                email: None,
                provider: None,
                profile_pic_url: None,
                created_at: "2024-01-01T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"users\""));
    }

    #[test]
    fn test_create_user_request_deserialization() {
        let json = r#"{"name": "bob"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "bob");
        assert!(req.display_name.is_none());
        assert!(req.email.is_none());

        let json = r#"{"name": "bob", "display_name": "Bob Smith", "email": "bob@example.com"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "bob");
        assert_eq!(req.display_name.as_deref(), Some("Bob Smith"));
        assert_eq!(
            req.email.as_ref().map(|e| e.as_str()),
            Some("bob@example.com")
        );
    }

    #[test]
    fn test_create_user_request_rejects_invalid_email() {
        let json = r#"{"name": "bob", "email": "not-an-email"}"#;
        let result: Result<CreateUserRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid email format"));
    }
}
