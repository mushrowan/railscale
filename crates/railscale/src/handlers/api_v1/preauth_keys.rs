//! preauth key endpoints for api v1 (headscale-compatible).

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use tracing::{debug, info, warn};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext, JsonBody};
use railscale_db::Database;
use railscale_types::{PreAuthKey, PreAuthKeyToken, UserId};

/// response wrapper for list preauth keys endpoint.
#[derive(Debug, Serialize)]
pub struct ListPreAuthKeysResponse {
    #[serde(rename = "preAuthKeys")]
    pub preauth_keys: Vec<PreAuthKeyResponse>,
}

/// preauthkey representation in api responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct PreAuthKeyResponse {
    pub id: String,
    pub key: String,
    pub user_id: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    pub created_at: String,
}

impl PreAuthKeyResponse {
    fn from_key_prefix_only(key: PreAuthKey) -> Self {
        Self {
            id: key.id.to_string(),
            key: key.key_prefix,
            user_id: key.user_id.to_string(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            tags: key.tags.iter().map(|t| t.to_string()).collect(),
            expiration: key.expiration.map(|dt| dt.to_rfc3339()),
            created_at: key.created_at.to_rfc3339(),
        }
    }

    fn from_key_with_full_token(key: PreAuthKey, full_key: &str) -> Self {
        Self {
            id: key.id.to_string(),
            key: full_key.to_string(),
            user_id: key.user_id.to_string(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            tags: key.tags.iter().map(|t| t.to_string()).collect(),
            expiration: key.expiration.map(|dt| dt.to_rfc3339()),
            created_at: key.created_at.to_rfc3339(),
        }
    }
}

/// request for creating a preauth key.
#[derive(Debug, Deserialize)]
pub struct CreatePreAuthKeyRequest {
    /// user id to associate the key with.
    pub user: u64,
    /// whether the key can be used multiple times.
    #[serde(default)]
    pub reusable: bool,
    /// whether nodes registered with this key are ephemeral.
    #[serde(default)]
    pub ephemeral: bool,
    /// expiration time in rfc3339 format.
    #[serde(default)]
    pub expiration: Option<String>,
    /// tags to apply to nodes registered with this key.
    /// format and count validated by Tags newtype during deserialization.
    #[serde(default, rename = "aclTags")]
    pub acl_tags: railscale_types::Tags,
}

/// response for create preauth key endpoint.
#[derive(Debug, Serialize)]
pub struct CreatePreAuthKeyResponse {
    #[serde(rename = "preAuthKey")]
    pub preauth_key: PreAuthKeyResponse,
}

/// request for expire preauth key endpoint.
#[derive(Debug, Deserialize)]
pub struct ExpirePreAuthKeyRequest {
    /// id of the key to expire.
    pub id: u64,
}

/// response for expire preauth key endpoint.
#[derive(Debug, Serialize)]
pub struct ExpirePreAuthKeyResponse {}

/// request for delete preauth key endpoint.
#[derive(Debug, Deserialize)]
pub struct DeletePreAuthKeyRequest {
    /// id of the key to delete.
    pub id: u64,
}

/// response for delete preauth key endpoint.
#[derive(Debug, Serialize)]
pub struct DeletePreAuthKeyResponse {}

/// create the preauth keys router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            get(list_preauth_keys)
                .post(create_preauth_key)
                .delete(delete_preauth_key_json), // legacy json body
        )
        .route("/{id}", delete(delete_preauth_key_path)) // preferred path param
        .route("/expire", post(expire_preauth_key))
}

/// list all preauth keys.
async fn list_preauth_keys(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<ListPreAuthKeysResponse>, ApiError> {
    let keys = state
        .db
        .get_all_preauth_keys()
        .await
        .map_err(ApiError::internal)?;

    debug!(count = keys.len(), "listing preauth keys");
    let preauth_keys: Vec<PreAuthKeyResponse> = keys
        .into_iter()
        .map(PreAuthKeyResponse::from_key_prefix_only)
        .collect();

    Ok(Json(ListPreAuthKeysResponse { preauth_keys }))
}

/// create a new preauth key.
///
/// `POST /api/v1/preauthkey`
async fn create_preauth_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<CreatePreAuthKeyRequest>,
) -> Result<(StatusCode, Json<CreatePreAuthKeyResponse>), ApiError> {
    let user_id = UserId::new(req.user);
    if state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("user {} not found", req.user)));
    }

    let expiration = if let Some(exp_str) = req.expiration {
        Some(
            chrono::DateTime::parse_from_rfc3339(&exp_str)
                .map_err(|_| ApiError::bad_request("invalid expiration format, expected RFC3339"))?
                .with_timezone(&Utc),
        )
    } else {
        Some(Utc::now() + Duration::days(90))
    };

    let token = PreAuthKeyToken::generate();

    let mut key = PreAuthKey::from_token(0, &token, user_id);
    key.reusable = req.reusable;
    key.ephemeral = req.ephemeral;
    key.tags = req.acl_tags.into_inner();
    key.expiration = expiration;

    let key = state
        .db
        .create_preauth_key(&key)
        .await
        .map_err(ApiError::internal)?;

    info!(
        key_id = key.id,
        user_id = user_id.as_u64(),
        reusable = key.reusable,
        ephemeral = key.ephemeral,
        "preauth key created"
    );
    Ok((
        StatusCode::CREATED,
        Json(CreatePreAuthKeyResponse {
            preauth_key: PreAuthKeyResponse::from_key_with_full_token(key, token.as_str()),
        }),
    ))
}

/// expire a preauth key.
///
/// `POST /api/v1/preauthkey/expire`
async fn expire_preauth_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<ExpirePreAuthKeyRequest>,
) -> Result<Json<ExpirePreAuthKeyResponse>, ApiError> {
    state
        .db
        .expire_preauth_key(req.id)
        .await
        .map_err(ApiError::internal)?;

    info!(key_id = req.id, "preauth key expired");
    Ok(Json(ExpirePreAuthKeyResponse {}))
}

/// delete a preauth key (legacy json body).
///
/// `DELETE /api/v1/preauthkey` with `{"id": N}`
async fn delete_preauth_key_json(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<DeletePreAuthKeyRequest>,
) -> Result<Json<DeletePreAuthKeyResponse>, ApiError> {
    state
        .db
        .delete_preauth_key(req.id)
        .await
        .map_err(ApiError::internal)?;

    warn!(key_id = req.id, "preauth key deleted");
    Ok(Json(DeletePreAuthKeyResponse {}))
}

/// delete a preauth key (path param).
///
/// `DELETE /api/v1/preauthkey/{id}`
async fn delete_preauth_key_path(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<DeletePreAuthKeyResponse>, ApiError> {
    state
        .db
        .delete_preauth_key(id)
        .await
        .map_err(ApiError::internal)?;

    warn!(key_id = id, "preauth key deleted");
    Ok(Json(DeletePreAuthKeyResponse {}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preauth_key_response_prefix_only() {
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(1, &token, UserId::new(42));
        let response = PreAuthKeyResponse::from_key_prefix_only(key);

        assert_eq!(response.id, "1");
        // should only contain the prefix
        assert_eq!(response.key, token.prefix());
        assert_eq!(response.user_id, "42");
        assert!(!response.reusable);
        assert!(!response.ephemeral);
    }

    #[test]
    fn test_preauth_key_response_with_full_token() {
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(1, &token, UserId::new(42));
        let response = PreAuthKeyResponse::from_key_with_full_token(key, token.as_str());

        assert_eq!(response.id, "1");
        // should contain the full token
        assert_eq!(response.key, token.as_str());
    }

    #[test]
    fn test_preauth_key_response_serialization() {
        let token = PreAuthKeyToken::generate();
        let mut key = PreAuthKey::from_token(1, &token, UserId::new(42));
        key.tags = vec!["tag:server".parse().unwrap()];
        let response = PreAuthKeyResponse::from_key_prefix_only(key);

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"id\""));
        assert!(json.contains("\"key\""));
        assert!(json.contains("\"user_id\""));
        assert!(json.contains("\"reusable\""));
        assert!(json.contains("\"tags\""));
    }

    #[test]
    fn test_list_response_serialization() {
        let response = ListPreAuthKeysResponse {
            preauth_keys: vec![],
        };
        let json = serde_json::to_string(&response).unwrap();
        // should use camelcase "preauthkeys"
        assert!(json.contains("\"preAuthKeys\""));
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{"user": 1, "reusable": true, "ephemeral": false, "aclTags": ["tag:web"]}"#;
        let req: CreatePreAuthKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user, 1);
        assert!(req.reusable);
        assert!(!req.ephemeral);
        assert_eq!(req.acl_tags.len(), 1);
    }

    #[test]
    fn test_create_request_minimal() {
        let json = r#"{"user": 1}"#;
        let req: CreatePreAuthKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user, 1);
        assert!(!req.reusable);
        assert!(!req.ephemeral);
        assert!(req.acl_tags.is_empty());
    }
}
