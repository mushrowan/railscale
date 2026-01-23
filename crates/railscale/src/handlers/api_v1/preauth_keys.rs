//! preauth key endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `GET /api/v1/preauthkey` - list all preauth keys
//! - `POST /api/v1/preauthkey` - create a preauth key
//! - `POST /api/v1/preauthkey/expire` - expire a preauth key
//! - `DELETE /api/v1/preauthkey` - delete a preauth key

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext};
use railscale_db::Database;
use railscale_types::{PreAuthKey, UserId};

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

impl From<PreAuthKey> for PreAuthKeyResponse {
    fn from(key: PreAuthKey) -> Self {
        Self {
            id: key.id.to_string(),
            key: key.key,
            user_id: key.user_id.0.to_string(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            tags: key.tags,
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
    #[serde(default, rename = "aclTags")]
    pub acl_tags: Vec<String>,
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
                .delete(delete_preauth_key),
        )
        .route("/expire", post(expire_preauth_key))
}

/// list all preauth keys.
///
/// `GET /api/v1/preauthkey`
async fn list_preauth_keys(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<ListPreAuthKeysResponse>, ApiError> {
    let keys = state
        .db
        .get_all_preauth_keys()
        .await
        .map_err(ApiError::internal)?;

    let preauth_keys: Vec<PreAuthKeyResponse> =
        keys.into_iter().map(PreAuthKeyResponse::from).collect();

    Ok(Json(ListPreAuthKeysResponse { preauth_keys }))
}

/// create a new preauth key.
///
/// `POST /api/v1/preauthkey`
async fn create_preauth_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<CreatePreAuthKeyRequest>,
) -> Result<(StatusCode, Json<CreatePreAuthKeyResponse>), ApiError> {
    // verify user exists
    let user_id = UserId(req.user);
    if state
        .db
        .get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("user {} not found", req.user)));
    }

    // validate tags
    for tag in &req.acl_tags {
        if !tag.starts_with("tag:") {
            return Err(ApiError::bad_request(format!(
                "tag '{}' must start with 'tag:'",
                tag
            )));
        }
        if tag.to_lowercase() != *tag {
            return Err(ApiError::bad_request(format!(
                "tag '{}' must be lowercase",
                tag
            )));
        }
    }

    // parse expiration or default to 90 days
    let expiration = if let Some(exp_str) = req.expiration {
        Some(
            chrono::DateTime::parse_from_rfc3339(&exp_str)
                .map_err(|_| ApiError::bad_request("invalid expiration format, expected RFC3339"))?
                .with_timezone(&Utc),
        )
    } else {
        Some(Utc::now() + Duration::days(90))
    };

    // generate key
    let key_str = generate_preauth_key();

    let mut key = PreAuthKey::new(0, key_str, user_id);
    key.reusable = req.reusable;
    key.ephemeral = req.ephemeral;
    key.tags = req.acl_tags;
    key.expiration = expiration;

    let key = state
        .db
        .create_preauth_key(&key)
        .await
        .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePreAuthKeyResponse {
            preauth_key: PreAuthKeyResponse::from(key),
        }),
    ))
}

/// expire a preauth key.
///
/// `POST /api/v1/preauthkey/expire`
async fn expire_preauth_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<ExpirePreAuthKeyRequest>,
) -> Result<Json<ExpirePreAuthKeyResponse>, ApiError> {
    state
        .db
        .expire_preauth_key(req.id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(ExpirePreAuthKeyResponse {}))
}

/// delete a preauth key.
///
/// `DELETE /api/v1/preauthkey`
async fn delete_preauth_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<DeletePreAuthKeyRequest>,
) -> Result<Json<DeletePreAuthKeyResponse>, ApiError> {
    state
        .db
        .delete_preauth_key(req.id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(DeletePreAuthKeyResponse {}))
}

/// generate a random preauth key string.
fn generate_preauth_key() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 24] = rng.random();
    format!("tskey-auth-{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preauth_key_response_from() {
        let key = PreAuthKey::new(1, "test-key".to_string(), UserId(42));
        let response = PreAuthKeyResponse::from(key);

        assert_eq!(response.id, "1");
        assert_eq!(response.key, "test-key");
        assert_eq!(response.user_id, "42");
        assert!(!response.reusable);
        assert!(!response.ephemeral);
    }

    #[test]
    fn test_preauth_key_response_serialization() {
        let mut key = PreAuthKey::new(1, "test-key".to_string(), UserId(42));
        key.tags = vec!["tag:server".to_string()];
        let response = PreAuthKeyResponse::from(key);

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

    #[test]
    fn test_generate_preauth_key() {
        let key = generate_preauth_key();
        assert!(key.starts_with("tskey-auth-"));
        assert_eq!(key.len(), "tskey-auth-".len() + 48); // 24 bytes = 48 hex chars
    }
}
