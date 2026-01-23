//! api key endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `get /api/v1/apikey` - list all api keys
//! - `post /api/v1/apikey` - create an api key
//! - `post /api/v1/apikey/expire` - expire an api key
//! - `delete /api/v1/apikey/{prefix}` - delete an api key by prefix

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext};
use railscale_db::Database;
use railscale_types::{ApiKey, ApiKeySecret, UserId};

/// response wrapper for list api keys endpoint.
#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    #[serde(rename = "apiKeys")]
    pub api_keys: Vec<ApiKeyResponse>,
}

/// api key representation in api responses.
/// NOTE: the actual secret is never returned after creation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    /// the key prefix for identification (e.g., "rsapi_abc12345").
    pub prefix: String,
    pub name: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id.to_string(),
            prefix: key.prefix(),
            name: key.name,
            user_id: key.user_id.0.to_string(),
            expiration: key.expiration.map(|dt| dt.to_rfc3339()),
            created_at: key.created_at.to_rfc3339(),
            last_used_at: key.last_used_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

/// request for creating an api key.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    /// user id to associate the key with.
    pub user: u64,
    /// human-readable name for the key.
    #[serde(default)]
    pub name: Option<String>,
    /// expiration time in rfc3339 format.
    #[serde(default)]
    pub expiration: Option<String>,
}

/// response for create api key endpoint.
/// includes the full key (only shown once).
#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    /// the full api key - only returned on creation, never again.
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// metadata about the created key.
    pub key: ApiKeyResponse,
}

/// request for expire api key endpoint.
#[derive(Debug, Deserialize)]
pub struct ExpireApiKeyRequest {
    /// id of the key to expire.
    #[serde(default)]
    pub id: Option<u64>,
    /// prefix of the key to expire (alternative to id).
    #[serde(default)]
    pub prefix: Option<String>,
}

/// response for expire api key endpoint.
#[derive(Debug, Serialize)]
pub struct ExpireApiKeyResponse {}

/// response for delete api key endpoint.
#[derive(Debug, Serialize)]
pub struct DeleteApiKeyResponse {}

/// create the api keys router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_api_keys).post(create_api_key))
        .route("/expire", post(expire_api_key))
        .route("/{prefix}", axum::routing::delete(delete_api_key))
}

/// list all api keys.
///
/// `GET /api/v1/apikey`
async fn list_api_keys(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<ListApiKeysResponse>, ApiError> {
    let keys = state
        .db
        .get_all_api_keys()
        .await
        .map_err(ApiError::internal)?;

    let api_keys: Vec<ApiKeyResponse> = keys.into_iter().map(ApiKeyResponse::from).collect();

    Ok(Json(ListApiKeysResponse { api_keys }))
}

/// create a new api key.
///
/// `POST /api/v1/apikey`
///
/// returns the full key only once - it cannot be retrieved later.
async fn create_api_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
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
    let secret = ApiKeySecret::generate();
    let name = req
        .name
        .unwrap_or_else(|| format!("API Key {}", &secret.selector[..8]));

    let mut key = ApiKey::new(0, &secret, name, user_id);
    key.expiration = expiration;

    let key = state
        .db
        .create_api_key(&key)
        .await
        .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            api_key: secret.full_key,
            key: ApiKeyResponse::from(key),
        }),
    ))
}

/// expire an api key.
///
/// `POST /api/v1/apikey/expire`
async fn expire_api_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Json(req): Json<ExpireApiKeyRequest>,
) -> Result<Json<ExpireApiKeyResponse>, ApiError> {
    let key_id = match (req.id, req.prefix) {
        (Some(id), _) => id,
        (None, Some(prefix)) => {
            // look up by prefix (selector prefix, first 8 chars)
            let selector_prefix = prefix.strip_prefix("rsapi_").unwrap_or(&prefix);
            let key = state
                .db
                .get_api_key_by_selector_prefix(selector_prefix)
                .await
                .map_err(ApiError::internal)?
                .ok_or_else(|| {
                    ApiError::not_found(format!("API key with prefix '{}' not found", prefix))
                })?;
            key.id
        }
        (None, None) => {
            return Err(ApiError::bad_request("must provide id or prefix"));
        }
    };

    state
        .db
        .expire_api_key(key_id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(ExpireApiKeyResponse {}))
}

/// delete an api key by prefix.
///
/// `DELETE /api/v1/apikey/{prefix}`
async fn delete_api_key(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(prefix): Path<String>,
) -> Result<Json<DeleteApiKeyResponse>, ApiError> {
    // look up by prefix (selector prefix, first 8 chars)
    let selector_prefix = prefix.strip_prefix("rsapi_").unwrap_or(&prefix);
    let key = state
        .db
        .get_api_key_by_selector_prefix(selector_prefix)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found(format!("API key with prefix '{}' not found", prefix))
        })?;

    state
        .db
        .delete_api_key(key.id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(DeleteApiKeyResponse {}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_response_from() {
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(1, &secret, "Test Key".to_string(), UserId(42));
        let response = ApiKeyResponse::from(key);

        assert_eq!(response.id, "1");
        assert!(response.prefix.starts_with("rsapi_"));
        assert_eq!(response.name, "Test Key");
        assert_eq!(response.user_id, "42");
    }

    #[test]
    fn test_api_key_response_serialization() {
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(1, &secret, "Test Key".to_string(), UserId(42));
        let response = ApiKeyResponse::from(key);

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"id\""));
        assert!(json.contains("\"prefix\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"user_id\""));
    }

    #[test]
    fn test_list_response_serialization() {
        let response = ListApiKeysResponse { api_keys: vec![] };
        let json = serde_json::to_string(&response).unwrap();
        // should use camelcase "apikeys"
        assert!(json.contains("\"apiKeys\""));
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{"user": 1, "name": "My Key"}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user, 1);
        assert_eq!(req.name.as_deref(), Some("My Key"));
    }

    #[test]
    fn test_create_request_minimal() {
        let json = r#"{"user": 1}"#;
        let req: CreateApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user, 1);
        assert!(req.name.is_none());
        assert!(req.expiration.is_none());
    }

    #[test]
    fn test_expire_request_by_id() {
        let json = r#"{"id": 123}"#;
        let req: ExpireApiKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Some(123));
        assert!(req.prefix.is_none());
    }

    #[test]
    fn test_expire_request_by_prefix() {
        let json = r#"{"prefix": "rsapi_abc12345"}"#;
        let req: ExpireApiKeyRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.prefix.as_deref(), Some("rsapi_abc12345"));
    }
}
