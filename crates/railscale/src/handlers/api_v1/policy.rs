//! policy endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `GET /api/v1/policy` - get the current policy
//! - `PUT /api/v1/policy` - set a new policy

use crate::handlers::JsonBody;
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};

use std::path::Path;

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext};
use railscale_grants::Policy;
use railscale_types::PolicyJson;

/// response for get policy endpoint.
#[derive(Debug, Serialize)]
pub struct GetPolicyResponse {
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// policy json (validated to not exceed size limits)
#[derive(Debug, Deserialize)]
pub struct SetPolicyRequest {
    /// policy json (validated to not exceed size limits).
    pub policy: PolicyJson,
}

/// response for set policy endpoint.
#[derive(Debug, Serialize)]
pub struct SetPolicyResponse {
    pub policy: String,
    pub updated_at: String,
}

/// persist a policy to a file atomically (write to temp, then rename).
///
/// returns Ok(()) on success, or an io error. failures are logged but
/// should not prevent the in-memory update from succeeding.
pub fn persist_policy(path: &Path, policy: &Policy) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(policy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // write to a temp file in the same directory, then rename for atomicity
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut temp, json.as_bytes())?;
    temp.persist(path).map_err(|e| e.error)?;

    Ok(())
}

/// create the policy router.
pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_policy).put(set_policy))
}

/// get the current policy.
///
/// `GET /api/v1/policy`
async fn get_policy(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<GetPolicyResponse>, ApiError> {
    let grants = state.grants.read().await;
    let policy = grants.policy();

    let policy_json =
        serde_json::to_string_pretty(policy).map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(GetPolicyResponse {
        policy: policy_json,
        updated_at: None, // We don't track update time currently
    }))
}

/// set a new policy.
///
/// `PUT /api/v1/policy`
async fn set_policy(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    JsonBody(req): JsonBody<SetPolicyRequest>,
) -> Result<Json<SetPolicyResponse>, ApiError> {
    // parse and validate the new policy
    // NOTE: size already validated by policyjson deserialisation
    let new_policy = Policy::from_json(req.policy.as_str()).map_err(|e| {
        tracing::warn!("Invalid policy submitted: {}", e);
        ApiError::bad_request("invalid policy format")
    })?;

    let grant_count = new_policy.grants.len();

    // update the policy
    {
        let mut grants = state.grants.write().await;
        grants.update_policy(new_policy);
    }

    // persist to file if configured (best-effort; don't fail the request)
    if let Some(ref path) = state.config.policy_file_path {
        let grants = state.grants.read().await;
        let current = grants.policy();
        if let Err(e) = persist_policy(path, current) {
            tracing::error!(path = ?path, error = %e, "failed to persist policy to file");
        } else {
            tracing::info!(path = ?path, "policy persisted to file");
        }
    }

    // notify connected clients about the policy change
    state.notifier.notify_state_changed();

    let updated_at = chrono::Utc::now().to_rfc3339();

    tracing::info!("Policy updated via REST API ({} grants)", grant_count);

    Ok(Json(SetPolicyResponse {
        policy: req.policy.into_inner(),
        updated_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_policy_response_serialization() {
        let response = GetPolicyResponse {
            policy: r#"{"grants": []}"#.to_string(),
            updated_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"policy\""));
        // updated_at should be skipped when None
        assert!(!json.contains("\"updated_at\""));
    }

    #[test]
    fn test_set_policy_request_deserialization() {
        let json = r#"{"policy": "{\"grants\": []}"}"#;
        let req: SetPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy.as_str(), r#"{"grants": []}"#);
    }

    #[test]
    fn test_set_policy_request_rejects_oversized() {
        use railscale_types::MAX_POLICY_SIZE;
        let large = "x".repeat(MAX_POLICY_SIZE + 1);
        let json = format!(r#"{{"policy": "{}"}}"#, large);
        let result: Result<SetPolicyRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        // error should be generic (not leak size)
        let err = result.unwrap_err().to_string();
        assert!(err.contains("policy exceeds maximum size"));
    }

    #[test]
    fn test_set_policy_response_serialization() {
        let response = SetPolicyResponse {
            policy: r#"{"grants": []}"#.to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"policy\""));
        assert!(json.contains("\"updated_at\""));
    }

    #[test]
    fn test_persist_policy_writes_file() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let policy = Policy::empty();
        persist_policy(&path, &policy).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: Policy = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.grants.len(), 0);
    }

    #[test]
    fn test_persist_policy_roundtrips_grants() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut policy = Policy::empty();
        policy.grants.push(railscale_grants::Grant {
            src: vec![railscale_grants::Selector::Wildcard],
            dst: vec![railscale_grants::Selector::Wildcard],
            ip: vec![railscale_grants::NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        persist_policy(&path, &policy).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: Policy = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.grants.len(), 1);
    }

    #[test]
    fn test_persist_policy_atomic_write() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("policy.json");

        // file doesn't exist yet
        assert!(!path.exists());

        let policy = Policy::empty();
        persist_policy(&path, &policy).unwrap();

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let _: Policy = serde_json::from_str(&content).unwrap();
    }
}
