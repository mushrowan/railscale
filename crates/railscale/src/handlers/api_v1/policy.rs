//! policy endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `GET /api/v1/policy` - get the current policy
//! - `PUT /api/v1/policy` - set a new policy

use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};

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
    Json(req): Json<SetPolicyRequest>,
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
}
