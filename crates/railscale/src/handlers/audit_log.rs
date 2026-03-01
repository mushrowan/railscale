//! /machine/audit-log handler for client-submitted audit log events

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use bytes::Bytes;
use tracing::debug;

use railscale_db::{AuditLog, Database};
use railscale_proto::AuditLogRequest;

use super::{ApiError, OptionExt, ResultExt};
use crate::AppState;

/// handle an audit-log POST request from a tailscale client.
///
/// the client sends audit events (e.g. SSH sessions) for centralised
/// logging. we validate the node exists and persist the log entry.
pub async fn audit_log(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let req: AuditLogRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("invalid JSON request body"))?;

    let node = super::VerifiedNode::verify(
        state
            .db
            .get_node_by_node_key(&req.node_key)
            .await
            .map_internal()?
            .or_unauthorized("node not found")?,
        &machine_key_ctx,
    )?;

    // parse client timestamp if provided
    let client_timestamp = req
        .timestamp
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let log = AuditLog {
        id: 0,
        node_id: node.id,
        action: req.action.clone(),
        details: req.details,
        client_timestamp,
        created_at: chrono::Utc::now(),
    };

    state.db.create_audit_log(&log).await.map_internal()?;

    debug!(
        node_id = node.id.as_u64(),
        action = %req.action,
        "audit-log: recorded"
    );

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_helpers::default_grants;
    use axum::body::Body;
    use axum::http::Request;
    use railscale_db::{Database, RailscaleDb};
    use railscale_types::test_utils::TestNodeBuilder;
    use railscale_types::{NodeKey, UserId};
    use tower::ServiceExt;

    fn test_node_key(seed: u8) -> NodeKey {
        NodeKey::from_bytes([seed; 32])
    }

    async fn setup() -> (axum::Router, RailscaleDb, railscale_types::Node) {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let config = railscale_types::Config {
            allow_non_noise_registration: true,
            ..Default::default()
        };
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let user = railscale_types::User::new(UserId::new(0), "alicja".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(test_node_key(1))
            .with_hostname("test-node")
            .build();
        let node = db.create_node(&node).await.unwrap();

        (app, db, node)
    }

    #[tokio::test]
    async fn audit_log_stores_entry() {
        let (app, _db, node) = setup().await;

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&node.node_key).unwrap(),
            "Action": "ssh-session-start",
            "Details": "user=root",
            "Timestamp": "2026-01-15T12:00:00Z"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/audit-log")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_log_unknown_node_returns_401() {
        let (app, _db, _node) = setup().await;
        let fake_key = NodeKey::from_bytes([0xFF; 32]);

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&fake_key).unwrap(),
            "Action": "test"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/audit-log")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_log_without_timestamp_succeeds() {
        let (app, _db, node) = setup().await;

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&node.node_key).unwrap(),
            "Action": "test-action"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/audit-log")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
