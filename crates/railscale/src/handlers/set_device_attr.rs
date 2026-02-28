//! /machine/set-device-attr handler for client-driven posture attribute updates

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use bytes::Bytes;
use tracing::debug;

use railscale_db::Database;
use railscale_proto::SetDeviceAttributesRequest;

use super::{ApiError, OptionExt, ResultExt};
use crate::AppState;

/// handle a set-device-attr PATCH request from a tailscale client.
///
/// the client sends this to update posture attributes (e.g. OS version,
/// disk encryption status) over the noise transport. attributes not in
/// the update map are left unchanged. null values delete the attribute.
pub async fn set_device_attr(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let req: SetDeviceAttributesRequest = serde_json::from_slice(&body)
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

    if req.update.is_empty() {
        return Ok(StatusCode::OK);
    }

    // merge updates: load existing attrs, apply patch, remove nulls
    let mut attrs = node.posture_attributes.clone();
    for (key, value) in &req.update {
        if value.is_null() {
            attrs.remove(key);
        } else {
            attrs.insert(key.clone(), value.clone());
        }
    }

    debug!(
        node_id = node.id.as_u64(),
        updated_keys = ?req.update.keys().collect::<Vec<_>>(),
        "set-device-attr: updating posture attributes"
    );

    state
        .db
        .set_node_posture_attributes(node.id, &attrs)
        .await
        .map_internal()?;

    // notify streaming clients so updated posture is visible to grants
    state.notifier.notify_state_changed();

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_helpers::default_grants;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use railscale_db::{Database, RailscaleDb};
    use railscale_types::test_utils::TestNodeBuilder;
    use railscale_types::{NodeKey, UserId};
    use tower::ServiceExt;

    fn test_node_key(seed: u8) -> NodeKey {
        NodeKey::from_bytes(vec![seed; 32])
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
    async fn set_device_attr_updates_posture_attributes() {
        let (app, db, node) = setup().await;

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&node.node_key).unwrap(),
            "Update": {
                "node:os": "linux",
                "custom:encrypted": true
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/machine/set-device-attr")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let updated = db.get_node(node.id).await.unwrap().unwrap();
        assert_eq!(
            updated.posture_attributes.get("node:os"),
            Some(&serde_json::json!("linux"))
        );
        assert_eq!(
            updated.posture_attributes.get("custom:encrypted"),
            Some(&serde_json::json!(true))
        );
    }

    #[tokio::test]
    async fn set_device_attr_null_deletes_attribute() {
        let (app, db, node) = setup().await;

        // first set an attribute
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("to-delete".to_string(), serde_json::json!("value"));
        db.set_node_posture_attributes(node.id, &attrs)
            .await
            .unwrap();

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&node.node_key).unwrap(),
            "Update": {
                "to-delete": null
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/machine/set-device-attr")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let updated = db.get_node(node.id).await.unwrap().unwrap();
        assert!(!updated.posture_attributes.contains_key("to-delete"));
    }

    #[tokio::test]
    async fn set_device_attr_unknown_node_returns_401() {
        let (app, _db, _node) = setup().await;
        let fake_key = NodeKey::from_bytes(vec![0xFF; 32]);

        let req_body = serde_json::json!({
            "Version": 106,
            "NodeKey": serde_json::to_value(&fake_key).unwrap(),
            "Update": {"foo": "bar"}
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/machine/set-device-attr")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
