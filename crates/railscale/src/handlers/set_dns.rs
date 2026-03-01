//! /machine/set-dns handler for ACME dns-01 challenges

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use bytes::Bytes;
use tracing::info;

use railscale_db::{Database, DnsChallengeRecord};
use railscale_proto::SetDNSRequest;

use super::{ApiError, OptionExt, ResultExt};
use crate::AppState;

/// handle a set-dns request from a tailscale client
///
/// the client sends this during `tailscale cert` to create a TXT record
/// for ACME dns-01 challenge validation. we validate the node owns the
/// requested domain, delegate to the configured dns provider, and persist
/// the record for later cleanup.
pub async fn set_dns(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let req: SetDNSRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("invalid JSON request body"))?;

    // validate record type — only TXT is supported for ACME dns-01
    if req.record_type != "TXT" {
        return Err(ApiError::bad_request("only TXT record type is supported"));
    }

    let node = super::VerifiedNode::verify(
        state
            .db
            .get_node_by_node_key(&req.node_key)
            .await
            .map_internal()?
            .or_unauthorized("node not found")?,
        &machine_key_ctx,
    )?;

    // get dns provider or fail
    let provider = state
        .dns_provider
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("dns provider not configured"))?;

    // validate the requested name is the ACME challenge for this node's cert domain
    let expected_name = format!(
        "_acme-challenge.{}.{}",
        node.display_hostname(),
        state.config.base_domain
    );
    if req.name != expected_name {
        info!(
            node_id = node.id.as_u64(),
            requested = %req.name,
            expected = %expected_name,
            "set-dns: name mismatch"
        );
        return Err(ApiError::unauthorized(
            "requested name does not match node's cert domain",
        ));
    }

    // delegate to dns provider
    let record_id = provider
        .set_txt_record(req.name.clone(), req.value)
        .await
        .map_err(|e| ApiError::internal(format!("dns provider error: {e}")))?;

    // persist the challenge record for cleanup
    let record = DnsChallengeRecord {
        id: 0,
        node_id: node.id,
        record_name: req.name,
        record_id,
        created_at: chrono::Utc::now(),
    };
    state
        .db
        .create_dns_challenge_record(&record)
        .await
        .map_internal()?;

    info!(node_id = node.id.as_u64(), "set-dns: TXT record created");

    Ok(Json(railscale_proto::SetDNSResponse {}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_helpers::default_grants;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use railscale_db::RailscaleDb;
    use railscale_types::test_utils::TestNodeBuilder;
    use railscale_types::{Config, DnsProviderConfig, NodeKey};
    use tower::ServiceExt;

    /// serialise a node key to its JSON string value (e.g. "nodekey:0102...")
    fn node_key_json(key: &railscale_types::NodeKey) -> serde_json::Value {
        serde_json::to_value(key).unwrap()
    }

    /// generate a 32-byte node key with a unique seed
    fn test_node_key(seed: u8) -> NodeKey {
        NodeKey::from_bytes([seed; 32])
    }

    fn test_config() -> Config {
        Config {
            allow_non_noise_registration: true,
            base_domain: "example.com".to_string(),
            // use webhook provider pointing at a dummy URL (will be mocked)
            dns_provider: Some(DnsProviderConfig::Webhook {
                url: "http://127.0.0.1:1/noop".to_string(),
                secret: None,
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_set_dns_rejects_non_txt_record_type() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let config = test_config();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        // create a user and node
        let user = railscale_types::User::new(railscale_types::UserId::new(0), "alicja".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(test_node_key(1))
            .build();
        let node = db.create_node(&node).await.unwrap();

        let req = serde_json::json!({
            "Version": 68,
            "NodeKey": node_key_json(&node.node_key),
            "Name": "_acme-challenge.test-node.example.com",
            "Type": "A",
            "Value": "test-value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/set-dns")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_set_dns_rejects_unknown_node() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let config = test_config();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req = serde_json::json!({
            "Version": 68,
            "NodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
            "Name": "_acme-challenge.test-node.example.com",
            "Type": "TXT",
            "Value": "test-value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/set-dns")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_set_dns_rejects_name_mismatch() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let config = test_config();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let user = railscale_types::User::new(railscale_types::UserId::new(0), "alicja".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(test_node_key(2))
            .build();
        let node = db.create_node(&node).await.unwrap();

        // request a name that doesn't match the node's hostname
        let req = serde_json::json!({
            "Version": 68,
            "NodeKey": node_key_json(&node.node_key),
            "Name": "_acme-challenge.evil-host.example.com",
            "Type": "TXT",
            "Value": "test-value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/set-dns")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_set_dns_rejects_when_no_provider() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let mut config = test_config();
        config.dns_provider = None; // no provider configured
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let user = railscale_types::User::new(railscale_types::UserId::new(0), "alicja".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(test_node_key(3))
            .build();
        let node = db.create_node(&node).await.unwrap();

        let req = serde_json::json!({
            "Version": 68,
            "NodeKey": node_key_json(&node.node_key),
            "Name": format!("_acme-challenge.{}.example.com", node.display_hostname()),
            "Type": "TXT",
            "Value": "test-value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/set-dns")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_set_dns_success_with_wiremock() {
        let mock_server = wiremock::MockServer::start().await;

        // mock the webhook endpoint to return a record id
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "record_id": "mock-record-123"
                })),
            )
            .mount(&mock_server)
            .await;

        let db = RailscaleDb::new_in_memory().await.unwrap();
        let mut config = test_config();
        config.dns_provider = Some(DnsProviderConfig::Webhook {
            url: format!("{}/set-dns", mock_server.uri()),
            secret: None,
        });

        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let user = railscale_types::User::new(railscale_types::UserId::new(0), "alicja".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(test_node_key(4))
            .build();
        let node = db.create_node(&node).await.unwrap();

        let req = serde_json::json!({
            "Version": 68,
            "NodeKey": node_key_json(&node.node_key),
            "Name": format!("_acme-challenge.{}.example.com", node.display_hostname()),
            "Type": "TXT",
            "Value": "acme-challenge-value-xyz"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/set-dns")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // verify the challenge record was persisted
        let records = db
            .list_dns_challenge_records_for_node(node.id)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].record_name.starts_with("_acme-challenge."));
    }
}
