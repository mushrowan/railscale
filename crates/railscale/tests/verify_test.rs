//! integration tests for the `/verify` endpoint
//!
//! the `/verify` endpoint is used by derp servers to verify that a client
//! is registered with this control server before allowing relay connections

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use railscale::{StateNotifier, create_app};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::{
    Config, DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId,
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

/// request body for verify endpoint (matches tailcfg.DERPAdmitClientRequest)
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct VerifyRequest {
    node_public: NodeKey,
    source: String,
}

/// response from the `/verify` endpoint (matches tailcfg.DERPAdmitClientResponse)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VerifyResponse {
    allow: bool,
}

/// test that POST /verify returns Allow: true for a registered node
#[tokio::test]
async fn test_verify_allows_registered_node() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");

    // create a user and node
    let user = User::new(UserId::new(0), "testuser".to_string());
    let user = db.create_user(&user).await.expect("failed to create user");

    let node_key = NodeKey::from_bytes([1u8; 32]);
    let node = Node {
        id: NodeId::new(0),
        machine_key: MachineKey::from_bytes([2u8; 32]),
        node_key: node_key.clone(),
        disco_key: DiscoKey::from_bytes([3u8; 32]),
        endpoints: vec![],
        hostinfo: None,
        ipv4: Some("100.64.0.1".parse().unwrap()),
        ipv6: None,
        hostname: "test-node".to_string(),
        given_name: "test-node".parse().unwrap(),
        user_id: Some(user.id),
        register_method: RegisterMethod::AuthKey,
        tags: vec![],
        auth_key_id: None,
        expiry: None,
        last_seen: None,
        approved_routes: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
        is_online: None,
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };
    db.create_node(&node).await.expect("failed to create node");

    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    let request_body = VerifyRequest {
        node_public: node_key,
        source: "192.168.1.1".to_string(),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let verify_response: VerifyResponse =
        serde_json::from_slice(&body).expect("failed to parse response");

    assert!(verify_response.allow, "should allow registered node");
}

/// test that POST /verify returns Allow: false for an unknown node
#[tokio::test]
async fn test_verify_denies_unknown_node() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    // use a node key that doesn't exist
    let unknown_key = NodeKey::from_bytes([99u8; 32]);
    let request_body = VerifyRequest {
        node_public: unknown_key,
        source: "192.168.1.1".to_string(),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let verify_response: VerifyResponse =
        serde_json::from_slice(&body).expect("failed to parse response");

    assert!(!verify_response.allow, "should deny unknown node");
}
