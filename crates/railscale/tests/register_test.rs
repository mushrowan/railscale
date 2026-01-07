//! tests for /machine/register endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_types::{MachineKey, NodeKey, PreAuthKey, User, UserId};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize)]
struct RegisterRequest {
    machine_key: Vec<u8>,
    node_key: Vec<u8>,
    preauth_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterResponse {
    node_id: u64,
    machine_key: Vec<u8>,
    node_key: Vec<u8>,
}

#[tokio::test]
async fn test_register_with_preauth_key() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key
    let mut preauth = PreAuthKey::new(1, "test-preauth-key-12345".to_string(), user.id);
    preauth.tags = vec![]; // user-owned node
    let preauth = db.create_preauth_key(&preauth).await.unwrap();

    // create test keys (32 bytes for curve25519)
    let machine_key_bytes = vec![1u8; 32];
    let node_key_bytes = vec![2u8; 32];
    let machine_key = MachineKey::from_bytes(machine_key_bytes.clone());
    let node_key = NodeKey::from_bytes(node_key_bytes.clone());

    // build request
    let request_body = RegisterRequest {
        machine_key: machine_key_bytes.clone(),
        node_key: node_key_bytes.clone(),
        preauth_key: preauth.key.clone(),
    };

    // create grants engine with wildcard policy (allow all)
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::Wildcard],
        dst: vec![Selector::Wildcard],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });
    let grants = GrantsEngine::new(policy);

    // create app
    let app = railscale::create_app(db, grants).await;

    // send request
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let register_response: RegisterResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(register_response.machine_key, machine_key.as_bytes());
    assert_eq!(register_response.node_key, node_key.as_bytes());
    assert!(register_response.node_id > 0);
}
