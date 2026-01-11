//! tests for /machine/register endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_types::{PreAuthKey, User, UserId};
use tower::ServiceExt;

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

    // create app with default config
    let config = railscale_types::Config::default();
    let app = railscale::create_app(
        db,
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // tailscale-format registerrequest json
    // nodekey is "nodekey:" + 64 hex chars (32 bytes)
    let tailscale_request = serde_json::json!({
        "Version": 95,
        "NodeKey": "nodekey:0101010101010101010101010101010101010101010101010101010101010101",
        "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        "Auth": {
            "AuthKey": preauth.key
        }
    });

    // send request
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(Body::from(tailscale_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // verify tailscale-format response fields
    assert!(json.get("MachineAuthorized").is_some());
    assert_eq!(json["MachineAuthorized"], true);
    assert!(json.get("User").is_some());
}

/// test that the register endpoint accepts tailscale-format requests.
///
/// tailscale clients send registerrequest with:
/// - Keys as prefixed hex strings (e.g., "nodekey:abc123...")
/// - Auth key nested in Auth.AuthKey
/// - PascalCase field names
#[tokio::test]
async fn test_register_with_tailscale_format() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key
    let mut preauth = PreAuthKey::new(1, "tskey-auth-test123".to_string(), user.id);
    preauth.tags = vec![];
    let preauth = db.create_preauth_key(&preauth).await.unwrap();

    // create grants engine with wildcard policy
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
    let config = railscale_types::Config::default();
    let app = railscale::create_app(
        db,
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // tailscale-format registerrequest json
    // nodekey is "nodekey:" + 64 hex chars (32 bytes)
    let tailscale_request = serde_json::json!({
        "Version": 95,
        "NodeKey": "nodekey:0202020202020202020202020202020202020202020202020202020202020202",
        "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        "Auth": {
            "AuthKey": preauth.key
        },
        "Hostinfo": {
            "Hostname": "test-machine",
            "OS": "linux",
            "GoArch": "amd64"
        }
    });

    // send request
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(Body::from(tailscale_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // should succeed with 200 ok
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Expected 200 OK for Tailscale-format request"
    );

    // parse response - should have user, login, machineauthorized fields
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // verify tailscale-format response fields
    assert!(
        json.get("MachineAuthorized").is_some(),
        "Response should have MachineAuthorized field"
    );
    assert!(
        json.get("User").is_some(),
        "Response should have User field"
    );
}

/// requests over the ts2021 http/2 connection. The body is json, but the header
///is missing
/// the real tailscale client does not send a content-type header when making
/// requests over the ts2021 HTTP/2 connection. The body is JSON, but the header
//set up test database
#[tokio::test]
async fn test_register_without_content_type_header() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key
    let mut preauth = PreAuthKey::new(1, "tskey-no-content-type".to_string(), user.id);
    preauth.tags = vec![];
    let preauth = db.create_preauth_key(&preauth).await.unwrap();

    // create grants engine with wildcard policy
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
    let config = railscale_types::Config::default();
    let app = railscale::create_app(
        db,
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // tailscale-format registerrequest json (same format, just no Content-Type)
    let tailscale_request = serde_json::json!({
        "Version": 95,
        "NodeKey": "nodekey:0303030303030303030303030303030303030303030303030303030303030303",
        "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        "Auth": {
            "AuthKey": preauth.key
        }
    });

    // send request WITHOUT Content-Type header (like real Tailscale client)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                // NOTE: no content-type header!
                .body(Body::from(tailscale_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // should succeed with 200 ok, not 415 Unsupported Media Type
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Expected 200 OK even without Content-Type header"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["MachineAuthorized"], true);
}
