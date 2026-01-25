//! tests for /machine/register endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_types::{PreAuthKey, PreAuthKeyToken, User, UserId};
use tower::ServiceExt;

#[tokio::test]
async fn test_register_with_preauth_key() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key using token
    let token = PreAuthKeyToken::generate();
    let mut preauth = PreAuthKey::from_token(1, &token, user.id);
    preauth.tags = vec![]; // user-owned node
    let _preauth = db.create_preauth_key(&preauth).await.unwrap();

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

    // create app with allow_non_noise_registration for testing without Noise
    let mut config = railscale_types::Config::default();
    config.allow_non_noise_registration = true;
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
            "AuthKey": token.as_str()
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

    // create a preauth key using token
    let token = PreAuthKeyToken::generate();
    let mut preauth = PreAuthKey::from_token(1, &token, user.id);
    preauth.tags = vec![];
    let _preauth = db.create_preauth_key(&preauth).await.unwrap();

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

    // create app with allow_non_noise_registration for testing without Noise
    let mut config = railscale_types::Config::default();
    config.allow_non_noise_registration = true;
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
            "AuthKey": token.as_str()
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

/// test that register allocates ip addresses to the node.
///
/// when a node registers, it should be assigned ipv4 and ipv6 addresses
/// from the configured prefixes.
#[tokio::test]
async fn test_register_allocates_ip_addresses() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key using token
    let token = PreAuthKeyToken::generate();
    let mut preauth = PreAuthKey::from_token(1, &token, user.id);
    preauth.tags = vec![];
    let _preauth = db.create_preauth_key(&preauth).await.unwrap();

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

    // create app with allow_non_noise_registration for testing without Noise
    let mut config = railscale_types::Config::default();
    config.allow_non_noise_registration = true;
    let app = railscale::create_app(
        db.clone(),
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // register a node
    let node_key = "nodekey:0404040404040404040404040404040404040404040404040404040404040404";
    let tailscale_request = serde_json::json!({
        "Version": 95,
        "NodeKey": node_key,
        "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        "Auth": {
            "AuthKey": token.as_str()
        },
        "Hostinfo": {
            "Hostname": "ip-alloc-test"
        }
    });

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

    assert_eq!(response.status(), StatusCode::OK);

    // verify the node was created with ip addresses
    // parse node key using serde (same format the server uses)
    let node_key_parsed: railscale_types::NodeKey =
        serde_json::from_value(serde_json::json!(node_key)).expect("valid node key");
    let node = db
        .get_node_by_node_key(&node_key_parsed)
        .await
        .expect("db query should succeed")
        .expect("node should exist");

    // node should have both ipv4 and ipv6 addresses assigned
    assert!(
        node.ipv4.is_some(),
        "Node should have an IPv4 address assigned"
    );
    assert!(
        node.ipv6.is_some(),
        "Node should have an IPv6 address assigned"
    );

    // ipv4 should be in the tailscale cgnat range (100.64.0.0/10)
    if let Some(ipv4) = node.ipv4 {
        let ip: std::net::Ipv4Addr = match ipv4 {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("Expected IPv4 address"),
        };
        assert!(
            ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] < 128,
            "IPv4 should be in 100.64.0.0/10 range, got {ip}"
        );
    }

    // ipv6 should be in the tailscale ula range (fd7a:115c:a1e0::/48)
    if let Some(ipv6) = node.ipv6 {
        let ip: std::net::Ipv6Addr = match ipv6 {
            std::net::IpAddr::V6(v6) => v6,
            _ => panic!("Expected IPv6 address"),
        };
        let segments = ip.segments();
        assert!(
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0,
            "IPv6 should be in fd7a:115c:a1e0::/48 range, got {ip}"
        );
    }
}

/// test that register accepts requests without content-type header.
///
/// the real tailscale client does not send a content-type header when making
/// requests over the ts2021 HTTP/2 connection. The body is JSON, but the header
/// is missing.
#[tokio::test]
async fn test_register_without_content_type_header() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a preauth key using token
    let token = PreAuthKeyToken::generate();
    let mut preauth = PreAuthKey::from_token(1, &token, user.id);
    preauth.tags = vec![];
    let _preauth = db.create_preauth_key(&preauth).await.unwrap();

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

    // create app with allow_non_noise_registration for testing without Noise
    let mut config = railscale_types::Config::default();
    config.allow_non_noise_registration = true;
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
            "AuthKey": token.as_str()
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
