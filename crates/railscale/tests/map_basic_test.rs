//! basic tests for /machine/map endpoint.
//!
//! tests for basic response fields: node info, peers, dns config, derp map.

mod map_common;

use axum::{body::Body, http::Request, http::StatusCode};
use map_common::{MapTestFixture, read_length_prefixed_response};
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{GrantsEngine, Policy};
use railscale_proto::MapRequest;
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tower::ServiceExt;

#[tokio::test]
async fn test_map_request_returns_node() {
    let fixture = MapTestFixture::new().await;
    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (map_response, remaining) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");
    assert!(remaining.is_empty());

    // should include the node's own information
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, fixture.node.id.0);
    assert_eq!(response_node.node_key, fixture.node_key);

    // should have addresses in CIDR notation
    assert!(!response_node.addresses.is_empty());
    assert!(
        response_node
            .addresses
            .contains(&"100.64.0.1/32".to_string())
    );
}

#[tokio::test]
async fn test_map_request_returns_peers() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    let node1_key = NodeKey::from_bytes(vec![1u8; 32]);
    let node2_key = NodeKey::from_bytes(vec![2u8; 32]);

    let now = chrono::Utc::now();

    let node1 = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![10u8; 32]),
        node_key: node1_key.clone(),
        disco_key: DiscoKey::from_bytes(vec![11u8; 32]),
        ipv4: Some("100.64.0.1".parse().unwrap()),
        ipv6: None,
        endpoints: vec![],
        hostinfo: None,
        hostname: "node1".to_string(),
        given_name: "node1".to_string(),
        user_id: Some(user.id),
        register_method: RegisterMethod::AuthKey,
        tags: vec![],
        auth_key_id: None,
        last_seen: Some(now),
        expiry: None,
        approved_routes: vec![],
        created_at: now,
        updated_at: now,
        is_online: None,
        posture_attributes: std::collections::HashMap::new(),
    };

    let node2 = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![20u8; 32]),
        node_key: node2_key.clone(),
        disco_key: DiscoKey::from_bytes(vec![21u8; 32]),
        ipv4: Some("100.64.0.2".parse().unwrap()),
        ipv6: None,
        endpoints: vec![],
        hostinfo: None,
        hostname: "node2".to_string(),
        given_name: "node2".to_string(),
        user_id: Some(user.id),
        register_method: RegisterMethod::AuthKey,
        tags: vec![],
        auth_key_id: None,
        last_seen: Some(now),
        expiry: None,
        approved_routes: vec![],
        created_at: now,
        updated_at: now,
        is_online: None,
        posture_attributes: std::collections::HashMap::new(),
    };

    db.create_node(&node1).await.unwrap();
    db.create_node(&node2).await.unwrap();

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node1_key.clone(),
        disco_key: None,
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: None,
    };

    let grants = GrantsEngine::new(map_common::wildcard_policy());
    let config = railscale_types::Config::default();
    let app = railscale::create_app(db, grants, config, None, StateNotifier::default(), None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (map_response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // should include peers (node2)
    assert_eq!(map_response.peers.len(), 1);
    let peer = &map_response.peers[0];
    assert_eq!(peer.node_key, node2_key);
}

#[tokio::test]
async fn test_map_request_returns_dns_config() {
    let fixture = MapTestFixture::with_policy(Policy::default()).await;
    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let (response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // verify dns config
    let dns = response.dns_config.expect("Missing DNS config");
    assert!(
        dns.resolvers.iter().any(|r| r.addr == "100.100.100.100"),
        "Should have MagicDNS resolver"
    );
    assert!(dns.domains.contains(&"railscale.net".to_string()));
    assert!(dns.routes.contains_key("railscale.net"));
}

#[tokio::test]
async fn test_map_request_returns_derp_map() {
    let fixture = MapTestFixture::with_policy(Policy::default()).await;
    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let (response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // verify derp map
    let derp = response.derp_map.expect("Missing DERP map");
    assert!(!derp.regions.is_empty());
}

#[tokio::test]
async fn test_map_response_node_includes_machine_authorized() {
    let fixture = MapTestFixture::new().await;
    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (map_response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // node should have machineauthorized set to true (it was registered)
    let node = map_response.node.expect("Missing node in response");
    assert!(
        node.machine_authorized,
        "MachineAuthorized should be true for registered nodes"
    );
}

#[tokio::test]
async fn test_map_response_includes_tka_info_when_enabled() {
    use railscale_db::TkaState;

    let fixture = MapTestFixture::new().await;

    // enable tka with a head hash
    let tka_state = TkaState {
        id: 0,
        enabled: true,
        head: Some("abc123deadbeef".to_string()),
        state_checkpoint: None,
        disablement_secrets: None,
        genesis_aum: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    fixture.db.upsert_tka_state(&tka_state).await.unwrap();

    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (map_response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // should include tka_info when enabled
    let tka_info = map_response.tka_info.expect("Missing TkaInfo in response");
    assert_eq!(tka_info.head, "abc123deadbeef");
    assert!(!tka_info.disabled);
}

#[tokio::test]
async fn test_map_response_tka_info_none_when_disabled() {
    let fixture = MapTestFixture::new().await;
    // no tka state set, so it should be disabled by default

    let map_request = fixture.map_request();

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (map_response, _) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // tka_info should be none when tka is not enabled
    assert!(map_response.tka_info.is_none());
}
