//! tests for response format in /machine/map endpoint
//!
//! tests for: zstd compression, disco key updates, cidr formatting

mod map_common;

use axum::{body::Body, http::Request, http::StatusCode};
use map_common::{
    MapTestFixture, read_length_prefixed_response, read_length_prefixed_zstd_response,
};
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::GrantsEngine;
use railscale_proto::MapRequest;
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tower::ServiceExt;

#[tokio::test]
async fn test_map_request_with_zstd_compression() {
    let fixture = MapTestFixture::new().await;
    let mut map_request = fixture.map_request();
    map_request.compress = Some("zstd".to_string());

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

    // body should be length-prefixed with zstd payload
    assert!(body.len() >= 4, "Response should have length prefix");

    // extract and decompress zstd payload
    let (map_response, _) = read_length_prefixed_zstd_response(&body)
        .expect("Should be valid length-prefixed zstd response");

    // verify response contents
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.node_key, fixture.node_key);
}

#[tokio::test]
async fn test_map_request_updates_disco_key() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a node with empty disco_key (simulating registration)
    let machine_key = MachineKey::from_bytes(vec![1u8; 32]);
    let node_key = NodeKey::from_bytes(vec![2u8; 32]);

    let now = chrono::Utc::now();
    let node = Node {
        id: NodeId(0),
        machine_key: machine_key.clone(),
        node_key: node_key.clone(),
        disco_key: DiscoKey::default(), // empty disco key!
        ipv4: Some("100.64.0.1".parse().unwrap()),
        ipv6: Some("fd7a:115c:a1e0::1".parse().unwrap()),
        endpoints: vec![],
        hostinfo: None,
        hostname: "test-node".to_string(),
        given_name: "test-node".to_string(),
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
    };

    db.create_node(&node).await.unwrap();

    // the disco key that the client will send
    let client_disco_key = DiscoKey::from_bytes(vec![3u8; 32]);

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(client_disco_key.clone()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: None,
    };

    let grants = GrantsEngine::new(map_common::wildcard_policy());
    let config = railscale_types::Config::default();
    let app = railscale::create_app(
        db.clone(),
        grants,
        config,
        None,
        StateNotifier::default(),
        None,
    )
    .await;

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

    // should include the node's own information with the disco_key from the request
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(
        response_node.disco_key, client_disco_key,
        "MapResponse should contain the disco_key sent by client"
    );

    // also verify it was persisted to the database
    let updated_node = db.get_node_by_node_key(&node_key).await.unwrap().unwrap();
    assert_eq!(
        updated_node.disco_key, client_disco_key,
        "Node in database should have the disco_key updated"
    );
}

#[tokio::test]
async fn test_map_response_addresses_are_cidr() {
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

    // verify addresses are in cidr notation
    let response_node = map_response.node.expect("should have node");
    assert!(
        response_node
            .addresses
            .iter()
            .all(|addr| addr.contains('/')),
        "All addresses should be in CIDR notation, got: {:?}",
        response_node.addresses
    );
    assert!(
        response_node
            .addresses
            .contains(&"100.64.0.1/32".to_string()),
        "Should contain IPv4 with /32 prefix"
    );
    assert!(
        response_node
            .addresses
            .contains(&"fd7a:115c:a1e0::1/128".to_string()),
        "Should contain IPv6 with /128 prefix"
    );

    // allowedips should also be in cidr notation
    assert!(
        response_node
            .allowed_ips
            .iter()
            .all(|addr| addr.contains('/')),
        "All allowed_ips should be in CIDR notation, got: {:?}",
        response_node.allowed_ips
    );
}
