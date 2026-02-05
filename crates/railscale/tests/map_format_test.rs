//! tests for response format in /machine/map endpoint.
//!
//! tests for: zstd compression, disco key updates, hostinfo updates, cidr formatting.

mod map_common;

use axum::{body::Body, http::Request, http::StatusCode};
use map_common::{
    MapTestFixture, read_length_prefixed_response, read_length_prefixed_zstd_response,
};
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::GrantsEngine;
use railscale_proto::MapRequest;
use railscale_types::{
    DiscoKey, HostInfo, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId,
};
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
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
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
async fn test_map_request_updates_hostinfo() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a node with NO hostinfo (simulating initial registration)
    let machine_key = MachineKey::from_bytes(vec![1u8; 32]);
    let node_key = NodeKey::from_bytes(vec![2u8; 32]);
    let disco_key = DiscoKey::from_bytes(vec![3u8; 32]);

    let now = chrono::Utc::now();
    let node = Node {
        id: NodeId(0),
        machine_key: machine_key.clone(),
        node_key: node_key.clone(),
        disco_key: disco_key.clone(),
        ipv4: Some("100.64.0.1".parse().unwrap()),
        ipv6: Some("fd7a:115c:a1e0::1".parse().unwrap()),
        endpoints: vec![],
        hostinfo: None, // No hostinfo!
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
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };

    db.create_node(&node).await.unwrap();

    // the hostinfo that the client will send in maprequest
    let client_hostinfo = HostInfo {
        os: Some("linux".to_string()),
        os_version: Some("6.12.63".to_string()),
        hostname: Some("test-node".to_string()),
        distro: Some("nixos".to_string()),
        distro_version: Some("26.05".to_string()),
        go_arch: Some("amd64".to_string()),
        ..Default::default()
    };

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(disco_key.clone()),
        endpoints: vec![],
        hostinfo: Some(client_hostinfo.clone()),
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

    // should include the node's own information with the hostinfo from the request
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert!(
        response_node.hostinfo.is_some(),
        "MapResponse should contain hostinfo"
    );
    let returned_hostinfo = response_node.hostinfo.unwrap();
    assert_eq!(
        returned_hostinfo.os, client_hostinfo.os,
        "Hostinfo OS should match"
    );
    assert_eq!(
        returned_hostinfo.hostname, client_hostinfo.hostname,
        "Hostinfo hostname should match"
    );

    // also verify it was persisted to the database
    let updated_node = db.get_node_by_node_key(&node_key).await.unwrap().unwrap();
    assert!(
        updated_node.hostinfo.is_some(),
        "Node in database should have hostinfo set"
    );
    let db_hostinfo = updated_node.hostinfo.unwrap();
    assert_eq!(
        db_hostinfo.os, client_hostinfo.os,
        "Database hostinfo OS should match"
    );
    assert_eq!(
        db_hostinfo.hostname, client_hostinfo.hostname,
        "Database hostinfo hostname should match"
    );
}

#[tokio::test]
async fn test_peer_hostinfo_included_in_map_response() {
    // test that when node a queries the map, peer node b's hostinfo is included
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    let now = chrono::Utc::now();

    // create peer node (node b) with hostinfo
    let peer_hostinfo = HostInfo {
        os: Some("linux".to_string()),
        hostname: Some("peer-node".to_string()),
        distro: Some("nixos".to_string()),
        ..Default::default()
    };

    let peer_node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![10u8; 32]),
        node_key: NodeKey::from_bytes(vec![20u8; 32]),
        disco_key: DiscoKey::from_bytes(vec![30u8; 32]),
        ipv4: Some("100.64.0.2".parse().unwrap()),
        ipv6: Some("fd7a:115c:a1e0::2".parse().unwrap()),
        endpoints: vec![],
        hostinfo: Some(peer_hostinfo.clone()), // Peer has hostinfo
        hostname: "peer-node".to_string(),
        given_name: "peer-node".to_string(),
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
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };
    db.create_node(&peer_node).await.unwrap();

    // create requesting node (node a)
    let node_key = NodeKey::from_bytes(vec![2u8; 32]);
    let node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![1u8; 32]),
        node_key: node_key.clone(),
        disco_key: DiscoKey::from_bytes(vec![3u8; 32]),
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
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };
    db.create_node(&node).await.unwrap();

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(DiscoKey::from_bytes(vec![3u8; 32])),
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

    // should have one peer (peer_node)
    assert_eq!(map_response.peers.len(), 1, "Should have one peer");

    let peer = &map_response.peers[0];
    assert!(
        peer.hostinfo.is_some(),
        "Peer should have hostinfo in MapResponse - Tailscale client needs this to display peer status"
    );

    let peer_hi = peer.hostinfo.as_ref().unwrap();
    assert_eq!(
        peer_hi.hostname,
        Some("peer-node".to_string()),
        "Peer hostinfo hostname should match"
    );
    assert_eq!(
        peer_hi.os,
        Some("linux".to_string()),
        "Peer hostinfo OS should match"
    );
}

#[tokio::test]
async fn test_peer_without_hostinfo_gets_default_hostinfo() {
    // test that when a peer has no hostinfo stored, we still send an empty hostinfo struct
    // to avoid nil pointer crashes in the Tailscale client when it accesses Hostinfo.Hostname()
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    let now = chrono::Utc::now();

    // create peer node (node b) without hostinfo - simulates a freshly registered node
    // that hasn't sent its first MapRequest yet
    let peer_node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![10u8; 32]),
        node_key: NodeKey::from_bytes(vec![20u8; 32]),
        disco_key: DiscoKey::from_bytes(vec![30u8; 32]),
        ipv4: Some("100.64.0.2".parse().unwrap()),
        ipv6: Some("fd7a:115c:a1e0::2".parse().unwrap()),
        endpoints: vec![],
        hostinfo: None, // NO hostinfo!
        hostname: "peer-node".to_string(),
        given_name: "peer-node".to_string(),
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
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };
    db.create_node(&peer_node).await.unwrap();

    // create requesting node (node a)
    let node_key = NodeKey::from_bytes(vec![2u8; 32]);
    let node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![1u8; 32]),
        node_key: node_key.clone(),
        disco_key: DiscoKey::from_bytes(vec![3u8; 32]),
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
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };
    db.create_node(&node).await.unwrap();

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(DiscoKey::from_bytes(vec![3u8; 32])),
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

    // should have one peer (peer_node)
    assert_eq!(map_response.peers.len(), 1, "Should have one peer");

    let peer = &map_response.peers[0];

    // critical: even when peer has no hostinfo stored, we must send a hostinfo struct
    // to prevent nil pointer dereference in Tailscale client when it calls Hostinfo.Hostname()
    assert!(
        peer.hostinfo.is_some(),
        "Peer MUST have hostinfo in MapResponse even if empty - Tailscale client crashes on nil Hostinfo"
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

#[tokio::test]
async fn test_map_response_includes_file_sharing_cap_when_taildrop_enabled() {
    // default config has taildrop_enabled = true
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

    let (map_response, _) = read_length_prefixed_response(&body).expect("Should be valid response");

    let response_node = map_response.node.expect("Should have self node");

    // when taildrop_enabled, self node should have CapabilityFileSharing in CapMap
    assert!(
        response_node.cap_map.is_some(),
        "Self node should have cap_map when taildrop enabled"
    );

    let cap_map = response_node.cap_map.unwrap();
    assert!(
        cap_map.contains_key(railscale_proto::CAP_FILE_SHARING),
        "Self node cap_map should contain file-sharing capability, got: {:?}",
        cap_map.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_map_response_excludes_file_sharing_cap_when_taildrop_disabled() {
    use railscale_types::Config;

    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    let node_key = NodeKey::from_bytes(vec![2u8; 32]);
    let disco_key = DiscoKey::from_bytes(vec![3u8; 32]);

    let now = chrono::Utc::now();
    let node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![1u8; 32]),
        node_key: node_key.clone(),
        disco_key: disco_key.clone(),
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
        posture_attributes: std::collections::HashMap::new(),
        nl_public_key: None,
        last_seen_country: None,
        ephemeral: false,
    };

    db.create_node(&node).await.unwrap();

    // config with taildrop DISABLED
    let mut config = Config::default();
    config.taildrop_enabled = false;

    let grants = GrantsEngine::new(map_common::wildcard_policy());
    let app = railscale::create_app(
        db.clone(),
        grants,
        config,
        None,
        StateNotifier::default(),
        None,
    )
    .await;

    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion::CURRENT,
        node_key: node_key.clone(),
        disco_key: Some(disco_key.clone()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: None,
    };

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

    let (map_response, _) = read_length_prefixed_response(&body).expect("Should be valid response");

    let response_node = map_response.node.expect("Should have self node");

    // when taildrop_disabled, self node should NOT have file-sharing capability
    if let Some(cap_map) = &response_node.cap_map {
        assert!(
            !cap_map.contains_key(railscale_proto::CAP_FILE_SHARING),
            "Self node should NOT have file-sharing capability when taildrop disabled"
        );
    }
    // cap_map being None is also acceptable when taildrop is disabled
}
