//! tests for /machine/map endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tower::ServiceExt;
use zstd::stream::decode_all;

#[tokio::test]
async fn test_map_request_returns_node() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a node
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

    let node = db.create_node(&node).await.unwrap();

    // build maprequest
    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(disco_key.clone()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: None,
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

    // send request
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

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let map_response: MapResponse = serde_json::from_slice(&body).unwrap();

    // should include the node's own information
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, node.id.0);
    assert_eq!(response_node.node_key, node_key);
    assert_eq!(response_node.machine_key, machine_key);
    assert_eq!(response_node.disco_key, disco_key);

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
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create two nodes
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
    };

    db.create_node(&node1).await.unwrap();
    db.create_node(&node2).await.unwrap();

    // build maprequest from node1
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

    // send request
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

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let map_response: MapResponse = serde_json::from_slice(&body).unwrap();

    // should include peers (node2)
    assert_eq!(map_response.peers.len(), 1);
    let peer = &map_response.peers[0];
    assert_eq!(peer.node_key, node2_key);
}

#[tokio::test]
async fn test_map_request_returns_dns_config() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

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

    let config = railscale_types::Config::default();
    let grants = GrantsEngine::new(Policy::default());
    let app = railscale::create_app(
        db.clone(),
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    let map_req = MapRequest {
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

    let response = Request::builder()
        .method("POST")
        .uri("/machine/map")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&map_req).unwrap()))
        .unwrap();

    let resp = app.oneshot(response).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let response: MapResponse = serde_json::from_slice(&body).unwrap();

    // verify dns config
    let dns = response.dns_config.expect("Missing DNS config");
    assert!(dns.nameservers.contains(&"100.100.100.100".to_string()));
    assert!(dns.domains.contains(&"railscale.net".to_string()));
    assert!(dns.routes.contains_key("railscale.net"));
}

#[tokio::test]
async fn test_map_request_returns_derp_map() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

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

    let config = railscale_types::Config::default();
    let grants = GrantsEngine::new(Policy::default());
    let app = railscale::create_app(
        db.clone(),
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    let map_req = MapRequest {
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

    let response = Request::builder()
        .method("POST")
        .uri("/machine/map")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&map_req).unwrap()))
        .unwrap();

    let resp = app.oneshot(response).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let response: MapResponse = serde_json::from_slice(&body).unwrap();

    // verify derp map
    let derp = response.derp_map.expect("Missing DERP map");
    assert!(!derp.regions.is_empty());
}

#[tokio::test]
async fn test_map_request_respects_user_grants() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create users
    let alice = db
        .create_user(&User::new(UserId(1), "alice@example.com".to_string()))
        .await
        .unwrap();
    let bob = db
        .create_user(&User::new(UserId(2), "bob@example.com".to_string()))
        .await
        .unwrap();
    let charlie = db
        .create_user(&User::new(UserId(3), "charlie@example.com".to_string()))
        .await
        .unwrap();

    // create nodes
    let now = chrono::Utc::now();
    let alice_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![1u8; 32]),
            node_key: NodeKey::from_bytes(vec![11u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![21u8; 32]),
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "alice-node".to_string(),
            given_name: "alice-node".to_string(),
            user_id: Some(alice.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            last_seen: Some(now),
            expiry: None,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
        })
        .await
        .unwrap();

    let bob_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![2u8; 32]),
            node_key: NodeKey::from_bytes(vec![12u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![22u8; 32]),
            ipv4: Some("100.64.0.2".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "bob-node".to_string(),
            given_name: "bob-node".to_string(),
            user_id: Some(bob.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            last_seen: Some(now),
            expiry: None,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
        })
        .await
        .unwrap();

    let _charlie_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![3u8; 32]),
            node_key: NodeKey::from_bytes(vec![13u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![23u8; 32]),
            ipv4: Some("100.64.0.3".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "charlie-node".to_string(),
            given_name: "charlie-node".to_string(),
            user_id: Some(charlie.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            last_seen: Some(now),
            expiry: None,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
        })
        .await
        .unwrap();

    // define policy: alice can see bob
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::User("alice@example.com".to_string())],
        dst: vec![Selector::User("bob@example.com".to_string())],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });

    let grants = GrantsEngine::new(policy);
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

    // helper to request map
    let request_map = |node_key: NodeKey| {
        let app = app.clone();
        async move {
            let req = MapRequest {
                version: railscale_proto::CapabilityVersion::CURRENT,
                node_key,
                disco_key: None,
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
                        .body(Body::from(serde_json::to_string(&req).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<MapResponse>(&body).unwrap()
        }
    };

    // alice should see bob
    let alice_map = request_map(alice_node.node_key).await;
    assert_eq!(alice_map.peers.len(), 1);
    assert_eq!(alice_map.peers[0].id, bob_node.id.0);

    // bob should not see anyone (directional grant)
    let bob_map = request_map(bob_node.node_key).await;
    assert_eq!(bob_map.peers.len(), 0);
}

#[tokio::test]
async fn test_map_request_with_zstd_compression() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a node
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

    // build maprequest with zstd compression
    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(disco_key.clone()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: Some("zstd".to_string()),
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

    // send request
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

    // verify response is zstd compressed
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    // body should be zstd compressed - decompress it
    let cursor = std::io::Cursor::new(&body[..]);
    let decompressed = decode_all(cursor).expect("Should be valid zstd data");

    // parse the decompressed json
    let map_response: MapResponse =
        serde_json::from_slice(&decompressed).expect("Should be valid JSON after decompression");

    // verify response contents
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.node_key, node_key);
}

#[tokio::test]
async fn test_map_request_updates_disco_key() {
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
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

    // build maprequest with disco_key
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
        db.clone(),
        grants,
        config,
        None,
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // send request
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

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let map_response: MapResponse = serde_json::from_slice(&body).unwrap();

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
    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create a user
    let user = User::new(UserId(1), "test-user".to_string());
    let user = db.create_user(&user).await.unwrap();

    // create a node with both IPv4 and IPv6
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

    // build maprequest
    let map_request = MapRequest {
        version: railscale_proto::CapabilityVersion(100),
        node_key: node_key.clone(),
        disco_key: Some(disco_key.clone()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
        compress: None,
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

    // send request
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

    // verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let map_response: MapResponse = serde_json::from_slice(&body).unwrap();

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
