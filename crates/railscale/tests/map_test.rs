//! tests for /machine/map endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use serde_json;
use tower::ServiceExt;

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
        disco_key: Some(disco_key.as_bytes().to_vec()),
        endpoints: vec![],
        hostinfo: None,
        omit_peers: false,
        stream: false,
        debug_flags: vec![],
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
    assert_eq!(response_node.node_key, node_key.as_bytes());
    assert_eq!(response_node.machine_key, machine_key.as_bytes());
    assert_eq!(response_node.disco_key, disco_key.as_bytes());

    // should have addresses
    assert!(!response_node.addresses.is_empty());
    assert!(response_node.addresses.contains(&"100.64.0.1".to_string()));
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
    assert_eq!(peer.node_key, node2_key.as_bytes());
}
