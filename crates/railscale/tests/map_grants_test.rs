//! tests for grants/visibility in /machine/map endpoint
//!
//! tests that peer visibility respects grants policy

mod map_common;

use axum::{body::Body, http::Request};
use map_common::read_length_prefixed_response;
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::MapRequest;
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tower::ServiceExt;

#[tokio::test]
async fn test_map_request_respects_user_grants() {
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
            posture_attributes: std::collections::HashMap::new(),
            last_seen_country: None,
            ephemeral: false,
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
            posture_attributes: std::collections::HashMap::new(),
            last_seen_country: None,
            ephemeral: false,
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
            posture_attributes: std::collections::HashMap::new(),
            last_seen_country: None,
            ephemeral: false,
        })
        .await
        .unwrap();

    // define policy: Alice can see Bob
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
    let app = railscale::create_app(db, grants, config, None, StateNotifier::default(), None).await;

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
            let (map_response, _) = read_length_prefixed_response(&body)
                .expect("failed to parse length-prefixed response");
            map_response
        }
    };

    // alice should see Bob
    let alice_map = request_map(alice_node.node_key).await;
    assert_eq!(alice_map.peers.len(), 1);
    assert_eq!(alice_map.peers[0].id, bob_node.id.0);

    // bob should not see anyone (directional grant)
    let bob_map = request_map(bob_node.node_key).await;
    assert_eq!(bob_map.peers.len(), 0);
}
