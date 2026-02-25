//! tests for policy hot-reload functionality.
//!
//! tests that policy can be reloaded at runtime without restarting the server.

mod map_common;

use axum::{body::Body, http::Request};
use map_common::read_length_prefixed_response;
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, NetworkCapability, Policy, Selector};
use railscale_proto::MapRequest;
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tower::ServiceExt;

#[tokio::test]
async fn test_policy_hot_reload_changes_visibility() {
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create users
    let alicja = db
        .create_user(&User::new(UserId(1), "alicja@example.com".to_string()))
        .await
        .unwrap();
    let ro = db
        .create_user(&User::new(UserId(2), "ro@example.com".to_string()))
        .await
        .unwrap();

    // create nodes
    let now = chrono::Utc::now();
    let alicja_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![1u8; 32]),
            node_key: NodeKey::from_bytes(vec![11u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![21u8; 32]),
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "alicja-node".to_string(),
            given_name: "alicja-node".parse().unwrap(),
            user_id: Some(alicja.id),
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
        })
        .await
        .unwrap();

    let ro_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![2u8; 32]),
            node_key: NodeKey::from_bytes(vec![12u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![22u8; 32]),
            ipv4: Some("100.64.0.2".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "ro-node".to_string(),
            given_name: "ro-node".parse().unwrap(),
            user_id: Some(ro.id),
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
        })
        .await
        .unwrap();

    // start with empty policy (deny all)
    let policy = Policy::empty();
    let config = railscale_types::Config::default();
    let (app, policy_handle) = railscale::create_app_with_policy_handle(
        db,
        policy,
        config,
        None,
        StateNotifier::default(),
        None,
        None,
    )
    .await;

    // helper to request map
    let request_map = |app: axum::Router, node_key: NodeKey| async move {
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
        let (map_response, _) =
            read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");
        map_response
    };

    // initially alicja should not see ro (empty policy)
    let alice_map = request_map(app.clone(), alicja_node.node_key.clone()).await;
    assert_eq!(
        alice_map.peers.len(),
        0,
        "With empty policy, Alicja should not see any peers"
    );

    // reload policy to allow alicja -> ro
    let mut new_policy = Policy::empty();
    new_policy.grants.push(Grant {
        src: vec![Selector::User("alicja@example.com".to_string())],
        dst: vec![Selector::User("ro@example.com".to_string())],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });
    policy_handle.reload(new_policy).await;

    // now alicja should see ro
    let alice_map = request_map(app.clone(), alicja_node.node_key.clone()).await;
    assert_eq!(
        alice_map.peers.len(),
        1,
        "After policy reload, Alicja should see Ro"
    );
    assert_eq!(alice_map.peers[0].id, ro_node.id.0);

    // reload back to empty policy
    policy_handle.reload(Policy::empty()).await;

    // alicja should not see ro again
    let alice_map = request_map(app.clone(), alicja_node.node_key).await;
    assert_eq!(
        alice_map.peers.len(),
        0,
        "After reverting policy, Alicja should not see any peers"
    );
}
