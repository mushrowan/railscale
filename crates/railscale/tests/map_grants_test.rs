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
    let alicja = db
        .create_user(&User::new(UserId(1), "alicja@example.com".to_string()))
        .await
        .unwrap();
    let ro = db
        .create_user(&User::new(UserId(2), "ro@example.com".to_string()))
        .await
        .unwrap();
    let esme = db
        .create_user(&User::new(UserId(3), "esme@example.com".to_string()))
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

    let _esme_node = db
        .create_node(&Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![3u8; 32]),
            node_key: NodeKey::from_bytes(vec![13u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![23u8; 32]),
            ipv4: Some("100.64.0.3".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "esme-node".to_string(),
            given_name: "esme-node".parse().unwrap(),
            user_id: Some(esme.id),
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

    // define policy: Alicja can see Ro
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::User("alicja@example.com".to_string())],
        dst: vec![Selector::User("ro@example.com".to_string())],
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

    // alicja should see Ro
    let alice_map = request_map(alicja_node.node_key).await;
    assert_eq!(alice_map.peers.len(), 1);
    assert_eq!(alice_map.peers[0].id, ro_node.id.0);

    // alicja's user_profiles should contain alicja + ro, but NOT esme
    let alice_profile_ids: std::collections::HashSet<u64> =
        alice_map.user_profiles.iter().map(|p| p.id).collect();
    assert!(
        alice_profile_ids.contains(&alicja.id.0),
        "alicja should see her own profile"
    );
    assert!(
        alice_profile_ids.contains(&ro.id.0),
        "alicja should see ro's profile (visible peer)"
    );
    assert!(
        !alice_profile_ids.contains(&esme.id.0),
        "alicja should NOT see esme's profile (not a visible peer)"
    );
    assert_eq!(
        alice_map.user_profiles.len(),
        2,
        "only alicja + ro profiles expected"
    );

    // ro should not see anyone (directional grant)
    let bob_map = request_map(ro_node.node_key).await;
    assert_eq!(bob_map.peers.len(), 0);

    // ro's user_profiles should only contain ro (no visible peers)
    let bob_profile_ids: std::collections::HashSet<u64> =
        bob_map.user_profiles.iter().map(|p| p.id).collect();
    assert!(
        bob_profile_ids.contains(&ro.id.0),
        "ro should see his own profile"
    );
    assert!(
        !bob_profile_ids.contains(&alicja.id.0),
        "ro should NOT see alicja's profile"
    );
    assert!(
        !bob_profile_ids.contains(&esme.id.0),
        "ro should NOT see esme's profile"
    );
    assert_eq!(
        bob_map.user_profiles.len(),
        1,
        "only ro's own profile expected"
    );
}
