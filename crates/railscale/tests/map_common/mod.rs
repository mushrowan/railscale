//! shared test utilities for map endpoint tests

#![allow(dead_code)] // Test utilities may not all be used in every test file

use axum::Router;
use bytes::Buf;
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{
    DiscoKey, MachineKey, Node, NodeKey, User, UserId, test_utils::TestNodeBuilder,
};

/// test fixture containing database, node, and app for map tests
pub struct MapTestFixture {
    pub db: RailscaleDb,
    pub node: Node,
    pub node_key: NodeKey,
    pub disco_key: DiscoKey,
    pub app: Router,
}

impl MapTestFixture {
    /// create a new test fixture with a single node and wildcard grants
    pub async fn new() -> Self {
        Self::with_policy(wildcard_policy()).await
    }

    /// create a new test fixture with custom policy
    pub async fn with_policy(policy: Policy) -> Self {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let user = User::new(UserId::new(1), "test-user".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node_key = NodeKey::from_bytes([2u8; 32]);
        let disco_key = DiscoKey::from_bytes([3u8; 32]);

        let node = TestNodeBuilder::new(0)
            .with_machine_key(MachineKey::from_bytes([1u8; 32]))
            .with_node_key(node_key.clone())
            .with_disco_key(disco_key.clone())
            .with_ipv4("100.64.0.1".parse().unwrap())
            .with_ipv6("fd7a:115c:a1e0::1".parse().unwrap())
            .with_hostname("test-node")
            .with_user_id(user.id)
            .build();

        let node = db.create_node(&node).await.unwrap();
        let grants = GrantsEngine::new(policy);
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

        Self {
            db,
            node,
            node_key,
            disco_key,
            app,
        }
    }

    /// build a maprequest for this fixture's node
    pub fn map_request(&self) -> MapRequest {
        MapRequest {
            version: railscale_proto::CapabilityVersion::CURRENT,
            node_key: self.node_key.clone(),
            disco_key: Some(self.disco_key.clone()),
            endpoints: vec![],
            hostinfo: None,
            omit_peers: false,
            stream: false,
            debug_flags: vec![],
            compress: None,
        }
    }
}

/// create a wildcard policy that allows all
pub fn wildcard_policy() -> Policy {
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::Wildcard],
        dst: vec![Selector::Wildcard],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });
    policy
}

/// helper to read a length-prefixed json message from a buffer
/// returns the parsed mapresponse and remaining bytes
pub fn read_length_prefixed_response(buf: &[u8]) -> Option<(MapResponse, &[u8])> {
    if buf.len() < 4 {
        return None;
    }

    let len = (&buf[..4]).get_u32_le() as usize;
    if buf.len() < 4 + len {
        return None;
    }

    let json_bytes = &buf[4..4 + len];
    let response: MapResponse = serde_json::from_slice(json_bytes).ok()?;
    Some((response, &buf[4 + len..]))
}

/// helper to read a length-prefixed zstd-compressed message from a buffer
pub fn read_length_prefixed_zstd_response(buf: &[u8]) -> Option<(MapResponse, &[u8])> {
    if buf.len() < 4 {
        return None;
    }

    let len = (&buf[..4]).get_u32_le() as usize;
    if buf.len() < 4 + len {
        return None;
    }

    let compressed_bytes = &buf[4..4 + len];
    let cursor = std::io::Cursor::new(compressed_bytes);
    let decompressed = zstd::stream::decode_all(cursor).ok()?;
    let response: MapResponse = serde_json::from_slice(&decompressed).ok()?;
    Some((response, &buf[4 + len..]))
}
