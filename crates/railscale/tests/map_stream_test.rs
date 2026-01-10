//! tests for streaming /machine/map endpoint.
//!
//! when `stream: true` is set in maprequest, the server keeps the connection
//! open and pushes updates as length-prefixed JSON messages.
//!
//! message format:
//! - 4 bytes: little-endian u32 length of json payload
//! - n bytes: json-encoded mapresponse

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bytes::Buf;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tokio::time::timeout;
use tower::ServiceExt;

/// test fixture containing database, node, and app for map tests.
struct MapTestFixture {
    #[allow(dead_code)] // May be needed for future tests adding nodes
    db: RailscaleDb,
    node: Node,
    node_key: NodeKey,
    disco_key: DiscoKey,
    app: Router,
}

impl MapTestFixture {
    /// create a new test fixture with a single node and wildcard grants.
    async fn new() -> Self {
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
        };

        let node = db.create_node(&node).await.unwrap();

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

        let config = railscale_types::Config::default();
        let app = railscale::create_app(db.clone(), grants, config, None).await;

        Self {
            db,
            node,
            node_key,
            disco_key,
            app,
        }
    }

    /// build a maprequest for this fixture's node.
    fn map_request(&self, stream: bool) -> MapRequest {
        MapRequest {
            version: railscale_proto::CapabilityVersion(100),
            node_key: self.node_key.clone(),
            disco_key: Some(self.disco_key.as_bytes().to_vec()),
            endpoints: vec![],
            hostinfo: None,
            omit_peers: false,
            stream,
            debug_flags: vec![],
        }
    }
}

/// helper to read a length-prefixed json message from a buffer.
/// returns the parsed mapresponse and remaining bytes.
fn read_length_prefixed_response(buf: &[u8]) -> Option<(MapResponse, &[u8])> {
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

#[tokio::test]
async fn test_streaming_map_request_returns_length_prefixed_response() {
    let fixture = MapTestFixture::new().await;
    let map_request = fixture.map_request(true);

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

    // read the body with a timeout (streaming would hang forever otherwise)
    let body_result = timeout(
        Duration::from_secs(2),
        axum::body::to_bytes(response.into_body(), 1024 * 1024),
    )
    .await;

    let body = body_result
        .expect("timeout waiting for response")
        .expect("failed to read body");

    // parse length-prefixed response
    let (map_response, remaining) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    // should have node info
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, fixture.node.id.0);
    assert_eq!(response_node.node_key, fixture.node_key.as_bytes());

    // keep_alive should be true for streaming
    assert!(map_response.keep_alive);

    // no remaining bytes after initial response (for this simple test)
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn test_non_streaming_map_request_returns_plain_json() {
    let fixture = MapTestFixture::new().await;
    let map_request = fixture.map_request(false);

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

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();

    // non-streaming should return plain json (no length prefix)
    let map_response: MapResponse = serde_json::from_slice(&body).unwrap();

    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, fixture.node.id.0);

    // keep_alive should be false for non-streaming
    assert!(!map_response.keep_alive);
}
