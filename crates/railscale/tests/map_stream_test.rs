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
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{DiscoKey, MachineKey, Node, NodeId, NodeKey, RegisterMethod, User, UserId};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tower::ServiceExt;

/// test fixture containing database, node, and app for map tests.
struct MapTestFixture {
    db: RailscaleDb,
    node: Node,
    node_key: NodeKey,
    disco_key: DiscoKey,
    app: Router,
    notifier: StateNotifier,
}

impl MapTestFixture {
    /// create a new test fixture with a single node and wildcard grants.
    async fn new() -> Self {
        Self::with_config(railscale_types::Config::default()).await
    }

    /// create a new test fixture with custom config.
    async fn with_config(config: railscale_types::Config) -> Self {
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
            last_seen_country: None,
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

        let notifier = StateNotifier::new();
        let app =
            railscale::create_app(db.clone(), grants, config, None, notifier.clone(), None).await;

        Self {
            db,
            node,
            node_key,
            disco_key,
            app,
            notifier,
        }
    }

    /// build a maprequest for this fixture's node.
    fn map_request(&self, stream: bool) -> MapRequest {
        MapRequest {
            version: railscale_proto::CapabilityVersion(100),
            node_key: self.node_key.clone(),
            disco_key: Some(self.disco_key.clone()),
            endpoints: vec![],
            hostinfo: None,
            omit_peers: false,
            stream,
            debug_flags: vec![],
            compress: None,
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

    // read the first frame from the body stream (streaming never completes)
    use http_body_util::BodyExt;
    let mut body = response.into_body();
    let frame = timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("timeout waiting for first frame")
        .expect("error reading frame")
        .expect("body ended without data");

    let data = frame.into_data().expect("frame is not data");

    // parse length-prefixed response
    let (map_response, remaining) =
        read_length_prefixed_response(&data).expect("failed to parse length-prefixed response");

    // should have node info
    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, fixture.node.id.0);
    assert_eq!(response_node.node_key, fixture.node_key);

    // first streaming response must have keep_alive=false so client processes node data.
    // tailscale client skips netmap callback when keep_alive=true, treating it as a ping.
    assert!(
        !map_response.keep_alive,
        "first streaming response must have keep_alive=false for client to process nodes"
    );

    // no remaining bytes after initial response (for this simple test)
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn test_non_streaming_map_request_returns_length_prefixed() {
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

    // non-streaming should also use length-prefixed framing (client expects it)
    let (map_response, remaining) =
        read_length_prefixed_response(&body).expect("failed to parse length-prefixed response");

    assert!(map_response.node.is_some());
    let response_node = map_response.node.unwrap();
    assert_eq!(response_node.id, fixture.node.id.0);

    // keep_alive should be false for non-streaming
    assert!(!map_response.keep_alive);

    // no remaining bytes for single response
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn test_streaming_map_receives_updates_on_state_change() {
    let fixture = MapTestFixture::new().await;
    let map_request = fixture.map_request(true);

    // start a server for true streaming (can't use oneshot for long-polling)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = fixture.app.clone();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // make streaming request using reqwest
    let client = reqwest::Client::new();
    let mut response = client
        .post(format!("http://{}/machine/map", addr))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&map_request).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // read first response (initial state)
    let first_chunk = timeout(Duration::from_secs(2), response.chunk())
        .await
        .expect("timeout waiting for first chunk")
        .expect("error reading first chunk")
        .expect("no data in first chunk");

    let (first_response, _) =
        read_length_prefixed_response(&first_chunk).expect("failed to parse first response");
    assert!(first_response.node.is_some());
    // first streaming response with data must have keep_alive=false so client processes it
    assert!(
        !first_response.keep_alive,
        "streaming response with node data must have keep_alive=false"
    );

    // now add a second node to trigger a state update
    let second_node_key = NodeKey::from_bytes(vec![4u8; 32]);
    let second_disco_key = DiscoKey::from_bytes(vec![5u8; 32]);
    let now = chrono::Utc::now();
    let second_node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(vec![6u8; 32]),
        node_key: second_node_key.clone(),
        disco_key: second_disco_key.clone(),
        ipv4: Some("100.64.0.2".parse().unwrap()),
        ipv6: Some("fd7a:115c:a1e0::2".parse().unwrap()),
        endpoints: vec![],
        hostinfo: None,
        hostname: "second-node".to_string(),
        given_name: "second-node".to_string(),
        user_id: Some(fixture.node.user_id.unwrap()),
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
    };
    fixture.db.create_node(&second_node).await.unwrap();

    // notify subscribers that state has changed
    fixture.notifier.notify_state_changed();

    // read second response (should include the new node as a peer)
    let second_chunk = timeout(Duration::from_secs(2), response.chunk())
        .await
        .expect("timeout waiting for second chunk - server didn't push update")
        .expect("error reading second chunk")
        .expect("no data in second chunk");

    let (second_response, _) =
        read_length_prefixed_response(&second_chunk).expect("failed to parse second response");

    // the second response should have the new node as a peer
    assert!(
        !second_response.peers.is_empty(),
        "should have at least one peer after state change"
    );

    // response with data must have keep_alive=false
    assert!(
        !second_response.keep_alive,
        "streaming response with node data must have keep_alive=false"
    );

    // clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_streaming_map_sends_keepalive_on_timeout() {
    // create a fixture with a 1-second keep-alive interval
    let mut config = railscale_types::Config::default();
    config.tuning.map_keepalive_interval_secs = 1;
    let fixture = MapTestFixture::with_config(config).await;
    let map_request = fixture.map_request(true);

    // start server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = fixture.app.clone();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // make streaming request
    let client = reqwest::Client::new();
    let mut response = client
        .post(format!("http://{}/machine/map", addr))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&map_request).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // read first response (initial full state)
    let first_chunk = timeout(Duration::from_secs(2), response.chunk())
        .await
        .expect("timeout waiting for first chunk")
        .expect("error reading first chunk")
        .expect("no data in first chunk");

    let (first_response, _) =
        read_length_prefixed_response(&first_chunk).expect("failed to parse first response");
    assert!(
        first_response.node.is_some(),
        "first response should have node"
    );

    // wait for keep-alive (should arrive after ~1 second, without any state change notification)
    let keepalive_chunk = timeout(Duration::from_secs(3), response.chunk())
        .await
        .expect("timeout waiting for keep-alive - keep-alive not sent")
        .expect("error reading keep-alive chunk")
        .expect("no data in keep-alive chunk");

    let (keepalive_response, _) = read_length_prefixed_response(&keepalive_chunk)
        .expect("failed to parse keep-alive response");

    // keep-alive should have keep_alive=true but no node data
    assert!(
        keepalive_response.keep_alive,
        "keep-alive response should have keep_alive=true"
    );
    assert!(
        keepalive_response.node.is_none(),
        "keep-alive response should not have node data"
    );
    assert!(
        keepalive_response.peers.is_empty(),
        "keep-alive response should not have peers"
    );

    // clean up
    server_handle.abort();
}
