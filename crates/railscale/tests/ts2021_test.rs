//! integration tests for the ts2021 protocol endpoint.
//!
//! these tests verify the websocket upgrade and noise handshake
//! at the `/ts2021` endpoint.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use http_body_util::BodyExt;
use railscale::{StateNotifier, create_app};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;
use tower::ServiceExt;

/// create a test app with default config.
async fn create_test_app() -> axum::Router {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    create_app(db, grants, config, None, notifier, None).await
}

/// test that /ts2021 endpoint exists and requires websocket upgrade.
#[tokio::test]
async fn test_ts2021_endpoint_requires_upgrade() {
    let app = create_test_app().await;

    // request without upgrade header should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ts2021")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // should return error indicating upgrade is required
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("upgrade") || body_str.contains("Upgrade"),
        "Response should mention upgrade requirement: {}",
        body_str
    );
}

/// test that /ts2021 recognizes websocket upgrade headers.
///
/// NOTE: tower::serviceext::oneshot() cannot fully test websocket upgrades
/// since it doesn't support connection hijacking. This test verifies the
/// endpoint recognizes upgrade headers but doesn't get 400 Bad Request.
/// full websocket testing requires a real server.
#[tokio::test]
async fn test_ts2021_recognizes_websocket_upgrade() {
    let app = create_test_app().await;

    // generate a client keypair for the handshake
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create initial handshake message (noise ik initiation)
    let init_message = create_test_initiation_message(&client_keypair.private);
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_message);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ts2021?X-Tailscale-Handshake={}", init_b64))
                .header(header::UPGRADE, "websocket")
                .header(header::CONNECTION, "upgrade")
                .header(header::SEC_WEBSOCKET_VERSION, "13")
                .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
                .header(header::SEC_WEBSOCKET_PROTOCOL, "tailscale-control-protocol")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // with tower::oneshot(), websocket upgrades return 426 because
    // the connection can't actually be hijacked. What matters is we
    // don't get 400 Bad Request (which would mean the endpoint rejected
    // the upgrade request itself) or 404 (which means the endpoint doesn't exist).
    assert!(
        response.status() != StatusCode::BAD_REQUEST && response.status() != StatusCode::NOT_FOUND,
        "Expected the endpoint to recognize WebSocket upgrade, got {}",
        response.status()
    );
}

/// create a test noise ik initiation message.
///
/// format (101 bytes total):
/// - 2 bytes: protocol version (big-endian)
/// - 1 byte: message type (0x01 = initiation)
/// - 2 bytes: payload length (96, big-endian)
/// - 32 bytes: client ephemeral public key (cleartext)
/// - 48 bytes: encrypted client static public key
/// - 16 bytes: authentication tag
fn create_test_initiation_message(client_private_key: &[u8]) -> Vec<u8> {
    // for now, create a placeholder message
    // the actual implementation will need proper noise handshake
    let mut msg = vec![0u8; 101];

    // protocol version (1)
    msg[0] = 0x00;
    msg[1] = 0x01;

    // message type (initiation = 1)
    msg[2] = 0x01;

    // payload length (96)
    msg[3] = 0x00;
    msg[4] = 0x60; // 96 in big-endian

    // rest is placeholder - ephemeral key, encrypted static key, tag
    // this will fail the handshake but tests the upgrade path
    _ = client_private_key; // Will be used in proper implementation

    msg
}

/// test that the /ts2021 endpoint performs noise handshake over websocket.
///
/// this test:
/// 1. Starts a real server
/// 2. Connects via WebSocket with a valid Noise IK initiation
/// 3. Receives and validates the Noise response
#[tokio::test]
async fn test_ts2021_noise_handshake() {
    use futures_util::StreamExt;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    // pass the keypair directly to create_app
    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // bind to a random port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().expect("failed to get local addr");

    // spawn the server
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("failed to accept");
        let io = hyper_util::rt::TokioIo::new(stream);
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection_with_upgrades(
                io,
                hyper::service::service_fn(move |req| {
                    let app = app.clone();
                    async move {
                        use tower::ServiceExt;
                        app.oneshot(req).await
                    }
                }),
            )
            .await
            .ok();
    });

    // create noise ik initiation message with tailscale framing
    let init_message = create_valid_initiation_message(
        &client_keypair.private,
        &client_keypair.public,
        &server_keypair.public,
    );
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_message);

    // connect via websocket
    let url = format!("ws://{}/ts2021?X-Tailscale-Handshake={}", addr, init_b64);

    let (mut ws_stream, response) = connect_async(&url)
        .await
        .expect("failed to connect WebSocket");

    // verify the subprotocol was accepted
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);

    // read the noise response message from WebSocket
    let msg = ws_stream
        .next()
        .await
        .expect("expected response message")
        .expect("failed to read message");

    let response_bytes = match msg {
        Message::Binary(data) => data,
        other => panic!("expected binary message, got {:?}", other),
    };

    // verify response format (51 bytes):
    // - 1 byte: message type (0x02 = response)
    // - 2 bytes: payload length (48, big-endian)
    // - 48 bytes: server ephemeral public + tag
    assert_eq!(
        response_bytes.len(),
        51,
        "response should be 51 bytes, got {}",
        response_bytes.len()
    );
    assert_eq!(response_bytes[0], 0x02, "response type should be 0x02");
    let payload_len = u16::from_be_bytes([response_bytes[1], response_bytes[2]]);
    assert_eq!(payload_len, 48, "payload length should be 48");

    // clean up
    ws_stream.close(None).await.ok();
    server_handle.abort();
}

/// test that http/2 works over the noise-encrypted websocket connection.
///
/// this test:
/// 1. Completes the Noise handshake
/// 2. sends an http/2 request to /machine/register
/// 3. Verifies the server responds correctly
#[tokio::test]
async fn test_ts2021_http2_over_noise() {
    use futures_util::StreamExt;
    use hyper::Request;
    use snow::Builder;
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;

    const PROTOCOL_VERSION: u16 = 1;
    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // bind to a random port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().expect("failed to get local addr");

    // spawn the server
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("failed to accept");
        let io = hyper_util::rt::TokioIo::new(stream);
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection_with_upgrades(
                io,
                hyper::service::service_fn(move |req| {
                    let app = app.clone();
                    async move {
                        use tower::ServiceExt;
                        app.oneshot(req).await
                    }
                }),
            )
            .await
            .ok();
    });

    // create the tailscale prologue
    let prologue = format!("Tailscale Control Protocol v{}", PROTOCOL_VERSION);

    // build client initiator
    let params: snow::params::NoiseParams = NOISE_PATTERN.parse().expect("valid pattern");
    let mut client_handshake = Builder::new(params)
        .local_private_key(&client_keypair.private)
        .expect("valid key")
        .remote_public_key(&server_keypair.public)
        .expect("valid key")
        .prologue(prologue.as_bytes())
        .expect("valid prologue")
        .build_initiator()
        .expect("build initiator");

    // generate the first message
    let mut noise_payload = vec![0u8; 65535];
    let len = client_handshake
        .write_message(&[], &mut noise_payload)
        .expect("write message");
    noise_payload.truncate(len);

    // build framed initiation message
    let payload_len = noise_payload.len() as u16;
    let mut init_msg = Vec::with_capacity(5 + noise_payload.len());
    init_msg.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    init_msg.push(0x01); // msgTypeInitiation
    init_msg.extend_from_slice(&payload_len.to_be_bytes());
    init_msg.extend_from_slice(&noise_payload);

    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via websocket
    let url = format!("ws://{}/ts2021?X-Tailscale-Handshake={}", addr, init_b64);
    let (ws_stream, _response) = connect_async(&url)
        .await
        .expect("failed to connect WebSocket");

    // split the websocket stream
    let (ws_write, mut ws_read) = ws_stream.split();

    // read the noise response
    let msg = ws_read
        .next()
        .await
        .expect("expected response message")
        .expect("failed to read message");

    let response_bytes = match msg {
        tokio_tungstenite::tungstenite::Message::Binary(data) => data,
        other => panic!("expected binary message, got {:?}", other),
    };

    // parse and process the response to complete handshake
    assert_eq!(response_bytes[0], 0x02, "response type should be 0x02");
    let response_payload = &response_bytes[3..]; // Skip type + length

    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    // handshake should be complete
    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    // convert to transport mode
    let client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // create a noisestream that wraps the websocket with noise encryption
    // this provides asyncread + asyncwrite for hyper
    let noise_stream = railscale::NoiseStream::new(ws_read, ws_write, client_transport);

    // use hyper's http/2 client over the encrypted stream
    let io = hyper_util::rt::TokioIo::new(noise_stream);

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .expect("HTTP/2 handshake failed");

    // spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // send a request to /machine/register
    let request = Request::builder()
        .method("POST")
        .uri("/machine/register")
        .header("Content-Type", "application/json")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("failed to build request");

    let response = sender
        .send_request(request)
        .await
        .expect("failed to send request");

    // we expect some response (even if it's an error due to missing auth)
    // the important thing is that http/2 worked over the encrypted channel
    assert!(
        response.status().is_client_error() || response.status().is_success(),
        "expected valid HTTP response, got {:?}",
        response.status()
    );

    // clean up
    server_handle.abort();
}

/// create a valid noise ik initiation message with tailscale framing.
///
/// uses the snow crate for cryptographic operations to ensure compatibility
/// with the server's snow-based responder.
fn create_valid_initiation_message(
    client_private: &[u8],
    _client_public: &[u8],
    server_public: &[u8],
) -> Vec<u8> {
    use snow::Builder;

    const PROTOCOL_VERSION: u16 = 1;
    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    // create the tailscale prologue
    let prologue = format!("Tailscale Control Protocol v{}", PROTOCOL_VERSION);

    // build initiator with prologue and remote static key
    let params = NOISE_PATTERN.parse().expect("valid pattern");
    let mut initiator = Builder::new(params)
        .local_private_key(client_private)
        .expect("valid key")
        .remote_public_key(server_public)
        .expect("valid key")
        .prologue(prologue.as_bytes())
        .expect("valid prologue")
        .build_initiator()
        .expect("build initiator");

    // generate the first message: -> e, es, s, ss
    let mut noise_payload = vec![0u8; 65535];
    let len = initiator
        .write_message(&[], &mut noise_payload)
        .expect("write message");
    noise_payload.truncate(len);

    // build the framed initiation message
    // header: [version:2][type:1=0x01][len:2]
    let payload_len = noise_payload.len() as u16;
    let mut msg = Vec::with_capacity(5 + noise_payload.len());
    msg.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    msg.push(0x01); // msgTypeInitiation
    msg.extend_from_slice(&payload_len.to_be_bytes());
    msg.extend_from_slice(&noise_payload);

    msg
}
