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

/// test that handlers receive the machine key from the noise handshake context.
///
/// this test verifies that when a registration request comes through the ts2021
/// protocol, the handler uses the machine key from the authenticated Noise
/// handshake rather than trusting any machine key in the request body.
#[tokio::test]
async fn test_ts2021_machine_key_from_noise_context() {
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

    // create client keypair - the public key is the machine key
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");

    // create a preauth key for registration
    use railscale_db::Database;
    use railscale_types::{PreAuthKey, User, UserId};

    // create user first (foreign key constraint)
    let user = User::new(UserId(1), "test".to_string());
    db.create_user(&user).await.expect("failed to create user");

    // create preauth key
    let mut preauth_key = PreAuthKey::new(0, "test-preauth-key".to_string(), UserId(1));
    preauth_key.reusable = true;
    preauth_key.expiration = Some(chrono::Utc::now() + chrono::Duration::hours(1));

    db.create_preauth_key(&preauth_key)
        .await
        .expect("failed to create preauth key");

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
    init_msg.push(0x01);
    init_msg.extend_from_slice(&payload_len.to_be_bytes());
    init_msg.extend_from_slice(&noise_payload);

    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via websocket
    let url = format!("ws://{}/ts2021?X-Tailscale-Handshake={}", addr, init_b64);
    let (ws_stream, _response) = connect_async(&url)
        .await
        .expect("failed to connect WebSocket");

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
    let response_payload = &response_bytes[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    // convert to transport mode
    let client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    let noise_stream = railscale::NoiseStream::new(ws_read, ws_write, client_transport);
    let io = hyper_util::rt::TokioIo::new(noise_stream);

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .expect("HTTP/2 handshake failed");

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // send a register request with a fake machine key in the body
    // the handler should use the real machine key from the noise context instead
    let fake_machine_key: Vec<u8> = (0..32).map(|i| i as u8).collect(); // 32 bytes of fake data
    let register_body = serde_json::json!({
        "machine_key": fake_machine_key,
        "node_key": client_keypair.public,  // Use real node key
        "preauth_key": "test-preauth-key"
    });

    let body = serde_json::to_vec(&register_body).expect("failed to serialize");

    let request = Request::builder()
        .method("POST")
        .uri("/machine/register")
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .expect("failed to build request");

    let response = sender
        .send_request(request)
        .await
        .expect("failed to send request");

    assert!(
        response.status().is_success(),
        "expected successful registration, got {:?}",
        response.status()
    );

    // read the response body
    let body = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let register_response: serde_json::Value =
        serde_json::from_slice(&body).expect("failed to parse response");

    // the machine key in the response should match the client's noise public key,
    // not the fake machine key we sent in the request body
    let response_machine_key = register_response["machine_key"]
        .as_array()
        .expect("machine_key should be array")
        .iter()
        .map(|v| v.as_u64().expect("should be u64") as u8)
        .collect::<Vec<u8>>();

    assert_eq!(
        response_machine_key, client_keypair.public,
        "machine key in response should match Noise handshake key, not request body"
    );
    assert_ne!(
        response_machine_key, fake_machine_key,
        "machine key should NOT match the fake key from request body"
    );

    server_handle.abort();
}

/// test that the /ts2021 endpoint supports http upgrade (not just websocket).
///
/// the real tailscale client uses `upgrade: tailscale-control-protocol` instead
/// of WebSocket. This test verifies that path works.
///
/// protocol:
/// ```text
/// post /ts2021 HTTP/1.1
/// upgrade: tailscale-control-protocol
/// connection: upgrade
/// x-tailscale-handshake: <base64 noise init>
///
/// response: 101 switching protocols
/// upgrade: tailscale-control-protocol
/// connection: upgrade
/// ```
#[tokio::test]
async fn test_ts2021_http_upgrade_protocol() {
    use snow::Builder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    // connect via raw tcp and send http upgrade request
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request (NOT WebSocket - using tailscale-control-protocol)
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // should get 101 switching protocols with tailscale-control-protocol
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );
    assert!(
        response_str
            .to_lowercase()
            .contains("upgrade: tailscale-control-protocol"),
        "expected Upgrade: tailscale-control-protocol header, got: {}",
        response_str
    );

    // after 101, the noise response should follow
    // read more data for the noise response (it may come in the same read or separately)
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let remaining = &response_buf[header_end..n];

    // the noise response should be: [type:1][len:2][payload:48] = 51 bytes
    let noise_response = if remaining.len() >= 51 {
        remaining[..51].to_vec()
    } else {
        // need to read more
        let mut full_response = remaining.to_vec();
        while full_response.len() < 51 {
            let mut more = vec![0u8; 1024];
            let n = stream.read(&mut more).await.expect("failed to read more");
            if n == 0 {
                panic!(
                    "connection closed before receiving full Noise response, got {} bytes",
                    full_response.len()
                );
            }
            full_response.extend_from_slice(&more[..n]);
        }
        full_response[..51].to_vec()
    };

    // verify noise response format
    assert_eq!(noise_response[0], 0x02, "response type should be 0x02");
    let response_payload_len = u16::from_be_bytes([noise_response[1], noise_response[2]]);
    assert_eq!(response_payload_len, 48, "payload length should be 48");

    // complete the handshake on client side
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    server_handle.abort();
}

/// test that large writes through noise transport are chunked into multiple frames.
///
/// tailscale's noise transport has a maximum frame size:
/// - Max plaintext per frame: 4077 bytes
/// - Max ciphertext per frame: 4093 bytes (plaintext + 16 byte AEAD tag)
/// - Max frame on wire: 4096 bytes (3 byte header + ciphertext)
///
/// this test verifies frame chunking works correctly via http/2 over noise.
#[tokio::test]
async fn test_noise_transport_chunks_large_writes() {
    use futures_util::StreamExt;
    use hyper::Request;
    use snow::Builder;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;

    const PROTOCOL_VERSION: u16 = 1;
    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    const MAX_CIPHERTEXT_SIZE: usize = 4093; // plaintext (4077) + 16 byte tag

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app
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
    init_msg.push(0x01);
    init_msg.extend_from_slice(&payload_len.to_be_bytes());
    init_msg.extend_from_slice(&noise_payload);

    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via websocket
    let url = format!("ws://{}/ts2021?X-Tailscale-Handshake={}", addr, init_b64);
    let (ws_stream, _response) = connect_async(&url)
        .await
        .expect("failed to connect WebSocket");

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

    let response_payload = &response_bytes[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    let client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // track max frame size received from server
    let max_frame_size = Arc::new(AtomicUsize::new(0));
    let max_frame_clone = max_frame_size.clone();

    // wrap the websocket reader to track frame sizes
    let tracking_reader = ws_read.map(move |result| {
        if let Ok(tokio_tungstenite::tungstenite::Message::Binary(ref data)) = result {
            let current_max = max_frame_clone.load(Ordering::Relaxed);
            if data.len() > current_max {
                max_frame_clone.store(data.len(), Ordering::Relaxed);
            }
        }
        result
    });

    let noise_stream = railscale::NoiseStream::new(tracking_reader, ws_write, client_transport);
    let io = hyper_util::rt::TokioIo::new(noise_stream);

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .expect("HTTP/2 handshake failed");

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("HTTP/2 connection error: {}", e);
        }
    });

    // send request - server will respond, and we check frame sizes
    let request = Request::builder()
        .method("POST")
        .uri("/machine/register")
        .header("Content-Type", "application/json")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("failed to build request");

    let response = sender.send_request(request).await;
    assert!(response.is_ok(), "request failed: {:?}", response.err());

    let response = response.unwrap();
    let _body = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body");

    // check that no frames exceeded the max size
    let observed_max = max_frame_size.load(Ordering::Relaxed);

    assert!(
        observed_max <= MAX_CIPHERTEXT_SIZE,
        "Server sent oversized Noise frame: {} bytes (max allowed: {} bytes)\n\
         Large writes must be chunked into frames <= {} bytes ciphertext",
        observed_max,
        MAX_CIPHERTEXT_SIZE,
        MAX_CIPHERTEXT_SIZE
    );

    server_handle.abort();
}

/// test that http upgraded noise frames use the correct format.
///
/// for raw tcp connections (http upgrade, not websocket), tailscale expects:
/// - Frame format: `[type:1][len:2 BE][ciphertext:N]`
/// - Type byte 0x03 = msgTypeRecord for data frames
///
/// this test verifies the server sends correctly formatted frames that
/// the real Tailscale client can parse.
#[tokio::test]
async fn test_http_upgrade_noise_frame_format() {
    use snow::Builder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PROTOCOL_VERSION: u16 = 131; // Use real Tailscale version
    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    const MSG_TYPE_RECORD: u8 = 0x04;
    const MAX_FRAME_SIZE: usize = 4096; // type + len + ciphertext

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

    // connect via raw tcp and send http upgrade request
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the http response + noise handshake response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");

    // parse http response
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );

    // find where http headers end
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let mut remaining = response_buf[header_end..n].to_vec();

    // read more if needed to get the full noise response (51 bytes)
    while remaining.len() < 51 {
        let mut more = vec![0u8; 1024];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed early");
        }
        remaining.extend_from_slice(&more[..n]);
    }

    // parse noise handshake response (doesn't use type byte for handshake messages)
    let noise_response = &remaining[..51];
    assert_eq!(noise_response[0], 0x02, "handshake response type");

    // complete the handshake
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    let mut client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // move past the noise handshake response
    let post_handshake = &remaining[51..];

    // now read the http/2 settings frame from the server
    // server should send http/2 preface: settings frame
    // this should be in format [type:1=0x03][len:2][ciphertext]

    let mut data_buf = post_handshake.to_vec();
    while data_buf.len() < 3 {
        let mut more = vec![0u8; 4096];
        let n = stream.read(&mut more).await.expect("failed to read data");
        if n == 0 {
            panic!(
                "connection closed before receiving data frame, got {} bytes",
                data_buf.len()
            );
        }
        data_buf.extend_from_slice(&more[..n]);
    }

    // verify frame format: [type:1][len:2][ciphertext]
    let frame_type = data_buf[0];
    let frame_len = u16::from_be_bytes([data_buf[1], data_buf[2]]) as usize;

    assert_eq!(
        frame_type, MSG_TYPE_RECORD,
        "Expected frame type 0x04 (msgTypeRecord), got 0x{:02x}.\n\
         HTTP upgraded Noise frames must use format [type:1][len:2][ciphertext]",
        frame_type
    );

    assert!(
        frame_len <= MAX_FRAME_SIZE - 3,
        "Frame length {} exceeds max {} bytes",
        frame_len,
        MAX_FRAME_SIZE - 3
    );

    // read the full ciphertext
    while data_buf.len() < 3 + frame_len {
        let mut more = vec![0u8; 4096];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed before full frame");
        }
        data_buf.extend_from_slice(&more[..n]);
    }

    let ciphertext = &data_buf[3..3 + frame_len];

    // try to decrypt - should succeed with properly formatted frames
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = client_transport
        .read_message(ciphertext, &mut decrypted)
        .expect("failed to decrypt frame");
    decrypted.truncate(decrypted_len);

    // the decrypted data should be http/2 settings frame
    // http/2 connection preface starts with "pri * http/2.0\r\n\r\nsm\r\n\r\n" for client
    // server sends settings frame which starts with frame header
    assert!(
        !decrypted.is_empty(),
        "decrypted frame should contain HTTP/2 data"
    );

    server_handle.abort();
}

/// 1. Complete the Noise handshake via http upgrade
///2. Client sends multiple encrypted frames (like http/2 preface + SETTINGS + HEADERS)
/// 3. Server decrypts all frames successfully
/// 1. Complete the Noise handshake via HTTP upgrade
/// 2. Client sends multiple encrypted frames (like HTTP/2 preface + SETTINGS + HEADERS)
/// 3. Server decrypts all frames successfully
#[tokio::test]
async fn test_http_upgrade_multi_frame_client_to_server() {
    use snow::Builder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PROTOCOL_VERSION: u16 = 131; // Use real Tailscale version
    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    const MSG_TYPE_RECORD: u8 = 0x04;

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

    // build client initiator
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

    // connect via raw tcp and send http upgrade request
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the http response + noise handshake response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");

    // parse http response
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );

    // find where http headers end
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let mut remaining = response_buf[header_end..n].to_vec();

    // read more if needed to get the full noise response (51 bytes)
    while remaining.len() < 51 {
        let mut more = vec![0u8; 1024];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed early");
        }
        remaining.extend_from_slice(&more[..n]);
    }

    // parse noise handshake response
    let noise_response = &remaining[..51];
    assert_eq!(noise_response[0], 0x02, "handshake response type");

    // complete the handshake
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    let mut client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // now send multiple encrypted frames from client to server
    let post_handshake = remaining[51..].to_vec();

    // frame 1: http/2 preface + SETTINGS + WINDOW_UPDATE
    // this simulates what the real tailscale client does

    // frame 1: http/2 preface + settings + window_update
    let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings_frame = [
        0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // SETTINGS header
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // HEADER_TABLE_SIZE
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH
        0x00, 0x04, 0x00, 0x40, 0x00, 0x00, // INITIAL_WINDOW_SIZE
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE
    ];
    let window_update = [
        0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // WINDOW_UPDATE header
        0x3f, 0xff, 0x00, 0x01, // increment
    ];

    let mut plaintext1 = Vec::new();
    plaintext1.extend_from_slice(http2_preface);
    plaintext1.extend_from_slice(&settings_frame);
    plaintext1.extend_from_slice(&window_update);

    // encrypt frame 1
    let mut ct1_buf = vec![0u8; plaintext1.len() + 16];
    let ct1_len = client_transport
        .write_message(&plaintext1, &mut ct1_buf)
        .expect("encrypt frame 1");
    let ciphertext1 = &ct1_buf[..ct1_len];

    // frame frame 1
    let mut frame1 = Vec::new();
    frame1.push(MSG_TYPE_RECORD);
    frame1.extend_from_slice(&(ciphertext1.len() as u16).to_be_bytes());
    frame1.extend_from_slice(ciphertext1);

    // frame 2: settings ack
    let settings_ack = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // SETTINGS ACK
    ];

    // encrypt frame 2
    let mut ct2_buf = vec![0u8; settings_ack.len() + 16];
    let ct2_len = client_transport
        .write_message(&settings_ack, &mut ct2_buf)
        .expect("encrypt frame 2");
    let ciphertext2 = &ct2_buf[..ct2_len];

    // frame frame 2
    let mut frame2 = Vec::new();
    frame2.push(MSG_TYPE_RECORD);
    frame2.extend_from_slice(&(ciphertext2.len() as u16).to_be_bytes());
    frame2.extend_from_slice(ciphertext2);

    // frame 3: some more data (headers)
    let headers_frame = [
        0x00, 0x00, 0x20, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, // HEADERS header
        0x82, 0x86, 0x84, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc, 0x78, 0x0f, 0x03,
        0x53, 0x03, 0x2a, 0x2f, 0x2a, 0x90, 0x7a, 0x8a, 0xaa, 0x69, 0xd2, 0x9a, 0xc4, 0xc0, 0x57,
        0x68, 0x0b,
    ];

    // encrypt frame 3
    let mut ct3_buf = vec![0u8; headers_frame.len() + 16];
    let ct3_len = client_transport
        .write_message(&headers_frame, &mut ct3_buf)
        .expect("encrypt frame 3");
    let ciphertext3 = &ct3_buf[..ct3_len];

    // frame frame 3
    let mut frame3 = Vec::new();
    frame3.push(MSG_TYPE_RECORD);
    frame3.extend_from_slice(&(ciphertext3.len() as u16).to_be_bytes());
    frame3.extend_from_slice(ciphertext3);

    // send all frames in a single tcp write (simulating batching)
    let mut all_frames = Vec::new();
    all_frames.extend_from_slice(&frame1);
    all_frames.extend_from_slice(&frame2);
    all_frames.extend_from_slice(&frame3);

    eprintln!(
        "Sending {} bytes containing 3 frames: {} + {} + {} bytes",
        all_frames.len(),
        frame1.len(),
        frame2.len(),
        frame3.len()
    );

    stream
        .write_all(&all_frames)
        .await
        .expect("failed to send frames");

    // read server response (should include http/2 settings)
    // if the server crashes due to decrypt error, we'll get an error or incomplete response
    let mut data_buf = post_handshake;
    let mut read_attempts = 0;
    while data_buf.len() < 3 && read_attempts < 10 {
        let mut more = vec![0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read(&mut more),
        )
        .await
        {
            Ok(Ok(0)) => {
                panic!(
                    "Server closed connection! This likely means decrypt failed. Got {} bytes",
                    data_buf.len()
                );
            }
            Ok(Ok(n)) => {
                data_buf.extend_from_slice(&more[..n]);
            }
            Ok(Err(e)) => {
                panic!(
                    "Read error: {}. Server may have crashed due to decrypt failure.",
                    e
                );
            }
            Err(_) => {
                read_attempts += 1;
            }
        }
    }

    assert!(
        data_buf.len() >= 3,
        "Should receive server HTTP/2 SETTINGS frame, got {} bytes. Server may have failed to decrypt client frames.",
        data_buf.len()
    );

    // verify server sent a valid noise frame
    let server_frame_type = data_buf[0];
    assert_eq!(
        server_frame_type, MSG_TYPE_RECORD,
        "Expected server frame type 0x04, got 0x{:02x}",
        server_frame_type
    );

    eprintln!("Test passed: Server successfully processed multiple client frames!");

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
