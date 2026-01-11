//! webSocket-based tests for the TS2021 protocol
//!
//! these tests verify Noise handshake and http/2 over WebSocket connections

mod ts2021_common;

use base64::Engine;
use futures_util::StreamExt;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::{Config, PreAuthKey, User, UserId};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use ts2021_common::{
    PROTOCOL_VERSION, build_client_handshake, create_framed_initiation,
    create_valid_initiation_message, spawn_test_server,
};

/// test that the /ts2021 endpoint performs Noise handshake over WebSocket
///
/// this test:
/// 1. Starts a real server
/// 2. Connects via WebSocket with a valid Noise IK initiation
/// 3. Receives and validates the Noise response
#[tokio::test]
async fn test_ts2021_noise_handshake() {
    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = railscale::StateNotifier::new();

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

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

/// test that http/2 works over the Noise-encrypted WebSocket connection
///
/// this test:
/// 1. Completes the Noise handshake
/// 2. sends an http/2 request to /machine/register
/// 3. Verifies the server responds correctly
#[tokio::test]
async fn test_ts2021_http2_over_noise() {
    use hyper::Request;

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = railscale::StateNotifier::new();

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
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

/// test that handlers receive the machine key from the Noise handshake context
///
/// this test verifies that when a registration request comes through the ts2021
/// protocol, the handler uses the machine key from the authenticated Noise
/// handshake rather than trusting any machine key in the request body
#[tokio::test]
async fn test_ts2021_machine_key_from_noise_context() {
    use http_body_util::BodyExt;
    use hyper::Request;

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair - the public key is the machine key
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair and a preauth key
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");

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
    let notifier = railscale::StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
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

    // send a register request via ts2021 (machine key comes from noise handshake)
    // tailscale format: nodekey is prefixed hex string, auth key in auth.authkey
    let node_key_hex = hex::encode(&client_keypair.public);
    let register_body = serde_json::json!({
        "Version": 95,
        "NodeKey": format!("nodekey:{}", node_key_hex),
        "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        "Auth": {
            "AuthKey": "test-preauth-key"
        }
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
        "expected successful registration, got {}",
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

    // verify tailscale-format response
    assert_eq!(
        register_response["MachineAuthorized"], true,
        "node should be authorized"
    );
    assert!(
        register_response.get("User").is_some(),
        "response should have User field"
    );

    server_handle.abort();
}

/// test that large writes through Noise transport are chunked into multiple frames
///
/// tailscale's noise transport has a maximum frame size:
/// - Max plaintext per frame: 4077 bytes
/// - Max ciphertext per frame: 4093 bytes (plaintext + 16 byte AEAD tag)
/// - Max frame on wire: 4096 bytes (3 byte header + ciphertext)
///
/// this test verifies frame chunking works correctly via http/2 over Noise
#[tokio::test]
async fn test_noise_transport_chunks_large_writes() {
    use http_body_util::BodyExt;
    use hyper::Request;

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
    let notifier = railscale::StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
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
