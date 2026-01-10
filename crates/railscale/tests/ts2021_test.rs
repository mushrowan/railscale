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
    use futures_util::{SinkExt, StreamExt};
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
    let mut config = Config::default();
    let notifier = StateNotifier::new();

    // need to set up noise keys in config - the create_app function needs them
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let key_path = temp_dir.path().join("noise.key");

    // write keypair to file (64 bytes: 32 private + 32 public)
    let mut key_data = server_keypair.private.clone();
    key_data.extend_from_slice(&server_keypair.public);
    std::fs::write(&key_path, &key_data).expect("failed to write keypair");
    config.noise_private_key_path = key_path;

    let app = railscale::create_app(db, grants, config, None, notifier, None).await;

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

/// create a valid noise ik initiation message with tailscale framing.
///
/// this implements the tailscale noise ik handshake with proper:
/// - Protocol version prologue mixing
/// - Message framing (5-byte header + 96-byte payload)
fn create_valid_initiation_message(
    client_private: &[u8],
    client_public: &[u8],
    server_public: &[u8],
) -> Vec<u8> {
    use blake2::digest::Update;
    use blake2::{Blake2s256, Digest};
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
    use x25519_dalek::{PublicKey, StaticSecret};

    const PROTOCOL_VERSION: u16 = 1;
    const NOISE_PATTERN: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

    // initialize symmetric state
    let mut h = Blake2s256::new();
    Update::update(&mut h, NOISE_PATTERN);
    let mut h: [u8; 32] = h.finalize().into();
    let mut ck = h;

    // mix protocol version prologue
    let prologue = format!("Tailscale Control Protocol v{}", PROTOCOL_VERSION);
    h = {
        let mut hasher = Blake2s256::new();
        Update::update(&mut hasher, &h);
        Update::update(&mut hasher, prologue.as_bytes());
        hasher.finalize().into()
    };

    // <- s: Mix server's static public key into h
    h = {
        let mut hasher = Blake2s256::new();
        Update::update(&mut hasher, &h);
        Update::update(&mut hasher, server_public);
        hasher.finalize().into()
    };

    // -> e: Generate client ephemeral keypair
    let client_ephemeral_private = StaticSecret::random_from_rng(rand_core::OsRng);
    let client_ephemeral_public = PublicKey::from(&client_ephemeral_private);

    // mix ephemeral public into h
    h = {
        let mut hasher = Blake2s256::new();
        Update::update(&mut hasher, &h);
        Update::update(&mut hasher, client_ephemeral_public.as_bytes());
        hasher.finalize().into()
    };

    // es: DH(client_ephemeral, server_static)
    let server_pub_key = PublicKey::from(<[u8; 32]>::try_from(server_public).unwrap());
    let es_shared = client_ephemeral_private.diffie_hellman(&server_pub_key);

    // hkdf to derive cipher key from es
    let (ck_new, k1) = hkdf_derive(&ck, es_shared.as_bytes());
    ck = ck_new;

    // encrypt client's static public key (s)
    let mut encrypted_static = client_public.to_vec();
    let cipher1 = ChaCha20Poly1305::new_from_slice(&k1).unwrap();
    let nonce = [0u8; 12];
    let tag1 = cipher1
        .encrypt_in_place_detached(&nonce.into(), &h, &mut encrypted_static)
        .expect("encryption failed");

    // mix ciphertext into h
    let ciphertext_with_tag: Vec<u8> = encrypted_static
        .iter()
        .chain(tag1.iter())
        .copied()
        .collect();
    h = {
        let mut hasher = Blake2s256::new();
        Update::update(&mut hasher, &h);
        Update::update(&mut hasher, &ciphertext_with_tag);
        hasher.finalize().into()
    };

    // ss: DH(client_static, server_static)
    let client_static_secret = StaticSecret::from(<[u8; 32]>::try_from(client_private).unwrap());
    let ss_shared = client_static_secret.diffie_hellman(&server_pub_key);

    // hkdf to derive cipher key from ss
    let (ck_new, k2) = hkdf_derive(&ck, ss_shared.as_bytes());
    let _ = ck_new; // ck updated but not used further in initiation

    // encrypt empty payload and get tag
    let mut empty_payload = Vec::new();
    let cipher2 = ChaCha20Poly1305::new_from_slice(&k2).unwrap();
    let tag2 = cipher2
        .encrypt_in_place_detached(&nonce.into(), &h, &mut empty_payload)
        .expect("encryption failed");

    // build the initiation message (101 bytes)
    let mut msg = vec![0u8; 101];

    // header (5 bytes)
    msg[0..2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    msg[2] = 0x01; // msgTypeInitiation
    msg[3..5].copy_from_slice(&96u16.to_be_bytes());

    // payload (96 bytes)
    msg[5..37].copy_from_slice(client_ephemeral_public.as_bytes()); // 32 bytes
    msg[37..69].copy_from_slice(&encrypted_static); // 32 bytes
    msg[69..85].copy_from_slice(&tag1); // 16 bytes
    msg[85..101].copy_from_slice(&tag2); // 16 bytes

    msg
}

/// hkdf-blake2s key derivation (manual implementation to avoid version conflicts)
///
/// hkdf extract + expand using blake2s as the underlying hash.
/// this follows the noise spec's mixkey operation.
fn hkdf_derive(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    use blake2::Blake2sMac256;
    use blake2::digest::{FixedOutput, KeyInit, Update};

    // hkdf-extract: prk = hmac(salt=ck, ikm=input)
    let mut hmac = Blake2sMac256::new_from_slice(ck).expect("valid key length");
    Update::update(&mut hmac, input);
    let prk: [u8; 32] = hmac.finalize_fixed().into();

    // hkdf-expand: output = hmac(prk, info || 0x01) || hmac(prk, t1 || info || 0x02)
    // for noise, info is empty and we need 64 bytes

    // t1 = hmac(prk, 0x01)
    let mut hmac1 = Blake2sMac256::new_from_slice(&prk).expect("valid key length");
    Update::update(&mut hmac1, &[0x01]);
    let t1: [u8; 32] = hmac1.finalize_fixed().into();

    // t2 = hmac(prk, t1 || 0x02)
    let mut hmac2 = Blake2sMac256::new_from_slice(&prk).expect("valid key length");
    Update::update(&mut hmac2, &t1);
    Update::update(&mut hmac2, &[0x02]);
    let t2: [u8; 32] = hmac2.finalize_fixed().into();

    (t1, t2)
}
