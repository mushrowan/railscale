//! shared test utilities for TS2021 protocol tests
//!
//! functions here may be used by different test files, so dead_code warnings
//! are expected (each test file is compiled separately)

#![allow(dead_code)]

use railscale::{StateNotifier, create_app};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;

pub const PROTOCOL_VERSION: u16 = 1;

/// create a test app with default config
pub async fn create_test_app() -> axum::Router {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    create_app(db, grants, config, None, notifier, None).await
}

/// create a test app with a specific keypair
pub async fn create_test_app_with_keypair(keypair: railscale::Keypair) -> axum::Router {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    create_app(db, grants, config, None, notifier, Some(keypair)).await
}

/// create a test Noise IK initiation message (placeholder)
///
/// format (101 bytes total):
/// - 2 bytes: protocol version (big-endian)
/// - 1 byte: message type (0x01 = initiation)
/// - 2 bytes: payload length (96, big-endian)
/// - 32 bytes: client ephemeral public key (cleartext)
/// - 48 bytes: encrypted client static public key
/// - 16 bytes: authentication tag
#[allow(dead_code)]
pub fn create_test_initiation_message(client_private_key: &[u8]) -> Vec<u8> {
    // for now, create a placeholder message
    // the actual implementation will need proper Noise handshake
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

/// create a valid Noise IK initiation message with tailscale framing
///
/// uses the snow crate for cryptographic operations to ensure compatibility
/// with the server's snow-based responder
pub fn create_valid_initiation_message(
    client_private: &[u8],
    _client_public: &[u8],
    server_public: &[u8],
) -> Vec<u8> {
    // create the tailscale prologue
    let prologue = format!("Tailscale Control Protocol v{}", PROTOCOL_VERSION);

    // build initiator with prologue and remote static key
    let mut initiator = railscale_proto::noise_builder()
        .expect("valid builder")
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

/// build a client Noise handshake initiator
pub fn build_client_handshake(
    client_private: &[u8],
    server_public: &[u8],
    protocol_version: u16,
) -> snow::HandshakeState {
    let prologue = format!("Tailscale Control Protocol v{}", protocol_version);

    railscale_proto::noise_builder()
        .expect("valid builder")
        .local_private_key(client_private)
        .expect("valid key")
        .remote_public_key(server_public)
        .expect("valid key")
        .prologue(prologue.as_bytes())
        .expect("valid prologue")
        .build_initiator()
        .expect("build initiator")
}

/// create a framed Noise initiation message from a handshake state
pub fn create_framed_initiation(
    handshake: &mut snow::HandshakeState,
    protocol_version: u16,
) -> Vec<u8> {
    let mut noise_payload = vec![0u8; 65535];
    let len = handshake
        .write_message(&[], &mut noise_payload)
        .expect("write message");
    noise_payload.truncate(len);

    let payload_len = noise_payload.len() as u16;
    let mut init_msg = Vec::with_capacity(5 + noise_payload.len());
    init_msg.extend_from_slice(&protocol_version.to_be_bytes());
    init_msg.push(0x01); // msgTypeInitiation
    init_msg.extend_from_slice(&payload_len.to_be_bytes());
    init_msg.extend_from_slice(&noise_payload);

    init_msg
}

/// spawn a test server and return the address
pub async fn spawn_test_server(
    app: axum::Router,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().expect("failed to get local addr");

    let handle = tokio::spawn(async move {
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

    (addr, handle)
}
