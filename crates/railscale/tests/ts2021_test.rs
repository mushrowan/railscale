//! integration tests for the TS2021 protocol endpoint
//!
//! these tests verify the websocket upgrade and noise handshake
//! at the `/ts2021` endpoint

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

/// create a test app with default config
async fn create_test_app() -> axum::Router {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::new();

    create_app(db, grants, config, None, notifier, None).await
}

/// test that /ts2021 endpoint exists and requires WebSocket upgrade
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

/// test that /ts2021 recognizes WebSocket upgrade headers
///
/// NOTE: tower::serviceext::oneshot() cannot fully test websocket upgrades
/// since it doesn't support connection hijacking. This test verifies the
/// endpoint recognizes upgrade headers but doesn't get 400 Bad Request
/// full WebSocket testing requires a real server
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
    // the upgrade request itself) or 404 (which means the endpoint doesn't exist)
    assert!(
        response.status() != StatusCode::BAD_REQUEST && response.status() != StatusCode::NOT_FOUND,
        "Expected the endpoint to recognize WebSocket upgrade, got {}",
        response.status()
    );
}

/// create a test Noise IK initiation message
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
