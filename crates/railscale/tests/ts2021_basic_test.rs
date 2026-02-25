//! basic tests for the TS2021 protocol endpoint

mod ts2021_common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use http_body_util::BodyExt;
use tower::ServiceExt;
use ts2021_common::{create_invalid_initiation_message, create_test_app};

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

    // create an invalid initiation message (correct framing, bad noise payload)
    let init_message = create_invalid_initiation_message();
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
