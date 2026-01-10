//! integration tests for the `/key` endpoint.
//!
//! the `/key` endpoint returns the server's noise public key for ts2021 protocol.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale::{StateNotifier, create_app};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;
use serde::Deserialize;
use tower::ServiceExt;

/// legacy NaCl crypto_box machine key (empty for Noise-only servers)
///
/// server's Noise public key as "mkey:" + hex(32 bytes)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyResponse {
    /// parse a machine key string ("mkey:" + hex) into raw bytes
    legacy_public_key: String,
    /// server's noise public key as "mkey:" + hex(32 bytes).
    public_key: String,
}

/// parse a machine key string ("mkey:" + hex) into raw bytes.
fn parse_machine_key(key: &str) -> Vec<u8> {
    let hex_str = key
        .strip_prefix("mkey:")
        .expect("key should have mkey: prefix");
    hex::decode(hex_str).expect("key should be valid hex")
}

/// test that get /key returns the server's noise public key.
#[tokio::test]
async fn test_key_endpoint_returns_public_key() {
    // create test fixtures
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    // make request to /key
    let request = Request::builder()
        .method("GET")
        .uri("/key")
        .body(Body::empty())
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

    // verify status code
    assert_eq!(response.status(), StatusCode::OK);

    // parse response body
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let key_response: KeyResponse =
        serde_json::from_slice(&body).expect("failed to parse response as KeyResponse");

    // verify public key format and length
    assert!(
        key_response.public_key.starts_with("mkey:"),
        "public key should have mkey: prefix"
    );
    let key_bytes = parse_machine_key(&key_response.public_key);
    assert_eq!(
        key_bytes.len(),
        32,
        "public key should be 32 bytes (Curve25519)"
    );

    // legacy key should be zero-valued (all zeros) for noise-only servers
    assert!(
        key_response.legacy_public_key.starts_with("mkey:"),
        "legacy key should have mkey: prefix"
    );
    let legacy_bytes = parse_machine_key(&key_response.legacy_public_key);
    assert!(
        legacy_bytes.iter().all(|&b| b == 0),
        "legacy key should be all zeros"
    );
}

/// test that get /key returns consistent key across requests.
#[tokio::test]
async fn test_key_endpoint_returns_consistent_key() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    // make two requests
    let request1 = Request::builder()
        .method("GET")
        .uri("/key")
        .body(Body::empty())
        .expect("failed to build request");

    let response1 = app.clone().oneshot(request1).await.expect("request failed");
    let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let key_response1: KeyResponse = serde_json::from_slice(&body1).expect("failed to parse");

    let request2 = Request::builder()
        .method("GET")
        .uri("/key")
        .body(Body::empty())
        .expect("failed to build request");

    let response2 = app.oneshot(request2).await.expect("request failed");
    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let key_response2: KeyResponse = serde_json::from_slice(&body2).expect("failed to parse");

    // keys should be identical
    assert_eq!(
        key_response1.public_key, key_response2.public_key,
        "public key should be consistent across requests"
    );
}
