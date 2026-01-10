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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyResponse {
    public_key: Vec<u8>,
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

    // verify public key is 32 bytes (curve25519)
    assert_eq!(
        key_response.public_key.len(),
        32,
        "public key should be 32 bytes (Curve25519)"
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
