//! integration tests for the `/health` endpoint
//!
//! the `/health` endpoint checks database connectivity and returns health status

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

/// response from the `/health` endpoint
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

/// test that GET /health returns pass status for healthy database
#[tokio::test]
async fn test_health_endpoint_returns_pass() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

    // verify status code
    assert_eq!(response.status(), StatusCode::OK);

    // verify content-type
    let content_type = response
        .headers()
        .get("content-type")
        .expect("should have content-type header")
        .to_str()
        .expect("content-type should be valid string");
    assert!(
        content_type.contains("application/health+json"),
        "content-type should be application/health+json, got: {}",
        content_type
    );

    // parse response body
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let health_response: HealthResponse =
        serde_json::from_slice(&body).expect("failed to parse response");

    assert_eq!(health_response.status, "pass");
}
