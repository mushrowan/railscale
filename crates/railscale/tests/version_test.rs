//! integration tests for the `/version` endpoint
//!
//! the `/version` endpoint returns build and version information

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

/// response from the `/version` endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionResponse {
    version: String,
    commit: String,
    build_time: String,
    rustc: String,
    dirty: bool,
}

/// test that GET /version returns version information
#[tokio::test]
async fn test_version_endpoint_returns_info() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    let app = create_app(db, grants, config, None, notifier, None).await;

    let request = Request::builder()
        .method("GET")
        .uri("/version")
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
        content_type.contains("application/json"),
        "content-type should be application/json, got: {}",
        content_type
    );

    // parse response body
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let version_response: VersionResponse =
        serde_json::from_slice(&body).expect("failed to parse response");

    // verify fields are present and reasonable
    assert!(
        !version_response.version.is_empty(),
        "version should not be empty"
    );
    assert!(
        !version_response.commit.is_empty(),
        "commit should not be empty"
    );
    assert!(
        !version_response.build_time.is_empty(),
        "build_time should not be empty"
    );
    assert!(
        !version_response.rustc.is_empty(),
        "rustc should not be empty"
    );
    // dirty is a bool, always valid
}
