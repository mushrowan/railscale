//! integration tests for the `/bootstrap-dns` endpoint
//!
//! the `/bootstrap-dns` endpoint provides dns resolution fallback for clients
//! whose local dns is broken, allowing them to bootstrap derp connections

use std::collections::HashMap;
use std::net::IpAddr;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use railscale::{StateNotifier, create_app_with_policy_handle};
use railscale_db::RailscaleDb;
use railscale_grants::Policy;
use railscale_proto::{DerpMap, DerpNode, DerpRegion};
use railscale_types::Config;
use tower::ServiceExt;

/// test that GET /bootstrap-dns returns resolved addresses for derp hostnames
#[tokio::test]
async fn test_bootstrap_dns_resolves_derp_hostnames() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let config = Config::default();
    let notifier = StateNotifier::default();

    // create a derp map with localhost (should always resolve)
    let derp_map = DerpMap {
        regions: [(
            1,
            DerpRegion {
                region_id: 1,
                region_code: "test".to_string(),
                region_name: "Test Region".to_string(),
                nodes: vec![DerpNode {
                    name: "1a".to_string(),
                    region_id: 1,
                    host_name: "localhost".to_string(),
                    ..Default::default()
                }],
            },
        )]
        .into_iter()
        .collect(),
        omit_default_regions: false,
    };

    let (app, _handle) = create_app_with_policy_handle(
        db,
        Policy::empty(),
        config,
        None,
        notifier,
        None,
        Some(derp_map),
    )
    .await;

    let request = Request::builder()
        .method("GET")
        .uri("/bootstrap-dns")
        .body(Body::empty())
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

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
    let dns_map: HashMap<String, Vec<IpAddr>> =
        serde_json::from_slice(&body).expect("failed to parse response");

    // localhost should resolve to 127.0.0.1 and/or ::1
    assert!(
        dns_map.contains_key("localhost"),
        "should contain localhost entry"
    );
    let addrs = dns_map.get("localhost").unwrap();
    assert!(
        !addrs.is_empty(),
        "localhost should resolve to at least one address"
    );
}

/// test that GET /bootstrap-dns returns empty map when derp map is empty
#[tokio::test]
async fn test_bootstrap_dns_empty_derp_map() {
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let config = Config::default();
    let notifier = StateNotifier::default();

    // empty derp map
    let derp_map = DerpMap::default();

    let (app, _handle) = create_app_with_policy_handle(
        db,
        Policy::empty(),
        config,
        None,
        notifier,
        None,
        Some(derp_map),
    )
    .await;

    let request = Request::builder()
        .method("GET")
        .uri("/bootstrap-dns")
        .body(Body::empty())
        .expect("failed to build request");

    let response = app.oneshot(request).await.expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read body");
    let dns_map: HashMap<String, Vec<IpAddr>> =
        serde_json::from_slice(&body).expect("failed to parse response");

    assert!(
        dns_map.is_empty(),
        "should return empty map for empty DERP map"
    );
}
