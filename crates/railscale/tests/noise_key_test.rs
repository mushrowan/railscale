//! tests for Noise key loading and persistence

use railscale::{StateNotifier, create_app, load_or_generate_noise_keypair};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;
use tempfile::TempDir;

#[tokio::test]
async fn test_load_or_generate_creates_new_key_file() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let key_path = temp_dir.path().join("noise.key");

    // key file should not exist yet
    assert!(!key_path.exists());

    // load or generate should create the file
    let keypair = load_or_generate_noise_keypair(&key_path)
        .await
        .expect("failed to load/generate keypair");

    // file should now exist
    assert!(key_path.exists());

    // key should be valid (32 bytes for curve25519)
    assert_eq!(keypair.public.len(), 32);
    assert_eq!(keypair.private.len(), 32);
}

#[tokio::test]
async fn test_load_or_generate_loads_existing_key() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let key_path = temp_dir.path().join("noise.key");

    // generate initial key
    let keypair1 = load_or_generate_noise_keypair(&key_path)
        .await
        .expect("failed to generate keypair");

    // load the same key
    let keypair2 = load_or_generate_noise_keypair(&key_path)
        .await
        .expect("failed to load keypair");

    // should be the same key
    assert_eq!(keypair1.public, keypair2.public);
    assert_eq!(keypair1.private, keypair2.private);
}

#[tokio::test]
async fn test_app_uses_provided_keypair() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let key_path = temp_dir.path().join("noise.key");

    // generate keypair
    let keypair = load_or_generate_noise_keypair(&key_path)
        .await
        .expect("failed to load/generate keypair");

    // save public key before moving keypair into create_app
    let expected_public_key = keypair.public.clone();

    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = StateNotifier::default();

    // create app with the keypair
    let app = create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // verify /key returns the correct public key
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let response = app
        .oneshot(Request::builder().uri("/key").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let key_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // the public key in response should match our keypair
    let returned_key: Vec<u8> = key_response["publicKey"]
        .as_array()
        .expect("publicKey should be array")
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    assert_eq!(returned_key, expected_public_key);
}
