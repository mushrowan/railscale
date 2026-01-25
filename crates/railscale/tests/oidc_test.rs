//! integration tests for oidc authentication flow.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use railscale_db::RailscaleDb;
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_types::{Config, OidcConfig, PkceConfig, PkceMethod, RegistrationId};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// test rsa private key (2048-bit) for signing jwts in tests.
/// this is a static test key - do not use in production.
const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA8QAHgeEUCGHmuZRpYYt4N2PLVPSfHZ0bOu2W7r7AtqiFGLTs
loNMN6kvu1uAchBnf/daK9Gy4NUFX7WsLRx6cDii4kvGkcGRHm0yfMXdBHATB7y4
UBBYrIduoKg+nJBmnSKMrENzOUbHAiAcoknNrbtrke9x/8lFV1IgX/AH9ZM+eIbP
SKR74W8TbylZEnqRUeVW5hnUjw1uNPrWVIEmHC+fme+ONEGKPT4Zc1oFYk+o5nft
q1ZanSGXHAKK3kEpRbLiiSZ/ak53vwqJm3gA3lAbT5Xhdvbh0dzKARVD5ST+OUlk
2sz2+/5U4VZkuTAOd2VRLngHgff5GkMUVBeNEQIDAQABAoIBAAjeo2gYTJByafdy
it5YL7h6J8Wcqy5/1by5edCXnKgcU6mxHvP7KRbzVxpiJ7wK9oQzKlJqiVbVADmh
ihCu96Khsvz5JPnAUgL4qd8FuTisl0a1n2Ly9xCCe4PWLVe9yMkHuH2ujdMR08k0
PVmLtdIrD65zTZLIaZDpKN/fCav0CRM7jMWqqhm4axRfSokvfKoH9SA9pFQZ/Rg5
uAq36lYFyF0hPXxKv25hUvrZWeYgljmbLHEVdDMlCxwibJAyKeNNk+6KZTrp6pGA
NNnFJ2mZeu/naqYyhu28OASXQDk9LrXosg+ywa/gCGIaLY+XWM50M5Dt4088+n52
Zwlz5wECgYEA/PnKeBqj+grUGyNCrV77ecveJ3urnoitGbKJ8EV2QT0v1rs87Zw1
m1b95xqeh1jPsrCyLZSE6Z87lVos9lq4jgzfhJV4HTsU5ZXm/Q3JzzCv/TR3KDNF
AlOaC8y7SXaj8uAsm8TIu+YFnsrW9Sug22lcVKU6pf7mriN0P7CJf7kCgYEA8+GW
jj3FGIKz7t9kBu1xvBXh6jGsIk+Tkq64MZTHR5WKW3P3jOb8rdMQ7Y1XOHeeESXq
d+Or8f1Xi5vjF2t4QKNxYOk+wLgExSr3kkmKaCbzRXENeI/85dVh+SFTGV8SPmPK
AKjSaYGfh5YDgTIvooTM6U/FolkB001R2wW8tBkCgYEAinygV1GWNNratKR/6vMV
Td7KFelA0T/XKzsvAia0jxBU8QN9XkJmokxkILDU2hlHUnYihItKm6486wz7kj2l
zLXFYwqEP9RJI0oFssBqmw73OPEQziQLAjQMH6uLV7MoG1yXbwqyLRLGPuCh/oNM
wvCRyBDP43GAjRIBoKAfFZkCgYAsmXegAZnWtqhTKdUwEyI2hEXxPy48hBL3wy36
GzwqUiWgPd/qi59v5mZ1GuD1eaKVfjqXvDIIqgzlgheQg93U7E7iqyUHt19f81Cd
FwfRrjXU4CzXfHWCTniBR9/bhvBeKn+ZiUYZd1QGRp/Tc6sUbHbQv/7jhqV3z+8F
P9JXmQKBgB5m4nXiyRz++ZejUTQzd1r/CD/m3kHcazakWc01aNL0Q2c6NhS9Qnla
4g2qAYBjjA6Nj7zr6vlNgOgm7fBePw/CZ+HuThKJ3wJgCzw+Yg3uqi88Y20jj6ES
d02SQNqbiFrs7JOdrqIv5cwHj2y4LxXqFCzoz6KX5AK1r/dOxQqm
-----END RSA PRIVATE KEY-----"#;

/// test rsa public key components for jwks.
/// these match the private key above (base64url encoded).
const TEST_RSA_MODULUS: &str = "8QAHgeEUCGHmuZRpYYt4N2PLVPSfHZ0bOu2W7r7AtqiFGLTsloNMN6kvu1uAchBnf_daK9Gy4NUFX7WsLRx6cDii4kvGkcGRHm0yfMXdBHATB7y4UBBYrIduoKg-nJBmnSKMrENzOUbHAiAcoknNrbtrke9x_8lFV1IgX_AH9ZM-eIbPSKR74W8TbylZEnqRUeVW5hnUjw1uNPrWVIEmHC-fme-ONEGKPT4Zc1oFYk-o5nftq1ZanSGXHAKK3kEpRbLiiSZ_ak53vwqJm3gA3lAbT5Xhdvbh0dzKARVD5ST-OUlk2sz2-_5U4VZkuTAOd2VRLngHgff5GkMUVBeNEQ";
const TEST_RSA_EXPONENT: &str = "AQAB";
const TEST_KEY_ID: &str = "test-key-1";

/// create a mock oidc discovery response for the given issuer url.
fn mock_discovery_response(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "email", "name", "preferred_username"]
    })
}

/// create a mock jwks response (empty - used for tests that don't need jwt verification).
fn mock_jwks_response() -> serde_json::Value {
    serde_json::json!({
        "keys": []
    })
}

/// create a jwks response with a test rsa public key.
fn test_jwks_response() -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": TEST_KEY_ID,
            "n": TEST_RSA_MODULUS,
            "e": TEST_RSA_EXPONENT
        }]
    })
}

/// jwt claims for id token.
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nonce: String,
    email: String,
    email_verified: bool,
    preferred_username: String,
    name: String,
}

/// create a signed id token jwt for testing.
fn create_test_id_token(issuer: &str, client_id: &str, nonce: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: "test-user-sub".to_string(),
        aud: client_id.to_string(),
        exp: now + 3600, // 1 hour from now
        iat: now,
        nonce: nonce.to_string(),
        email: "alice@example.com".to_string(),
        email_verified: true,
        preferred_username: "alice".to_string(),
        name: "Alice Smith".to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KEY_ID.to_string());

    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
        .expect("test RSA key should be valid");

    jsonwebtoken::encode(&header, &claims, &key).expect("JWT encoding should succeed")
}

/// create a test oidc config pointing to the mock server.
fn test_oidc_config(issuer: &str) -> OidcConfig {
    OidcConfig {
        issuer: issuer.to_string(),
        client_id: "test-client".to_string(),
        client_secret: SecretString::from("test-secret"),
        client_secret_path: None,
        scope: vec!["openid".to_string(), "email".to_string()],
        email_verified_required: false,
        pkce: PkceConfig {
            enabled: false,
            method: PkceMethod::S256,
        },
        allowed_domains: vec![],
        allowed_users: vec![],
        allowed_groups: vec![],
        group_prefix: None,
        expiry_secs: 180 * 24 * 3600,
        use_expiry_from_token: false,
        extra_params: HashMap::new(),
        rate_limit_per_minute: 0, // Disable rate limiting for tests
    }
}

/// helper to create a default grants engine.
fn default_grants() -> GrantsEngine {
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::Wildcard],
        dst: vec![Selector::Wildcard],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });
    GrantsEngine::new(policy)
}

#[tokio::test]
async fn test_register_redirect_with_mock_oidc() {
    // start mock oidc server
    let mock_server = MockServer::start().await;
    let issuer = mock_server.uri();

    // set up discovery endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_discovery_response(&issuer)))
        .mount(&mock_server)
        .await;

    // set up jwks endpoint (needed for provider metadata)
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_jwks_response()))
        .mount(&mock_server)
        .await;

    // create oidc provider pointing to mock server
    let oidc_config = test_oidc_config(&issuer);
    let oidc = railscale::oidc::AuthProviderOidc::new(oidc_config, "http://localhost:8080")
        .await
        .expect("OIDC provider creation should succeed");

    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create app with OIDC
    let config = Config::default();
    let app = railscale::create_app(
        db,
        default_grants(),
        config,
        Some(oidc),
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // generate a test registration id
    let reg_id = RegistrationId::new([42u8; 32]);
    let reg_id_str = reg_id.to_string();

    // send register request
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/register/{}", reg_id_str))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // should get a redirect to the oidc provider
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // extract the location header
    let location = response
        .headers()
        .get("location")
        .expect("should have location header")
        .to_str()
        .expect("location should be valid string");

    // verify the redirect url points to our mock oidc server's authorize endpoint
    assert!(
        location.starts_with(&format!("{}/authorize", issuer)),
        "redirect should go to authorize endpoint, got: {}",
        location
    );

    // verify required oauth2 parameters are present
    assert!(
        location.contains("client_id=test-client"),
        "should have client_id"
    );
    assert!(
        location.contains("redirect_uri="),
        "should have redirect_uri"
    );
    assert!(
        location.contains("response_type=code"),
        "should have response_type=code"
    );
    assert!(location.contains("scope="), "should have scope");
    assert!(location.contains("state="), "should have state parameter");
    assert!(location.contains("nonce="), "should have nonce parameter");
}

#[tokio::test]
async fn test_oidc_callback_with_invalid_state() {
    // start mock oidc server
    let mock_server = MockServer::start().await;
    let issuer = mock_server.uri();

    // set up discovery endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_discovery_response(&issuer)))
        .mount(&mock_server)
        .await;

    // set up jwks endpoint
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_jwks_response()))
        .mount(&mock_server)
        .await;

    // create oidc provider
    let oidc_config = test_oidc_config(&issuer);
    let oidc = railscale::oidc::AuthProviderOidc::new(oidc_config, "http://localhost:8080")
        .await
        .expect("OIDC provider creation should succeed");

    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create app with OIDC
    let config = Config::default();
    let app = railscale::create_app(
        db,
        default_grants(),
        config,
        Some(oidc),
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // call callback with invalid state (not in cache)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oidc/callback?code=test_code&state=invalid_state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // should get 400 bad request because state is not in cache
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oidc_callback_full_flow_creates_user() {
    use railscale_db::Database;

    // start mock oidc server
    let mock_server = MockServer::start().await;
    let issuer = mock_server.uri();

    // set up discovery endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_discovery_response(&issuer)))
        .mount(&mock_server)
        .await;

    // set up jwks endpoint with a test RSA key
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_response()))
        .mount(&mock_server)
        .await;

    // create oidc provider
    let oidc_config = test_oidc_config(&issuer);
    let oidc = railscale::oidc::AuthProviderOidc::new(oidc_config, "http://localhost:8080")
        .await
        .expect("OIDC provider creation should succeed");

    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // generate authorization url to get a valid state and nonce in the cache
    let reg_id = RegistrationId::new([42u8; 32]);
    let (_auth_url, csrf_token, _) = oidc.authorization_url(reg_id);

    // get the state and nonce from the cache
    let state = csrf_token.secret();
    let reg_info = oidc
        .get_registration_info(state)
        .expect("registration info should be in cache");
    let nonce = &reg_info.nonce;

    // create a valid id token jwt signed with our test key
    let id_token = create_test_id_token(&issuer, "test-client", nonce);

    // mock token endpoint - returns a token response with our signed id token
    let token_response = serde_json::json!({
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    });

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response))
        .mount(&mock_server)
        .await;

    // create app with the same OIDC provider (shares the cache)
    let config = Config::default();
    let app = railscale::create_app(
        db.clone(),
        default_grants(),
        config,
        Some(oidc),
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // call callback with valid state from cache
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oidc/callback?code=test_code&state={}", state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // should succeed with 200 ok
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "full OIDC flow should succeed"
    );

    // verify user was created in database
    let provider_identifier = format!("{}:test-user-sub", issuer);
    let user = db
        .get_user_by_oidc_identifier(&provider_identifier)
        .await
        .expect("database query should succeed")
        .expect("user should have been created");

    assert_eq!(user.email, Some("alice@example.com".to_string()));
    assert_eq!(user.name, "alice");
}

/// full integration test for interactive login flow:
/// 1. Client sends register request without auth_key
/// 2. Server returns auth_url
/// 3. User authenticates via OIDC (simulated)
/// 4. Server receives OIDC callback, creates node
/// 5. Client sends followup request
/// 6. Server returns machine_authorized: true
#[tokio::test]
async fn test_full_interactive_login_flow() {
    use railscale::handlers::RegisterResponse;
    use railscale_db::Database;

    // start mock oidc server
    let mock_server = MockServer::start().await;
    let issuer = mock_server.uri();

    // set up discovery endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_discovery_response(&issuer)))
        .mount(&mock_server)
        .await;

    // set up jwks endpoint with test RSA key
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_response()))
        .mount(&mock_server)
        .await;

    // create oidc provider
    let oidc_config = test_oidc_config(&issuer);
    let oidc = railscale::oidc::AuthProviderOidc::new(oidc_config, "http://localhost:8080")
        .await
        .expect("OIDC provider creation should succeed");

    // set up test database
    let db = RailscaleDb::new_in_memory().await.unwrap();
    db.migrate().await.unwrap();

    // create app with OIDC
    // enable allow_non_noise_registration for testing without noise handshake
    let mut config = Config::default();
    config.allow_non_noise_registration = true;
    let app = railscale::create_app(
        db.clone(),
        default_grants(),
        config,
        Some(oidc.clone()),
        railscale::StateNotifier::default(),
        None,
    )
    .await;

    // step 1: initial register request without auth_key
    let register_body = serde_json::json!({
        "Version": 68,
        "NodeKey": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let register_resp: RegisterResponse = serde_json::from_slice(&body).unwrap();

    // should not be authorized yet
    assert!(!register_resp.machine_authorized);
    // should have auth_url
    assert!(
        register_resp.auth_url.starts_with("/register/"),
        "auth_url should start with /register/"
    );

    let auth_url = register_resp.auth_url;
    let _reg_id = auth_url.strip_prefix("/register/").unwrap();

    // step 2: follow the auth_url - this redirects to oidc
    let redirect_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&auth_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(redirect_response.status(), StatusCode::SEE_OTHER);

    // get the oidc redirect url to extract state and nonce
    let oidc_redirect = redirect_response
        .headers()
        .get("location")
        .expect("should have location header")
        .to_str()
        .unwrap();

    // extract state from the redirect url
    let url = url::Url::parse(oidc_redirect).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("should have state parameter");

    // get nonce from the registration info
    let reg_info = oidc
        .get_registration_info(&state)
        .expect("registration info should be in cache");
    let nonce = reg_info.nonce.clone();

    // step 3: create signed id token and mock token endpoint
    let id_token = create_test_id_token(&issuer, "test-client", &nonce);
    let token_response = serde_json::json!({
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    });

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response))
        .mount(&mock_server)
        .await;

    // step 4: call oidc callback - this creates the node
    let callback_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oidc/callback?code=test_code&state={}", state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        callback_response.status(),
        StatusCode::OK,
        "OIDC callback should succeed"
    );

    // step 5: send followup request - should now be authorized
    let followup_body = serde_json::json!({
        "Version": 68,
        "NodeKey": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "Followup": auth_url
    });

    let followup_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&followup_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(followup_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(followup_response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let followup_resp: RegisterResponse = serde_json::from_slice(&body).unwrap();

    // should now be authorized
    assert!(
        followup_resp.machine_authorized,
        "machine should be authorized after OIDC flow"
    );
    assert!(
        followup_resp.auth_url.is_empty(),
        "auth_url should be empty after authorization"
    );
    assert_eq!(followup_resp.login.provider, "oidc");
    assert_eq!(followup_resp.login.login_name, "alice");

    // verify user was created
    let provider_identifier = format!("{}:test-user-sub", issuer);
    let user = db
        .get_user_by_oidc_identifier(&provider_identifier)
        .await
        .expect("database query should succeed")
        .expect("user should have been created");

    assert_eq!(user.email, Some("alice@example.com".to_string()));

    // verify node was created
    let nodes = db.list_nodes().await.expect("should list nodes");
    assert_eq!(nodes.len(), 1, "should have created one node");
    assert_eq!(nodes[0].user_id, Some(user.id));
}
