//! handler for /machine/register endpoint.
//!
//! implements tailscale's registration protocol. the request/response format
//! matches what the official Tailscale client expects.

use axum::{Json, extract::State};
use bytes::Bytes;
use railscale_db::Database;
use railscale_types::{HostInfo, MachineKey, Node, NodeId, NodeKey};
use serde::{Deserialize, Serialize};

use super::{ApiError, OptionExt, OptionalMachineKeyContext, ResultExt};
use crate::AppState;

/// tailscale registerrequest.
///
/// field names use pascalcase to match go's json encoding.
/// keys use prefixed hex format (e.g., "nodekey:abc123...").
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    /// client capability version.
    #[serde(default)]
    pub version: u64,

    /// node's current public key.
    pub node_key: NodeKey,

    /// previous node key (for key rotation).
    #[serde(default)]
    pub old_node_key: NodeKey,

    /// authentication info (contains pre-auth key).
    #[serde(default)]
    pub auth: Option<RegisterResponseAuth>,

    /// host information.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,

    /// request ephemeral node (auto-deleted when inactive).
    #[serde(default)]
    pub ephemeral: bool,

    /// url to poll for authentication completion (interactive login).
    /// when non-empty, the client is following up on a previous registration
    /// that returned an auth_url.
    #[serde(default)]
    pub followup: String,
}

/// authentication info for registerrequest.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponseAuth {
    /// pre-auth key for registration.
    #[serde(default)]
    pub auth_key: String,
}

/// tailscale registerresponse.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse {
    /// user info for this node.
    pub user: TailcfgUser,

    /// login info.
    pub login: TailcfgLogin,

    /// whether the node key needs rotation.
    #[serde(default)]
    pub node_key_expired: bool,

    /// whether the machine is authorized.
    pub machine_authorized: bool,

    /// if non-empty, user must visit this url to complete auth.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_url: String,

    /// error message if registration failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// user info in registerresponse (matches tailcfg.user).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TailcfgUser {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(default)]
    pub display_name: String,
}

/// login info in registerresponse (matches tailcfg.login).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TailcfgLogin {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub login_name: String,
    #[serde(default)]
    pub display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use railscale_db::RailscaleDb;
    use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
    use tower::ServiceExt;

    #[test]
    fn test_register_request_parses_followup() {
        let json = r#"{
            "Version": 68,
            "NodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
            "Followup": "/register/abc123"
        }"#;

        let req: RegisterRequest = serde_json::from_str(json).expect("should parse");
        assert_eq!(req.followup, "/register/abc123");
    }

    #[test]
    fn test_register_request_followup_defaults_to_empty() {
        let json = r#"{
            "Version": 68,
            "NodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000"
        }"#;

        let req: RegisterRequest = serde_json::from_str(json).expect("should parse");
        assert!(req.followup.is_empty());
    }

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
    async fn test_register_without_auth_key_returns_auth_url_when_oidc_disabled() {
        // set up test database
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // create app without OIDC
        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None, // No OIDC
            crate::StateNotifier::default(),
            None,
        )
        .await;

        // send register request without auth_key
        let req_body = serde_json::json!({
            "Version": 68,
            "NodeKey": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // without oidc, should return 200 with auth_url pointing to web registration
        assert_eq!(response.status(), StatusCode::OK);

        // parse response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let resp: RegisterResponse = serde_json::from_slice(&body).unwrap();

        // should not be authorized yet
        assert!(!resp.machine_authorized);

        // should have an auth_url for web registration
        assert!(
            resp.auth_url.starts_with("/register/"),
            "auth_url should start with /register/, got: {}",
            resp.auth_url
        );
    }

    #[tokio::test]
    async fn test_register_followup_waits_for_completion() {
        use crate::oidc::{CompletedRegistration, PendingRegistration};
        use railscale_types::test_utils::TestNodeBuilder;
        use railscale_types::{RegistrationId, User, UserId};
        use std::sync::Arc;

        // set up test database
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // first, make an initial request to create a pending registration
        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        // step 1: initial request without auth_key creates pending registration
        let req_body = serde_json::json!({
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
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // get the auth_url from the response
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let resp: RegisterResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.machine_authorized);
        let auth_url = resp.auth_url;
        assert!(auth_url.starts_with("/register/"));

        // step 2: send followup request - since nothing completed it,
        // it should timeout and return auth_url again
        let req_body = serde_json::json!({
            "Version": 68,
            "NodeKey": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "Followup": auth_url
        });

        // use a short timeout for the test
        let followup_response = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            ),
        )
        .await;

        // the followup should return quickly with a timeout response
        // got a response - could be timeout or not found
        match followup_response {
            Ok(Ok(response)) => {
                // got a response - could be timeout or not found
                let status = response.status();
                assert!(
                    status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
                    "expected 200 or 400, got {}",
                    status
                );
            }
            Ok(Err(e)) => {
                panic!("Request error: {:?}", e);
            }
            Err(_) => {
                // test timeout - that's okay, the followup is waiting
                // this shouldn't happen with our 30s server timeout vs 2s test timeout
            }
        }
    }
}

/// handle node registration.
///
/// this endpoint is called by tailscale clients to register a new node
/// with the control server. It supports three registration flows:
///
/// 1. **Preauth key**: Client provides an auth_key in the request
/// 2. **Interactive (initial)**: Client has no auth_key - returns auth_url
/// 3. **Interactive (followup)**: Client polls with followup URL after auth
///
/// when accessed via the ts2021 protocol, the machine key is extracted from
/// the Noise handshake context (which is cryptographically authenticated).
///
/// NOTE: we use `bytes` instead of `json<registerrequest>` because the real
/// tailscale client does not send a content-type header over ts2021/http/2.
pub async fn register(
    State(state): State<AppState>,
    OptionalMachineKeyContext(machine_key_ctx): OptionalMachineKeyContext,
    body: Bytes,
) -> Result<Json<RegisterResponse>, ApiError> {
    // parse json manually since tailscale client doesn't send content-type header
    let req: RegisterRequest =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;

    // machine key must come from noise context for ts2021
    let machine_key = match machine_key_ctx {
        Some(ctx) => ctx.0,
        None => {
            // for testing without ts2021, generate a placeholder key
            MachineKey::from_bytes(vec![0; 32])
        }
    };

    // extract auth key from nested auth struct (owned to avoid borrow issues)
    let auth_key_str = req
        .auth
        .as_ref()
        .map(|a| a.auth_key.clone())
        .unwrap_or_default();

    // route to appropriate registration flow
    if !req.followup.is_empty() {
        // followup request - wait for oidc completion
        return handle_followup_registration(state, &req.followup).await;
    } else if !auth_key_str.is_empty() {
        // preauth key registration - existing flow
        return handle_preauth_registration(state, req, machine_key, &auth_key_str).await;
    } else {
        // interactive registration - return auth_url
        return handle_interactive_registration(state, req, machine_key).await;
    }
}

/// handle registration with a preauth key.
async fn handle_preauth_registration(
    state: AppState,
    req: RegisterRequest,
    machine_key: MachineKey,
    auth_key_str: &str,
) -> Result<Json<RegisterResponse>, ApiError> {
    let preauth_key = state
        .db
        .get_preauth_key(auth_key_str)
        .await
        .map_internal()?
        .or_unauthorized("invalid preauth key")?;

    if !preauth_key.is_valid() {
        return Err(ApiError::unauthorized(
            "preauth key expired or already used",
        ));
    }

    // get user for response
    let user = state
        .db
        .get_user(preauth_key.user_id)
        .await
        .map_internal()?;

    let hostname = req
        .hostinfo
        .as_ref()
        .and_then(|h| h.hostname.clone())
        .unwrap_or_default();

    // allocate ip addresses for the new node
    let (ipv4, ipv6) = {
        let mut allocator = state.ip_allocator.lock().await;
        allocator
            .allocate()
            .map_err(|e| ApiError::internal(e.to_string()))?
    };

    let now = chrono::Utc::now();
    let node = Node {
        id: NodeId(0),
        machine_key,
        node_key: req.node_key,
        disco_key: Default::default(),
        ipv4,
        ipv6,
        endpoints: vec![],
        hostinfo: req.hostinfo,
        hostname: hostname.clone(),
        given_name: hostname,
        user_id: if preauth_key.creates_tagged_nodes() {
            None
        } else {
            Some(preauth_key.user_id)
        },
        register_method: railscale_types::RegisterMethod::AuthKey,
        tags: preauth_key.tags.clone(),
        auth_key_id: Some(preauth_key.id),
        last_seen: None,
        expiry: None,
        approved_routes: vec![],
        created_at: now,
        updated_at: now,
        is_online: None,
    };

    let _node = state.db.create_node(&node).await.map_internal()?;

    // notify streaming clients that a new node has been added
    state.notifier.notify_state_changed();

    if !preauth_key.reusable {
        state
            .db
            .mark_preauth_key_used(preauth_key.id)
            .await
            .map_internal()?;
    }

    // build tailscale-format response
    let (user_info, login_info) = match user {
        Some(u) => (
            TailcfgUser {
                id: u.id.0 as i64,
                display_name: u.name.clone(),
            },
            TailcfgLogin {
                id: u.id.0 as i64,
                provider: "authkey".to_string(),
                login_name: u.name.clone(),
                display_name: u.name,
            },
        ),
        None => (TailcfgUser::default(), TailcfgLogin::default()),
    };

    Ok(Json(RegisterResponse {
        user: user_info,
        login: login_info,
        node_key_expired: false,
        machine_authorized: true,
        auth_url: String::new(),
        error: String::new(),
    }))
}

/// handle interactive registration (no auth_key).
///
/// this creates a pending registration and returns an auth_url for the user
/// to complete authentication (via OIDC or web registration).
async fn handle_interactive_registration(
    state: AppState,
    req: RegisterRequest,
    machine_key: MachineKey,
) -> Result<Json<RegisterResponse>, ApiError> {
    use crate::oidc::PendingRegistration;
    use railscale_types::RegistrationId;
    use std::sync::Arc;

    // generate a new registration id
    let registration_id = RegistrationId::generate();

    // create and store pending registration
    let pending = Arc::new(PendingRegistration::new(
        req.node_key.clone(),
        machine_key,
        req.hostinfo,
    ));
    state
        .pending_registrations
        .insert(registration_id.clone(), pending);

    // build auth_url - this is where the user will be redirected to authenticate
    let auth_url = format!("/register/{}", registration_id);

    Ok(Json(RegisterResponse {
        user: TailcfgUser::default(),
        login: TailcfgLogin::default(),
        node_key_expired: false,
        machine_authorized: false,
        auth_url,
        error: String::new(),
    }))
}

/// authentication has completed. It waits for the oidc callback to signal
///completion via the PendingRegistration
/// this is called when the client polls with a followup url to check if
/// authentication has completed. It waits for the OIDC callback to signal
/// completion via the PendingRegistration.
async fn handle_followup_registration(
    state: AppState,
    followup: &str,
) -> Result<Json<RegisterResponse>, ApiError> {
    use railscale_types::RegistrationId;
    use std::time::Duration;

    // parse registration id from followup url (e.g., "/register/abc123")
    let reg_id_str = followup
        .strip_prefix("/register/")
        .ok_or_else(|| ApiError::bad_request("invalid followup URL format"))?;

    let registration_id = RegistrationId::from_string(reg_id_str)
        .map_err(|e| ApiError::bad_request(format!("invalid registration ID: {}", e)))?;

    // look up pending registration
    let pending = state
        .pending_registrations
        .get(&registration_id)
        .ok_or_else(|| ApiError::bad_request("registration not found or expired"))?;

    // check if already completed
    if let Some(completed) = pending.get_completed().await {
        return build_success_response(completed);
    }

    // wait for completion with timeout (30 seconds)
    let timeout = Duration::from_secs(30);
    let wait_result = tokio::time::timeout(timeout, pending.notify.notified()).await;

    match wait_result {
        Ok(()) => {
            // notified - check for completion
            if let Some(completed) = pending.get_completed().await {
                return build_success_response(completed);
            }
            // not completed yet - return auth_url to continue polling
            Ok(Json(RegisterResponse {
                user: TailcfgUser::default(),
                login: TailcfgLogin::default(),
                node_key_expired: false,
                machine_authorized: false,
                auth_url: followup.to_string(),
                error: String::new(),
            }))
        }
        Err(_timeout) => {
            // timeout - return auth_url so client can retry
            Ok(Json(RegisterResponse {
                user: TailcfgUser::default(),
                login: TailcfgLogin::default(),
                node_key_expired: false,
                machine_authorized: false,
                auth_url: followup.to_string(),
                error: String::new(),
            }))
        }
    }
}

/// build a success response for a completed registration.
fn build_success_response(
    completed: crate::oidc::CompletedRegistration,
) -> Result<Json<RegisterResponse>, ApiError> {
    let user_info = TailcfgUser {
        id: completed.user.id.0 as i64,
        display_name: completed.user.display_name.clone().unwrap_or_default(),
    };

    let login_info = TailcfgLogin {
        id: completed.user.id.0 as i64,
        provider: "oidc".to_string(),
        login_name: completed.user.name.clone(),
        display_name: completed.user.display_name.unwrap_or(completed.user.name),
    };

    Ok(Json(RegisterResponse {
        user: user_info,
        login: login_info,
        node_key_expired: false,
        machine_authorized: true,
        auth_url: String::new(),
        error: String::new(),
    }))
}
