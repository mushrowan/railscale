//! handler for /machine/register endpoint.
//!
//! implements tailscale's registration protocol. the request/response format
//! matches what the official Tailscale client expects.

use axum::{Json, extract::State, response::IntoResponse};
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

/// handle node registration via preauth key.
///
/// this endpoint is called by tailscale clients to register a new node
/// with the control server.
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
) -> Result<impl IntoResponse, ApiError> {
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

    // extract auth key from nested auth struct
    let auth_key_str = req.auth.as_ref().map(|a| a.auth_key.as_str()).unwrap_or("");

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
