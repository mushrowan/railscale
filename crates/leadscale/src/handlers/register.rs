//! handler for /machine/register endpoint

use axum::{extract::State, response::IntoResponse, Json};
use leadscale_db::Database;
use leadscale_types::{MachineKey, Node, NodeId, NodeKey};
use serde::{Deserialize, Serialize};

use super::{ApiError, OptionExt, ResultExt};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub machine_key: Vec<u8>,
    pub node_key: Vec<u8>,
    pub preauth_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: u64,
    pub machine_key: Vec<u8>,
    pub node_key: Vec<u8>,
}

/// handle node registration via preauth key
///
/// endpoint is called by tailscale clients to register a new node
/// with the control server
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let preauth_key = state
        .db
        .get_preauth_key(&req.preauth_key)
        .await
        .map_internal()?
        .or_unauthorized("invalid preauth key")?;

    if !preauth_key.is_valid() {
        return Err(ApiError::unauthorized("preauth key expired or already used"));
    }

    let now = chrono::Utc::now();
    let node = Node {
        id: NodeId(0),
        machine_key: MachineKey::from_bytes(req.machine_key),
        node_key: NodeKey::from_bytes(req.node_key),
        disco_key: Default::default(),
        ipv4: None,
        ipv6: None,
        endpoints: vec![],
        hostinfo: None,
        hostname: String::new(),
        given_name: String::new(),
        user_id: if preauth_key.creates_tagged_nodes() {
            None
        } else {
            Some(preauth_key.user_id)
        },
        register_method: leadscale_types::RegisterMethod::AuthKey,
        tags: preauth_key.tags.clone(),
        auth_key_id: Some(preauth_key.id),
        last_seen: None,
        expiry: None,
        approved_routes: vec![],
        created_at: now,
        updated_at: now,
        is_online: None,
    };

    let node = state.db.create_node(&node).await.map_internal()?;

    if !preauth_key.reusable {
        state
            .db
            .mark_preauth_key_used(preauth_key.id)
            .await
            .map_internal()?;
    }

    Ok(Json(RegisterResponse {
        node_id: node.id.0,
        machine_key: node.machine_key.as_bytes().to_vec(),
        node_key: node.node_key.as_bytes().to_vec(),
    }))
}
