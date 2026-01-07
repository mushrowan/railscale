//! handler for /machine/map endpoint.

use axum::{extract::State, response::IntoResponse, Json};
use leadscale_db::Database;
use leadscale_proto::{MapRequest, MapResponse, MapResponseNode, UserProfile};
use leadscale_types::{Node, UserId};

use super::{OptionExt, ResultExt};
use crate::AppState;

/// handle map requests from tailscale clients.
///
/// clients send maprequests periodically to get:
/// - their own node information
/// - list of peer nodes
/// - dns configuration
/// - derp relay information
pub async fn map(
    State(state): State<AppState>,
    Json(req): Json<MapRequest>,
) -> Result<impl IntoResponse, super::ApiError> {
    let node = state
        .db
        .get_node_by_node_key(&req.node_key)
        .await
        .map_internal()?
        .or_unauthorized("node not found")?;

    let all_nodes = state.db.list_nodes().await.map_internal()?;

    // use grants engine to filter visible peers
    let visible_peers = state.grants.get_visible_peers(&node, &all_nodes);

    let peers: Vec<MapResponseNode> = visible_peers
        .iter()
        .map(|n| node_to_map_response_node(n))
        .collect();

    let users = state.db.list_users().await.map_internal()?;

    let user_profiles: Vec<UserProfile> = users
        .iter()
        .map(|u| UserProfile {
            id: u.id.0,
            login_name: u.username().to_string(),
            display_name: u.display().to_string(),
            profile_pic_url: u.profile_pic_url.clone(),
        })
        .collect();

    // generate packet filter rules from grants
    let packet_filter = state.grants.generate_filter_rules(&node, &all_nodes);

    let response = MapResponse {
        keep_alive: req.stream,
        node: Some(node_to_map_response_node(&node)),
        peers,
        dns_config: None,
        derp_map: None,
        packet_filter,
        user_profiles,
        control_time: Some(chrono::Utc::now().to_rfc3339()),
    };

    Ok(Json(response))
}

/// convert a node to mapresponsenode.
fn node_to_map_response_node(node: &Node) -> MapResponseNode {
    let mut addresses = Vec::new();
    if let Some(ipv4) = node.ipv4 {
        addresses.push(ipv4.to_string());
    }
    if let Some(ipv6) = node.ipv6 {
        addresses.push(ipv6.to_string());
    }

    let mut allowed_ips = addresses.clone();
    allowed_ips.extend(node.approved_routes.iter().map(|r| r.to_string()));

    MapResponseNode {
        id: node.id.0,
        stable_id: node.id.stable_id(),
        name: if node.given_name.is_empty() {
            node.hostname.clone()
        } else {
            node.given_name.clone()
        },
        node_key: node.node_key.as_bytes().to_vec(),
        machine_key: node.machine_key.as_bytes().to_vec(),
        disco_key: node.disco_key.as_bytes().to_vec(),
        addresses,
        allowed_ips,
        endpoints: node.endpoints.iter().map(|e| e.to_string()).collect(),
        derp: String::new(),
        hostinfo: node.hostinfo.clone(),
        online: node.is_online,
        tags: node.tags.clone(),
        primary_routes: node.approved_routes.iter().map(|r| r.to_string()).collect(),
        key_expiry: node.expiry.as_ref().map(|e| e.to_rfc3339()),
        expired: node.is_expired(),
        user: node.user_id.unwrap_or(UserId::TAGGED_DEVICES).0,
    }
}
