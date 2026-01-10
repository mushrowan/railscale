//! handler for /machine/map endpoint.

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use railscale_db::Database;
use railscale_proto::{MapRequest, MapResponse, MapResponseNode, UserProfile};
use railscale_types::{Node, NodeKey, UserId};
use tokio::sync::broadcast;

use super::{OptionExt, ResultExt};
use crate::AppState;

/// handle map requests from tailscale clients.
///
/// clients send maprequests periodically to get:
/// - their own node information
/// - list of peer nodes
/// - dns configuration
/// - derp relay information
///
/// when `stream: true`, the connection stays open and updates are pushed
/// when state changes (nodes added/removed/updated).
pub async fn map(
    State(state): State<AppState>,
    Json(req): Json<MapRequest>,
) -> Result<impl IntoResponse, super::ApiError> {
    // validate the node exists
    let node = state
        .db
        .get_node_by_node_key(&req.node_key)
        .await
        .map_internal()?
        .or_unauthorized("node not found")?;

    if req.stream {
        // streaming mode: keep connection open and push updates
        Ok(streaming_response(state, node.node_key).into_response())
    } else {
        // non-streaming mode: return single json response
        let mut response = build_map_response(&state, &req.node_key).await?;
        response.keep_alive = false;
        Ok(Json(response).into_response())
    }
}

/// what type of message to send next in the streaming response.
enum StreamMessage {
    /// full state update (initial or after state change).
    FullUpdate,
    /// keep-alive message (no state change, just preventing timeout).
    KeepAlive,
    /// end the stream.
    End,
}

/// build a streaming response that pushes updates when state changes.
fn streaming_response(state: AppState, node_key: NodeKey) -> Response {
    // subscribe to state changes before building initial response
    let receiver = state.notifier.subscribe();

    // get keep-alive interval from config (0 means disabled)
    let keepalive_secs = state.config.tuning.map_keepalive_interval_secs;
    let keepalive_interval = if keepalive_secs > 0 {
        Some(Duration::from_secs(keepalive_secs))
    } else {
        None
    };

    // create a stream that yields length-prefixed responses
    let stream = stream::unfold(
        (state, node_key, receiver, true, keepalive_interval),
        |(state, node_key, mut receiver, is_first, keepalive_interval)| async move {
            // determine what message to send
            let message_type = if is_first {
                StreamMessage::FullUpdate
            } else {
                wait_for_next_message(&mut receiver, keepalive_interval).await
            };

            match message_type {
                StreamMessage::FullUpdate => {
                    let response = match build_map_response(&state, &node_key).await {
                        Ok(r) => r,
                        Err(_) => return None,
                    };
                    let bytes = encode_length_prefixed(&response)?;
                    Some((
                        bytes,
                        (state, node_key, receiver, false, keepalive_interval),
                    ))
                }
                StreamMessage::KeepAlive => {
                    let response = MapResponse::keepalive();
                    let bytes = encode_length_prefixed(&response)?;
                    Some((
                        bytes,
                        (state, node_key, receiver, false, keepalive_interval),
                    ))
                }
                StreamMessage::End => None,
            }
        },
    );

    // convert to a stream of result<bytes, infallible> for axum
    let body_stream = stream.map(Ok::<_, Infallible>);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid status and headers")
}

/// wait for either a state change notification or a keep-alive timeout.
async fn wait_for_next_message(
    receiver: &mut broadcast::Receiver<crate::notifier::StateChanged>,
    keepalive_interval: Option<Duration>,
) -> StreamMessage {
    match keepalive_interval {
        Some(interval) => {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            StreamMessage::FullUpdate
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            StreamMessage::End
                        }
                    }
                }
                _ = tokio::time::sleep(interval) => {
                    StreamMessage::KeepAlive
                }
            }
        }
        None => {
            // no keep-alive configured, just wait for state changes
            match receiver.recv().await {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => StreamMessage::FullUpdate,
                Err(broadcast::error::RecvError::Closed) => StreamMessage::End,
            }
        }
    }
}

/// build a mapresponse for the given node.
async fn build_map_response(
    state: &AppState,
    node_key: &NodeKey,
) -> Result<MapResponse, super::ApiError> {
    let node = state
        .db
        .get_node_by_node_key(node_key)
        .await
        .map_internal()?
        .or_unauthorized("node not found")?;

    let all_nodes = state.db.list_nodes().await.map_internal()?;
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

    let resolver = crate::resolver::MapUserResolver::new(users);

    // use grants engine to filter visible peers
    let visible_peers = state.grants.get_visible_peers(&node, &all_nodes, &resolver);

    // generate packet filter rules from grants
    let packet_filter = state
        .grants
        .generate_filter_rules(&node, &all_nodes, &resolver);

    // generate dns configuration
    let dns_config = crate::dns::generate_dns_config(&state.config);

    // generate derp map
    let derp_map = crate::derp::generate_derp_map(&state.config);
    let preferred_derp = derp_map
        .regions
        .keys()
        .next()
        .map(|id| id.to_string())
        .unwrap_or_default();

    Ok(MapResponse {
        keep_alive: true,
        node: Some(node_to_map_response_node(&node, &preferred_derp)),
        peers: visible_peers
            .iter()
            .map(|n| node_to_map_response_node(n, &preferred_derp))
            .collect(),
        dns_config,
        derp_map: Some(derp_map),
        packet_filter,
        user_profiles,
        control_time: Some(chrono::Utc::now().to_rfc3339()),
    })
}

/// encode a mapresponse with a 4-byte little-endian length prefix.
fn encode_length_prefixed(response: &MapResponse) -> Option<Bytes> {
    let json_bytes = serde_json::to_vec(response).ok()?;
    let len = u32::try_from(json_bytes.len()).unwrap_or(u32::MAX);

    let mut body = Vec::with_capacity(4 + json_bytes.len());
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(&json_bytes);

    Some(Bytes::from(body))
}

/// convert a node to mapresponsenode.
fn node_to_map_response_node(node: &Node, preferred_derp: &str) -> MapResponseNode {
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
        derp: preferred_derp.to_string(),
        hostinfo: node.hostinfo.clone(),
        online: node.is_online,
        tags: node.tags.clone(),
        primary_routes: node.approved_routes.iter().map(|r| r.to_string()).collect(),
        key_expiry: node.expiry.as_ref().map(|e| e.to_rfc3339()),
        expired: node.is_expired(),
        user: node.user_id.unwrap_or(UserId::TAGGED_DEVICES).0,
    }
}
