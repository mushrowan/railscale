//! handler for /machine/map endpoint.

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, State},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::Stream;
use futures_util::stream::{self, StreamExt};
use railscale_db::Database;
use railscale_grants::GeoIpResolver;
use railscale_proto::{MapRequest, MapResponse, MapResponseNode, TkaInfo, UserProfile};
use railscale_types::{Node, NodeId, NodeKey, UserId};
use tokio::sync::broadcast;

/// extractor for optional client socket address.
/// returns Some(addr) if ConnectInfo is available, None otherwise.
/// useful for handlers that need to work in both production and test contexts.
pub struct OptionalClientAddr(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalClientAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);
        Ok(OptionalClientAddr(addr))
    }
}

use super::{OptionExt, ResultExt};
use crate::AppState;

/// compression type requested by client.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Compression {
    None,
    Zstd,
}

impl From<Option<&String>> for Compression {
    fn from(s: Option<&String>) -> Self {
        match s.map(String::as_str) {
            Some("zstd") => Compression::Zstd,
            _ => Compression::None,
        }
    }
}

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
///
/// NOTE: we use `bytes` instead of `json<maprequest>` because the real
/// tailscale client does not send a content-type header over ts2021/http/2.
pub async fn map(
    State(state): State<AppState>,
    OptionalClientAddr(client_addr): OptionalClientAddr,
    body: Bytes,
) -> Result<impl IntoResponse, super::ApiError> {
    // parse json manually since tailscale client doesn't send content-type header
    let req: MapRequest = serde_json::from_slice(&body)
        .map_err(|_| super::ApiError::bad_request("invalid JSON request body"))?;
    // validate the node exists
    let mut node = state
        .db
        .get_node_by_node_key(&req.node_key)
        .await
        .map_internal()?
        .or_unauthorized("node not found")?;

    // update node with disco_key and hostinfo from request if provided
    let mut needs_update = false;
    let mut country_changed = false;

    if let Some(ref disco_key) = req.disco_key
        && node.disco_key.as_bytes() != disco_key.as_bytes()
    {
        node.disco_key = disco_key.clone();
        needs_update = true;
    }

    if let Some(ref hostinfo) = req.hostinfo {
        node.hostinfo = Some(hostinfo.clone());
        needs_update = true;
    }

    // lookup country from client IP if geoip is configured
    if let (Some(geoip), Some(addr)) = (&state.geoip, client_addr) {
        let client_ip = addr.ip();
        if let Some(country) = geoip.lookup_country(client_ip) {
            if node.last_seen_country.as_ref() != Some(&country) {
                tracing::debug!(
                    node_id = node.id.0,
                    old_country = ?node.last_seen_country,
                    new_country = %country,
                    "node country changed"
                );
                node.last_seen_country = Some(country);
                needs_update = true;
                country_changed = true;
            }
        }
    }

    if needs_update {
        state.db.update_node(&node).await.map_internal()?;
        // notify streaming clients that node state has changed
        // country changes affect other nodes' filter rules, so always notify
        if country_changed {
            tracing::debug!(
                node_id = node.id.0,
                "notifying state change due to country update"
            );
        }
        state.notifier.notify_state_changed();
    }

    let compression = Compression::from(req.compress.as_ref());

    if req.stream {
        // streaming mode: keep connection open and push updates
        Ok(
            streaming_response(state, node.id, node.node_key, compression, node.ephemeral)
                .await
                .into_response(),
        )
    } else {
        // non-streaming mode: return single length-prefixed response
        let response = build_map_response(&state, &req.node_key, req.omit_peers).await?;
        // use length-prefixed framing - client expects 4-byte le size prefix
        let bytes = encode_length_prefixed(&response, &compression)
            .ok_or_else(|| super::ApiError::internal("failed to encode response"))?;
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(bytes))
            .expect("valid status and headers")
            .into_response())
    }
}

/// compress data using zstd.
fn compress_zstd(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1)?; // Level 1 for fastest compression
    encoder.write_all(data)?;
    encoder.finish()
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

/// stream wrapper that tracks presence and cleans up on drop.
///
/// when the stream is dropped (client disconnects), it marks the node as offline
/// and notifies other clients of the state change. for ephemeral nodes, it
/// schedules deletion after the configured inactivity timeout.
struct PresenceTrackingStream<S> {
    inner: Pin<Box<S>>,
    state: AppState,
    node_id: NodeId,
    connected: bool,
    ephemeral: bool,
}

impl<S> PresenceTrackingStream<S> {
    fn new(inner: S, state: AppState, node_id: NodeId, ephemeral: bool) -> Self {
        Self {
            inner: Box::pin(inner),
            state,
            node_id,
            connected: false,
            ephemeral,
        }
    }
}

impl<S, T> Stream for PresenceTrackingStream<S>
where
    S: Stream<Item = T>,
{
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl<S> Drop for PresenceTrackingStream<S> {
    fn drop(&mut self) {
        if self.connected {
            let state = self.state.clone();
            let node_id = self.node_id;
            let ephemeral = self.ephemeral;

            // spawn a task to mark the node as disconnected and notify peers
            // we can't use async in drop, so we spawn a background task
            tokio::spawn(async move {
                state.presence.disconnect(node_id).await;
                // notify other streaming clients that node went offline
                state.notifier.notify_state_changed();

                // schedule ephemeral node for deletion after timeout
                if ephemeral {
                    state.ephemeral_gc.schedule_deletion(node_id).await;
                }
            });
        }
    }
}

/// build a streaming response that pushes updates when state changes.
///
/// this function marks the node as online when the stream starts,
/// and marks it offline when the stream ends (client disconnects).
/// for ephemeral nodes, reconnecting cancels any scheduled deletion.
async fn streaming_response(
    state: AppState,
    node_id: NodeId,
    node_key: NodeKey,
    compression: Compression,
    ephemeral: bool,
) -> Response {
    // mark node as connected before starting stream
    state.presence.connect(node_id, node_key.clone()).await;
    // notify other clients that this node came online
    state.notifier.notify_state_changed();

    // cancel any scheduled deletion if ephemeral node reconnects
    if ephemeral {
        state.ephemeral_gc.cancel_deletion(node_id).await;
    }

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
    let inner_stream = stream::unfold(
        (
            state.clone(),
            node_key,
            receiver,
            true,
            keepalive_interval,
            compression,
        ),
        |(state, node_key, mut receiver, is_first, keepalive_interval, compression)| async move {
            // determine what message to send
            let message_type = if is_first {
                StreamMessage::FullUpdate
            } else {
                wait_for_next_message(&mut receiver, keepalive_interval).await
            };

            match message_type {
                StreamMessage::FullUpdate => {
                    // streaming mode always sends full peer list
                    let response = match build_map_response(&state, &node_key, false).await {
                        Ok(r) => r,
                        Err(_) => return None,
                    };
                    let bytes = encode_length_prefixed(&response, &compression)?;
                    Some((
                        bytes,
                        (
                            state,
                            node_key,
                            receiver,
                            false,
                            keepalive_interval,
                            compression,
                        ),
                    ))
                }
                StreamMessage::KeepAlive => {
                    let response = MapResponse::keepalive();
                    let bytes = encode_length_prefixed(&response, &compression)?;
                    Some((
                        bytes,
                        (
                            state,
                            node_key,
                            receiver,
                            false,
                            keepalive_interval,
                            compression,
                        ),
                    ))
                }
                StreamMessage::End => None,
            }
        },
    );

    // wrap the stream to track presence - marks node offline on drop
    // for ephemeral nodes, also schedules deletion on disconnect
    let mut presence_stream = PresenceTrackingStream::new(inner_stream, state, node_id, ephemeral);
    presence_stream.connected = true;

    // convert to a stream of result<bytes, infallible> for axum
    let body_stream = presence_stream.map(Ok::<_, Infallible>);

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
///
/// when `omit_peers` is true, skips expensive peer computation and returns
/// only the node's own info. used for lightweight state-reporting requests.
async fn build_map_response(
    state: &AppState,
    node_key: &NodeKey,
    omit_peers: bool,
) -> Result<MapResponse, super::ApiError> {
    let node = state
        .db
        .get_node_by_node_key(node_key)
        .await
        .map_internal()?
        .or_unauthorized("node not found")?;

    // use shared derp map from state (generated once at startup)
    let derp_map = state.derp_map.read().await.clone();
    let home_derp = derp_map.regions.keys().next().copied().unwrap_or(1);

    // fetch tka info from database
    let tka_info = get_tka_info(&state.db).await;

    // when omit_peers is set, skip expensive peer/filter/ssh computation
    if omit_peers {
        // fetch self node's TKA signature if TKA is enabled
        let self_sig = if tka_info.is_some() {
            state
                .db
                .get_node_key_signature(node.id)
                .await
                .unwrap_or(None)
        } else {
            None
        };

        // self is always online when making this request
        let mut self_node =
            node_to_map_response_node(&node, home_derp, Some(true), self_sig.as_deref());
        self_node.cap_map = build_self_cap_map(&state.config);

        return Ok(MapResponse {
            keep_alive: false,
            node: Some(self_node),
            peers: vec![],
            dns_config: state.map_cache.dns_config(),
            derp_map: Some(derp_map),
            packet_filter: vec![],
            user_profiles: vec![],
            control_time: Some(chrono::Utc::now().to_rfc3339()),
            ssh_policy: None,
            tka_info,
        });
    }

    let (all_nodes, users) = state
        .map_cache
        .get_snapshot(&state.db)
        .await
        .map_internal()?;

    // acquire read lock on grants engine for policy evaluation
    let grants = state.grants.read().await;

    // get oidc group prefix if configured
    let oidc_group_prefix = state
        .config
        .oidc
        .as_ref()
        .and_then(|oidc| oidc.group_prefix.clone());

    let resolver = crate::resolver::MapUserResolver::with_groups(
        users.clone(),
        grants.policy().groups.clone(),
        oidc_group_prefix,
    );

    // use grants engine to filter visible peers
    let visible_peers = grants.get_visible_peers(&node, &all_nodes, &resolver);

    // collect user IDs from visible peers + self node, then filter profiles
    let mut visible_user_ids: std::collections::HashSet<u64> = visible_peers
        .iter()
        .filter_map(|n| n.user_id.map(|id| id.0))
        .collect();
    if let Some(self_uid) = node.user_id {
        visible_user_ids.insert(self_uid.0);
    }

    let user_profiles: Vec<UserProfile> = users
        .iter()
        .filter(|u| visible_user_ids.contains(&u.id.0))
        .map(|u| UserProfile {
            id: u.id.0,
            login_name: u.username().to_string(),
            display_name: u.display().to_string(),
            profile_pic_url: u.profile_pic_url.clone(),
        })
        .collect();

    // generate packet filter rules from grants
    let packet_filter = grants.generate_filter_rules(&node, &all_nodes, &resolver);

    // compile ssh policy for this node
    let ssh_policy = grants.compile_ssh_policy(&node, &all_nodes, &resolver);

    // use pre-computed dns config from cache
    let dns_config = state.map_cache.dns_config();

    // batch-fetch TKA key signatures when tailnet lock is enabled
    let key_signatures = if tka_info.is_some() {
        let mut all_ids: Vec<NodeId> = visible_peers.iter().map(|n| n.id).collect();
        all_ids.push(node.id);
        state
            .db
            .get_node_key_signatures_batch(&all_ids)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // build self node with capabilities (self is always online if we're making this request)
    let self_sig = key_signatures.get(&node.id).map(|v| v.as_slice());
    let mut self_node = node_to_map_response_node(&node, home_derp, Some(true), self_sig);
    self_node.cap_map = build_self_cap_map(&state.config);

    // get online status for all visible peers
    let peer_ids: Vec<NodeId> = visible_peers.iter().map(|n| n.id).collect();
    let online_statuses = state.presence.get_online_statuses(&peer_ids).await;

    // build peer nodes with online status and TKA signatures
    let peers: Vec<MapResponseNode> = visible_peers
        .iter()
        .map(|n| {
            let online = online_statuses.get(&n.id).copied();
            let sig = key_signatures.get(&n.id).map(|v| v.as_slice());
            node_to_map_response_node(n, home_derp, online, sig)
        })
        .collect();

    Ok(MapResponse {
        // keep_alive=false signals "this response has real data, process it"
        // keep_alive=true (only in MapResponse::keepalive()) signals "just a ping, skip processing"
        // tailscale client skips netmap callback when keep_alive=true
        keep_alive: false,
        node: Some(self_node),
        peers,
        dns_config,
        derp_map: Some(derp_map),
        packet_filter,
        user_profiles,
        control_time: Some(chrono::Utc::now().to_rfc3339()),
        ssh_policy,
        tka_info,
    })
}

/// encode a mapresponse with a 4-byte little-endian length prefix.
/// if compression is zstd, the json payload is zstd-compressed before framing.
/// returns None if serialisation fails or payload exceeds u32::MAX bytes.
fn encode_length_prefixed(response: &MapResponse, compression: &Compression) -> Option<Bytes> {
    let json_bytes = serde_json::to_vec(response).ok()?;

    let payload = match compression {
        Compression::Zstd => compress_zstd(&json_bytes).ok()?,
        Compression::None => json_bytes,
    };

    // reject payloads that exceed framing limit
    let len = u32::try_from(payload.len()).ok()?;

    let mut body = Vec::with_capacity(4 + payload.len());
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(&payload);

    Some(Bytes::from(body))
}

/// convert an ip address to cidr notation (host route).
fn ip_to_cidr(ip: std::net::IpAddr) -> String {
    use ipnet::{Ipv4Net, Ipv6Net};
    match ip {
        std::net::IpAddr::V4(v4) => Ipv4Net::from(v4).to_string(),
        std::net::IpAddr::V6(v6) => Ipv6Net::from(v6).to_string(),
    }
}

/// convert a node to mapresponsenode.
///
/// `online` is the online status from presence tracking. if `Some(true)`, the node
/// is currently connected via a streaming map session. if `Some(false)`, it's not.
/// if `None`, the status is unknown (shouldn't happen in practice).
///
/// `key_sig` is the TKA key signature for this node (if TKA is enabled and the node
/// has been signed). when present, the tailscale client uses it to verify the node
/// is approved by tailnet lock.
fn node_to_map_response_node(
    node: &Node,
    home_derp: i32,
    online: Option<bool>,
    key_sig: Option<&[u8]>,
) -> MapResponseNode {
    // addresses must be in cidr notation for tailscale client
    let mut addresses = Vec::new();
    if let Some(ip) = node.ipv4 {
        addresses.push(ip_to_cidr(ip));
    }
    if let Some(ip) = node.ipv6 {
        addresses.push(ip_to_cidr(ip));
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
        node_key: node.node_key.clone(),
        machine_key: node.machine_key.clone(),
        disco_key: node.disco_key.clone(),
        addresses,
        allowed_ips,
        endpoints: node.endpoints.iter().map(|e| e.to_string()).collect(),
        derp: String::new(), // Deprecated - use home_derp instead
        home_derp,
        // always include hostinfo (default to empty if none) to prevent nil pointer
        // crashes in Tailscale client when accessing Hostinfo.Hostname() on peers
        hostinfo: Some(node.hostinfo.clone().unwrap_or_default()),
        online,
        tags: node.tags.iter().map(|t| t.to_string()).collect(),
        primary_routes: node.approved_routes.iter().map(|r| r.to_string()).collect(),
        key_expiry: node.expiry.as_ref().map(|e| e.to_rfc3339()),
        key_signature: key_sig
            .map(|s| railscale_tka::MarshaledSignature::from(s.to_vec()))
            .unwrap_or_default(),
        expired: node.is_expired(),
        user: node.user_id.unwrap_or(UserId::TAGGED_DEVICES).0,
        // nodes in the database that respond to map requests are authorized
        machine_authorized: true,
        // cap_map is populated separately for self node based on config
        cap_map: None,
    }
}

/// build capability map for self node based on config.
///
/// currently only includes file-sharing capability when taildrop_enabled.
fn build_self_cap_map(
    config: &railscale_types::Config,
) -> Option<std::collections::HashMap<String, Vec<serde_json::Value>>> {
    if config.taildrop_enabled {
        let mut cap_map = std::collections::HashMap::new();
        cap_map.insert(railscale_proto::CAP_FILE_SHARING.to_string(), vec![]);
        Some(cap_map)
    } else {
        None
    }
}

/// fetch tka info from the database.
///
/// returns `Some(TkaInfo)` if tka is enabled with a head hash,
/// `None` otherwise (tka not enabled or no state).
async fn get_tka_info(db: &impl Database) -> Option<TkaInfo> {
    let tka_state = db.get_tka_state().await.ok()??;
    if tka_state.enabled {
        tka_state.head.map(TkaInfo::new)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::test_utils::TestNodeBuilder;

    #[test]
    fn test_node_to_map_response_includes_key_signature() {
        let node = TestNodeBuilder::new(1)
            .with_ipv4("100.64.0.1".parse().unwrap())
            .build();

        let sig_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let result = node_to_map_response_node(&node, 1, Some(true), Some(&sig_bytes));

        assert!(
            !result.key_signature.is_empty(),
            "key_signature should be populated when provided"
        );
        assert_eq!(result.key_signature.as_bytes(), &sig_bytes);
    }

    #[test]
    fn test_node_to_map_response_empty_signature_when_none() {
        let node = TestNodeBuilder::new(2)
            .with_ipv4("100.64.0.1".parse().unwrap())
            .build();

        let result = node_to_map_response_node(&node, 1, Some(true), None);

        assert!(
            result.key_signature.is_empty(),
            "key_signature should be empty when not provided"
        );
    }
}
