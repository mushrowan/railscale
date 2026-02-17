//! per-connection session state for delta map responses.
//!
//! tracks the last-sent peer snapshot so subsequent updates can be
//! delta-encoded (PeersChanged/PeersRemoved/PeersChangedPatch/OnlineChange)
//! instead of sending the full peer list every time.

use std::collections::HashMap;

use railscale_proto::{MapResponse, MapResponseNode, PeerChange};

/// snapshot of a peer node's mutable fields, used for diff computation
#[derive(Debug, Clone)]
struct PeerSnapshot {
    node: MapResponseNode,
}

/// per-streaming-connection session state
pub struct MapSession {
    /// last-sent peers keyed by node ID
    peers: HashMap<u64, PeerSnapshot>,
    /// session handle for resumption
    handle: String,
    /// monotonic sequence number
    seq: i64,
}

impl MapSession {
    /// create a new session with the given handle
    pub fn new(handle: String) -> Self {
        Self {
            peers: HashMap::new(),
            handle,
            seq: 0,
        }
    }

    /// the session handle
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// current sequence number
    pub fn seq(&self) -> i64 {
        self.seq
    }

    /// apply a full peer list (first response), updating session state.
    /// returns the response with map_session_handle set on first message.
    pub fn apply_full(&mut self, mut response: MapResponse) -> MapResponse {
        self.seq += 1;
        response.seq = self.seq;

        // only send handle on the first message
        if self.peers.is_empty() {
            response.map_session_handle = self.handle.clone();
        }

        // record all peers for future delta computation
        self.peers.clear();
        for peer in &response.peers {
            self.peers
                .insert(peer.id, PeerSnapshot { node: peer.clone() });
        }

        response
    }

    /// compute a delta from the last-sent state to the new full peer list.
    /// updates internal state to reflect the new snapshot.
    pub fn compute_delta(
        &mut self,
        new_peers: Vec<MapResponseNode>,
        mut response: MapResponse,
    ) -> MapResponse {
        self.seq += 1;
        response.seq = self.seq;

        let new_peer_map: HashMap<u64, MapResponseNode> =
            new_peers.into_iter().map(|p| (p.id, p)).collect();

        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut patches = Vec::new();
        let mut online_changes: HashMap<u64, bool> = HashMap::new();

        // detect removed peers
        for old_id in self.peers.keys() {
            if !new_peer_map.contains_key(old_id) {
                removed.push(*old_id);
            }
        }

        // detect changed / added peers
        for (id, new_node) in &new_peer_map {
            match self.peers.get(id) {
                None => {
                    // new peer — send full node
                    changed.push(new_node.clone());
                }
                Some(old) => match compute_peer_patch(&old.node, new_node) {
                    PatchResult::Identical => {}
                    PatchResult::NeedsFull => {
                        changed.push(new_node.clone());
                    }
                    PatchResult::Patch(patch) => {
                        if is_online_only_change(&patch) {
                            if let Some(online) = patch.online {
                                online_changes.insert(*id, online);
                            }
                        } else {
                            patches.push(patch);
                        }
                    }
                },
            }
        }

        // clear the full peers list — we're sending deltas
        response.peers = vec![];
        response.peers_changed = changed;
        response.peers_removed = removed;
        response.peers_changed_patch = patches;
        response.online_change = online_changes;

        // update session state
        self.peers.clear();
        for (id, node) in new_peer_map {
            self.peers.insert(id, PeerSnapshot { node });
        }

        response
    }
}

/// result of comparing two peer node snapshots
enum PatchResult {
    /// nodes are identical
    Identical,
    /// structural change requiring full peer resend
    NeedsFull,
    /// lightweight patch
    Patch(PeerChange),
}

/// compute a PeerChange patch between old and new node state
fn compute_peer_patch(old: &MapResponseNode, new: &MapResponseNode) -> PatchResult {
    // fields that can't be patched — force full PeersChanged
    if old.name != new.name
        || old.addresses != new.addresses
        || old.allowed_ips != new.allowed_ips
        || old.tags != new.tags
        || old.primary_routes != new.primary_routes
        || old.user != new.user
        || old.machine_key != new.machine_key
        || old.machine_authorized != new.machine_authorized
        || old.expired != new.expired
        || old.stable_id != new.stable_id
        || !hostinfo_eq(&old.hostinfo, &new.hostinfo)
    {
        return PatchResult::NeedsFull;
    }

    let mut patch = PeerChange {
        node_id: old.id,
        ..Default::default()
    };
    let mut has_change = false;

    if old.home_derp != new.home_derp {
        patch.derp_region = Some(new.home_derp);
        has_change = true;
    }

    if old.cap != new.cap {
        patch.cap = Some(new.cap);
        has_change = true;
    }

    if old.cap_map != new.cap_map {
        patch.cap_map = new.cap_map.clone();
        has_change = true;
    }

    if old.endpoints != new.endpoints {
        let endpoints: Option<Vec<std::net::SocketAddr>> = Some(
            new.endpoints
                .iter()
                .filter_map(|e| e.parse().ok())
                .collect(),
        );
        patch.endpoints = endpoints;
        has_change = true;
    }

    if old.node_key != new.node_key {
        patch.key = Some(new.node_key.clone());
        has_change = true;
    }

    if old.disco_key != new.disco_key {
        patch.disco_key = Some(new.disco_key.clone());
        has_change = true;
    }

    if old.online != new.online {
        patch.online = new.online;
        has_change = true;
    }

    if old.key_expiry != new.key_expiry {
        patch.key_expiry = new.key_expiry.clone();
        has_change = true;
    }

    if old.key_signature != new.key_signature {
        patch.key_signature = if new.key_signature.is_empty() {
            None
        } else {
            Some(new.key_signature.clone())
        };
        has_change = true;
    }

    if has_change {
        PatchResult::Patch(patch)
    } else {
        PatchResult::Identical
    }
}

/// compare hostinfo by JSON serialisation (HostInfo doesn't derive PartialEq)
fn hostinfo_eq(
    a: &Option<railscale_types::HostInfo>,
    b: &Option<railscale_types::HostInfo>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => serde_json::to_string(a).ok() == serde_json::to_string(b).ok(),
        _ => false,
    }
}

/// check if a PeerChange only contains an online status change
fn is_online_only_change(patch: &PeerChange) -> bool {
    patch.online.is_some()
        && patch.derp_region.is_none()
        && patch.cap.is_none()
        && patch.cap_map.is_none()
        && patch.endpoints.is_none()
        && patch.key.is_none()
        && patch.disco_key.is_none()
        && patch.key_expiry.is_none()
        && patch.key_signature.is_none()
        && patch.last_seen.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::{DiscoKey, MachineKey, NodeKey};

    fn make_peer(id: u64, online: bool) -> MapResponseNode {
        MapResponseNode {
            id,
            stable_id: format!("stable-{id}"),
            name: format!("node-{id}.example.com."),
            node_key: NodeKey::from_bytes(vec![id as u8; 32]),
            machine_key: MachineKey::from_bytes(vec![id as u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![id as u8; 32]),
            addresses: vec![format!("100.64.0.{id}/32")],
            allowed_ips: vec![format!("100.64.0.{id}/32")],
            endpoints: vec!["1.2.3.4:5678".to_string()],
            home_derp: 1,
            online: Some(online),
            user: 1,
            machine_authorized: true,
            cap: 106,
            ..Default::default()
        }
    }

    #[test]
    fn first_response_is_full_with_handle_and_seq() {
        let mut session = MapSession::new("sess-1".to_string());
        let resp = MapResponse {
            peers: vec![make_peer(1, true), make_peer(2, true)],
            ..Default::default()
        };

        let result = session.apply_full(resp);
        assert_eq!(result.map_session_handle, "sess-1");
        assert_eq!(result.seq, 1);
        assert_eq!(result.peers.len(), 2);
        assert!(result.peers_changed.is_empty());
        assert!(result.peers_removed.is_empty());
    }

    #[test]
    fn second_full_does_not_resend_handle() {
        let mut session = MapSession::new("sess-1".to_string());
        let resp1 = MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        };
        session.apply_full(resp1);

        let resp2 = MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        };
        let result = session.apply_full(resp2);
        assert!(
            result.map_session_handle.is_empty(),
            "handle should not repeat"
        );
        assert_eq!(result.seq, 2);
    }

    #[test]
    fn delta_detects_removed_peer() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true), make_peer(2, true)],
            ..Default::default()
        });

        // peer 2 gone
        let result = session.compute_delta(vec![make_peer(1, true)], MapResponse::default());
        assert!(
            result.peers.is_empty(),
            "full peers should be empty in delta"
        );
        assert_eq!(result.peers_removed, vec![2]);
        assert!(result.peers_changed.is_empty());
        assert_eq!(result.seq, 2);
    }

    #[test]
    fn delta_detects_added_peer() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        // peer 3 added
        let result = session.compute_delta(
            vec![make_peer(1, true), make_peer(3, true)],
            MapResponse::default(),
        );
        assert!(result.peers_removed.is_empty());
        assert_eq!(result.peers_changed.len(), 1);
        assert_eq!(result.peers_changed[0].id, 3);
    }

    #[test]
    fn delta_online_change_uses_online_change_map() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        // peer 1 went offline
        let result = session.compute_delta(vec![make_peer(1, false)], MapResponse::default());
        assert!(result.peers_changed.is_empty());
        assert!(result.peers_changed_patch.is_empty());
        assert_eq!(result.online_change.get(&1), Some(&false));
    }

    #[test]
    fn delta_derp_change_uses_patch() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        let mut changed = make_peer(1, true);
        changed.home_derp = 5;
        let result = session.compute_delta(vec![changed], MapResponse::default());
        assert_eq!(result.peers_changed_patch.len(), 1);
        assert_eq!(result.peers_changed_patch[0].node_id, 1);
        assert_eq!(result.peers_changed_patch[0].derp_region, Some(5));
    }

    #[test]
    fn delta_structural_change_sends_full_peer() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        // address changed — can't be patched
        let mut changed = make_peer(1, true);
        changed.addresses = vec!["100.64.0.99/32".to_string()];
        changed.allowed_ips = vec!["100.64.0.99/32".to_string()];
        let result = session.compute_delta(vec![changed], MapResponse::default());
        assert_eq!(result.peers_changed.len(), 1);
        assert_eq!(result.peers_changed[0].id, 1);
        assert!(result.peers_changed_patch.is_empty());
    }

    #[test]
    fn delta_identical_peers_sends_nothing() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true), make_peer(2, true)],
            ..Default::default()
        });

        let result = session.compute_delta(
            vec![make_peer(1, true), make_peer(2, true)],
            MapResponse::default(),
        );
        assert!(result.peers.is_empty());
        assert!(result.peers_changed.is_empty());
        assert!(result.peers_removed.is_empty());
        assert!(result.peers_changed_patch.is_empty());
        assert!(result.online_change.is_empty());
    }

    #[test]
    fn delta_endpoint_change_uses_patch() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        let mut changed = make_peer(1, true);
        changed.endpoints = vec!["5.6.7.8:9999".to_string()];
        let result = session.compute_delta(vec![changed], MapResponse::default());
        assert_eq!(result.peers_changed_patch.len(), 1);
        assert!(result.peers_changed_patch[0].endpoints.is_some());
    }

    #[test]
    fn delta_key_change_uses_patch() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });

        let mut changed = make_peer(1, true);
        changed.node_key = NodeKey::from_bytes(vec![0xFF; 32]);
        let result = session.compute_delta(vec![changed], MapResponse::default());
        assert_eq!(result.peers_changed_patch.len(), 1);
        assert!(result.peers_changed_patch[0].key.is_some());
    }

    #[test]
    fn delta_multiple_changes_mixed() {
        let mut session = MapSession::new("s".to_string());
        session.apply_full(MapResponse {
            peers: vec![make_peer(1, true), make_peer(2, true), make_peer(3, true)],
            ..Default::default()
        });

        // peer 1: just went offline (online_change)
        // peer 2: removed
        // peer 3: DERP changed (patch)
        // peer 4: new (peers_changed)
        let mut peer3 = make_peer(3, true);
        peer3.home_derp = 7;

        let result = session.compute_delta(
            vec![make_peer(1, false), peer3, make_peer(4, true)],
            MapResponse::default(),
        );
        assert_eq!(result.online_change.get(&1), Some(&false));
        assert_eq!(result.peers_removed, vec![2]);
        assert_eq!(result.peers_changed_patch.len(), 1);
        assert_eq!(result.peers_changed_patch[0].node_id, 3);
        assert_eq!(result.peers_changed.len(), 1);
        assert_eq!(result.peers_changed[0].id, 4);
    }

    #[test]
    fn seq_increments_across_full_and_delta() {
        let mut session = MapSession::new("s".to_string());
        let r1 = session.apply_full(MapResponse {
            peers: vec![make_peer(1, true)],
            ..Default::default()
        });
        assert_eq!(r1.seq, 1);

        let r2 = session.compute_delta(vec![make_peer(1, true)], MapResponse::default());
        assert_eq!(r2.seq, 2);

        let r3 = session.compute_delta(vec![make_peer(1, false)], MapResponse::default());
        assert_eq!(r3.seq, 3);
    }
}
