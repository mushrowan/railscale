//! in-memory node store with copy-on-write semantics.
//!
//! nodestore provides fast, thread-safe access to node data with
//! copy-on-write semantics for safe concurrent reads.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use railscale_types::{Node, NodeId, NodeView};

/// in-memory cache for nodes with copy-on-write semantics.
///
/// this is the rust equivalent of go's nodestore in headscale.
/// it provides:
/// - fast reads without locking (using arc)
/// - copy-on-write updates
/// - thread-safe concurrent access
pub struct NodeStore {
    /// the actual node data, wrapped in arc for copy-on-write.
    nodes: RwLock<Arc<HashMap<NodeId, NodeView>>>,
    /// precomputed peer maps for each node.
    peers: RwLock<Arc<HashMap<NodeId, Vec<NodeView>>>>,
    // TODO: add batch processing like go's nodestore
}

impl NodeStore {
    /// create a new nodestore with initial nodes.
    pub fn new(initial_nodes: Vec<Node>) -> Self {
        let mut nodes = HashMap::new();
        for node in initial_nodes {
            nodes.insert(node.id, NodeView::new(node));
        }

        let store = Self {
            nodes: RwLock::new(Arc::new(nodes)),
            peers: RwLock::new(Arc::new(HashMap::new())),
        };
        store.rebuild_peers();
        store
    }

    /// get a node by id.
    pub fn get(&self, id: NodeId) -> Option<NodeView> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(&id).cloned()
    }

    /// get all nodes.
    pub fn get_all(&self) -> Vec<NodeView> {
        let nodes = self.nodes.read().unwrap();
        nodes.values().cloned().collect()
    }

    /// get peers for a node.
    ///
    /// returns all nodes visible to the given node based on policy.
    pub fn get_peers(&self, node_id: NodeId) -> Vec<NodeView> {
        let peers = self.peers.read().unwrap();
        peers.get(&node_id).cloned().unwrap_or_default()
    }

    /// update a node in the store.
    ///
    /// this uses copy-on-write: it creates a new hashmap with the updated
    /// node and atomically swaps it in.
    pub fn update(&self, node: Node) -> NodeView {
        let view = NodeView::new(node);
        let id = view.id();

        // copy-on-write update
        {
            let mut nodes_guard = self.nodes.write().unwrap();
            let mut new_nodes = (**nodes_guard).clone();
            new_nodes.insert(id, view.clone());
            *nodes_guard = Arc::new(new_nodes);
        }

        // TODO: rebuild peer maps
        self.rebuild_peers();

        view
    }

    /// remove a node from the store.
    pub fn remove(&self, id: NodeId) {
        {
            let mut nodes_guard = self.nodes.write().unwrap();
            let mut new_nodes = (**nodes_guard).clone();
            new_nodes.remove(&id);
            *nodes_guard = Arc::new(new_nodes);
        }

        self.rebuild_peers();
    }

    /// set a node's online status.
    pub fn set_online(&self, id: NodeId, online: bool) {
        // for online status, we need to update the node in place
        // this is a special case that doesn't need full cow
        let nodes = self.nodes.read().unwrap();
        if let Some(view) = nodes.get(&id) {
            // NOTE: this is a limitation - we can't easily update
            // the inner node due to Arc immutability.
            // in production, we'd want a more sophisticated approach.
            let _ = (view, online);
            // TODO: implement proper online status tracking
        }
    }

    /// rebuild peer maps based on policy.
    ///
    /// this is called after node updates to recalculate which nodes
    /// can see which other nodes.
    fn rebuild_peers(&self) {
        let nodes = self.nodes.read().unwrap();

        // for now, simple implementation: all nodes can see all other nodes
        // TODO: integrate with grants/policy system
        let mut new_peers = HashMap::new();

        for (node_id, _) in nodes.iter() {
            let peers: Vec<NodeView> = nodes
                .iter()
                .filter(|(id, _)| *id != node_id)
                .map(|(_, view)| view.clone())
                .collect();
            new_peers.insert(*node_id, peers);
        }

        let mut peers_guard = self.peers.write().unwrap();
        *peers_guard = Arc::new(new_peers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use railscale_types::{DiscoKey, MachineKey, NodeKey, RegisterMethod, UserId};

    fn test_node(id: u64) -> Node {
        Node {
            id: NodeId(id),
            machine_key: MachineKey::default(),
            node_key: NodeKey::default(),
            disco_key: DiscoKey::default(),
            endpoints: vec![],
            hostinfo: None,
            ipv4: None,
            ipv6: None,
            hostname: format!("node-{id}"),
            given_name: format!("node-{id}"),
            user_id: Some(UserId(1)),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            approved_routes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_online: None,
        }
    }

    #[test]
    fn test_node_store_basic() {
        let store = NodeStore::new(vec![test_node(1), test_node(2)]);

        assert!(store.get(NodeId(1)).is_some());
        assert!(store.get(NodeId(2)).is_some());
        assert!(store.get(NodeId(3)).is_none());
    }

    #[test]
    fn test_node_store_update() {
        let store = NodeStore::new(vec![test_node(1)]);

        let mut node = test_node(1);
        node.hostname = "updated-node".to_string();
        store.update(node);

        let view = store.get(NodeId(1)).unwrap();
        assert_eq!(view.hostname, "updated-node");
    }

    #[test]
    fn test_node_store_remove() {
        let store = NodeStore::new(vec![test_node(1), test_node(2)]);

        store.remove(NodeId(1));

        assert!(store.get(NodeId(1)).is_none());
        assert!(store.get(NodeId(2)).is_some());
    }

    #[test]
    fn test_node_store_peers() {
        let store = NodeStore::new(vec![test_node(1), test_node(2), test_node(3)]);

        let peers = store.get_peers(NodeId(1));
        assert_eq!(peers.len(), 2);
    }
}
