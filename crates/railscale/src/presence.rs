//! presence tracking for connected nodes.
//!
//! tracks which nodes are currently connected via streaming map sessions,
//! enabling online status to be sent to peers (required for taildrop).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use railscale_types::{NodeId, NodeKey};
use tokio::sync::RwLock;

/// tracks the online status of connected nodes.
///
/// nodes are marked online when they establish a streaming map session,
/// and marked offline when the session ends. this is used to populate
/// the `online` field in map responses sent to peers.
#[derive(Debug, Clone, Default)]
pub struct PresenceTracker {
    /// map of node id to connection info for currently connected nodes.
    connected: Arc<RwLock<HashMap<NodeId, ConnectionInfo>>>,
}

/// information about a connected node.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// node key of the connected node.
    pub node_key: NodeKey,
    /// when the connection was established.
    pub connected_at: DateTime<Utc>,
}

impl PresenceTracker {
    /// create a new presence tracker.
    pub fn new() -> Self {
        Self {
            connected: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// mark a node as connected (online).
    ///
    /// called when a streaming map session is established.
    pub async fn connect(&self, node_id: NodeId, node_key: NodeKey) {
        let mut connected = self.connected.write().await;
        connected.insert(
            node_id,
            ConnectionInfo {
                node_key,
                connected_at: Utc::now(),
            },
        );
    }

    /// mark a node as disconnected (offline).
    ///
    /// called when a streaming map session ends.
    pub async fn disconnect(&self, node_id: NodeId) {
        let mut connected = self.connected.write().await;
        connected.remove(&node_id);
    }

    /// check if a node is currently connected.
    pub async fn is_online(&self, node_id: NodeId) -> bool {
        let connected = self.connected.read().await;
        connected.contains_key(&node_id)
    }

    /// get the online status of multiple nodes.
    ///
    /// returns a map of node id to online status for the given nodes.
    pub async fn get_online_statuses(&self, node_ids: &[NodeId]) -> HashMap<NodeId, bool> {
        let connected = self.connected.read().await;
        node_ids
            .iter()
            .map(|id| (*id, connected.contains_key(id)))
            .collect()
    }

    /// get the number of currently connected nodes.
    pub async fn connected_count(&self) -> usize {
        let connected = self.connected.read().await;
        connected.len()
    }

    /// get all currently connected node ids.
    pub async fn connected_nodes(&self) -> Vec<NodeId> {
        let connected = self.connected.read().await;
        connected.keys().copied().collect()
    }

    /// get connection info for a specific node, if connected.
    pub async fn get_connection_info(&self, node_id: NodeId) -> Option<ConnectionInfo> {
        let connected = self.connected.read().await;
        connected.get(&node_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::NodeKey;

    fn test_node_key() -> NodeKey {
        NodeKey::from_bytes(vec![1u8; 32])
    }

    #[tokio::test]
    async fn test_connect_disconnect() {
        let tracker = PresenceTracker::new();
        let node_id = NodeId(1);
        let node_key = test_node_key();

        // initially offline
        assert!(!tracker.is_online(node_id).await);
        assert_eq!(tracker.connected_count().await, 0);

        // connect
        tracker.connect(node_id, node_key.clone()).await;
        assert!(tracker.is_online(node_id).await);
        assert_eq!(tracker.connected_count().await, 1);

        // disconnect
        tracker.disconnect(node_id).await;
        assert!(!tracker.is_online(node_id).await);
        assert_eq!(tracker.connected_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_nodes() {
        let tracker = PresenceTracker::new();
        let node_key = test_node_key();

        tracker.connect(NodeId(1), node_key.clone()).await;
        tracker.connect(NodeId(2), node_key.clone()).await;
        tracker.connect(NodeId(3), node_key.clone()).await;

        assert_eq!(tracker.connected_count().await, 3);
        assert!(tracker.is_online(NodeId(1)).await);
        assert!(tracker.is_online(NodeId(2)).await);
        assert!(tracker.is_online(NodeId(3)).await);
        assert!(!tracker.is_online(NodeId(4)).await);

        // disconnect one
        tracker.disconnect(NodeId(2)).await;
        assert_eq!(tracker.connected_count().await, 2);
        assert!(tracker.is_online(NodeId(1)).await);
        assert!(!tracker.is_online(NodeId(2)).await);
        assert!(tracker.is_online(NodeId(3)).await);
    }

    #[tokio::test]
    async fn test_get_online_statuses() {
        let tracker = PresenceTracker::new();
        let node_key = test_node_key();

        tracker.connect(NodeId(1), node_key.clone()).await;
        tracker.connect(NodeId(3), node_key.clone()).await;

        let statuses = tracker
            .get_online_statuses(&[NodeId(1), NodeId(2), NodeId(3), NodeId(4)])
            .await;

        assert_eq!(statuses.get(&NodeId(1)), Some(&true));
        assert_eq!(statuses.get(&NodeId(2)), Some(&false));
        assert_eq!(statuses.get(&NodeId(3)), Some(&true));
        assert_eq!(statuses.get(&NodeId(4)), Some(&false));
    }

    #[tokio::test]
    async fn test_get_connection_info() {
        let tracker = PresenceTracker::new();
        let node_id = NodeId(1);
        let node_key = test_node_key();

        // not connected
        assert!(tracker.get_connection_info(node_id).await.is_none());

        // connect
        tracker.connect(node_id, node_key.clone()).await;
        let info = tracker.get_connection_info(node_id).await.unwrap();
        assert_eq!(info.node_key, node_key);

        // disconnect
        tracker.disconnect(node_id).await;
        assert!(tracker.get_connection_info(node_id).await.is_none());
    }

    #[tokio::test]
    async fn test_connected_nodes() {
        let tracker = PresenceTracker::new();
        let node_key = test_node_key();

        tracker.connect(NodeId(5), node_key.clone()).await;
        tracker.connect(NodeId(10), node_key.clone()).await;

        let mut nodes = tracker.connected_nodes().await;
        nodes.sort_by_key(|n| n.0);
        assert_eq!(nodes, vec![NodeId(5), NodeId(10)]);
    }
}
