//! state management for leadscale
//!
//! central state coordinator that manages:
//! - in-memory node cache (nodestore) with copy-on-write semantics
//! - coordination between database, ip allocation, and policy
//! - peer visibility calculations
//!
//! the state struct is the main entry point for all state operations

mod error;
mod node_store;

pub use error::Error;
pub use node_store::NodeStore;

use std::sync::Arc;

use leadscale_db::LeadscaleDb;
use leadscale_types::{Config, Node, NodeId, NodeView};

/// result type for state operations
pub type Result<T> = std::result::Result<T, Error>;

/// central state coordinator for leadscale
///
/// state manages:
/// - database persistence
/// - in-memory node cache with copy-on-write semantics
/// - ip allocation
/// - peer visibility calculations (via policy/grants)
///
/// all methods are thread-safe
pub struct State {
    config: Arc<Config>,
    db: Arc<LeadscaleDb>,
    node_store: NodeStore,
    // TODO: add ip allocator, policy manager, derp map, etc
}

impl State {
    /// create new state instance
    pub async fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let db = Arc::new(
            LeadscaleDb::new(&config)
                .await
                .map_err(|e| Error::Database(e.to_string()))?,
        );

        // load nodes from database
        // TODO: implement database loading
        let nodes = Vec::new();
        let node_store = NodeStore::new(nodes);

        Ok(Self {
            config,
            db,
            node_store,
        })
    }

    /// get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// get node by id
    pub fn get_node(&self, id: NodeId) -> Option<NodeView> {
        self.node_store.get(id)
    }

    /// get all nodes
    pub fn get_all_nodes(&self) -> Vec<NodeView> {
        self.node_store.get_all()
    }

    /// get peers for a specific node
    ///
    /// returns all nodes that the given node can see based on
    /// policy/grants evaluation
    pub fn get_peers(&self, node_id: NodeId) -> Vec<NodeView> {
        self.node_store.get_peers(node_id)
    }

    /// update node in the store
    pub async fn update_node(&self, node: Node) -> Result<NodeView> {
        // update in database
        // TODO: implement database update

        // update in-memory store
        let view = self.node_store.update(node);
        Ok(view)
    }

    /// delete a node
    pub async fn delete_node(&self, id: NodeId) -> Result<()> {
        // delete from database
        // TODO: implement database delete

        // remove from in-memory store
        self.node_store.remove(id);
        Ok(())
    }

    /// set node's online status
    pub fn set_node_online(&self, id: NodeId, online: bool) {
        self.node_store.set_online(id, online);
    }

    /// register a new node
    pub async fn register_node(&self, _node: Node) -> Result<NodeView> {
        // TODO: implement node registration
        // 1. validate registration (preauth key, oidc, etc.)
        // 2. allocate ips
        // 3. persist to database
        // 4. add to node store
        Err(Error::NotImplemented("register_node".to_string()))
    }

    /// gracefully shutdown the state
    pub async fn close(&self) -> Result<()> {
        self.db
            .close()
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }
}
