//! db layer
//!
//! persistent storage:
//! - nodes
//! - users
//! - preauthkeys
//! - api keys
//!
//! handles ip allocation

mod error;
mod ip_allocator;

pub use error::Error;
pub use ip_allocator::IpAllocator;

use std::future::Future;

use leadscale_types::{Node, NodeId, PreAuthKey, User, UserId};

/// db ops result
pub type Result<T> = std::result::Result<T, Error>;

/// trait for leadscale storage operations
///
/// abstracts over different database backends
pub trait Database: Send + Sync {
    // user ops
    fn create_user(&self, user: &User) -> impl Future<Output = Result<User>> + Send;
    fn get_user(&self, id: UserId) -> impl Future<Output = Result<Option<User>>> + Send;
    fn get_user_by_name(&self, name: &str) -> impl Future<Output = Result<Option<User>>> + Send;
    fn list_users(&self) -> impl Future<Output = Result<Vec<User>>> + Send;
    fn delete_user(&self, id: UserId) -> impl Future<Output = Result<()>> + Send;

    // node ops
    fn create_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;
    fn get_node(&self, id: NodeId) -> impl Future<Output = Result<Option<Node>>> + Send;
    fn list_nodes(&self) -> impl Future<Output = Result<Vec<Node>>> + Send;
    fn update_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;
    fn delete_node(&self, id: NodeId) -> impl Future<Output = Result<()>> + Send;

    // preauthkey ops
    fn create_preauth_key(&self, key: &PreAuthKey) -> impl Future<Output = Result<PreAuthKey>> + Send;
    fn get_preauth_key(&self, key: &str) -> impl Future<Output = Result<Option<PreAuthKey>>> + Send;
    fn list_preauth_keys(&self, user_id: UserId) -> impl Future<Output = Result<Vec<PreAuthKey>>> + Send;
    fn mark_preauth_key_used(&self, id: u64) -> impl Future<Output = Result<()>> + Send;
    fn delete_preauth_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;
}

/// placeholder for the actual database implementation
///
/// TODO: implement with database crate (sqlx, sea-orm, diesel)
pub struct LeadscaleDb {
    // db connection pool will go here
}

impl LeadscaleDb {
    /// create a new db connection
    pub async fn new(_config: &leadscale_types::Config) -> Result<Self> {
        // TODO: initialise database connection
        Ok(Self {})
    }

    /// run database migrations
    pub async fn migrate(&self) -> Result<()> {
        // TODO: run migrations
        Ok(())
    }

    /// close the database connection
    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
}
