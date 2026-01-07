//! database layer for railscale
//!
//! this crate provides persistent storage for:
//! - Nodes
//! - Users
//! - PreAuthKeys
//! - API Keys
//!
//! it also handles ip address allocation for new nodes.

mod entity;
mod error;
mod ip_allocator;
mod migration;

pub use error::Error;
pub use ip_allocator::IpAllocator;

use std::future::Future;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database as SeaOrmDatabase, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;

use railscale_types::{Config, Node, NodeId, PreAuthKey, User, UserId};

/// result type for database operations.
pub type Result<T> = std::result::Result<T, Error>;

/// database trait for railscale storage operations.
///
/// this trait abstracts over different database backends (sqlite, postgresql).
pub trait Database: Send + Sync {
    // user operations
    fn create_user(&self, user: &User) -> impl Future<Output = Result<User>> + Send;
    fn get_user(&self, id: UserId) -> impl Future<Output = Result<Option<User>>> + Send;
    fn get_user_by_name(&self, name: &str) -> impl Future<Output = Result<Option<User>>> + Send;
    fn list_users(&self) -> impl Future<Output = Result<Vec<User>>> + Send;
    fn delete_user(&self, id: UserId) -> impl Future<Output = Result<()>> + Send;

    // node operations
    fn create_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;
    fn get_node(&self, id: NodeId) -> impl Future<Output = Result<Option<Node>>> + Send;
    fn get_node_by_node_key(
        &self,
        node_key: &railscale_types::NodeKey,
    ) -> impl Future<Output = Result<Option<Node>>> + Send;
    fn list_nodes(&self) -> impl Future<Output = Result<Vec<Node>>> + Send;
    fn update_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;
    fn delete_node(&self, id: NodeId) -> impl Future<Output = Result<()>> + Send;

    // preauthkey operations
    fn create_preauth_key(
        &self,
        key: &PreAuthKey,
    ) -> impl Future<Output = Result<PreAuthKey>> + Send;
    fn get_preauth_key(&self, key: &str) -> impl Future<Output = Result<Option<PreAuthKey>>> + Send;
    fn list_preauth_keys(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<PreAuthKey>>> + Send;
    fn mark_preauth_key_used(&self, id: u64) -> impl Future<Output = Result<()>> + Send;
    fn delete_preauth_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;
}

/// the main database implementation using sea-orm.
#[derive(Clone)]
pub struct railscaleDb {
    conn: DatabaseConnection,
}

impl railscaleDb {
    /// create a new database connection from config.
    pub async fn new(config: &Config) -> Result<Self> {
        let url = Self::build_connection_url(&config.database)?;
        let conn: DatabaseConnection = SeaOrmDatabase::connect(&url)
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        let db = Self { conn };
        db.migrate().await?;
        Ok(db)
    }

    /// build a sea-orm compatible connection url from config.
    fn build_connection_url(config: &railscale_types::DatabaseConfig) -> Result<String> {
        match config.db_type.as_str() {
            "sqlite" => {
                // for sqlite, prefix with "sqlite:" if not already present
                if config.connection_string.starts_with("sqlite:") {
                    Ok(config.connection_string.clone())
                } else {
                    Ok(format!("sqlite:{}", config.connection_string))
                }
            }
            "postgres" | "postgresql" => {
                // postgresql urls should already be properly formatted
                Ok(config.connection_string.clone())
            }
            other => Err(Error::InvalidData(format!(
                "unsupported database type: {}",
                other
            ))),
        }
    }

    /// create an in-memory sqlite database for testing.
    pub async fn new_in_memory() -> Result<Self> {
        let conn: DatabaseConnection = SeaOrmDatabase::connect("sqlite::memory:")
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        let db = Self { conn };
        db.migrate().await?;
        Ok(db)
    }

    /// run database migrations.
    pub async fn migrate(&self) -> Result<()> {
        migration::Migrator::up(&self.conn, None)
            .await
            .map_err(|e| Error::Migration(e.to_string()))?;
        Ok(())
    }

    /// close the database connection.
    ///
    /// NOTE: sea-orm connections are reference-counted and cleaned up on drop.
    /// this method exists for explicit cleanup and logging purposes.
    pub async fn close(&self) -> Result<()> {
        // sea-orm handles connection cleanup on drop
        // this method is kept for api compatibility and potential future cleanup logic
        tracing::debug!("database connection marked for close");
        Ok(())
    }
}

impl Database for railscaleDb {
    // user operations

    async fn create_user(&self, user: &User) -> Result<User> {
        let model: entity::user::ActiveModel = user.into();
        let result = model.insert(&self.conn).await?;
        Ok(result.into())
    }

    async fn get_user(&self, id: UserId) -> Result<Option<User>> {
        let result = entity::user::Entity::find_by_id(id.0 as i64)
            .filter(entity::user::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn get_user_by_name(&self, name: &str) -> Result<Option<User>> {
        let result = entity::user::Entity::find()
            .filter(entity::user::Column::Name.eq(name))
            .filter(entity::user::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let results = entity::user::Entity::find()
            .filter(entity::user::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn delete_user(&self, id: UserId) -> Result<()> {
        entity::user::Entity::update_many()
            .col_expr(
                entity::user::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::user::Column::Id.eq(id.0 as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    // node operations

    async fn create_node(&self, node: &Node) -> Result<Node> {
        let model: entity::node::ActiveModel = node.into();
        let result = model.insert(&self.conn).await?;
        Ok(result.into())
    }

    async fn get_node(&self, id: NodeId) -> Result<Option<Node>> {
        let result = entity::node::Entity::find_by_id(id.0 as i64)
            .filter(entity::node::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn get_node_by_node_key(
        &self,
        node_key: &railscale_types::NodeKey,
    ) -> Result<Option<Node>> {
        let result = entity::node::Entity::find()
            .filter(entity::node::Column::NodeKey.eq(node_key.as_bytes()))
            .filter(entity::node::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn list_nodes(&self) -> Result<Vec<Node>> {
        let results = entity::node::Entity::find()
            .filter(entity::node::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn update_node(&self, node: &Node) -> Result<Node> {
        let mut model: entity::node::ActiveModel = node.into();
        model.updated_at = Set(Utc::now());
        let result = model.update(&self.conn).await?;
        Ok(result.into())
    }

    async fn delete_node(&self, id: NodeId) -> Result<()> {
        entity::node::Entity::update_many()
            .col_expr(
                entity::node::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::node::Column::Id.eq(id.0 as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    // preauthkey operations

    async fn create_preauth_key(&self, key: &PreAuthKey) -> Result<PreAuthKey> {
        let model: entity::preauth_key::ActiveModel = key.into();
        let result = model.insert(&self.conn).await?;
        Ok(result.into())
    }

    async fn get_preauth_key(&self, key: &str) -> Result<Option<PreAuthKey>> {
        let result = entity::preauth_key::Entity::find()
            .filter(entity::preauth_key::Column::Key.eq(key))
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn list_preauth_keys(&self, user_id: UserId) -> Result<Vec<PreAuthKey>> {
        let results = entity::preauth_key::Entity::find()
            .filter(entity::preauth_key::Column::UserId.eq(user_id.0 as i64))
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn mark_preauth_key_used(&self, id: u64) -> Result<()> {
        entity::preauth_key::Entity::update_many()
            .col_expr(
                entity::preauth_key::Column::Used,
                sea_orm::sea_query::Expr::value(true),
            )
            .filter(entity::preauth_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    async fn delete_preauth_key(&self, id: u64) -> Result<()> {
        entity::preauth_key::Entity::update_many()
            .col_expr(
                entity::preauth_key::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::preauth_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> railscaleDb {
        railscaleDb::new_in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn test_user_crud() {
        let db = setup_test_db().await;

        // create
        let user = User::new(UserId(0), "testuser".to_string());
        let created = db.create_user(&user).await.unwrap();
        assert!(created.id.0 > 0);
        assert_eq!(created.name, "testuser");

        // get by ID
        let fetched = db.get_user(created.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "testuser");

        // get by name
        let by_name = db.get_user_by_name("testuser").await.unwrap();
        assert!(by_name.is_some());

        // list
        let users = db.list_users().await.unwrap();
        assert_eq!(users.len(), 1);

        // delete (soft)
        db.delete_user(created.id).await.unwrap();
        let deleted = db.get_user(created.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_preauth_key_crud() {
        let db = setup_test_db().await;

        // create user first
        let user = User::new(UserId(0), "keyowner".to_string());
        let user = db.create_user(&user).await.unwrap();

        // create key
        let key = PreAuthKey::new(0, "test-key-123".to_string(), user.id);
        let created = db.create_preauth_key(&key).await.unwrap();
        assert!(created.id > 0);

        // get by key
        let fetched = db.get_preauth_key("test-key-123").await.unwrap();
        assert!(fetched.is_some());

        // list by user
        let keys = db.list_preauth_keys(user.id).await.unwrap();
        assert_eq!(keys.len(), 1);

        // mark used
        db.mark_preauth_key_used(created.id).await.unwrap();
        let updated = db.get_preauth_key("test-key-123").await.unwrap().unwrap();
        assert!(updated.used);

        // delete
        db.delete_preauth_key(created.id).await.unwrap();
        let deleted = db.get_preauth_key("test-key-123").await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_node_crud() {
        use railscale_types::{DiscoKey, MachineKey, NodeKey, RegisterMethod};

        let db = setup_test_db().await;

        // create user first
        let user = User::new(UserId(0), "nodeowner".to_string());
        let user = db.create_user(&user).await.unwrap();

        // create node
        let node = Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![1, 2, 3, 4]),
            node_key: NodeKey::from_bytes(vec![5, 6, 7, 8]),
            disco_key: DiscoKey::from_bytes(vec![9, 10, 11, 12]),
            endpoints: vec!["192.168.1.1:41641".parse().unwrap()],
            hostinfo: None,
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            hostname: "test-node".to_string(),
            given_name: "test-node".to_string(),
            user_id: Some(user.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec!["tag:server".to_string()],
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            approved_routes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_online: None,
        };

        let created = db.create_node(&node).await.unwrap();
        assert!(created.id.0 > 0);

        // get
        let fetched = db.get_node(created.id).await.unwrap().unwrap();
        assert_eq!(fetched.hostname, "test-node");
        assert_eq!(fetched.tags, vec!["tag:server".to_string()]);
        assert_eq!(fetched.endpoints.len(), 1);

        // list
        let nodes = db.list_nodes().await.unwrap();
        assert_eq!(nodes.len(), 1);

        // update
        let mut updated_node = fetched.clone();
        updated_node.hostname = "updated-node".to_string();
        let updated = db.update_node(&updated_node).await.unwrap();
        assert_eq!(updated.hostname, "updated-node");

        // delete
        db.delete_node(created.id).await.unwrap();
        let deleted = db.get_node(created.id).await.unwrap();
        assert!(deleted.is_none());
    }
}
