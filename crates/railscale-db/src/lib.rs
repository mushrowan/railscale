//! database layer for railscale.
//!
//! this crate provides persistent storage for:
//! - Nodes
//! - Users
//! - PreAuthKeys
//! - API Keys
//!
//! it also handles ip address allocation for new nodes.

#![warn(missing_docs)]

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

use railscale_types::{ApiKey, Config, Node, NodeId, PreAuthKey, User, UserId};

/// result type for database operations.
pub type Result<T> = std::result::Result<T, Error>;

/// database trait for railscale storage operations.
///
/// this trait abstracts over different database backends (sqlite, postgresql).
/// all operations use soft-delete semantics - records are marked with a `deleted_at`
/// timestamp rather than being physically removed.
pub trait Database: Send + Sync {
    // ─── Health Check ─────────────────────────────────────────────────────────

    /// ping the database to verify connectivity.
    ///
    /// returns `ok(())` if the database is reachable, `err` otherwise.
    /// used for health checks with a recommended timeout of 1 second.
    fn ping(&self) -> impl Future<Output = Result<()>> + Send;

    // ─── User Operations ─────────────────────────────────────────────────────

    /// create a new user. Returns the created user with its assigned ID.
    fn create_user(&self, user: &User) -> impl Future<Output = Result<User>> + Send;

    /// get a user by id. Returns `None` if not found or soft-deleted.
    fn get_user(&self, id: UserId) -> impl Future<Output = Result<Option<User>>> + Send;

    /// get a user by username. returns `none` if not found or soft-deleted.
    fn get_user_by_name(&self, name: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    /// get a user by oidc provider identifier (issuer + subject claim).
    fn get_user_by_oidc_identifier(
        &self,
        identifier: &str,
    ) -> impl Future<Output = Result<Option<User>>> + Send;

    /// list all non-deleted users.
    fn list_users(&self) -> impl Future<Output = Result<Vec<User>>> + Send;

    /// update an existing user. returns the updated user.
    fn update_user(&self, user: &User) -> impl Future<Output = Result<User>> + Send;

    /// soft-delete a user by setting `deleted_at` timestamp.
    fn delete_user(&self, id: UserId) -> impl Future<Output = Result<()>> + Send;

    // ─── Node Operations ─────────────────────────────────────────────────────

    /// create a new node. returns the created node with its assigned id.
    fn create_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;

    /// get a node by id. Returns `None` if not found or soft-deleted.
    fn get_node(&self, id: NodeId) -> impl Future<Output = Result<Option<Node>>> + Send;

    /// get a node by its current node key (session key).
    fn get_node_by_node_key(
        &self,
        node_key: &railscale_types::NodeKey,
    ) -> impl Future<Output = Result<Option<Node>>> + Send;

    /// list all non-deleted nodes.
    fn list_nodes(&self) -> impl Future<Output = Result<Vec<Node>>> + Send;

    /// list all non-deleted nodes belonging to a specific user.
    fn list_nodes_for_user(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<Node>>> + Send;

    /// update an existing node. also updates `updated_at` timestamp.
    fn update_node(&self, node: &Node) -> impl Future<Output = Result<Node>> + Send;

    /// soft-delete a node by setting `deleted_at` timestamp.
    fn delete_node(&self, id: NodeId) -> impl Future<Output = Result<()>> + Send;

    // ─── PreAuthKey Operations ───────────────────────────────────────────────

    /// create a new pre-authentication key. returns the key with its assigned id.
    fn create_preauth_key(
        &self,
        key: &PreAuthKey,
    ) -> impl Future<Output = Result<PreAuthKey>> + Send;

    /// get a pre-auth key by its key string.
    fn get_preauth_key(&self, key: &str)
    -> impl Future<Output = Result<Option<PreAuthKey>>> + Send;

    /// list all pre-auth keys created by a specific user.
    fn list_preauth_keys(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<PreAuthKey>>> + Send;

    /// list all pre-auth keys across all users.
    fn get_all_preauth_keys(&self) -> impl Future<Output = Result<Vec<PreAuthKey>>> + Send;

    /// mark a non-reusable pre-auth key as used.
    fn mark_preauth_key_used(&self, id: u64) -> impl Future<Output = Result<()>> + Send;

    /// soft-delete a pre-auth key.
    fn delete_preauth_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;

    /// expire a pre-auth key by setting its expiration to now.
    fn expire_preauth_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;

    // ─── ApiKey Operations ───────────────────────────────────────────────────

    /// create a new api key. Returns the key with its assigned ID.
    fn create_api_key(&self, key: &ApiKey) -> impl Future<Output = Result<ApiKey>> + Send;

    /// get an api key by its selector (for split-token lookup).
    fn get_api_key_by_selector(
        &self,
        selector: &str,
    ) -> impl Future<Output = Result<Option<ApiKey>>> + Send;

    /// get an api key by a prefix of its selector (first 8 chars).
    /// used for user-facing lookups where only the prefix is shown.
    fn get_api_key_by_selector_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Option<ApiKey>>> + Send;

    /// get an api key by its numeric id.
    fn get_api_key_by_id(&self, id: u64) -> impl Future<Output = Result<Option<ApiKey>>> + Send;

    /// list all api keys belonging to a specific user.
    fn list_api_keys(&self, user_id: UserId) -> impl Future<Output = Result<Vec<ApiKey>>> + Send;

    /// list all api keys across all users.
    fn get_all_api_keys(&self) -> impl Future<Output = Result<Vec<ApiKey>>> + Send;

    /// soft-delete an api key.
    fn delete_api_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;

    /// expire an api key by setting its expiration to now.
    fn expire_api_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;

    /// update the `last_used_at` timestamp for an api key.
    fn touch_api_key(&self, id: u64) -> impl Future<Output = Result<()>> + Send;
}

/// the main database implementation using sea-orm.
#[derive(Clone)]
pub struct RailscaleDb {
    conn: DatabaseConnection,
}

impl RailscaleDb {
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
                // for sqlite, build the connection url with create mode
                let path = if config.connection_string.starts_with("sqlite:") {
                    config.connection_string.clone()
                } else {
                    format!("sqlite:{}", config.connection_string)
                };
                // add ?mode=rwc to create file if it doesn't exist
                if path.contains('?') {
                    Ok(path)
                } else {
                    Ok(format!("{}?mode=rwc", path))
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

impl Database for RailscaleDb {
    // health check

    async fn ping(&self) -> Result<()> {
        use sea_orm::ConnectionTrait;
        self.conn
            .execute_unprepared("SELECT 1")
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;
        Ok(())
    }

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

    async fn get_user_by_oidc_identifier(&self, identifier: &str) -> Result<Option<User>> {
        let result = entity::user::Entity::find()
            .filter(entity::user::Column::ProviderIdentifier.eq(identifier))
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

    async fn update_user(&self, user: &User) -> Result<User> {
        let model: entity::user::ActiveModel = user.into();
        let result = model.update(&self.conn).await?;
        Ok(result.into())
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

    async fn list_nodes_for_user(&self, user_id: UserId) -> Result<Vec<Node>> {
        let results = entity::node::Entity::find()
            .filter(entity::node::Column::UserId.eq(user_id.0 as i64))
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

    async fn get_all_preauth_keys(&self) -> Result<Vec<PreAuthKey>> {
        let results = entity::preauth_key::Entity::find()
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn expire_preauth_key(&self, id: u64) -> Result<()> {
        entity::preauth_key::Entity::update_many()
            .col_expr(
                entity::preauth_key::Column::Expiration,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::preauth_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    // apikey operations

    async fn create_api_key(&self, key: &ApiKey) -> Result<ApiKey> {
        let model: entity::api_key::ActiveModel = key.into();
        let result = model.insert(&self.conn).await?;
        Ok(result.into())
    }

    async fn get_api_key_by_selector(&self, selector: &str) -> Result<Option<ApiKey>> {
        let result = entity::api_key::Entity::find()
            .filter(entity::api_key::Column::Selector.eq(selector))
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn get_api_key_by_selector_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        let result = entity::api_key::Entity::find()
            .filter(entity::api_key::Column::Selector.starts_with(prefix))
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn get_api_key_by_id(&self, id: u64) -> Result<Option<ApiKey>> {
        let result = entity::api_key::Entity::find_by_id(id as i64)
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn list_api_keys(&self, user_id: UserId) -> Result<Vec<ApiKey>> {
        let results = entity::api_key::Entity::find()
            .filter(entity::api_key::Column::UserId.eq(user_id.0 as i64))
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn get_all_api_keys(&self) -> Result<Vec<ApiKey>> {
        let results = entity::api_key::Entity::find()
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn delete_api_key(&self, id: u64) -> Result<()> {
        entity::api_key::Entity::update_many()
            .col_expr(
                entity::api_key::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::api_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    async fn expire_api_key(&self, id: u64) -> Result<()> {
        entity::api_key::Entity::update_many()
            .col_expr(
                entity::api_key::Column::Expiration,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::api_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    async fn touch_api_key(&self, id: u64) -> Result<()> {
        entity::api_key::Entity::update_many()
            .col_expr(
                entity::api_key::Column::LastUsedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::api_key::Column::Id.eq(id as i64))
            .exec(&self.conn)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> RailscaleDb {
        RailscaleDb::new_in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn test_ping() {
        let db = setup_test_db().await;
        // should succeed for a healthy database
        db.ping().await.unwrap();
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
    async fn test_get_user_by_oidc_identifier() {
        let db = setup_test_db().await;

        // create user with OIDC identifier
        let mut user = User::new(UserId(0), "oidc-user".to_string());
        user.provider = Some("oidc".to_string());
        user.provider_identifier = Some("https://accounts.google.com:12345678".to_string());
        user.email = Some("test@example.com".to_string());

        let created = db.create_user(&user).await.unwrap();
        assert!(created.id.0 > 0);

        // get by OIDC identifier
        let fetched = db
            .get_user_by_oidc_identifier("https://accounts.google.com:12345678")
            .await
            .unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.email, Some("test@example.com".to_string()));
        assert_eq!(
            fetched.provider_identifier,
            Some("https://accounts.google.com:12345678".to_string())
        );

        // non-existent identifier returns none
        let not_found = db.get_user_by_oidc_identifier("nonexistent").await.unwrap();
        assert!(not_found.is_none());

        // soft-deleted users are not returned
        db.delete_user(created.id).await.unwrap();
        let deleted = db
            .get_user_by_oidc_identifier("https://accounts.google.com:12345678")
            .await
            .unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_api_key_crud() {
        use railscale_types::ApiKeySecret;

        let db = setup_test_db().await;

        // create user first
        let user = User::new(UserId(0), "apikeyowner".to_string());
        let user = db.create_user(&user).await.unwrap();

        // generate api key secret (split-token pattern)
        let secret = ApiKeySecret::generate();

        // create key
        let key = ApiKey::new(0, &secret, "My API Key".to_string(), user.id);
        let created = db.create_api_key(&key).await.unwrap();
        assert!(created.id > 0);

        // get by selector
        let fetched = db.get_api_key_by_selector(&secret.selector).await.unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.name, "My API Key");

        // verify the full token works
        assert!(fetched.verify(&secret.full_key));

        // get by ID
        let fetched_by_id = db.get_api_key_by_id(created.id).await.unwrap();
        assert!(fetched_by_id.is_some());

        // list by user
        let keys = db.list_api_keys(user.id).await.unwrap();
        assert_eq!(keys.len(), 1);

        // get all
        let all_keys = db.get_all_api_keys().await.unwrap();
        assert_eq!(all_keys.len(), 1);

        // touch (update last_used_at)
        db.touch_api_key(created.id).await.unwrap();
        let touched = db
            .get_api_key_by_selector(&secret.selector)
            .await
            .unwrap()
            .unwrap();
        assert!(touched.last_used_at.is_some());

        // expire
        db.expire_api_key(created.id).await.unwrap();
        let expired = db
            .get_api_key_by_selector(&secret.selector)
            .await
            .unwrap()
            .unwrap();
        assert!(expired.is_expired());

        // delete
        db.delete_api_key(created.id).await.unwrap();
        let deleted = db.get_api_key_by_selector(&secret.selector).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_api_key_lookup_by_selector_prefix() {
        use railscale_types::ApiKeySecret;
        let db = setup_test_db().await;

        // create user
        let user = User::new(UserId(0), "apiuser".to_string());
        let user = db.create_user(&user).await.unwrap();

        // generate api key
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(0, &secret, "Prefix Test Key".to_string(), user.id);
        let created = db.create_api_key(&key).await.unwrap();

        // the full selector is 32 hex chars, but prefix() returns first 8
        assert_eq!(secret.selector.len(), 32);
        let prefix_8 = &secret.selector[..8];

        // look up by 8-char prefix (this is what the api does)
        let found = db.get_api_key_by_selector_prefix(prefix_8).await.unwrap();
        assert!(found.is_some(), "Should find key by 8-char prefix");
        assert_eq!(found.unwrap().id, created.id);
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
