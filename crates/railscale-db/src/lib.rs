//! database layer for railscale.
//!
//! this crate provides persistent storage for:
//! - Nodes
//! - Users
//! - PreAuthKeys
//! - API Keys
//! - TKA State
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

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, Database as SeaOrmDatabase,
    DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;

use railscale_types::{ApiKey, Config, Node, NodeId, PreAuthKey, PreAuthKeyToken, User, UserId};

/// tailnet key authority state.
#[derive(Clone, Debug, Default)]
pub struct TkaState {
    /// database id (always 1 for single-tenant)
    pub id: u64,
    /// whether tka is enabled
    pub enabled: bool,
    /// current head aum hash (hex)
    pub head: Option<String>,
    /// cbor-serialized State checkpoint
    pub state_checkpoint: Option<Vec<u8>>,
    /// cbor-serialized hashed disablement secrets
    pub disablement_secrets: Option<Vec<u8>>,
    /// cbor-serialized genesis aum for bootstrapping new nodes
    pub genesis_aum: Option<Vec<u8>>,
    /// when this state was created
    pub created_at: DateTime<Utc>,
    /// when this state was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<entity::tka_state::Model> for TkaState {
    fn from(model: entity::tka_state::Model) -> Self {
        Self {
            id: model.id as u64,
            enabled: model.enabled,
            head: model.head,
            state_checkpoint: model.state_checkpoint,
            disablement_secrets: model.disablement_secrets,
            genesis_aum: model.genesis_aum,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<&TkaState> for entity::tka_state::ActiveModel {
    fn from(state: &TkaState) -> Self {
        Self {
            id: if state.id == 0 {
                NotSet
            } else {
                Set(state.id as i64)
            },
            enabled: Set(state.enabled),
            head: Set(state.head.clone()),
            state_checkpoint: Set(state.state_checkpoint.clone()),
            disablement_secrets: Set(state.disablement_secrets.clone()),
            genesis_aum: Set(state.genesis_aum.clone()),
            created_at: Set(state.created_at),
            updated_at: Set(state.updated_at),
        }
    }
}

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

    /// set posture attributes for a node
    fn set_node_posture_attributes(
        &self,
        id: NodeId,
        attrs: &std::collections::HashMap<String, serde_json::Value>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// soft-delete a node by setting `deleted_at` timestamp.
    fn delete_node(&self, id: NodeId) -> impl Future<Output = Result<()>> + Send;

    /// soft-delete all nodes belonging to a user.
    fn delete_nodes_for_user(&self, user_id: UserId) -> impl Future<Output = Result<u64>> + Send;

    // ─── PreAuthKey Operations ───────────────────────────────────────────────

    /// create a new pre-authentication key. returns the key with its assigned id.
    fn create_preauth_key(
        &self,
        key: &PreAuthKey,
    ) -> impl Future<Output = Result<PreAuthKey>> + Send;

    /// get a pre-auth key by its token (lookup by hash).
    fn get_preauth_key(
        &self,
        token: &PreAuthKeyToken,
    ) -> impl Future<Output = Result<Option<PreAuthKey>>> + Send;

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

    /// soft-delete all pre-auth keys belonging to a user.
    fn delete_preauth_keys_for_user(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<u64>> + Send;

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

    /// get all api keys matching a prefix of its selector
    /// returns all matches to allow callers to detect ambiguous prefixes
    fn get_api_keys_by_selector_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<ApiKey>>> + Send;

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

    // ─── TKA Operations ────────────────────────────────────────────────────────

    /// get the current tka state, or none if not initialised.
    fn get_tka_state(&self) -> impl Future<Output = Result<Option<TkaState>>> + Send;

    /// create or update the tka state.
    fn upsert_tka_state(&self, state: &TkaState) -> impl Future<Output = Result<TkaState>> + Send;

    /// get a node's key signature.
    fn get_node_key_signature(
        &self,
        node_id: NodeId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// set a node's key signature.
    fn set_node_key_signature(
        &self,
        node_id: NodeId,
        signature: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// store an AUM in the chain.
    fn store_aum(
        &self,
        hash: &str,
        prev_hash: Option<&str>,
        data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// get an AUM by its hash.
    fn get_aum(&self, hash: &str) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// get all AUMs from a given hash to the current head.
    /// returns AUMs in order from oldest to newest.
    fn get_aums_after(&self, hash: &str) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send;
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

        // enable WAL mode for sqlite if configured
        if config.database.db_type == "sqlite" && config.database.sqlite.write_ahead_log {
            db.enable_wal_mode().await?;
        }

        db.migrate().await?;
        Ok(db)
    }

    /// enable write-ahead logging mode for sqlite.
    ///
    /// WAL mode allows concurrent reads during writes and generally
    /// improves performance. must be called before any writes.
    async fn enable_wal_mode(&self) -> Result<()> {
        use sea_orm::ConnectionTrait;
        self.conn
            .execute_unprepared("PRAGMA journal_mode=WAL")
            .await
            .map_err(|e| Error::Connection(format!("failed to enable WAL mode: {}", e)))?;
        tracing::info!("sqlite WAL mode enabled");
        Ok(())
    }

    /// get the current sqlite journal mode.
    #[cfg(test)]
    async fn get_journal_mode(&self) -> Result<String> {
        use sea_orm::{ConnectionTrait, FromQueryResult};

        #[derive(FromQueryResult)]
        struct JournalMode {
            journal_mode: String,
        }

        let result: Option<JournalMode> = self
            .conn
            .query_one(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "PRAGMA journal_mode".to_string(),
            ))
            .await
            .map_err(|e| Error::Connection(e.to_string()))?
            .map(|row| JournalMode::from_query_result(&row, "").unwrap());

        Ok(result.map(|r| r.journal_mode).unwrap_or_default())
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

    async fn set_node_posture_attributes(
        &self,
        id: NodeId,
        attrs: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let attrs_json = if attrs.is_empty() {
            None
        } else {
            Some(serde_json::to_string(attrs)?)
        };
        entity::node::Entity::update_many()
            .col_expr(
                entity::node::Column::PostureAttributes,
                sea_orm::sea_query::Expr::value(attrs_json),
            )
            .col_expr(
                entity::node::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::node::Column::Id.eq(id.0 as i64))
            .filter(entity::node::Column::DeletedAt.is_null())
            .exec(&self.conn)
            .await?;
        Ok(())
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

    async fn delete_nodes_for_user(&self, user_id: UserId) -> Result<u64> {
        let result = entity::node::Entity::update_many()
            .col_expr(
                entity::node::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::node::Column::UserId.eq(user_id.0 as i64))
            .filter(entity::node::Column::DeletedAt.is_null())
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }

    // preauthkey operations

    async fn create_preauth_key(&self, key: &PreAuthKey) -> Result<PreAuthKey> {
        let model: entity::preauth_key::ActiveModel = key.into();
        let result = model.insert(&self.conn).await?;
        Ok(result.into())
    }

    async fn get_preauth_key(&self, token: &PreAuthKeyToken) -> Result<Option<PreAuthKey>> {
        // compute the hash of the provided token for lookup
        let key_hash = hex::encode(token.hash());
        let result = entity::preauth_key::Entity::find()
            .filter(entity::preauth_key::Column::KeyHash.eq(key_hash))
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
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
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

    async fn delete_preauth_keys_for_user(&self, user_id: UserId) -> Result<u64> {
        let result = entity::preauth_key::Entity::update_many()
            .col_expr(
                entity::preauth_key::Column::DeletedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::preauth_key::Column::UserId.eq(user_id.0 as i64))
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
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
            .filter(entity::preauth_key::Column::DeletedAt.is_null())
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

    async fn get_api_keys_by_selector_prefix(&self, prefix: &str) -> Result<Vec<ApiKey>> {
        let results = entity::api_key::Entity::find()
            .filter(entity::api_key::Column::Selector.starts_with(prefix))
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .all(&self.conn)
            .await?;
        Ok(results.into_iter().map(Into::into).collect())
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
            .filter(entity::api_key::Column::DeletedAt.is_null())
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
            .filter(entity::api_key::Column::DeletedAt.is_null())
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    // tka operations

    async fn get_tka_state(&self) -> Result<Option<TkaState>> {
        let result = entity::tka_state::Entity::find_by_id(1i64)
            .one(&self.conn)
            .await?;
        Ok(result.map(Into::into))
    }

    async fn upsert_tka_state(&self, state: &TkaState) -> Result<TkaState> {
        // check if state exists
        let existing = entity::tka_state::Entity::find_by_id(1i64)
            .one(&self.conn)
            .await?;

        let mut model: entity::tka_state::ActiveModel = state.into();
        model.id = Set(1); // always use id 1 for single-tenant
        model.updated_at = Set(Utc::now());

        let result = if existing.is_some() {
            model.update(&self.conn).await?
        } else {
            model.created_at = Set(Utc::now());
            model.insert(&self.conn).await?
        };

        Ok(result.into())
    }

    async fn get_node_key_signature(&self, node_id: NodeId) -> Result<Option<Vec<u8>>> {
        let result = entity::node::Entity::find_by_id(node_id.0 as i64)
            .filter(entity::node::Column::DeletedAt.is_null())
            .one(&self.conn)
            .await?;
        Ok(result.and_then(|m| m.key_signature))
    }

    async fn set_node_key_signature(&self, node_id: NodeId, signature: &[u8]) -> Result<()> {
        entity::node::Entity::update_many()
            .col_expr(
                entity::node::Column::KeySignature,
                sea_orm::sea_query::Expr::value(signature.to_vec()),
            )
            .col_expr(
                entity::node::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(Utc::now()),
            )
            .filter(entity::node::Column::Id.eq(node_id.0 as i64))
            .filter(entity::node::Column::DeletedAt.is_null())
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    async fn store_aum(&self, hash: &str, prev_hash: Option<&str>, data: &[u8]) -> Result<()> {
        use sea_orm::ActiveValue::Set;

        let model = entity::tka_aum::ActiveModel {
            hash: Set(hash.to_string()),
            prev_hash: Set(prev_hash.map(|s| s.to_string())),
            aum_data: Set(data.to_vec()),
            created_at: Set(Utc::now()),
        };

        // use insert or ignore to handle duplicate hashes (idempotent)
        entity::tka_aum::Entity::insert(model)
            .on_conflict(
                sea_orm::sea_query::OnConflict::column(entity::tka_aum::Column::Hash)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&self.conn)
            .await
            .ok(); // ignore conflict errors

        Ok(())
    }

    async fn get_aum(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        let result = entity::tka_aum::Entity::find_by_id(hash.to_string())
            .one(&self.conn)
            .await?;
        Ok(result.map(|m| m.aum_data))
    }

    async fn get_aums_after(&self, hash: &str) -> Result<Vec<Vec<u8>>> {
        // walk the chain from the given hash to the head
        // we need to find all AUMs where this hash appears in their ancestry
        // for now, do a simple approach: get all AUMs and filter

        // get the current head from tka_state
        let tka_state = self.get_tka_state().await?;
        let head = match tka_state.and_then(|s| s.head) {
            Some(h) => h,
            None => return Ok(vec![]),
        };

        // if the requested hash is the head, nothing to return
        if hash == head {
            return Ok(vec![]);
        }

        // walk backwards from head collecting AUMs until we find the requested hash
        let mut aums = Vec::new();
        let mut current = head;

        loop {
            if current == hash {
                break;
            }

            let aum = match entity::tka_aum::Entity::find_by_id(current.clone())
                .one(&self.conn)
                .await?
            {
                Some(a) => a,
                None => break, // chain is broken, stop
            };

            aums.push(aum.aum_data.clone());

            match aum.prev_hash {
                Some(prev) => current = prev,
                None => break, // reached genesis
            }
        }

        // reverse to get oldest-to-newest order
        aums.reverse();
        Ok(aums)
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

        // create key using token
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(0, &token, user.id);
        let created = db.create_preauth_key(&key).await.unwrap();
        assert!(created.id > 0);

        // get by token (looks up by hash)
        let fetched = db.get_preauth_key(&token).await.unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert!(fetched.verify(&token));

        // list by user
        let keys = db.list_preauth_keys(user.id).await.unwrap();
        assert_eq!(keys.len(), 1);

        // mark used
        db.mark_preauth_key_used(created.id).await.unwrap();
        let updated = db.get_preauth_key(&token).await.unwrap().unwrap();
        assert!(updated.used);

        // delete
        db.delete_preauth_key(created.id).await.unwrap();
        let deleted = db.get_preauth_key(&token).await.unwrap();
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
        let found = db.get_api_keys_by_selector_prefix(prefix_8).await.unwrap();
        assert_eq!(
            found.len(),
            1,
            "Should find exactly one key by 8-char prefix"
        );
        assert_eq!(found[0].id, created.id);
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
            tags: vec!["tag:server".parse().unwrap()],
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            last_seen_country: None,
            approved_routes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_online: None,
            posture_attributes: std::collections::HashMap::new(),
            ephemeral: false,
        };

        let created = db.create_node(&node).await.unwrap();
        assert!(created.id.0 > 0);

        // get
        let fetched = db.get_node(created.id).await.unwrap().unwrap();
        assert_eq!(fetched.hostname, "test-node");
        assert_eq!(fetched.tags.len(), 1);
        assert!(fetched.tags[0] == "tag:server");
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

    #[tokio::test]
    async fn test_tka_state_crud() {
        let db = setup_test_db().await;

        // initially no tka state
        let state = db.get_tka_state().await.unwrap();
        assert!(state.is_none());

        // create tka state
        let new_state = TkaState {
            id: 0, // will be set to 1
            enabled: true,
            head: Some("abc123".to_string()),
            state_checkpoint: Some(vec![1, 2, 3]),
            disablement_secrets: Some(vec![4, 5, 6]),
            genesis_aum: Some(vec![7, 8, 9]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let created = db.upsert_tka_state(&new_state).await.unwrap();
        assert_eq!(created.id, 1);
        assert!(created.enabled);
        assert_eq!(created.head, Some("abc123".to_string()));

        // get tka state
        let fetched = db.get_tka_state().await.unwrap().unwrap();
        assert!(fetched.enabled);
        assert_eq!(fetched.head, Some("abc123".to_string()));

        // update tka state
        let mut updated_state = fetched;
        updated_state.head = Some("def456".to_string());
        let updated = db.upsert_tka_state(&updated_state).await.unwrap();
        assert_eq!(updated.head, Some("def456".to_string()));
    }

    #[tokio::test]
    async fn test_node_key_signature() {
        use railscale_types::{DiscoKey, MachineKey, NodeKey, RegisterMethod};

        let db = setup_test_db().await;

        // create user and node
        let user = User::new(UserId(0), "sigowner".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node = Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![1, 2, 3, 4]),
            node_key: NodeKey::from_bytes(vec![5, 6, 7, 8]),
            disco_key: DiscoKey::from_bytes(vec![9, 10, 11, 12]),
            endpoints: vec![],
            hostinfo: None,
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            hostname: "sig-node".to_string(),
            given_name: "sig-node".to_string(),
            user_id: Some(user.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            last_seen_country: None,
            approved_routes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_online: None,
            posture_attributes: std::collections::HashMap::new(),
            ephemeral: false,
        };
        let created = db.create_node(&node).await.unwrap();

        // initially no signature
        let sig = db.get_node_key_signature(created.id).await.unwrap();
        assert!(sig.is_none());

        // set signature
        let signature = vec![0xde, 0xad, 0xbe, 0xef];
        db.set_node_key_signature(created.id, &signature)
            .await
            .unwrap();

        // get signature
        let fetched = db.get_node_key_signature(created.id).await.unwrap();
        assert_eq!(fetched, Some(signature));
    }

    #[tokio::test]
    async fn test_sqlite_wal_mode_enabled() {
        // WAL mode requires a file-based database, not :memory:
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_wal.db");

        let mut config = Config::default();
        config.database.db_type = "sqlite".to_string();
        config.database.connection_string = db_path.to_string_lossy().to_string();
        config.database.sqlite.write_ahead_log = true;

        let db = RailscaleDb::new(&config).await.unwrap();
        let mode = db.get_journal_mode().await.unwrap();

        // WAL mode should be enabled
        assert_eq!(mode.to_lowercase(), "wal", "journal mode should be WAL");
    }

    #[tokio::test]
    async fn test_sqlite_wal_mode_disabled_by_default() {
        // default in-memory db should not have WAL
        let db = setup_test_db().await;
        let mode = db.get_journal_mode().await.unwrap();

        // in-memory sqlite uses "memory" journal mode, not "wal"
        assert_ne!(
            mode.to_lowercase(),
            "wal",
            "default should not use WAL mode"
        );
    }

    #[tokio::test]
    async fn test_delete_nodes_for_user() {
        let db = setup_test_db().await;

        let user = User::new(UserId(0), "alice".to_string());
        let user = db.create_user(&user).await.unwrap();

        // create two nodes for this user
        for i in 0..2u8 {
            let node = railscale_types::test_utils::TestNodeBuilder::new(0)
                .with_node_key(railscale_types::NodeKey::from_bytes(vec![i + 1; 32]))
                .with_user_id(user.id)
                .build();
            db.create_node(&node).await.unwrap();
        }

        let nodes = db.list_nodes_for_user(user.id).await.unwrap();
        assert_eq!(nodes.len(), 2);

        let deleted = db.delete_nodes_for_user(user.id).await.unwrap();
        assert_eq!(deleted, 2);

        let nodes = db.list_nodes_for_user(user.id).await.unwrap();
        assert_eq!(nodes.len(), 0, "nodes should be soft-deleted");
    }

    #[tokio::test]
    async fn test_delete_preauth_keys_for_user() {
        let db = setup_test_db().await;

        let user = User::new(UserId(0), "bob".to_string());
        let user = db.create_user(&user).await.unwrap();

        // create two preauth keys
        for _ in 0..2 {
            let token = railscale_types::PreAuthKeyToken::generate();
            let key = railscale_types::PreAuthKey::from_token(0, &token, user.id);
            db.create_preauth_key(&key).await.unwrap();
        }

        let keys = db.list_preauth_keys(user.id).await.unwrap();
        assert_eq!(keys.len(), 2);

        let deleted = db.delete_preauth_keys_for_user(user.id).await.unwrap();
        assert_eq!(deleted, 2);

        let keys = db.list_preauth_keys(user.id).await.unwrap();
        assert_eq!(keys.len(), 0, "preauth keys should be soft-deleted");
    }

    #[tokio::test]
    async fn test_duplicate_username_rejected() {
        let db = setup_test_db().await;

        let user1 = User::new(UserId(0), "alice".to_string());
        db.create_user(&user1).await.unwrap();

        // second user with same name should fail
        let user2 = User::new(UserId(0), "alice".to_string());
        let result = db.create_user(&user2).await;
        assert!(result.is_err(), "duplicate username should be rejected");
    }
}
