//! shared snapshot cache for map response data
//!
//! caches node and user lists to avoid redundant DB queries when multiple
//! streaming clients are woken by the same state change. uses lazy
//! invalidation via generation counters — the cache is only rebuilt
//! from the database on the first read after a state change.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use railscale_db::{Database, RailscaleDb};
use railscale_proto::DnsConfig;
use railscale_types::{Node, User};
use tokio::sync::RwLock;
use tracing::debug;

/// cached snapshot of nodes and users for map response building
struct Snapshot {
    nodes: Arc<Vec<Node>>,
    users: Arc<Vec<User>>,
    generation: u64,
}

/// shared map response cache with lazy invalidation
///
/// when state changes, [`invalidate`] bumps the generation counter.
/// the next call to [`get_snapshot`] detects the stale cache and
/// rebuilds from the database. concurrent readers during rebuild
/// wait on the write lock and then share the fresh data.
pub struct MapCache {
    /// current snapshot (lazily rebuilt on read after invalidation)
    snapshot: RwLock<Option<Snapshot>>,
    /// monotonically increasing counter bumped on each state change
    generation: AtomicU64,
    /// generation of the current snapshot (0 = no snapshot)
    cached_generation: AtomicU64,
    /// pre-computed dns config (config-derived, never changes at runtime)
    dns_config: Option<DnsConfig>,
}

impl MapCache {
    /// create a new empty cache with pre-computed dns config
    pub fn new(dns_config: Option<DnsConfig>) -> Self {
        Self {
            snapshot: RwLock::new(None),
            generation: AtomicU64::new(1), // start at 1 so 0 means "never cached"
            cached_generation: AtomicU64::new(0),
            dns_config,
        }
    }

    /// mark the cache as stale — next read will rebuild from DB
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// get the current generation counter (for testing)
    #[cfg(test)]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// get the pre-computed dns config
    pub fn dns_config(&self) -> Option<DnsConfig> {
        self.dns_config.clone()
    }

    /// get a fresh snapshot of nodes and users
    ///
    /// returns Arc-wrapped vecs so concurrent readers share the same
    /// allocation instead of cloning on every map request.
    pub async fn get_snapshot(
        &self,
        db: &RailscaleDb,
    ) -> Result<(Arc<Vec<Node>>, Arc<Vec<User>>), railscale_db::Error> {
        let current_gen = self.generation.load(Ordering::Acquire);
        let cached_gen = self.cached_generation.load(Ordering::Acquire);

        // fast path: cache is fresh
        if current_gen == cached_gen {
            let guard = self.snapshot.read().await;
            if let Some(ref snap) = *guard {
                return Ok((Arc::clone(&snap.nodes), Arc::clone(&snap.users)));
            }
            // snapshot is None despite generations matching — fall through to rebuild
        }

        // slow path: cache is stale, take write lock and rebuild
        let mut guard = self.snapshot.write().await;

        // double-check: another task may have rebuilt while we waited for the lock
        let current_gen = self.generation.load(Ordering::Acquire);
        if let Some(ref snap) = *guard
            && snap.generation == current_gen
        {
            return Ok((Arc::clone(&snap.nodes), Arc::clone(&snap.users)));
        }

        // rebuild from database
        debug!("map cache: rebuilding snapshot from database");
        let nodes = Arc::new(db.list_nodes().await?);
        let users = Arc::new(db.list_users().await?);

        let snapshot = Snapshot {
            nodes: Arc::clone(&nodes),
            users: Arc::clone(&users),
            generation: current_gen,
        };

        *guard = Some(snapshot);
        self.cached_generation.store(current_gen, Ordering::Release);

        Ok((nodes, users))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_db::Database;

    #[tokio::test]
    async fn cache_returns_data_from_db() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // create a user and node
        let user = User::new(railscale_types::UserId(1), "test-user".to_string());
        db.create_user(&user).await.unwrap();

        let node = railscale_types::test_utils::TestNodeBuilder::new(1)
            .with_node_key(railscale_types::NodeKey::from_bytes(vec![1u8; 32]))
            .build();
        db.create_node(&node).await.unwrap();

        let cache = MapCache::new(None);
        let (nodes, users) = cache.get_snapshot(&db).await.unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(users.len(), 1);
    }

    #[tokio::test]
    async fn cache_returns_same_data_without_invalidation() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let user = User::new(railscale_types::UserId(1), "test-user".to_string());
        db.create_user(&user).await.unwrap();

        let cache = MapCache::new(None);

        // first read
        let (_, users1) = cache.get_snapshot(&db).await.unwrap();
        assert_eq!(users1.len(), 1);

        // add another user directly to DB (without invalidating cache)
        let user2 = User::new(railscale_types::UserId(2), "second-user".to_string());
        db.create_user(&user2).await.unwrap();

        // second read should return cached data (still 1 user)
        let (_, users2) = cache.get_snapshot(&db).await.unwrap();
        assert_eq!(
            users2.len(),
            1,
            "cache should return stale data without invalidation"
        );
    }

    #[tokio::test]
    async fn cache_rebuilds_after_invalidation() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let user = User::new(railscale_types::UserId(1), "test-user".to_string());
        db.create_user(&user).await.unwrap();

        let cache = MapCache::new(None);

        // first read
        let (_, users1) = cache.get_snapshot(&db).await.unwrap();
        assert_eq!(users1.len(), 1);

        // add another user and invalidate
        let user2 = User::new(railscale_types::UserId(2), "second-user".to_string());
        db.create_user(&user2).await.unwrap();
        cache.invalidate();

        // should now see 2 users
        let (_, users2) = cache.get_snapshot(&db).await.unwrap();
        assert_eq!(users2.len(), 2, "cache should rebuild after invalidation");
    }

    #[tokio::test]
    async fn invalidation_increments_generation() {
        let cache = MapCache::new(None);
        let gen1 = cache.generation();
        cache.invalidate();
        let gen2 = cache.generation();
        assert_eq!(gen2, gen1 + 1);
    }

    #[tokio::test]
    async fn dns_config_is_cached() {
        use railscale_proto::DnsConfig;

        let dns = DnsConfig {
            resolvers: vec![],
            domains: vec!["example.com".to_string()],
            routes: std::collections::HashMap::new(),
            cert_domains: vec![],
        };

        let cache = MapCache::new(Some(dns.clone()));
        let cached_dns = cache.dns_config().unwrap();
        assert_eq!(cached_dns.domains, dns.domains);
    }
}
