//! ephemeral node garbage collection.
//!
//! automatically deletes ephemeral nodes after they disconnect and remain
//! inactive for a configurable timeout period.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use railscale_db::{Database, IpAllocator, RailscaleDb};
use railscale_types::NodeId;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// garbage collector for ephemeral nodes.
///
/// tracks disconnected ephemeral nodes and deletes them after
/// the configured inactivity timeout.
#[derive(Clone)]
pub struct EphemeralGarbageCollector {
    /// scheduled deletions: node_id -> time when node should be deleted.
    scheduled: Arc<RwLock<HashMap<NodeId, DateTime<Utc>>>>,
    /// database for deleting nodes.
    db: RailscaleDb,
    /// ip allocator for releasing addresses on deletion.
    ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    /// inactivity timeout before deletion.
    timeout: Duration,
}

impl EphemeralGarbageCollector {
    /// create a new garbage collector.
    ///
    /// # Arguments
    /// * `db` - database connection for node operations
    /// * `timeout_secs` - seconds of inactivity before ephemeral nodes are deleted
    ///
    /// if `timeout_secs` is 0, garbage collection is disabled.
    pub fn new(db: RailscaleDb, timeout_secs: u64) -> Self {
        Self {
            scheduled: Arc::new(RwLock::new(HashMap::new())),
            db,
            ip_allocator: None,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// set the ip allocator for releasing addresses on node deletion.
    pub fn with_ip_allocator(mut self, allocator: Arc<Mutex<IpAllocator>>) -> Self {
        self.ip_allocator = Some(allocator);
        self
    }

    /// check if garbage collection is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.timeout.is_zero()
    }

    /// schedule an ephemeral node for deletion.
    ///
    /// the node will be deleted after the configured timeout unless
    /// `cancel_deletion` is called first.
    pub async fn schedule_deletion(&self, node_id: NodeId) {
        if !self.is_enabled() {
            return;
        }

        let delete_at = Utc::now() + chrono::Duration::from_std(self.timeout).unwrap();
        debug!(
            ?node_id,
            ?delete_at,
            "scheduling ephemeral node for deletion"
        );

        let mut scheduled = self.scheduled.write().await;
        scheduled.insert(node_id, delete_at);
    }

    /// cancel a scheduled deletion (node reconnected).
    pub async fn cancel_deletion(&self, node_id: NodeId) {
        let mut scheduled = self.scheduled.write().await;
        if scheduled.remove(&node_id).is_some() {
            debug!(?node_id, "cancelled scheduled deletion for ephemeral node");
        }
    }

    /// get the number of nodes scheduled for deletion.
    pub async fn scheduled_count(&self) -> usize {
        let scheduled = self.scheduled.read().await;
        scheduled.len()
    }

    /// run one garbage collection cycle.
    ///
    /// checks all scheduled nodes and deletes any that have exceeded
    /// the timeout. returns the number of nodes deleted.
    pub async fn collect(&self) -> usize {
        if !self.is_enabled() {
            return 0;
        }

        let now = Utc::now();
        let mut to_delete = Vec::new();

        // find expired nodes
        {
            let scheduled = self.scheduled.read().await;
            for (&node_id, &delete_at) in scheduled.iter() {
                if now >= delete_at {
                    to_delete.push(node_id);
                }
            }
        }

        // delete expired nodes
        let mut deleted = 0;
        for node_id in to_delete {
            // remove from scheduled first to avoid race conditions
            {
                let mut scheduled = self.scheduled.write().await;
                scheduled.remove(&node_id);
            }

            // fetch node to get IPs before deletion
            let node_ips: Vec<IpAddr> = match self.db.get_node(node_id).await {
                Ok(Some(n)) => {
                    let mut ips = Vec::new();
                    if let Some(v4) = n.ipv4 {
                        ips.push(v4);
                    }
                    if let Some(v6) = n.ipv6 {
                        ips.push(v6);
                    }
                    ips
                }
                _ => Vec::new(),
            };

            // delete from database
            match self.db.delete_node(node_id).await {
                Ok(()) => {
                    // release IPs back to the pool
                    if let Some(ref allocator) = self.ip_allocator {
                        let mut alloc = allocator.lock().await;
                        for ip in &node_ips {
                            alloc.release(*ip);
                        }
                    }
                    info!(?node_id, "deleted inactive ephemeral node");
                    deleted += 1;
                }
                Err(e) => {
                    warn!(?node_id, error = %e, "failed to delete ephemeral node");
                }
            }
        }

        deleted
    }

    /// spawn the background garbage collection task.
    ///
    /// runs collection every `interval` and continues until the
    /// returned handle is dropped.
    pub fn spawn_collector(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if !self.is_enabled() {
                debug!("ephemeral garbage collector disabled (timeout = 0)");
                return;
            }

            info!(
                timeout_secs = self.timeout.as_secs(),
                interval_secs = interval.as_secs(),
                "starting ephemeral garbage collector"
            );

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                let deleted = self.collect().await;
                if deleted > 0 {
                    debug!(deleted, "garbage collection cycle completed");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_db::{Database, RailscaleDb};
    use railscale_types::test_utils::TestNodeBuilder;
    use railscale_types::{User, UserId};

    async fn setup_test_db() -> RailscaleDb {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    #[tokio::test]
    async fn test_schedule_and_cancel() {
        let db = setup_test_db().await;
        let gc = EphemeralGarbageCollector::new(db, 60);

        assert!(gc.is_enabled());
        assert_eq!(gc.scheduled_count().await, 0);

        // schedule deletion
        gc.schedule_deletion(NodeId(1)).await;
        assert_eq!(gc.scheduled_count().await, 1);

        gc.schedule_deletion(NodeId(2)).await;
        assert_eq!(gc.scheduled_count().await, 2);

        // cancel one
        gc.cancel_deletion(NodeId(1)).await;
        assert_eq!(gc.scheduled_count().await, 1);

        // cancel non-existent (should be no-op)
        gc.cancel_deletion(NodeId(999)).await;
        assert_eq!(gc.scheduled_count().await, 1);
    }

    #[tokio::test]
    async fn test_disabled_when_timeout_zero() {
        let db = setup_test_db().await;
        let gc = EphemeralGarbageCollector::new(db, 0);

        assert!(!gc.is_enabled());

        // schedule should be no-op when disabled
        gc.schedule_deletion(NodeId(1)).await;
        assert_eq!(gc.scheduled_count().await, 0);

        // collect should return 0 when disabled
        assert_eq!(gc.collect().await, 0);
    }

    #[tokio::test]
    async fn test_collect_deletes_expired_nodes() {
        let db = setup_test_db().await;

        // create user and ephemeral node
        let user = User::new(UserId(0), "test@example.com".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node = TestNodeBuilder::new(1)
            .with_user_id(user.id)
            .ephemeral()
            .build();
        let node = db.create_node(&node).await.unwrap();

        // create gc with 1 second timeout
        let gc = EphemeralGarbageCollector::new(db.clone(), 1);

        // schedule deletion
        gc.schedule_deletion(node.id).await;
        assert_eq!(gc.scheduled_count().await, 1);

        // collect immediately - should not delete (not expired yet)
        assert_eq!(gc.collect().await, 0);
        assert_eq!(gc.scheduled_count().await, 1);
        assert!(db.get_node(node.id).await.unwrap().is_some());

        // wait for timeout
        tokio::time::sleep(Duration::from_secs(2)).await;

        // now collect should delete
        assert_eq!(gc.collect().await, 1);
        assert_eq!(gc.scheduled_count().await, 0);
        assert!(db.get_node(node.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cancel_prevents_deletion() {
        let db = setup_test_db().await;

        // create user and ephemeral node
        let user = User::new(UserId(0), "test@example.com".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node = TestNodeBuilder::new(1)
            .with_user_id(user.id)
            .ephemeral()
            .build();
        let node = db.create_node(&node).await.unwrap();

        // create gc with 1 second timeout
        let gc = EphemeralGarbageCollector::new(db.clone(), 1);

        // schedule deletion
        gc.schedule_deletion(node.id).await;
        assert_eq!(gc.scheduled_count().await, 1);

        // wait a bit then cancel (simulating reconnect)
        tokio::time::sleep(Duration::from_millis(500)).await;
        gc.cancel_deletion(node.id).await;
        assert_eq!(gc.scheduled_count().await, 0);

        // wait past timeout
        tokio::time::sleep(Duration::from_secs(1)).await;

        // collect should not delete (was cancelled)
        assert_eq!(gc.collect().await, 0);
        assert!(db.get_node(node.id).await.unwrap().is_some());
    }
}
