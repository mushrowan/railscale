//! dns challenge record garbage collection
//!
//! periodically removes stale ACME dns-01 TXT records from DNS
//! and deletes the corresponding database entries

use std::sync::Arc;
use std::time::Duration;

use railscale_db::{Database, RailscaleDb};
use tracing::{debug, info, warn};

use crate::dns_provider::DnsProviderBoxed;

/// garbage collector for stale dns challenge records
#[derive(Clone)]
pub struct DnsChallengeGarbageCollector {
    db: RailscaleDb,
    provider: Arc<dyn DnsProviderBoxed>,
    /// max age before a record is considered stale
    max_age: chrono::Duration,
}

impl DnsChallengeGarbageCollector {
    /// create a new collector
    ///
    /// `max_age_secs` is how old a challenge record must be before cleanup
    pub fn new(db: RailscaleDb, provider: Arc<dyn DnsProviderBoxed>, max_age_secs: u64) -> Self {
        Self {
            db,
            provider,
            max_age: chrono::Duration::seconds(max_age_secs as i64),
        }
    }

    /// run one garbage collection cycle
    ///
    /// finds all challenge records older than max_age, removes TXT records
    /// from DNS, and deletes the DB entries. returns the number cleaned up.
    pub async fn collect(&self) -> usize {
        let stale = match self.db.list_stale_dns_challenge_records(self.max_age).await {
            Ok(records) => records,
            Err(e) => {
                warn!(error = %e, "failed to query stale dns challenge records");
                return 0;
            }
        };

        if stale.is_empty() {
            return 0;
        }

        debug!(count = stale.len(), "found stale dns challenge records");

        let mut cleaned = 0;
        for record in stale {
            // best-effort DNS cleanup — don't block on provider failures
            if let Err(e) = self
                .provider
                .clear_txt_record(record.record_name.clone(), record.record_id.clone())
                .await
            {
                warn!(
                    record_id = %record.record_id,
                    record_name = %record.record_name,
                    error = %e,
                    "failed to clear stale TXT record from DNS provider"
                );
            }

            // delete from DB regardless of provider result
            match self.db.delete_dns_challenge_record(record.id).await {
                Ok(()) => {
                    cleaned += 1;
                    debug!(
                        record_id = %record.record_id,
                        record_name = %record.record_name,
                        "cleaned up stale dns challenge record"
                    );
                }
                Err(e) => {
                    warn!(
                        id = record.id,
                        error = %e,
                        "failed to delete stale dns challenge record from DB"
                    );
                }
            }
        }

        if cleaned > 0 {
            info!(cleaned, "dns challenge garbage collection completed");
        }

        cleaned
    }

    /// spawn the background collection task
    ///
    /// runs every `interval`, cleaning up stale challenge records
    pub fn spawn_collector(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                max_age_secs = self.max_age.num_seconds(),
                interval_secs = interval.as_secs(),
                "starting dns challenge garbage collector"
            );

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                self.collect().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_db::DnsChallengeRecord;
    use railscale_types::test_utils::TestNodeBuilder;
    use railscale_types::{NodeKey, User, UserId};

    /// mock dns provider that tracks calls
    #[derive(Default)]
    struct MockDnsProvider {
        cleared: tokio::sync::Mutex<Vec<(String, String)>>,
    }

    impl crate::dns_provider::DnsProvider for MockDnsProvider {
        fn set_txt_record(
            &self,
            _name: String,
            _value: String,
        ) -> impl std::future::Future<
            Output = Result<String, crate::dns_provider::DnsProviderError>,
        > + Send {
            async { Ok("mock-id".to_string()) }
        }

        fn clear_txt_record(
            &self,
            name: String,
            record_id: String,
        ) -> impl std::future::Future<Output = Result<(), crate::dns_provider::DnsProviderError>> + Send
        {
            async move {
                self.cleared.lock().await.push((name, record_id));
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_collect_removes_stale_records() {
        let db = RailscaleDb::new_in_memory().await.unwrap();

        // create user + node
        let user = User::new(UserId(0), "alice".into());
        let user = db.create_user(&user).await.unwrap();
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(NodeKey::from_bytes(vec![1; 32]))
            .build();
        let node = db.create_node(&node).await.unwrap();

        // insert a challenge record with a past timestamp
        let old_record = DnsChallengeRecord {
            id: 0,
            node_id: node.id,
            record_name: "_acme-challenge.old.example.com".to_string(),
            record_id: "old-record-id".to_string(),
            created_at: chrono::Utc::now() - chrono::Duration::minutes(20),
        };
        db.create_dns_challenge_record(&old_record).await.unwrap();

        // insert a fresh record
        let fresh_record = DnsChallengeRecord {
            id: 0,
            node_id: node.id,
            record_name: "_acme-challenge.fresh.example.com".to_string(),
            record_id: "fresh-record-id".to_string(),
            created_at: chrono::Utc::now(),
        };
        db.create_dns_challenge_record(&fresh_record).await.unwrap();

        let provider = Arc::new(MockDnsProvider::default());
        // max age = 10 minutes — old record is 20 min old (stale), fresh is 0 (not stale)
        let gc = DnsChallengeGarbageCollector::new(db.clone(), provider.clone(), 600);

        let cleaned = gc.collect().await;
        assert_eq!(cleaned, 1, "should clean up exactly the stale record");

        // verify provider was called to clear the old record
        let cleared = provider.cleared.lock().await;
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].0, "_acme-challenge.old.example.com");
        assert_eq!(cleared[0].1, "old-record-id");

        // verify fresh record still exists
        let remaining = db
            .list_dns_challenge_records_for_node(node.id)
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].record_name,
            "_acme-challenge.fresh.example.com"
        );
    }

    #[tokio::test]
    async fn test_collect_no_stale_records() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        let provider = Arc::new(MockDnsProvider::default());
        let gc = DnsChallengeGarbageCollector::new(db, provider.clone(), 600);

        let cleaned = gc.collect().await;
        assert_eq!(cleaned, 0);

        let cleared = provider.cleared.lock().await;
        assert!(cleared.is_empty());
    }
}
