//! benchmark harness - sets up a railscale server and simulates clients

use std::time::{Duration, Instant};

use axum::{Router, body::Body, http::Request};
use bytes::Buf;
use railscale::StateNotifier;
use railscale_db::{Database, RailscaleDb};
use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
use railscale_proto::{MapRequest, MapResponse};
use railscale_types::{MachineKey, NodeKey, PreAuthKey, PreAuthKeyToken, User, UserId};
use tower::ServiceExt;

/// a registered node that can poll for map responses
pub struct SimNode {
    pub node_key: NodeKey,
    pub machine_key: MachineKey,
    pub hostname: String,
}

/// timing results from a benchmark run
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub scenario: String,
    pub node_count: usize,
    pub durations: Vec<Duration>,
}

impl BenchResult {
    pub fn total(&self) -> Duration {
        self.durations.iter().sum()
    }

    pub fn mean(&self) -> Duration {
        self.total() / self.durations.len() as u32
    }

    pub fn min(&self) -> Duration {
        self.durations.iter().copied().min().unwrap_or_default()
    }

    pub fn max(&self) -> Duration {
        self.durations.iter().copied().max().unwrap_or_default()
    }

    pub fn p50(&self) -> Duration {
        percentile(&self.durations, 50)
    }

    pub fn p95(&self) -> Duration {
        percentile(&self.durations, 95)
    }

    pub fn p99(&self) -> Duration {
        percentile(&self.durations, 99)
    }

    pub fn ops_per_sec(&self) -> f64 {
        let total_secs = self.total().as_secs_f64();
        if total_secs == 0.0 {
            return 0.0;
        }
        self.durations.len() as f64 / total_secs
    }
}

fn percentile(durations: &[Duration], p: usize) -> Duration {
    if durations.is_empty() {
        return Duration::default();
    }
    let mut sorted: Vec<Duration> = durations.to_vec();
    sorted.sort();
    let idx = (p * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}

/// in-process benchmark harness for railscale
///
/// spins up a railscale app with an in-memory database
/// and drives it via tower::ServiceExt (no network)
pub struct Harness {
    db: RailscaleDb,
    app: Router,
    preauth_token: PreAuthKeyToken,
    nodes: Vec<SimNode>,
}

impl Harness {
    /// create a new harness with an in-memory database and wildcard policy
    pub async fn new() -> Self {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let user = User::new(UserId::new(1), "bench-user".to_string());
        let user = db.create_user(&user).await.unwrap();

        // create a reusable preauth key
        let token = PreAuthKeyToken::generate();
        let mut preauth = PreAuthKey::from_token(1, &token, user.id);
        preauth.reusable = true;
        db.create_preauth_key(&preauth).await.unwrap();

        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        let grants = GrantsEngine::new(policy);

        let config = railscale_types::Config {
            allow_non_noise_registration: true,
            ..Default::default()
        };

        let app = railscale::create_app(
            db.clone(),
            grants,
            config,
            None,
            StateNotifier::default(),
            None,
        )
        .await;

        Self {
            db,
            app,
            preauth_token: token,
            nodes: Vec::new(),
        }
    }

    /// register n nodes sequentially, returning per-registration timings
    pub async fn bench_registration(&mut self, n: usize) -> BenchResult {
        let mut durations = Vec::with_capacity(n);

        for i in 0..n {
            let mut node_key_bytes = [0u8; 32];
            let idx_bytes = (i as u64 + 1).to_le_bytes();
            node_key_bytes[..8].copy_from_slice(&idx_bytes);
            let node_key = NodeKey::from_bytes(node_key_bytes);

            let mut machine_key_bytes = [0u8; 32];
            machine_key_bytes[..8].copy_from_slice(&idx_bytes);
            machine_key_bytes[8] = 0xff; // distinguish from node key
            let machine_key = MachineKey::from_bytes(machine_key_bytes);

            let hostname = format!("bench-node-{}", i);

            let request_body = serde_json::json!({
                "Version": 95,
                "NodeKey": node_key,
                "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
                "Auth": {
                    "AuthKey": self.preauth_token.as_str()
                },
                "Hostinfo": {
                    "Hostname": hostname,
                    "OS": "linux",
                    "GoArch": "amd64"
                }
            });

            let start = Instant::now();
            let response = self
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/machine/register")
                        .header("content-type", "application/json")
                        .body(Body::from(request_body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let elapsed = start.elapsed();

            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "registration failed for node {i}"
            );

            durations.push(elapsed);
            self.nodes.push(SimNode {
                node_key,
                machine_key,
                hostname,
            });
        }

        BenchResult {
            scenario: "registration".to_string(),
            node_count: n,
            durations,
        }
    }

    /// poll map for each registered node, returning per-poll timings
    pub async fn bench_map_poll(&self) -> BenchResult {
        let mut durations = Vec::with_capacity(self.nodes.len());

        for sim in &self.nodes {
            let map_request = MapRequest {
                version: railscale_proto::CapabilityVersion::CURRENT,
                node_key: sim.node_key.clone(),
                disco_key: None,
                endpoints: vec![],
                hostinfo: None,
                omit_peers: false,
                stream: false,
                debug_flags: vec![],
                compress: None,
            };

            let start = Instant::now();
            let response = self
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/machine/map")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&map_request).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let elapsed = start.elapsed();

            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "map poll failed for {}",
                sim.hostname
            );

            // verify we got a valid response
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let _map_response = read_map_response(&body).expect("failed to parse map response");

            durations.push(elapsed);
        }

        BenchResult {
            scenario: "map_poll".to_string(),
            node_count: self.nodes.len(),
            durations,
        }
    }

    /// number of currently registered nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// parse a length-prefixed map response
fn read_map_response(buf: &[u8]) -> Option<MapResponse> {
    if buf.len() < 4 {
        return None;
    }
    let len = (&buf[..4]).get_u32_le() as usize;
    if buf.len() < 4 + len {
        return None;
    }
    serde_json::from_slice(&buf[4..4 + len]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn harness_registers_nodes_and_returns_timings() {
        let mut harness = Harness::new().await;
        let result = harness.bench_registration(10).await;

        assert_eq!(result.node_count, 10);
        assert_eq!(result.durations.len(), 10);
        assert_eq!(harness.node_count(), 10);
        // every registration should complete in under 1s (in-process, no network)
        for d in &result.durations {
            assert!(*d < Duration::from_secs(1), "registration too slow: {d:?}");
        }
    }

    #[tokio::test]
    async fn harness_polls_maps_and_returns_timings() {
        let mut harness = Harness::new().await;
        harness.bench_registration(5).await;
        let result = harness.bench_map_poll().await;

        assert_eq!(result.node_count, 5);
        assert_eq!(result.durations.len(), 5);
        // every poll should complete in under 1s
        for d in &result.durations {
            assert!(*d < Duration::from_secs(1), "map poll too slow: {d:?}");
        }
    }

    #[tokio::test]
    async fn bench_result_stats_are_sane() {
        let mut harness = Harness::new().await;
        let result = harness.bench_registration(20).await;

        assert!(result.min() <= result.p50());
        assert!(result.p50() <= result.p95());
        assert!(result.p95() <= result.max());
        assert!(result.ops_per_sec() > 0.0);
    }
}
