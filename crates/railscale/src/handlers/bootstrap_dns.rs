//! bootstrap dns endpoint handler.
//!
//! # security considerations
//!
//! this endpoint is unauthenticated by design (clients need dns before they can
//! authenticate). to mitigate abuse:
//!
//! - dns lookups have a 5-second timeout to prevent slow loris attacks
//! - results are cached for 60 seconds to avoid repeated lookups
//! - concurrent resolution is capped to prevent dns amplification
//! - only hostnames from the configured derp map are resolved (not arbitrary input)
//!
//! for additional protection, restrict this endpoint at the network layer.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use axum::{Json, extract::State};
use futures_util::stream::StreamExt;
use tokio::net::lookup_host;
use tokio::time::timeout;

use crate::AppState;

/// dns lookup timeout - prevents slow dns servers from blocking requests
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// max concurrent dns lookups - prevents dns amplification
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// get /bootstrap-dns - resolve derp hostnames for dns fallback.
///
/// returns a map of derp hostnames to their resolved ip addresses.
/// clients use this when their local dns is broken to bootstrap
/// connections to DERP relay servers.
///
/// results are cached for 60 seconds. concurrent lookups are performed
/// with a 5-second timeout per hostname
pub async fn bootstrap_dns(State(state): State<AppState>) -> Json<HashMap<String, Vec<IpAddr>>> {
    let mut dns_map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    // get current derp map and collect unique hostnames
    let hostnames: HashSet<String> = {
        let derp_map = state.derp_map.read().await;
        derp_map
            .regions
            .values()
            .flat_map(|region| region.nodes.iter())
            .map(|node| node.host_name.clone())
            .collect()
    };

    // check cache first, collect hostnames that need resolution
    let mut to_resolve = Vec::new();
    for hostname in &hostnames {
        if let Some(ips) = state.dns_cache.get(hostname) {
            dns_map.insert(hostname.clone(), ips);
        } else {
            to_resolve.push(hostname.clone());
        }
    }

    // resolve uncached hostnames with bounded concurrency
    if !to_resolve.is_empty() {
        let results: Vec<_> = futures_util::stream::iter(to_resolve)
            .map(|hostname| async move {
                let addr_str = format!("{}:0", hostname);
                let result = timeout(DNS_LOOKUP_TIMEOUT, lookup_host(&addr_str)).await;

                // process result immediately to avoid lifetime issues
                let ips: Option<Vec<IpAddr>> = match result {
                    Ok(Ok(addrs)) => {
                        let ips: Vec<IpAddr> =
                            addrs.map(|addr: std::net::SocketAddr| addr.ip()).collect();
                        if ips.is_empty() { None } else { Some(ips) }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(hostname = %hostname, error = %e, "dns lookup failed");
                        None
                    }
                    Err(_) => {
                        tracing::debug!(hostname = %hostname, "dns lookup timed out");
                        None
                    }
                };
                (hostname, ips)
            })
            .buffer_unordered(MAX_CONCURRENT_LOOKUPS)
            .collect()
            .await;

        for (hostname, ips) in results {
            if let Some(ips) = ips {
                // cache the result
                state.dns_cache.insert(hostname.clone(), ips.clone());
                dns_map.insert(hostname, ips);
            }
        }
    }

    Json(dns_map)
}
