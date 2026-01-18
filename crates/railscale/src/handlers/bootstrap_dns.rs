//! bootstrap dns endpoint handler
//!
//! this endpoint provides dns resolution fallback for clients whose local dns
//! is broken, allowing them to bootstrap derp connections by directly connecting
//! to the control server's IP and resolving derp hostnames

use std::collections::HashMap;
use std::net::IpAddr;

use axum::{Json, extract::State};
use tokio::net::lookup_host;

use crate::AppState;

/// gET /bootstrap-dns - Resolve derp hostnames for dns fallback
///
/// returns a map of derp hostnames to their resolved ips
/// clients use this when their local dns is broken to bootstrap
/// connections to derp relay servers
pub async fn bootstrap_dns(State(state): State<AppState>) -> Json<HashMap<String, Vec<IpAddr>>> {
    let mut dns_map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    // get current derp map
    let derp_map = state.derp_map.read().await;

    // collect all unique hostnames from derp nodes
    let hostnames: Vec<String> = derp_map
        .regions
        .values()
        .flat_map(|region| region.nodes.iter())
        .map(|node| node.host_name.clone())
        .collect();

    // resolve each hostname
    for hostname in hostnames {
        if dns_map.contains_key(&hostname) {
            continue; // Already resolved
        }

        // try to resolve the hostname
        let addr_str = format!("{}:0", hostname);
        match lookup_host(&addr_str).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                if !ips.is_empty() {
                    dns_map.insert(hostname, ips);
                }
            }
            Err(e) => {
                tracing::debug!(hostname = %hostname, error = %e, "failed to resolve DERP hostname");
            }
        }
    }

    Json(dns_map)
}
