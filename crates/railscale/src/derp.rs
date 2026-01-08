//! derp map generation for relay coordination.

use railscale_proto::{DerpMap, DerpNode, DerpRegion};
use railscale_types::Config;
use std::collections::HashMap;

/// generate the derp map for clients.
pub fn generate_derp_map(config: &Config) -> DerpMap {
    let mut regions = HashMap::new();

    // if embedded derp is enabled, add it to the map
    if config.derp.embedded_derp.enabled {
        let region_id = config.derp.embedded_derp.region_id;
        let host_name = config
            .server_url
            .split("://")
            .nth(1)
            .unwrap_or("localhost")
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_string();

        let region = DerpRegion {
            region_id,
            region_code: "embedded".to_string(),
            region_name: config.derp.embedded_derp.region_name.clone(),
            nodes: vec![DerpNode {
                name: format!("{}a", region_id),
                region_id,
                host_name,
                ipv4: None,
                ipv6: None,
                stun_port: 3478,
                stun_only: false,
                derp_port: 443,
            }],
        };
        regions.insert(region_id, region);
    }

    // if we have no regions, add a default one (e.g., tailscale's new york region)
    // so that nodes can at least communicate via relay if they can't p2p.
    // in a real scenario, we'd probably fetch this from the url in config.
    if regions.is_empty() {
        regions.insert(
            1,
            DerpRegion {
                region_id: 1,
                region_code: "nyc".to_string(),
                region_name: "New York City".to_string(),
                nodes: vec![DerpNode {
                    name: "1a".to_string(),
                    region_id: 1,
                    host_name: "derp1a.tailscale.com".to_string(),
                    ipv4: None,
                    ipv6: None,
                    stun_port: 3478,
                    stun_only: false,
                    derp_port: 443,
                }],
            },
        );
    }

    DerpMap { regions }
}
