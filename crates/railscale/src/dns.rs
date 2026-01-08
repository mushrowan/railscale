//! dns configuration generation for magicdns.

use ipnet::IpNet;
use railscale_proto::DnsConfig;
use railscale_types::Config;
use std::collections::HashMap;

/// generate dns configuration for a client.
pub fn generate_dns_config(config: &Config) -> Option<DnsConfig> {
    if !config.dns.magic_dns {
        return None;
    }

    let mut nameservers = vec!["100.100.100.100".to_string()];
    nameservers.extend(config.dns.nameservers.iter().map(|ip| ip.to_string()));

    let mut domains = vec![config.base_domain.clone()];
    domains.extend(config.dns.search_domains.clone());

    let mut routes = HashMap::new();

    // add base domain route
    routes.insert(
        config.base_domain.clone(),
        vec!["100.100.100.100".to_string()],
    );

    // generate reverse dns routes for ipv4 prefix
    if let Some(prefix_v4) = config.prefix_v4 {
        let v4_routes = generate_ipv4_reverse_dns_routes(prefix_v4);
        for route in v4_routes {
            routes.insert(route, vec!["100.100.100.100".to_string()]);
        }
    }

    // generate reverse dns routes for ipv6 prefix
    if let Some(prefix_v6) = config.prefix_v6 {
        let v6_routes = generate_ipv6_reverse_dns_routes(prefix_v6);
        for route in v6_routes {
            routes.insert(route, vec!["100.100.100.100".to_string()]);
        }
    }

    Some(DnsConfig {
        nameservers,
        domains,
        routes,
    })
}

/// generate ipv4 reverse dns routes (e.g., "64.100.in-addr.arpa.").
///
/// for 100.64.0.0/10, this generates:
/// - 64.100.in-addr.arpa. through 127.100.in-addr.arpa.
fn generate_ipv4_reverse_dns_routes(prefix: IpNet) -> Vec<String> {
    if !prefix.addr().is_ipv4() {
        return vec![];
    }

    let addr = prefix.addr();
    let octets = match addr {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return vec![],
    };

    let prefix_len = prefix.prefix_len();
    let mask_bits = prefix_len as usize;

    // determine which octet we're working with
    let last_octet = mask_bits / 8;
    if last_octet >= 4 {
        return vec![];
    }

    let wildcard_bits = 8 - (mask_bits % 8);
    let min = octets[last_octet] as u32;
    let max = min + (1 << wildcard_bits) - 1;

    let mut routes = Vec::new();

    let mut base_parts: Vec<String> = octets
        .iter()
        .take(last_octet)
        .map(|o| o.to_string())
        .collect();
    base_parts.reverse();

    let base = if base_parts.is_empty() {
        "in-addr.arpa.".to_string()
    } else {
        format!("{}.in-addr.arpa.", base_parts.join("."))
    };

    for i in min..=max {
        routes.push(format!("{}.{}", i, base));
    }

    routes
}

/// generate ipv6 reverse dns routes (e.g., "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.").
///
/// for fd7a:115c:a1e0::/48, this generates the appropriate ip6.arpa entries.
fn generate_ipv6_reverse_dns_routes(prefix: IpNet) -> Vec<String> {
    if !prefix.addr().is_ipv6() {
        return vec![];
    }

    let addr = prefix.addr();
    let segments = match addr {
        std::net::IpAddr::V6(v6) => v6.segments(),
        _ => return vec![],
    };

    let prefix_len = prefix.prefix_len() as usize;
    let nibble_len = 4;
    let mask_bits = prefix_len;

    // convert segments to hex string
    let hex_str = segments
        .iter()
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join("");

    // build the constant part (nibbles covered by the mask)
    let constant_nibbles = mask_bits / nibble_len;
    let mut prefix_parts: Vec<String> = hex_str
        .chars()
        .take(constant_nibbles)
        .map(|c| c.to_string())
        .collect();
    prefix_parts.reverse();

    let base = if prefix_parts.is_empty() {
        "ip6.arpa.".to_string()
    } else {
        format!("{}.ip6.arpa.", prefix_parts.join("."))
    };

    // if mask is aligned to nibble boundary, return single entry
    if mask_bits.is_multiple_of(nibble_len) {
        return vec![base];
    }

    // otherwise, generate entries for the partial nibble
    let var_bits = mask_bits % nibble_len;
    let count = 1 << var_bits;
    let mut routes = Vec::new();

    for i in 0..count {
        let var_nibble = format!("{:x}", i);
        let route = if prefix_parts.is_empty() {
            format!("{}.ip6.arpa.", var_nibble)
        } else {
            format!("{}.{}.ip6.arpa.", var_nibble, prefix_parts.join("."))
        };
        routes.push(route);
    }

    routes
}
