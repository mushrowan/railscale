//! dns configuration generation for magicdns.

use ipnet::IpNet;
use railscale_proto::{DnsConfig, DnsResolver};
use railscale_types::Config;
use std::collections::HashMap;

/// the magicdns resolver address.
/// returns `None` if:
/// - Magicdns is disabled, OR
const MAGIC_DNS_RESOLVER: &str = "100.100.100.100";

//if override_local_dns is false, don't override client's dns
//(but we still need routes for tailscale-specific domains)
/// returns `none` if:
/// - MagicDNS is disabled, OR
/// - `override_local_dns` is false (client keeps local DNS settings)
pub fn generate_dns_config(config: &Config) -> Option<DnsConfig> {
    // global resolvers from config (these handle general dns queries)
    if !config.dns.magic_dns {
        return None;
    }

    // if override_local_dns is false, don't override client's dns
    // (but we still need routes for Tailscale-specific domains)
    if !config.dns.override_local_dns {
        return generate_minimal_dns_config(config);
    }

    let magic_resolver = DnsResolver::new(MAGIC_DNS_RESOLVER);

    // route base domain to MagicDNS
    let mut resolvers: Vec<DnsResolver> = config
        .dns
        .nameservers
        .global
        .iter()
        .map(|addr| DnsResolver::new(addr.clone()))
        .collect();

    // add magicdns resolver last (for tailscale-specific lookups)
    resolvers.push(magic_resolver.clone());

    // search domains: base domain first, then any configured search domains
    let mut domains = vec![config.base_domain.clone()];
    domains.extend(config.dns.search_domains.clone());

    // build routes map for split dns
    let mut routes = HashMap::new();

    // route base domain to magicdns
    routes.insert(config.base_domain.clone(), vec![magic_resolver.clone()]);

    // add split dns routes from config
    for (domain, nameservers) in &config.dns.nameservers.split {
        let resolvers: Vec<DnsResolver> = nameservers
            .iter()
            .map(|addr| DnsResolver::new(addr.clone()))
            .collect();
        routes.insert(domain.clone(), resolvers);
    }

    // generate reverse dns routes for ipv4 prefix (for PTR lookups)
    if let Some(prefix_v4) = config.prefix_v4 {
        let v4_routes = generate_ipv4_reverse_dns_routes(prefix_v4);
        for route in v4_routes {
            routes.insert(route, vec![magic_resolver.clone()]);
        }
    }

    // generate reverse dns routes for ipv6 prefix
    if let Some(prefix_v6) = config.prefix_v6 {
        let v6_routes = generate_ipv6_reverse_dns_routes(prefix_v6);
        for route in v6_routes {
            routes.insert(route, vec![magic_resolver.clone()]);
        }
    }

    Some(DnsConfig {
        resolvers,
        domains,
        routes,
        cert_domains: vec![],
    })
}

/// generate minimal dns config when override_local_dns is false.
/// only includes routes for tailscale-specific domains, not global resolvers.
fn generate_minimal_dns_config(config: &Config) -> Option<DnsConfig> {
    let magic_resolver = DnsResolver::new(MAGIC_DNS_RESOLVER);

    let mut routes = HashMap::new();

    // add reverse dns routes
    routes.insert(config.base_domain.clone(), vec![magic_resolver.clone()]);

    // add reverse dns routes
    if let Some(prefix_v4) = config.prefix_v4 {
        for route in generate_ipv4_reverse_dns_routes(prefix_v4) {
            routes.insert(route, vec![magic_resolver.clone()]);
        }
    }
    if let Some(prefix_v6) = config.prefix_v6 {
        for route in generate_ipv6_reverse_dns_routes(prefix_v6) {
            routes.insert(route, vec![magic_resolver.clone()]);
        }
    }

    Some(DnsConfig {
        resolvers: vec![], // empty = don't override client's resolvers
        domains: vec![config.base_domain.clone()],
        routes,
        cert_domains: vec![],
    })
}

/// add cert_domains for a specific node to a cloned dns config.
///
/// when a dns_provider is configured, each node gets its FQDN as a cert domain
/// so `tailscale cert` can provision TLS certificates via ACME dns-01.
///
/// when `wildcard_certs` is true (node has `dns-subdomain-resolve` capability),
/// also adds `*.hostname.base_domain` for wildcard TLS certificate provisioning
pub fn with_cert_domains(
    dns_config: Option<DnsConfig>,
    hostname: &str,
    base_domain: &str,
    has_dns_provider: bool,
    wildcard_certs: bool,
) -> Option<DnsConfig> {
    let mut config = dns_config?;

    if has_dns_provider && !base_domain.is_empty() && !hostname.is_empty() {
        let fqdn = format!("{}.{}", hostname, base_domain);
        config.cert_domains = if wildcard_certs {
            vec![fqdn.clone(), format!("*.{}", fqdn)]
        } else {
            vec![fqdn]
        };
    }

    Some(config)
}

/// generate ipv4 reverse dns routes (e.g., "64.100.in-addr.arpa.").
///
/// for 100.64.0.0/10, this generates:
/// - 64.100.in-addr.arpa. through 127.100.in-addr.arpa.
fn generate_ipv4_reverse_dns_routes(prefix: IpNet) -> Vec<String> {
    let IpNet::V4(v4_prefix) = prefix else {
        return vec![];
    };

    let octets = v4_prefix.addr().octets();
    let prefix_len = v4_prefix.prefix_len();
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
    let IpNet::V6(v6_prefix) = prefix else {
        return vec![];
    };

    let segments = v6_prefix.addr().segments();
    let prefix_len = v6_prefix.prefix_len() as usize;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dns_config() -> DnsConfig {
        DnsConfig {
            resolvers: vec![DnsResolver::new("8.8.8.8")],
            domains: vec!["example.com".into()],
            routes: HashMap::new(),
            cert_domains: vec![],
        }
    }

    #[test]
    fn with_cert_domains_adds_fqdn_when_provider_configured() {
        let config = with_cert_domains(
            Some(sample_dns_config()),
            "myhost",
            "example.com",
            true,
            false,
        );
        let config = config.unwrap();
        assert_eq!(config.cert_domains, vec!["myhost.example.com"]);
    }

    #[test]
    fn with_cert_domains_empty_when_no_provider() {
        let config = with_cert_domains(
            Some(sample_dns_config()),
            "myhost",
            "example.com",
            false,
            false,
        );
        let config = config.unwrap();
        assert!(config.cert_domains.is_empty());
    }

    #[test]
    fn with_cert_domains_none_passthrough() {
        let config = with_cert_domains(None, "myhost", "example.com", true, false);
        assert!(config.is_none());
    }

    #[test]
    fn with_cert_domains_empty_base_domain() {
        let config = with_cert_domains(Some(sample_dns_config()), "myhost", "", true, false);
        let config = config.unwrap();
        assert!(config.cert_domains.is_empty());
    }

    #[test]
    fn with_cert_domains_empty_hostname() {
        let config = with_cert_domains(Some(sample_dns_config()), "", "example.com", true, false);
        let config = config.unwrap();
        assert!(config.cert_domains.is_empty());
    }

    #[test]
    fn with_cert_domains_wildcard_adds_both() {
        let config = with_cert_domains(
            Some(sample_dns_config()),
            "myhost",
            "example.com",
            true,
            true,
        );
        let config = config.unwrap();
        assert_eq!(
            config.cert_domains,
            vec!["myhost.example.com", "*.myhost.example.com"]
        );
    }

    #[test]
    fn with_cert_domains_wildcard_false_only_adds_fqdn() {
        let config = with_cert_domains(
            Some(sample_dns_config()),
            "myhost",
            "example.com",
            true,
            false,
        );
        let config = config.unwrap();
        assert_eq!(config.cert_domains, vec!["myhost.example.com"]);
    }
}
