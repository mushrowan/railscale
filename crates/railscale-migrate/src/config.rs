//! convert headscale config.yaml to railscale config

use std::collections::HashMap;

use serde::Deserialize;

use railscale_types::Config;

/// headscale config.yaml (subset of fields we care about)
#[derive(Debug, Deserialize)]
pub struct HeadscaleConfig {
    pub server_url: String,

    #[serde(default)]
    pub prefixes: HeadscalePrefixes,

    #[serde(default)]
    pub dns: HeadscaleDns,

    #[serde(default)]
    pub oidc: Option<HeadscaleOidc>,

    #[serde(default)]
    pub derp: HeadscaleDerp,
}

#[derive(Debug, Default, Deserialize)]
pub struct HeadscalePrefixes {
    pub v4: Option<String>,
    pub v6: Option<String>,
    #[serde(default)]
    pub allocation: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HeadscaleDns {
    #[serde(default)]
    pub magic_dns: bool,
    #[serde(default)]
    pub base_domain: Option<String>,
    #[serde(default)]
    pub override_local_dns: bool,
    #[serde(default)]
    pub nameservers: HeadscaleNameservers,
    #[serde(default)]
    pub search_domains: Vec<String>,
    #[serde(default)]
    pub extra_records: Vec<HeadscaleExtraRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HeadscaleNameservers {
    #[serde(default)]
    pub global: Vec<String>,
    #[serde(default)]
    pub split: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct HeadscaleExtraRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct HeadscaleOidc {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub extra_params: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HeadscaleDerp {
    #[serde(default)]
    pub urls: Vec<String>,
}

/// convert headscale config to railscale config
///
/// produces a config with sensible defaults filled in. the caller
/// will still need to set secrets (oidc client_secret, noise key)
pub fn convert_config(hs: &HeadscaleConfig) -> Config {
    let mut cfg = Config::default();

    cfg.server_url = hs.server_url.clone();

    if let Some(ref v4) = hs.prefixes.v4 {
        cfg.prefix_v4 = v4.parse().ok();
    }
    if let Some(ref v6) = hs.prefixes.v6 {
        cfg.prefix_v6 = v6.parse().ok();
    }
    if let Some(ref alloc) = hs.prefixes.allocation {
        cfg.ip_allocation = alloc.parse().unwrap_or_default();
    }

    // dns
    if let Some(ref domain) = hs.dns.base_domain {
        cfg.base_domain = domain.clone();
    }
    cfg.dns.magic_dns = hs.dns.magic_dns;
    cfg.dns.override_local_dns = hs.dns.override_local_dns;
    cfg.dns.nameservers.global = hs.dns.nameservers.global.clone();
    cfg.dns.nameservers.split = hs.dns.nameservers.split.clone();
    cfg.dns.search_domains = hs.dns.search_domains.clone();
    cfg.dns.extra_records = hs
        .dns
        .extra_records
        .iter()
        .map(|r| railscale_types::DnsRecord {
            name: r.name.clone(),
            record_type: r.record_type.clone(),
            value: r.value.clone(),
        })
        .collect();

    // derp - headscale uses a list of urls, railscale uses a single url
    if let Some(url) = hs.derp.urls.first() {
        cfg.derp.derp_map_url = Some(url.clone());
    }

    // OidcConfig contains SecretString (no Default), so we round-trip
    // through serde to get defaults for fields we don't set (client_secret,
    // pkce, expiry_secs, etc). the caller sets the actual secret afterwards
    cfg.oidc = hs.oidc.as_ref().map(|o| {
        serde_json::from_value(serde_json::json!({
            "issuer": o.issuer,
            "client_id": o.client_id,
            "scope": o.scope,
            "allowed_domains": o.allowed_domains,
            "allowed_users": o.allowed_users,
            "allowed_groups": o.allowed_groups,
            "extra_params": o.extra_params,
        }))
        .expect("oidc config should be valid")
    });

    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::AllocationStrategy;

    fn sample_config() -> HeadscaleConfig {
        serde_json::from_value(serde_json::json!({
            "server_url": "https://vpn.example.com",
            "prefixes": {
                "v4": "100.64.0.0/10",
                "v6": "fd7a:115c:a1e0::/48",
                "allocation": "sequential"
            },
            "dns": {
                "magic_dns": true,
                "base_domain": "example.internal",
                "override_local_dns": true,
                "nameservers": {
                    "global": ["1.1.1.1", "1.0.0.1"]
                },
                "search_domains": [],
                "extra_records": [
                    {"name": "gpu-box", "type": "A", "value": "100.64.0.9"}
                ]
            },
            "oidc": {
                "issuer": "https://accounts.google.com",
                "client_id": "123456.apps.googleusercontent.com",
                "scope": ["openid", "profile", "email"],
                "allowed_domains": ["example.com"],
                "extra_params": {"domain_hint": "example.com"}
            },
            "derp": {
                "urls": ["https://controlplane.tailscale.com/derpmap/default"]
            }
        }))
        .unwrap()
    }

    #[test]
    fn convert_server_url() {
        let hs = sample_config();
        let cfg = convert_config(&hs);
        assert_eq!(cfg.server_url, "https://vpn.example.com");
    }

    #[test]
    fn convert_prefixes() {
        let hs = sample_config();
        let cfg = convert_config(&hs);
        assert_eq!(cfg.prefix_v4.unwrap().to_string(), "100.64.0.0/10");
        assert_eq!(cfg.prefix_v6.unwrap().to_string(), "fd7a:115c:a1e0::/48");
        assert_eq!(cfg.ip_allocation, AllocationStrategy::Sequential);
    }

    #[test]
    fn convert_dns() {
        let hs = sample_config();
        let cfg = convert_config(&hs);
        assert_eq!(cfg.base_domain, "example.internal");
        assert!(cfg.dns.magic_dns);
        assert!(cfg.dns.override_local_dns);
        assert_eq!(cfg.dns.nameservers.global, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(cfg.dns.extra_records.len(), 1);
        assert_eq!(cfg.dns.extra_records[0].name, "gpu-box");
    }

    #[test]
    fn convert_oidc() {
        let hs = sample_config();
        let cfg = convert_config(&hs);
        let oidc = cfg.oidc.unwrap();
        assert_eq!(oidc.issuer, "https://accounts.google.com");
        assert_eq!(oidc.client_id, "123456.apps.googleusercontent.com");
        assert_eq!(oidc.scope, vec!["openid", "profile", "email"]);
        assert_eq!(oidc.allowed_domains, vec!["example.com"]);
        assert_eq!(oidc.extra_params.get("domain_hint").unwrap(), "example.com");
    }

    #[test]
    fn convert_no_oidc() {
        let hs: HeadscaleConfig = serde_json::from_value(serde_json::json!({
            "server_url": "https://vpn.example.com"
        }))
        .unwrap();
        let cfg = convert_config(&hs);
        assert!(cfg.oidc.is_none());
    }

    #[test]
    fn convert_derp_url_preserved() {
        let hs = sample_config();
        let cfg = convert_config(&hs);
        assert_eq!(
            cfg.derp.derp_map_url.as_deref(),
            Some("https://controlplane.tailscale.com/derpmap/default")
        );
    }
}
