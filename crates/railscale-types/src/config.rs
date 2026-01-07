//! configuration types for railscale

use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// main configuration for railscale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// server address to listen on.
    pub server_url: String,

    /// address to bind the http server to.
    pub listen_addr: String,

    /// path to the noise protocol private key file.
    pub noise_private_key_path: PathBuf,

    /// ipv4 prefix for node address allocation.
    pub prefix_v4: Option<IpNet>,

    /// ipv6 prefix for node address allocation.
    pub prefix_v6: Option<IpNet>,

    /// base domain for magicdns.
    pub base_domain: String,

    /// database configuration.
    pub database: DatabaseConfig,

    /// derp configuration.
    pub derp: DerpConfig,

    /// dns configuration.
    pub dns: DnsConfig,

    /// oidc configuration (optional).
    pub oidc: Option<OidcConfig>,

    /// performance tuning options.
    pub tuning: TuningConfig,

    /// enable taildrop file sharing.
    pub taildrop_enabled: bool,

    /// randomize client port (for nat traversal).
    pub randomize_client_port: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            listen_addr: "0.0.0.0:8080".to_string(),
            noise_private_key_path: PathBuf::from("/var/lib/railscale/noise_private.key"),
            prefix_v4: Some("100.64.0.0/10".parse().unwrap()),
            prefix_v6: Some("fd7a:115c:a1e0::/48".parse().unwrap()),
            base_domain: "railscale.net".to_string(),
            database: DatabaseConfig::default(),
            derp: DerpConfig::default(),
            dns: DnsConfig::default(),
            oidc: None,
            tuning: TuningConfig::default(),
            taildrop_enabled: true,
            randomize_client_port: false,
        }
    }
}

/// database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// database type: "sqlite" or "postgres".
    pub db_type: String,

    /// database connection string or file path.
    pub connection_string: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            db_type: "sqlite".to_string(),
            connection_string: "/var/lib/railscale/db.sqlite".to_string(),
        }
    }
}

/// derp (relay) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpConfig {
    /// url to fetch the derp map from.
    pub derp_map_url: Option<String>,

    /// path to a local derp map file.
    pub derp_map_path: Option<PathBuf>,

    /// whether to run an embedded derp server.
    pub embedded_derp: EmbeddedDerpConfig,

    /// how often to update the derp map (in seconds).
    pub update_frequency_secs: u64,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            derp_map_url: Some("https://controlplane.tailscale.com/derpmap/default".to_string()),
            derp_map_path: None,
            embedded_derp: EmbeddedDerpConfig::default(),
            update_frequency_secs: 3600,
        }
    }
}

/// embedded derp server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedDerpConfig {
    /// whether to enable the embedded derp server.
    pub enabled: bool,

    /// region id for the embedded derp server.
    pub region_id: i32,

    /// region name.
    pub region_name: String,

    /// stun listen address.
    pub stun_listen_addr: Option<String>,
}

impl Default for EmbeddedDerpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region_id: 999,
            region_name: "railscale".to_string(),
            stun_listen_addr: Some("0.0.0.0:3478".to_string()),
        }
    }
}

/// dns configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// enable magicdns.
    pub magic_dns: bool,

    /// nameservers to use.
    pub nameservers: Vec<IpAddr>,

    /// search domains.
    pub search_domains: Vec<String>,

    /// extra dns records.
    pub extra_records: Vec<DnsRecord>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            magic_dns: true,
            nameservers: vec![],
            search_domains: vec![],
            extra_records: vec![],
        }
    }
}

/// a dns record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// record name.
    pub name: String,
    /// record type (a, aaaa, cname, etc.).
    pub record_type: String,
    /// record value.
    pub value: String,
}

/// oidc configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// oidc issuer url.
    pub issuer: String,

    /// client id.
    pub client_id: String,

    /// client secret.
    pub client_secret: String,

    /// scopes to request.
    pub scope: Vec<String>,

    /// whether email must be verified.
    pub email_verified_required: bool,
}

/// performance tuning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningConfig {
    /// nodestore batch size for write operations.
    pub node_store_batch_size: usize,

    /// nodestore batch timeout in milliseconds.
    pub node_store_batch_timeout_ms: u64,

    /// registration cache expiration in seconds.
    pub register_cache_expiration_secs: u64,

    /// registration cache cleanup interval in seconds.
    pub register_cache_cleanup_secs: u64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            node_store_batch_size: 100,
            node_store_batch_timeout_ms: 500,
            register_cache_expiration_secs: 900,  // 15 minutes
            register_cache_cleanup_secs: 1200,    // 20 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.database.db_type, "sqlite");
        assert!(config.prefix_v4.is_some());
        assert!(config.prefix_v6.is_some());
    }
}
