//! configuration types for railscale.

use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// main configuration for railscale.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

    /// rest api configuration.
    pub api: ApiConfig,

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
            api: ApiConfig::default(),
            taildrop_enabled: true,
            randomize_client_port: false,
        }
    }
}

/// database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
pub struct EmbeddedDerpConfig {
    /// whether to enable the embedded derp server.
    pub enabled: bool,

    /// region id for the embedded derp server.
    pub region_id: i32,

    /// region name.
    pub region_name: String,

    /// address to bind the derp https listener to.
    #[serde(default = "default_derp_listen_addr")]
    pub listen_addr: String,

    /// hostname or ip advertised to clients. defaults to the server url host.
    #[serde(default)]
    pub advertise_host: Option<String>,

    /// port advertised to clients. defaults to the parsed listen port.
    #[serde(default)]
    pub advertise_port: Option<u16>,

    /// path to the derp certificate (pem).
    #[serde(default = "default_derp_cert_path")]
    pub cert_path: PathBuf,

    /// path to the derp tls private key (pem).
    #[serde(default = "default_derp_tls_key_path")]
    pub tls_key_path: PathBuf,

    /// path to the derp protocol private key (curve25519, 64 bytes).
    #[serde(default = "default_derp_private_key_path")]
    pub private_key_path: PathBuf,

    /// stun listen address.
    pub stun_listen_addr: Option<String>,

    /// runtime details populated when the derp server starts.
    #[serde(skip)]
    pub runtime: Option<EmbeddedDerpRuntime>,
}

impl Default for EmbeddedDerpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region_id: 999,
            region_name: "railscale".to_string(),
            listen_addr: default_derp_listen_addr(),
            advertise_host: None,
            advertise_port: None,
            cert_path: default_derp_cert_path(),
            tls_key_path: default_derp_tls_key_path(),
            private_key_path: default_derp_private_key_path(),
            stun_listen_addr: Some("0.0.0.0:3478".to_string()),
            runtime: None,
        }
    }
}

fn default_derp_listen_addr() -> String {
    "0.0.0.0:3340".to_string()
}

fn default_derp_cert_path() -> PathBuf {
    PathBuf::from("/var/lib/railscale/derp_cert.pem")
}

fn default_derp_tls_key_path() -> PathBuf {
    PathBuf::from("/var/lib/railscale/derp_tls_key.pem")
}

fn default_derp_private_key_path() -> PathBuf {
    PathBuf::from("/var/lib/railscale/derp_private.key")
}

/// runtime information for the embedded derp server populated at startup.
#[derive(Debug, Clone)]
pub struct EmbeddedDerpRuntime {
    /// the hostname to advertise to clients for this derp server.
    pub advertise_host: String,
    /// the port to advertise to clients.
    pub advertise_port: u16,
    /// sha-256 fingerprint of the tls certificate (hex-encoded).
    pub cert_fingerprint: String,
}

/// dns configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// enable magicdns.
    pub magic_dns: bool,

    /// override local dns settings on clients.
    /// when true, forces clients to use railscale's dns config.
    /// when false, clients keep their local dns settings.
    pub override_local_dns: bool,

    /// nameservers configuration (global and split dns).
    pub nameservers: Nameservers,

    /// search domains.
    pub search_domains: Vec<String>,

    /// extra dns records.
    pub extra_records: Vec<DnsRecord>,
}

fn default_true() -> bool {
    true
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            magic_dns: true,
            override_local_dns: true,
            nameservers: Nameservers::default(),
            search_domains: vec![],
            extra_records: vec![],
        }
    }
}

/// nameserver configuration with global and split dns support.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Nameservers {
    /// global nameservers used for all dns queries.
    /// can be ip addresses or doh urls (e.g., "https://dns.nextdns.io/abc123").
    pub global: Vec<String>,

    /// split dns: map of domain suffixes to nameservers.
    /// queries for these domains use the specified nameservers instead of global.
    #[serde(default)]
    pub split: std::collections::HashMap<String, Vec<String>>,
}

impl Default for Nameservers {
    fn default() -> Self {
        Self {
            global: vec![
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
                "8.8.8.8".to_string(),
                "8.8.4.4".to_string(),
            ],
            split: std::collections::HashMap::new(),
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

    /// client secret (set directly or loaded from `client_secret_path`).
    #[serde(default)]
    pub client_secret: String,

    /// path to file containing client secret.
    /// if set, the secret is loaded from this file at startup.
    /// this is useful for secrets management (e.g., sops, systemd credentials).
    #[serde(default)]
    pub client_secret_path: Option<std::path::PathBuf>,

    /// scopes to request.
    pub scope: Vec<String>,

    /// whether email must be verified.
    pub email_verified_required: bool,

    /// pkce configuration.
    #[serde(default)]
    pub pkce: PkceConfig,

    /// allowed email domains.
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// allowed email addresses.
    #[serde(default)]
    pub allowed_users: Vec<String>,

    /// allowed groups.
    #[serde(default)]
    pub allowed_groups: Vec<String>,

    /// node expiry in seconds (default: 180 days).
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,

    /// use expiry from the id token instead of expiry_secs.
    #[serde(default)]
    pub use_expiry_from_token: bool,

    /// extra oauth2 parameters.
    #[serde(default)]
    pub extra_params: std::collections::HashMap<String, String>,
}

fn default_expiry_secs() -> u64 {
    180 * 24 * 3600 // 180 days in seconds
}

/// pkce (proof key for code exchange) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceConfig {
    /// whether pkce is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// pkce challenge method (s256 or plain).
    #[serde(default)]
    pub method: PkceMethod,
}

impl Default for PkceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            method: PkceMethod::S256,
        }
    }
}

/// pkce challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PkceMethod {
    /// sha256 challenge method (recommended).
    #[default]
    S256,
    /// plain text challenge method.
    Plain,
}

/// performance tuning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TuningConfig {
    /// nodestore batch size for write operations.
    pub node_store_batch_size: usize,

    /// nodestore batch timeout in milliseconds.
    pub node_store_batch_timeout_ms: u64,

    /// registration cache expiration in seconds.
    pub register_cache_expiration_secs: u64,

    /// registration cache cleanup interval in seconds.
    pub register_cache_cleanup_secs: u64,

    /// interval between keep-alive messages for streaming map connections (in seconds).
    /// tailscale uses ~60 seconds. set to 0 to disable keep-alives.
    pub map_keepalive_interval_secs: u64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            node_store_batch_size: 100,
            node_store_batch_timeout_ms: 500,
            register_cache_expiration_secs: 900, // 15 minutes
            register_cache_cleanup_secs: 1200,   // 20 minutes
            map_keepalive_interval_secs: 60,     // 60 seconds
        }
    }
}

/// rest api configuration.
///
/// the rest api provides headscale-compatible endpoints for remote administration.
/// it is disabled by default and must be explicitly enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// whether the rest api is enabled.
    /// whether rate limiting is enabled for api requests
    pub enabled: bool,

    /// whether rate limiting is enabled for api requests.
    /// enabled by default to protect against abuse.
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,

    /// maximum requests per minute per ip address.
    /// only applies when `rate_limit_enabled` is true.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
}

fn default_rate_limit_per_minute() -> u32 {
    100
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate_limit_enabled: true,
            rate_limit_per_minute: 100,
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
        // api is disabled by default
        assert!(!config.api.enabled);
    }

    #[test]
    fn test_api_config_default_disabled() {
        let api = ApiConfig::default();
        assert!(!api.enabled, "API should be disabled by default");
    }

    #[test]
    fn test_api_config_serde() {
        let json = r#"{"enabled": true}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(api.enabled);

        // test with missing fields (should use default)
        let json = r#"{}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(!api.enabled);
    }

    #[test]
    fn test_api_config_rate_limiting_defaults() {
        let api = ApiConfig::default();
        // rate limiting should be enabled by default
        assert!(
            api.rate_limit_enabled,
            "rate limiting should be enabled by default"
        );
        // default to 100 requests per minute
        assert_eq!(api.rate_limit_per_minute, 100);
    }

    #[test]
    fn test_api_config_rate_limiting_serde() {
        // when not specified, rate_limit_enabled should default to true
        let json = r#"{"enabled": true}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(
            api.rate_limit_enabled,
            "rate_limit_enabled should default to true"
        );
        assert_eq!(api.rate_limit_per_minute, 100);

        // can be explicitly disabled
        let json = r#"{"enabled": true, "rate_limit_enabled": false, "rate_limit_per_minute": 50}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(!api.rate_limit_enabled);
        assert_eq!(api.rate_limit_per_minute, 50);
    }

    #[test]
    fn test_oidc_config_full() {
        let oidc = OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            client_id: "railscale".to_string(),
            client_secret: "secret".to_string(),
            client_secret_path: None,
            scope: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            email_verified_required: true,
            pkce: PkceConfig {
                enabled: true,
                method: PkceMethod::S256,
            },
            allowed_domains: vec!["example.com".to_string()],
            allowed_users: vec!["alice@example.com".to_string()],
            allowed_groups: vec!["headscale_users".to_string()],
            expiry_secs: 180 * 24 * 3600, // 180 days in seconds
            use_expiry_from_token: false,
            extra_params: std::collections::HashMap::new(),
        };

        assert!(oidc.pkce.enabled);
        assert_eq!(oidc.allowed_domains.len(), 1);
        assert_eq!(oidc.allowed_users.len(), 1);
        assert_eq!(oidc.allowed_groups.len(), 1);
    }

    #[test]
    fn test_pkce_method_default() {
        let pkce = PkceConfig::default();
        assert!(!pkce.enabled);
        assert_eq!(pkce.method, PkceMethod::S256);
    }

    #[test]
    fn test_oidc_config_serde() {
        let json = r#"{
            "issuer": "https://sso.example.com",
            "client_id": "railscale",
            "client_secret": "secret",
            "scope": ["openid", "profile"],
            "email_verified_required": false,
            "pkce": {
                "enabled": true,
                "method": "S256"
            },
            "allowed_domains": ["example.com"],
            "allowed_users": [],
            "allowed_groups": [],
            "expiry_secs": 15552000,
            "use_expiry_from_token": false,
            "extra_params": {"domain_hint": "example.com"}
        }"#;

        let oidc: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(oidc.issuer, "https://sso.example.com");
        assert!(oidc.pkce.enabled);
        assert_eq!(
            oidc.extra_params.get("domain_hint"),
            Some(&"example.com".to_string())
        );
        assert!(oidc.client_secret_path.is_none());
    }

    #[test]
    fn test_oidc_config_with_secret_path() {
        let json = r#"{
            "issuer": "https://sso.example.com",
            "client_id": "railscale",
            "client_secret_path": "/run/secrets/oidc-secret",
            "scope": ["openid", "profile"],
            "email_verified_required": false
        }"#;

        let oidc: OidcConfig = serde_json::from_str(json).unwrap();
        assert_eq!(oidc.issuer, "https://sso.example.com");
        assert!(
            oidc.client_secret.is_empty(),
            "client_secret should default to empty"
        );
        assert_eq!(
            oidc.client_secret_path,
            Some(std::path::PathBuf::from("/run/secrets/oidc-secret"))
        );
    }
}
