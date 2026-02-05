//! configuration types for railscale.

use std::path::PathBuf;

use ipnet::IpNet;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::oidc_group_prefix::OidcGroupPrefix;

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

    /// verify endpoint configuration (derp client verification).
    pub verify: VerifyConfig,

    /// enable taildrop file sharing.
    pub taildrop_enabled: bool,

    /// randomize client port (for nat traversal).
    pub randomize_client_port: bool,

    /// path to the maxmind geoip database (GeoLite2-Country.mmdb).
    /// when set, enables ip:country posture checks for geolocation-based access control.
    pub geoip_database_path: Option<PathBuf>,

    /// log level: trace, debug, info, warn, error.
    pub log_level: LogLevel,

    /// ip allocation strategy: sequential or random.
    pub ip_allocation: AllocationStrategy,

    /// inactivity timeout for ephemeral nodes (in seconds).
    /// ephemeral nodes that haven't been seen for this duration will be deleted.
    /// set to 0 to disable (ephemeral nodes won't be auto-deleted).
    /// default: 120 seconds (2 minutes).
    pub ephemeral_node_inactivity_timeout_secs: u64,

    /// hide build metadata (commit, rustc, build time) from /version endpoint.
    /// when true, only the crate version is returned, preventing fingerprinting.
    #[serde(default)]
    pub hide_build_metadata: bool,

    /// allow registration without noise context (for testing only).
    ///
    /// when false (default), `/machine/register` requires a valid noise handshake
    /// context which cryptographically binds the machine key to the request.
    /// **DANGEROUS**: allow registration without noise protocol.
    ///
    /// when true, registration without noise context is allowed with a zero
    /// machine key. this bypasses cryptographic binding and may allow spoofing.
    ///
    /// **NEVER enable in production** - only for testing without real clients.
    #[serde(default)]
    pub allow_non_noise_registration: bool,

    /// runtime-only: path to persist policy file on updates.
    /// set by CLI, not serialised to config.
    #[serde(skip)]
    pub policy_file_path: Option<PathBuf>,
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
            verify: VerifyConfig::default(),
            taildrop_enabled: true,
            randomize_client_port: false,
            geoip_database_path: None,
            log_level: LogLevel::default(),
            ip_allocation: AllocationStrategy::default(),
            ephemeral_node_inactivity_timeout_secs: 120,
            hide_build_metadata: false,
            allow_non_noise_registration: false,
            policy_file_path: None,
        }
    }
}

/// ip allocation strategy for assigning addresses to new nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AllocationStrategy {
    /// allocate ips sequentially (100.64.0.1, 100.64.0.2, ...).
    /// predictable and compact, good for most deployments.
    #[default]
    Sequential,
    /// allocate ips randomly within the prefix.
    /// harder to predict node ips, may help with privacy.
    Random,
}

impl std::fmt::Display for AllocationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocationStrategy::Sequential => write!(f, "sequential"),
            AllocationStrategy::Random => write!(f, "random"),
        }
    }
}

impl std::str::FromStr for AllocationStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sequential" => Ok(AllocationStrategy::Sequential),
            "random" => Ok(AllocationStrategy::Random),
            _ => Err(format!("invalid allocation strategy: {}", s)),
        }
    }
}

/// log level for tracing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// most verbose, includes all trace spans
    Trace,
    /// debug messages
    Debug,
    /// informational messages (default)
    #[default]
    Info,
    /// warnings only
    Warn,
    /// errors only
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("invalid log level: {}", s)),
        }
    }
}

/// database configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// database type: "sqlite" or "postgres".
    pub db_type: String,

    /// database connection string or file path.
    pub connection_string: String,

    /// sqlite-specific options.
    pub sqlite: SqliteConfig,
}

/// sqlite-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SqliteConfig {
    /// enable write-ahead logging (WAL) mode.
    ///
    /// WAL mode improves concurrency by allowing simultaneous readers
    /// and a single writer. recommended for production use.
    /// see: https://www.sqlite.org/wal.html
    pub write_ahead_log: bool,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            write_ahead_log: true,
        }
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("db_type", &self.db_type)
            .field(
                "connection_string",
                &redact_connection_string(&self.connection_string),
            )
            .field("sqlite", &self.sqlite)
            .finish()
    }
}

/// redact password from a database connection string.
///
/// handles postgresql urls like `postgres://user:password@host:port/database`.
/// returns the original string for non-url formats (like sqlite file paths).
fn redact_connection_string(s: &str) -> String {
    // check if it looks like a url with credentials
    if let Some(at_pos) = s.find('@')
        && let Some(scheme_end) = s.find("://")
    {
        let credentials_start = scheme_end + 3;
        let credentials = &s[credentials_start..at_pos];

        // check if credentials contain a password (colon-separated)
        if let Some(colon_pos) = credentials.find(':') {
            let user = &credentials[..colon_pos];
            let scheme = &s[..scheme_end + 3];
            let rest = &s[at_pos..];
            return format!("{}{}:[REDACTED]{}", scheme, user, rest);
        }
    }

    // no password found, return as-is
    s.to_string()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            db_type: "sqlite".to_string(),
            connection_string: "/var/lib/railscale/db.sqlite".to_string(),
            sqlite: SqliteConfig::default(),
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

/// default maximum concurrent derp connections.
pub const DEFAULT_DERP_MAX_CONNECTIONS: usize = 1000;

/// default idle timeout for derp connections (5 minutes).
pub const DEFAULT_DERP_IDLE_TIMEOUT_SECS: u64 = 300;

/// default derp message rate limit (bytes per second). 100kb/s sustained.
pub const DEFAULT_DERP_BYTES_PER_SECOND: u32 = 102400;

/// default derp message burst size (bytes). 200kb burst.
pub const DEFAULT_DERP_BYTES_BURST: u32 = 204800;

/// default derp connection rate limit (connections per minute per ip).
pub const DEFAULT_DERP_CONNECTION_RATE_PER_MINUTE: u32 = 10;

/// default stun rate limit (requests per minute per ip).
pub const DEFAULT_STUN_RATE_PER_MINUTE: u32 = 60;

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

    /// maximum concurrent connections. prevents resource exhaustion.
    #[serde(default = "default_derp_max_connections")]
    pub max_connections: usize,

    /// idle connection timeout in seconds.
    /// connections with no activity for this long are closed.
    /// set to 0 to disable (not recommended).
    /// default: 300 seconds (5 minutes).
    #[serde(default = "default_derp_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// message rate limit in bytes per second (client-enforced via serverinfo).
    /// sent to clients in the derp handshake; clients self-rate-limit.
    /// default: 102400 (100kb/s sustained).
    #[serde(default = "default_derp_bytes_per_second")]
    pub bytes_per_second: u32,

    /// message burst size in bytes (client-enforced via serverinfo).
    /// maximum bytes a client can send in a burst before rate limiting kicks in.
    /// default: 204800 (200kb burst).
    #[serde(default = "default_derp_bytes_burst")]
    pub bytes_burst: u32,

    /// connection rate limit per ip (connections per minute).
    /// server-enforced to prevent connection floods from a single ip.
    /// set to 0 to disable.
    /// default: 10 connections/minute per ip.
    #[serde(default = "default_derp_connection_rate_per_minute")]
    pub connection_rate_per_minute: u32,

    /// stun rate limit per ip (requests per minute).
    /// server-enforced to prevent stun abuse from a single ip.
    /// set to 0 to disable.
    /// default: 60 requests/minute per ip.
    #[serde(default = "default_stun_rate_per_minute")]
    pub stun_rate_per_minute: u32,

    /// enable server-side message rate limiting.
    /// when enabled, the server enforces the rate limit in addition to
    /// sending it to clients via ServerInfo (client-side enforcement).
    /// this protects against malicious or misconfigured clients that ignore
    /// the ServerInfo rate limits.
    /// default: true (server enforces, don't rely on client self-enforcement)
    #[serde(default = "default_server_side_rate_limit")]
    pub server_side_rate_limit: bool,

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
            max_connections: default_derp_max_connections(),
            idle_timeout_secs: default_derp_idle_timeout(),
            bytes_per_second: default_derp_bytes_per_second(),
            bytes_burst: default_derp_bytes_burst(),
            connection_rate_per_minute: default_derp_connection_rate_per_minute(),
            stun_rate_per_minute: default_stun_rate_per_minute(),
            server_side_rate_limit: true,
            runtime: None,
        }
    }
}

fn default_server_side_rate_limit() -> bool {
    true
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

fn default_derp_max_connections() -> usize {
    DEFAULT_DERP_MAX_CONNECTIONS
}

fn default_derp_idle_timeout() -> u64 {
    DEFAULT_DERP_IDLE_TIMEOUT_SECS
}

fn default_derp_bytes_per_second() -> u32 {
    DEFAULT_DERP_BYTES_PER_SECOND
}

fn default_derp_bytes_burst() -> u32 {
    DEFAULT_DERP_BYTES_BURST
}

fn default_derp_connection_rate_per_minute() -> u32 {
    DEFAULT_DERP_CONNECTION_RATE_PER_MINUTE
}

fn default_stun_rate_per_minute() -> u32 {
    DEFAULT_STUN_RATE_PER_MINUTE
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
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// oidc issuer url.
    pub issuer: String,

    /// client id.
    pub client_id: String,

    /// client secret (set directly or loaded from `client_secret_path`).
    /// wrapped in secretstring to prevent accidental logging/serialisation.
    #[serde(default, skip_serializing)]
    pub client_secret: SecretString,

    /// path to file containing client secret.
    /// if set, the secret is loaded from this file at startup.
    /// this is useful for secrets management (e.g., sops, systemd credentials).
    #[serde(default)]
    pub client_secret_path: Option<std::path::PathBuf>,

    /// scopes to request.
    pub scope: Vec<String>,

    /// whether email must be verified.
    /// defaults to true for security — unverified emails can allow account takeover.
    #[serde(default = "default_true")]
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

    /// prefix to apply to oidc groups when mapping to policy groups.
    ///
    /// for example, with prefix "oidc-", an oidc group "engineering" becomes
    /// "oidc-engineering" for matching against `group:oidc-engineering` in grants.
    ///
    /// if not set, oidc groups are used as-is.
    #[serde(default)]
    pub group_prefix: Option<OidcGroupPrefix>,

    /// node expiry in seconds (default: 180 days).
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,

    /// use expiry from the id token instead of expiry_secs.
    #[serde(default)]
    pub use_expiry_from_token: bool,

    /// extra oauth2 parameters.
    #[serde(default)]
    pub extra_params: std::collections::HashMap<String, String>,

    /// rate limit for oidc endpoints (requests per minute per ip).
    /// set to 0 to disable rate limiting.
    /// default: 30 requests/minute (more restrictive than api).
    #[serde(default = "default_oidc_rate_limit")]
    pub rate_limit_per_minute: u32,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            // secretstring's debug already redacts, but we explicitly show [redacted]
            // to make it clear in logs that a secret exists but is hidden
            .field("client_secret", &"[REDACTED]")
            .field("client_secret_path", &self.client_secret_path)
            .field("scope", &self.scope)
            .field("email_verified_required", &self.email_verified_required)
            .field("pkce", &self.pkce)
            .field("allowed_domains", &self.allowed_domains)
            .field("allowed_users", &self.allowed_users)
            .field("allowed_groups", &self.allowed_groups)
            .field("group_prefix", &self.group_prefix)
            .field("expiry_secs", &self.expiry_secs)
            .field("use_expiry_from_token", &self.use_expiry_from_token)
            .field("extra_params", &self.extra_params)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .finish()
    }
}

fn default_oidc_rate_limit() -> u32 {
    30
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
            enabled: true,
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
    /// reserved for future use — not yet wired into runtime.
    #[serde(default = "default_node_store_batch_size")]
    pub node_store_batch_size: usize,

    /// reserved for future use — not yet wired into runtime.
    #[serde(default = "default_node_store_batch_timeout_ms")]
    pub node_store_batch_timeout_ms: u64,

    /// reserved for future use — not yet wired into runtime.
    #[serde(default = "default_register_cache_expiration_secs")]
    pub register_cache_expiration_secs: u64,

    /// reserved for future use — not yet wired into runtime.
    #[serde(default = "default_register_cache_cleanup_secs")]
    pub register_cache_cleanup_secs: u64,

    /// interval between keep-alive messages for streaming map connections (in seconds).
    /// tailscale uses ~60 seconds. set to 0 to disable keep-alives.
    pub map_keepalive_interval_secs: u64,
}

fn default_node_store_batch_size() -> usize {
    100
}
fn default_node_store_batch_timeout_ms() -> u64 {
    500
}
fn default_register_cache_expiration_secs() -> u64 {
    900
}
fn default_register_cache_cleanup_secs() -> u64 {
    1200
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
    /// disabled by default for security.
    pub enabled: bool,

    /// host/ip to bind the api listener to.
    ///
    /// if `none` (default), the api routes are served on the main server port.
    /// if `some`, the api runs on a separate listener at `listen_host:listen_port`.
    ///
    /// examples:
    /// - `None` - API on same port as protocol (simple setup)
    /// - `Some("127.0.0.1")` - API on localhost only (secure)
    /// - `Some("0.0.0.0")` - API on all interfaces
    #[serde(default)]
    pub listen_host: Option<String>,

    /// port to bind the api listener to.
    /// only used when `listen_host` is set.
    /// defaults to 9090.
    #[serde(default = "default_api_port")]
    pub listen_port: u16,

    /// whether rate limiting is enabled for api requests.
    /// enabled by default to protect against abuse.
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,

    /// maximum requests per minute per ip address.
    /// only applies when `rate_limit_enabled` is true.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,

    /// whether the server is behind a reverse proxy.
    /// when true, client ips are extracted from x-forwarded-for headers
    /// but ONLY from requests originating from `trusted_proxies`.
    #[serde(default)]
    pub behind_proxy: bool,

    /// list of trusted proxy ip addresses or cidr ranges.
    /// only requests from these ips will have x-forwarded-for headers trusted.
    /// examples: ["127.0.0.1", "10.0.0.0/8", "::1", "fd00::/8"]
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

fn default_api_port() -> u16 {
    9090
}

fn default_rate_limit_per_minute() -> u32 {
    100
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_host: None,
            listen_port: default_api_port(),
            rate_limit_enabled: true,
            rate_limit_per_minute: 100,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
        }
    }
}

/// verify endpoint configuration (/verify for derp client verification).
///
/// this endpoint is intentionally unauthenticated for compatibility with
/// tailscale's derp server. protect it with rate limiting and/or IP allowlists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyConfig {
    /// rate limit for verify requests (requests per minute per IP).
    /// set to 0 to disable rate limiting.
    /// default: 60 requests/minute.
    pub rate_limit_per_minute: u32,

    /// ip allowlist for the verify endpoint.
    /// when non-empty, only requests from these IPs/CIDRs are allowed.
    /// examples: ["10.0.0.0/8", "192.168.1.100", "::1"]
    /// default: empty (allow all).
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// trusted proxy addresses for X-Forwarded-For extraction.
    /// when the verify endpoint is behind a reverse proxy, set this to the
    /// proxy's IP/CIDR so the real client IP is extracted from the XFF header.
    /// only used when `allowed_ips` is non-empty.
    /// examples: ["127.0.0.1", "10.0.0.0/8"]
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: 60,
            allowed_ips: Vec::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_database_config_debug_redacts_password() {
        let config = DatabaseConfig {
            db_type: "postgres".to_string(),
            connection_string: "postgres://admin:supersecretpassword@localhost:5432/railscale"
                .to_string(),
            ..Default::default()
        };

        let debug_output = format!("{:?}", config);
        // password must not appear in debug output
        assert!(
            !debug_output.contains("supersecretpassword"),
            "connection_string password should be redacted in Debug output"
        );
        // but host and database should be visible for debugging
        assert!(
            debug_output.contains("localhost"),
            "host should be visible in Debug output"
        );
    }

    #[test]
    fn test_database_config_debug_sqlite_unchanged() {
        let config = DatabaseConfig {
            db_type: "sqlite".to_string(),
            connection_string: "/var/lib/railscale/db.sqlite".to_string(),
            ..Default::default()
        };

        let debug_output = format!("{:?}", config);
        // sqlite paths have no password to redact
        assert!(debug_output.contains("/var/lib/railscale/db.sqlite"));
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.database.db_type, "sqlite");
        assert!(config.prefix_v4.is_some());
        assert!(config.prefix_v6.is_some());
        // api is disabled by default
        assert!(!config.api.enabled);
        // wal should be enabled by default for better concurrency
        assert!(
            config.database.sqlite.write_ahead_log,
            "sqlite WAL should be enabled by default"
        );
    }

    #[test]
    fn test_api_config_default_disabled() {
        let api = ApiConfig::default();
        assert!(!api.enabled, "API should be disabled by default");
        assert!(
            api.listen_host.is_none(),
            "listen_host should be None by default (merge with main server)"
        );
        assert_eq!(api.listen_port, 9090, "listen_port should default to 9090");
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
    fn test_api_config_proxy_defaults() {
        let api = ApiConfig::default();
        // behind proxy should be disabled by default
        assert!(!api.behind_proxy, "behind_proxy should be false by default");
        // trusted proxies should be empty by default
        assert!(
            api.trusted_proxies.is_empty(),
            "trusted_proxies should be empty by default"
        );
    }

    #[test]
    fn test_api_config_proxy_serde() {
        // configure for reverse proxy setup
        let json = r#"{
            "enabled": true,
            "behind_proxy": true,
            "trusted_proxies": ["127.0.0.1", "10.0.0.0/8", "::1"]
        }"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(api.behind_proxy);
        assert_eq!(api.trusted_proxies.len(), 3);
        assert!(api.trusted_proxies.contains(&"127.0.0.1".to_string()));
        assert!(api.trusted_proxies.contains(&"10.0.0.0/8".to_string()));
        assert!(api.trusted_proxies.contains(&"::1".to_string()));
    }

    #[test]
    fn test_api_config_listen_serde() {
        // default: no listen_host means merge with main server
        let json = r#"{"enabled": true}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert!(api.listen_host.is_none());
        assert_eq!(api.listen_port, 9090);

        // separate listener on localhost with custom port
        let json = r#"{"enabled": true, "listen_host": "127.0.0.1", "listen_port": 8081}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(api.listen_host, Some("127.0.0.1".to_string()));
        assert_eq!(api.listen_port, 8081);

        // separate listener on all interfaces with default port
        let json = r#"{"enabled": true, "listen_host": "0.0.0.0"}"#;
        let api: ApiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(api.listen_host, Some("0.0.0.0".to_string()));
        assert_eq!(api.listen_port, 9090);
    }

    #[test]
    fn test_derp_rate_limit_defaults() {
        let derp = EmbeddedDerpConfig::default();
        // message rate limiting (client-enforced via serverinfo)
        assert_eq!(derp.bytes_per_second, 102400); // 100KB/s
        assert_eq!(derp.bytes_burst, 204800); // 200KB
        // connection rate limiting (server-enforced)
        assert_eq!(derp.connection_rate_per_minute, 10);
        // stun rate limiting
        assert_eq!(derp.stun_rate_per_minute, 60);
        // server-side rate limiting enabled by default for security
        assert!(
            derp.server_side_rate_limit,
            "server_side_rate_limit should be true by default"
        );
    }

    #[test]
    fn test_derp_rate_limit_serde() {
        let json = r#"{
            "enabled": true,
            "bytes_per_second": 51200,
            "bytes_burst": 102400,
            "connection_rate_per_minute": 5,
            "stun_rate_per_minute": 30
        }"#;
        let derp: EmbeddedDerpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(derp.bytes_per_second, 51200);
        assert_eq!(derp.bytes_burst, 102400);
        assert_eq!(derp.connection_rate_per_minute, 5);
        assert_eq!(derp.stun_rate_per_minute, 30);
        // default when not specified is now true
        assert!(derp.server_side_rate_limit);
    }

    #[test]
    fn test_derp_server_side_rate_limit_serde() {
        let json = r#"{
            "enabled": true,
            "server_side_rate_limit": true
        }"#;
        let derp: EmbeddedDerpConfig = serde_json::from_str(json).unwrap();
        assert!(derp.server_side_rate_limit);
    }

    #[test]
    fn test_oidc_config_full() {
        use secrecy::SecretString;

        let oidc = OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            client_id: "railscale".to_string(),
            client_secret: SecretString::from("secret"),
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
            group_prefix: None,
            expiry_secs: 180 * 24 * 3600, // 180 days in seconds
            use_expiry_from_token: false,
            extra_params: std::collections::HashMap::new(),
            rate_limit_per_minute: 30,
        };

        assert!(oidc.pkce.enabled);
        assert_eq!(oidc.allowed_domains.len(), 1);
        assert_eq!(oidc.allowed_users.len(), 1);
        assert_eq!(oidc.allowed_groups.len(), 1);
    }

    #[test]
    fn test_pkce_method_default() {
        let pkce = PkceConfig::default();
        assert!(pkce.enabled); // PKCE enabled by default for security
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
    fn test_oidc_email_verified_defaults_to_true() {
        // when email_verified_required is omitted, it should default to true
        let json = r#"{
            "issuer": "https://sso.example.com",
            "client_id": "railscale",
            "client_secret": "secret",
            "scope": ["openid"]
        }"#;
        let oidc: OidcConfig = serde_json::from_str(json).unwrap();
        assert!(
            oidc.email_verified_required,
            "email_verified_required should default to true for security"
        );
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
            oidc.client_secret.expose_secret().is_empty(),
            "client_secret should default to empty"
        );
        assert_eq!(
            oidc.client_secret_path,
            Some(std::path::PathBuf::from("/run/secrets/oidc-secret"))
        );
    }

    #[test]
    fn test_oidc_client_secret_debug_redacted() {
        use secrecy::SecretString;

        let oidc = OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            client_id: "railscale".to_string(),
            client_secret: SecretString::from("super-secret-value"),
            client_secret_path: None,
            scope: vec!["openid".to_string()],
            email_verified_required: true,
            pkce: PkceConfig::default(),
            allowed_domains: vec![],
            allowed_users: vec![],
            allowed_groups: vec![],
            group_prefix: None,
            expiry_secs: default_expiry_secs(),
            use_expiry_from_token: false,
            extra_params: std::collections::HashMap::new(),
            rate_limit_per_minute: 30,
        };

        let debug_output = format!("{:?}", oidc);
        // secret must not appear in debug output
        assert!(
            !debug_output.contains("super-secret-value"),
            "client_secret should be redacted in Debug output"
        );
    }

    #[test]
    fn test_oidc_client_secret_not_serialized() {
        use secrecy::SecretString;

        let oidc = OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            client_id: "railscale".to_string(),
            client_secret: SecretString::from("super-secret-value"),
            client_secret_path: None,
            scope: vec!["openid".to_string()],
            email_verified_required: true,
            pkce: PkceConfig::default(),
            allowed_domains: vec![],
            allowed_users: vec![],
            allowed_groups: vec![],
            group_prefix: None,
            expiry_secs: default_expiry_secs(),
            use_expiry_from_token: false,
            extra_params: std::collections::HashMap::new(),
            rate_limit_per_minute: 30,
        };

        let json = serde_json::to_string(&oidc).unwrap();
        // secret must not appear in serialized output
        assert!(
            !json.contains("super-secret-value"),
            "client_secret should not be serialized"
        );
    }
}
