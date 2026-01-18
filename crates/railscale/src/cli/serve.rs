//! the `serve` subcommand - runs the control server.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::RailscaleDb;
use railscale_grants::Policy;
use railscale_types::{Config, EmbeddedDerpRuntime};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::derp_server::{self, DerpListenerConfig, EmbeddedDerpOptions};

/// default config file search paths (in order of priority).
const CONFIG_SEARCH_PATHS: &[&str] = &[
    "/etc/railscale/config.toml",
    "~/.config/railscale/config.toml",
    "./config.toml",
];

/// environment variable suffixes that support headscale_* fallback.
const ENV_VAR_SUFFIXES: &[&str] = &[
    "CONFIG",
    "DATABASE_URL",
    "LISTEN_ADDR",
    "SERVER_URL",
    "POLICY_FILE",
    "NOISE_KEY",
    "BASE_DOMAIN",
    "PREFIX_V4",
    "PREFIX_V6",
    "LOG_LEVEL",
    "DERP_EMBEDDED_ENABLED",
    "DERP_REGION_ID",
    "DERP_REGION_NAME",
    "DERP_LISTEN_ADDR",
    "DERP_ADVERTISE_HOST",
    "DERP_ADVERTISE_PORT",
    "DERP_CERT_PATH",
    "DERP_TLS_KEY_PATH",
    "DERP_PRIVATE_KEY_PATH",
    // for tests
    "TEST_VAR",
];

/// migrate a single env var from headscale_* to railscale_* if needed.
///
/// returns the value to use (railscale_* takes precedence).
fn migrate_env_var(
    _suffix: &str,
    headscale_val: Option<&str>,
    railscale_val: Option<&str>,
) -> Option<String> {
    match (railscale_val, headscale_val) {
        (Some(rs), _) => Some(rs.to_string()),
        (None, Some(hs)) => Some(hs.to_string()),
        (None, None) => None,
    }
}

/// apply headscale_* -> railscale_* environment variable migration.
///
/// for each known env var suffix, if headscale_x is set but railscale_x is not,
/// set RAILSCALE_X to the HEADSCALE_X value. This allows users migrating from
/// headscale to use their existing environment configuration.
///
/// call this before clap parses arguments.
pub fn apply_headscale_env_migration() {
    use std::env;

    for suffix in ENV_VAR_SUFFIXES {
        let rs_key = format!("RAILSCALE_{}", suffix);
        let hs_key = format!("HEADSCALE_{}", suffix);

        let rs_val = env::var(&rs_key).ok();
        let hs_val = env::var(&hs_key).ok();

        // only set railscale_* if it's not already set and headscale_* is
        if rs_val.is_none() {
            if let Some(hs) = hs_val {
                tracing::debug!(
                    "Migrating {} -> {} = {}",
                    hs_key,
                    rs_key,
                    if suffix.contains("SECRET") || suffix.contains("KEY") {
                        "[redacted]"
                    } else {
                        &hs
                    }
                );
                // SAFETY: we're setting env vars before any threads are spawned,
                // during CLI initialization. This is the standard pattern for
                // env var configuration at startup.
                unsafe {
                    env::set_var(&rs_key, &hs);
                }
            }
        }
    }
}

/// run the railscale control server
#[derive(Args, Debug)]
pub struct ServeCommand {
    /// path to config file (toml format)
    #[arg(short, long, env = "RAILSCALE_CONFIG")]
    config: Option<PathBuf>,

    /// database url (sqlite:// or postgres://)
    #[arg(long, env = "RAILSCALE_DATABASE_URL")]
    database_url: Option<String>,

    /// address to listen on
    #[arg(long, env = "RAILSCALE_LISTEN_ADDR")]
    listen_addr: Option<String>,

    /// server url (for client configuration)
    #[arg(long, env = "RAILSCALE_SERVER_URL")]
    server_url: Option<String>,

    /// path to policy file (json grants)
    #[arg(long, env = "RAILSCALE_POLICY_FILE")]
    policy_file: Option<PathBuf>,

    /// path to noise protocol private key
    #[arg(long, env = "RAILSCALE_NOISE_KEY")]
    noise_key_path: Option<PathBuf>,

    /// base domain for magicdns
    #[arg(long, env = "RAILSCALE_BASE_DOMAIN")]
    base_domain: Option<String>,

    /// ipv4 prefix (cidr)
    #[arg(long, env = "RAILSCALE_PREFIX_V4")]
    prefix_v4: Option<String>,

    /// ipv6 prefix (cidr)
    #[arg(long, env = "RAILSCALE_PREFIX_V6")]
    prefix_v6: Option<String>,

    /// log level
    #[arg(long, env = "RAILSCALE_LOG_LEVEL")]
    log_level: Option<String>,

    /// enable embedded derp relay server
    #[arg(long, env = "RAILSCALE_DERP_EMBEDDED_ENABLED")]
    derp_embedded_enabled: Option<bool>,

    /// derp region id to advertise
    #[arg(long, env = "RAILSCALE_DERP_REGION_ID")]
    derp_region_id: Option<i32>,

    /// derp region name to advertise
    #[arg(long, env = "RAILSCALE_DERP_REGION_NAME")]
    derp_region_name: Option<String>,

    /// derp listener address (host:port)
    #[arg(long, env = "RAILSCALE_DERP_LISTEN_ADDR")]
    derp_listen_addr: Option<String>,

    /// hostname or ip advertised to clients for derp
    #[arg(long, env = "RAILSCALE_DERP_ADVERTISE_HOST")]
    derp_advertise_host: Option<String>,

    /// port advertised to clients for derp
    #[arg(long, env = "RAILSCALE_DERP_ADVERTISE_PORT")]
    derp_advertise_port: Option<u16>,

    /// derp tls certificate path
    #[arg(long, env = "RAILSCALE_DERP_CERT_PATH")]
    derp_cert_path: Option<PathBuf>,

    /// derp tls private key path (pem)
    #[arg(long, env = "RAILSCALE_DERP_TLS_KEY_PATH")]
    derp_tls_key_path: Option<PathBuf>,

    /// derp protocol private key path (curve25519)
    #[arg(long, env = "RAILSCALE_DERP_PRIVATE_KEY_PATH")]
    derp_private_key_path: Option<PathBuf>,
}

impl ServeCommand {
    /// find and load config file, returning none if no config file is found.
    fn load_config_file(config_path: Option<&PathBuf>) -> Result<Option<Config>> {
        // if explicit path provided, it must exist
        if let Some(path) = config_path {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read config file: {:?}", path))?;
            let config: Config = toml::from_str(&content)
                .with_context(|| format!("failed to parse config file: {:?}", path))?;
            return Ok(Some(config));
        }

        // search default paths
        for path_str in CONFIG_SEARCH_PATHS {
            let path = expand_tilde::expand_tilde(path_str)
                .map(|p| p.into_owned())
                .unwrap_or_else(|_| PathBuf::from(path_str));
            if path.exists() {
                debug!("Found config file at {:?}", path);
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read config file: {:?}", path))?;
                let config: Config = toml::from_str(&content)
                    .with_context(|| format!("failed to parse config file: {:?}", path))?;
                return Ok(Some(config));
            }
        }

        Ok(None)
    }

    /// convert cli arguments into a config struct, merging with config file if present.
    ///
    /// priority order: defaults -> config file -> cli flags
    fn into_config(self) -> Result<Config> {
        // start with defaults, then overlay config file if found
        let mut config = match Self::load_config_file(self.config.as_ref())? {
            Some(file_config) => {
                info!("Loaded configuration from file");
                file_config
            }
            None => {
                debug!("No config file found, using defaults");
                Config::default()
            }
        };

        // cli overrides (only if explicitly set)
        if let Some(db_url) = self.database_url {
            config.database = parse_database_url(&db_url)?;
        }
        if let Some(listen_addr) = self.listen_addr {
            config.listen_addr = listen_addr;
        }
        if let Some(server_url) = self.server_url {
            config.server_url = server_url;
        }
        if let Some(noise_key_path) = self.noise_key_path {
            config.noise_private_key_path = noise_key_path;
        }
        if let Some(base_domain) = self.base_domain {
            config.base_domain = base_domain;
        }
        if let Some(prefix_v4) = self.prefix_v4 {
            config.prefix_v4 = Some(prefix_v4.parse().context("invalid IPv4 prefix")?);
        }
        if let Some(prefix_v6) = self.prefix_v6 {
            config.prefix_v6 = Some(prefix_v6.parse().context("invalid IPv6 prefix")?);
        }

        // derp overrides
        if let Some(enabled) = self.derp_embedded_enabled {
            config.derp.embedded_derp.enabled = enabled;
        }
        if let Some(id) = self.derp_region_id {
            config.derp.embedded_derp.region_id = id;
        }
        if let Some(name) = self.derp_region_name {
            config.derp.embedded_derp.region_name = name;
        }
        if let Some(listen) = self.derp_listen_addr {
            config.derp.embedded_derp.listen_addr = listen;
        }
        if let Some(host) = self.derp_advertise_host {
            config.derp.embedded_derp.advertise_host = Some(host);
        }
        if let Some(port) = self.derp_advertise_port {
            config.derp.embedded_derp.advertise_port = Some(port);
        }
        if let Some(cert_path) = self.derp_cert_path {
            config.derp.embedded_derp.cert_path = cert_path;
        }
        if let Some(tls_key_path) = self.derp_tls_key_path {
            config.derp.embedded_derp.tls_key_path = tls_key_path;
        }
        if let Some(private_key_path) = self.derp_private_key_path {
            config.derp.embedded_derp.private_key_path = private_key_path;
        }

        Ok(config)
    }

    /// run the serve command
    pub async fn run(self) -> Result<()> {
        // initialize logging (use CLI override or default to info)
        let log_level_str = self.log_level.clone().unwrap_or_else(|| "info".to_string());
        let log_level = match log_level_str.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        };

        let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
        tracing::subscriber::set_global_default(subscriber)?;

        info!("Starting railscale...");

        // save policy file path for hot-reload (before into_config consumes self)
        let policy_file_path = self.policy_file.clone();

        // load policy if provided
        let policy = if let Some(policy_path) = &policy_file_path {
            info!("Loading policy from {:?}", policy_path);
            let policy_content = std::fs::read_to_string(policy_path)
                .with_context(|| format!("failed to read policy file: {:?}", policy_path))?;
            serde_json::from_str::<Policy>(&policy_content)
                .context("failed to parse policy file")?
        } else {
            warn!("No policy file provided, using empty policy (deny-all)");
            Policy::empty()
        };

        info!("Loaded policy with {} grants", policy.grants.len());

        // load configuration
        let config = self.into_config()?;
        info!("Database: {}", config.database.connection_string);
        info!("Listen address: {}", config.listen_addr);
        info!("Server URL: {}", config.server_url);

        // ensure parent directory exists for sqlite databases
        if config.database.db_type == "sqlite" {
            let db_path = std::path::Path::new(&config.database.connection_string);
            if let Some(parent) = db_path.parent()
                && !parent.exists()
            {
                info!("Creating database directory: {:?}", parent);
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create database directory: {:?}", parent)
                })?;
            }
        }

        // initialize database
        let db = RailscaleDb::new(&config)
            .await
            .context("failed to initialize database")?;

        info!("Running database migrations...");
        db.migrate()
            .await
            .context("failed to run database migrations")?;

        info!("Database initialized successfully");

        // load or generate noise keypair
        info!(
            "Loading Noise keypair from {:?}",
            config.noise_private_key_path
        );
        let keypair = crate::load_or_generate_noise_keypair(&config.noise_private_key_path)
            .await
            .with_context(|| {
                format!(
                    "failed to load/generate noise keypair: {:?}",
                    config.noise_private_key_path
                )
            })?;
        info!("Noise public key loaded ({} bytes)", keypair.public.len());

        // set up embedded derp server if enabled
        let mut config = config;
        if config.derp.embedded_derp.enabled {
            info!("Setting up embedded DERP server...");

            // load or generate derp keypair (separate from noise key for key isolation)
            let derp_keypair =
                crate::load_or_generate_noise_keypair(&config.derp.embedded_derp.private_key_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to load/generate DERP keypair: {:?}",
                            config.derp.embedded_derp.private_key_path
                        )
                    })?;
            info!("DERP keypair loaded");

            // determine advertised host (from config or extract from server_url)
            let advertise_host = config
                .derp
                .embedded_derp
                .advertise_host
                .clone()
                .unwrap_or_else(|| extract_host(&config.server_url));

            // determine advertised port (from config or parse from listen_addr)
            let advertise_port = config.derp.embedded_derp.advertise_port.unwrap_or_else(|| {
                extract_port(&config.derp.embedded_derp.listen_addr).unwrap_or(3340)
            });

            // load or generate tls certificate
            let tls_assets = derp_server::load_or_generate_derp_tls(
                &config.derp.embedded_derp.cert_path,
                &config.derp.embedded_derp.tls_key_path,
                &[advertise_host.clone()],
            )
            .context("failed to set up DERP TLS")?;
            info!(
                fingerprint = %tls_assets.fingerprint,
                "DERP TLS certificate loaded"
            );

            // populate runtime info so generate_derp_map() includes this region
            config.derp.embedded_derp.runtime = Some(EmbeddedDerpRuntime {
                advertise_host: advertise_host.clone(),
                advertise_port,
                cert_fingerprint: tls_assets.fingerprint.clone(),
            });

            // parse listen address and spawn DERP listener
            let derp_listen_addr: SocketAddr = config
                .derp
                .embedded_derp
                .listen_addr
                .parse()
                .context("invalid DERP listen address")?;

            let derp_server =
                derp_server::EmbeddedDerpServer::new(EmbeddedDerpOptions::new(derp_keypair));
            derp_server::spawn_derp_listener(DerpListenerConfig {
                listen_addr: derp_listen_addr,
                tls_config: tls_assets.tls_config,
                server: derp_server,
            })
            .await
            .context("failed to spawn DERP listener")?;

            info!(
                addr = %derp_listen_addr,
                host = %advertise_host,
                port = %advertise_port,
                "Embedded DERP server started"
            );
        }

        // initialize oidc if configured
        let oidc = if let Some(ref oidc_config) = config.oidc {
            info!("Initializing OIDC provider...");

            // load client_secret from path if specified
            let mut oidc_config = oidc_config.clone();
            if let Some(ref secret_path) = oidc_config.client_secret_path {
                info!("Loading OIDC client secret from {:?}", secret_path);
                oidc_config.client_secret = std::fs::read_to_string(secret_path)
                    .with_context(|| {
                        format!("failed to read OIDC client secret from {:?}", secret_path)
                    })?
                    .trim()
                    .to_string();
            }

            if oidc_config.client_secret.is_empty() {
                bail!("OIDC client_secret is required (set client_secret or client_secret_path)");
            }

            let provider = crate::oidc::AuthProviderOidc::new(oidc_config, &config.server_url)
                .await
                .map_err(|e| {
                    color_eyre::eyre::eyre!("failed to initialize OIDC provider: {}", e)
                })?;
            info!("OIDC provider initialized");
            Some(provider)
        } else {
            None
        };

        // build router with policy handle for hot-reload
        let notifier = crate::StateNotifier::new();
        let (app, policy_handle) = crate::create_app_with_policy_handle(
            db,
            policy,
            config.clone(),
            oidc,
            notifier,
            Some(keypair),
            None,
        )
        .await;

        // spawn sighup handler for policy hot-reload
        if let Some(policy_path) = policy_file_path {
            let policy_handle = policy_handle.clone();
            tokio::spawn(async move {
                let mut sighup = match signal(SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to register SIGHUP handler: {}", e);
                        return;
                    }
                };

                loop {
                    sighup.recv().await;
                    info!("Received SIGHUP, reloading policy from {:?}", policy_path);

                    match std::fs::read_to_string(&policy_path) {
                        Ok(content) => match serde_json::from_str::<Policy>(&content) {
                            Ok(new_policy) => {
                                let grant_count = new_policy.grants.len();
                                policy_handle.reload(new_policy).await;
                                info!("Policy reloaded successfully ({} grants)", grant_count);
                            }
                            Err(e) => {
                                error!("Failed to read policy file: {}", e);
                            }
                        },
                        Err(e) => {
                            error!("Failed to read policy file: {}", e);
                        }
                    }
                }
            });
        }

        // parse listen address
        let addr: SocketAddr = config
            .listen_addr
            .parse()
            .context("invalid listen address")?;

        info!("Starting HTTP server on {}", addr);

        // start server
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await.context("server error")?;

        Ok(())
    }
}

/// extract hostname from a url, stripping scheme and port.
fn extract_host(url_str: &str) -> String {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "localhost".to_string())
}

/// extract port from an address string like "0.0.0.0:3340".
/// handles both ipv4 (host:port) and ipv6 ([::1]:port) formats.
fn extract_port(addr: &str) -> Option<u16> {
    // try parsing as a socket address first (handles ipv6)
    if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
        return Some(socket_addr.port());
    }
    // fallback: take last colon-separated part (ipv4 case)
    addr.rsplit(':').next()?.parse().ok()
}

/// parse a database url into databaseconfig.
fn parse_database_url(db_url: &str) -> Result<railscale_types::DatabaseConfig> {
    let parsed =
        url::Url::parse(db_url).with_context(|| format!("invalid database URL: {}", db_url))?;

    match parsed.scheme() {
        "postgres" | "postgresql" => Ok(railscale_types::DatabaseConfig {
            db_type: "postgres".to_string(),
            connection_string: db_url.to_string(),
        }),
        "sqlite" => {
            // extract path from sqlite:// url
            let path = parsed.path();
            Ok(railscale_types::DatabaseConfig {
                db_type: "sqlite".to_string(),
                connection_string: path.to_string(),
            })
        }
        scheme => bail!(
            "unsupported database scheme '{}', expected 'sqlite' or 'postgres'",
            scheme
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_database_url() {
        // sqlite
        let db = parse_database_url("sqlite:///var/lib/railscale/db.sqlite").unwrap();
        assert_eq!(db.db_type, "sqlite");
        assert_eq!(db.connection_string, "/var/lib/railscale/db.sqlite");

        // postgres
        let db = parse_database_url("postgres://user:pass@host/db").unwrap();
        assert_eq!(db.db_type, "postgres");
        assert_eq!(db.connection_string, "postgres://user:pass@host/db");

        // invalid
        assert!(parse_database_url("mysql://localhost/db").is_err());
    }

    #[test]
    fn test_load_config_from_toml_file() {
        let toml_content = r#"
server_url = "https://ts.example.com"
listen_addr = "0.0.0.0:443"
noise_private_key_path = "/etc/railscale/noise.key"
prefix_v4 = "100.64.0.0/16"
prefix_v6 = "fd7a:115c:a1e0::/48"
base_domain = "example.ts.net"
taildrop_enabled = true
randomize_client_port = false

[database]
db_type = "sqlite"
connection_string = "/var/lib/railscale/db.sqlite"

[derp]
derp_map_url = "https://controlplane.tailscale.com/derpmap/default"
update_frequency_secs = 3600

[derp.embedded_derp]
enabled = true
region_id = 900
region_name = "my-derp"
listen_addr = "0.0.0.0:3340"
cert_path = "/etc/railscale/derp_cert.pem"
tls_key_path = "/etc/railscale/derp_tls_key.pem"
private_key_path = "/etc/railscale/derp_private.key"
stun_listen_addr = "0.0.0.0:3478"

[dns]
magic_dns = true
override_local_dns = false
search_domains = ["internal.example.com"]

[dns.nameservers]
global = ["9.9.9.9", "149.112.112.112"]

[dns.nameservers.split]
"corp.example.com" = ["10.0.0.53"]

[tuning]
node_store_batch_size = 50
node_store_batch_timeout_ms = 250
register_cache_expiration_secs = 600
register_cache_cleanup_secs = 900
map_keepalive_interval_secs = 30
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();
        file.flush().unwrap();

        let config = ServeCommand::load_config_file(Some(&file.path().to_path_buf()))
            .unwrap()
            .expect("config should be loaded");

        assert_eq!(config.server_url, "https://ts.example.com");
        assert_eq!(config.listen_addr, "0.0.0.0:443");
        assert_eq!(config.base_domain, "example.ts.net");
        assert!(!config.dns.override_local_dns);
        assert_eq!(
            config.dns.nameservers.global,
            vec!["9.9.9.9", "149.112.112.112"]
        );
        assert_eq!(
            config.dns.nameservers.split.get("corp.example.com"),
            Some(&vec!["10.0.0.53".to_string()])
        );
        assert!(config.derp.embedded_derp.enabled);
        assert_eq!(config.derp.embedded_derp.region_id, 900);
        assert_eq!(config.tuning.node_store_batch_size, 50);
    }

    #[test]
    fn test_cli_overrides_config_file() {
        let toml_content = r#"
server_url = "https://ts.example.com"
listen_addr = "0.0.0.0:443"
noise_private_key_path = "/etc/railscale/noise.key"
prefix_v4 = "100.64.0.0/16"
prefix_v6 = "fd7a:115c:a1e0::/48"
base_domain = "example.ts.net"
taildrop_enabled = true
randomize_client_port = false

[database]
db_type = "sqlite"
connection_string = "/var/lib/railscale/db.sqlite"

[derp]
update_frequency_secs = 3600

[derp.embedded_derp]
enabled = false
region_id = 999
region_name = "railscale"
listen_addr = "0.0.0.0:3340"
cert_path = "/var/lib/railscale/derp_cert.pem"
tls_key_path = "/var/lib/railscale/derp_tls_key.pem"
private_key_path = "/var/lib/railscale/derp_private.key"

[dns]
magic_dns = true
override_local_dns = true
search_domains = []

[dns.nameservers]
global = ["1.1.1.1"]

[tuning]
node_store_batch_size = 100
node_store_batch_timeout_ms = 500
register_cache_expiration_secs = 900
register_cache_cleanup_secs = 1200
map_keepalive_interval_secs = 60
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();
        file.flush().unwrap();

        // create command with CLI overrides
        let cmd = ServeCommand {
            config: Some(file.path().to_path_buf()),
            database_url: Some("sqlite:///tmp/override.db".to_string()),
            listen_addr: Some("127.0.0.1:8080".to_string()),
            server_url: None, // Not overriding
            policy_file: None,
            noise_key_path: None,
            base_domain: Some("override.ts.net".to_string()),
            prefix_v4: None,
            prefix_v6: None,
            log_level: None,
            derp_embedded_enabled: Some(true), // Override to enable
            derp_region_id: Some(123),
            derp_region_name: None,
            derp_listen_addr: None,
            derp_advertise_host: None,
            derp_advertise_port: None,
            derp_cert_path: None,
            derp_tls_key_path: None,
            derp_private_key_path: None,
        };

        let config = cmd.into_config().unwrap();

        // cli overrides should win
        assert_eq!(config.database.connection_string, "/tmp/override.db");
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.base_domain, "override.ts.net");
        assert!(config.derp.embedded_derp.enabled);
        assert_eq!(config.derp.embedded_derp.region_id, 123);

        // config file values should be preserved when not overridden
        assert_eq!(config.server_url, "https://ts.example.com");
        assert_eq!(config.derp.embedded_derp.region_name, "railscale");
    }

    #[test]
    fn test_no_config_file_uses_defaults() {
        let config = ServeCommand::load_config_file(None).unwrap();
        assert!(config.is_none());

        // when no config file, into_config should use defaults
        let cmd = ServeCommand {
            config: None,
            database_url: None,
            listen_addr: None,
            server_url: None,
            policy_file: None,
            noise_key_path: None,
            base_domain: None,
            prefix_v4: None,
            prefix_v6: None,
            log_level: None,
            derp_embedded_enabled: None,
            derp_region_id: None,
            derp_region_name: None,
            derp_listen_addr: None,
            derp_advertise_host: None,
            derp_advertise_port: None,
            derp_cert_path: None,
            derp_tls_key_path: None,
            derp_private_key_path: None,
        };

        let config = cmd.into_config().unwrap();
        assert_eq!(config.server_url, "http://127.0.0.1:8080");
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.base_domain, "railscale.net");
    }

    #[test]
    fn test_migrate_headscale_env_vars() {
        // test that headscale_* env vars are migrated to railscale_*
        // when RAILSCALE_* is not set

        // headscale_server_url -> railscale_server_url
        assert_eq!(
            migrate_env_var("SERVER_URL", Some("https://hs.example.com"), None),
            Some("https://hs.example.com".to_string())
        );

        // railscale_* takes precedence over headscale_*
        assert_eq!(
            migrate_env_var(
                "SERVER_URL",
                Some("https://hs.example.com"),
                Some("https://rs.example.com")
            ),
            Some("https://rs.example.com".to_string())
        );

        // neither set returns none
        assert_eq!(migrate_env_var("SERVER_URL", None, None), None);
    }

    #[test]
    fn test_apply_headscale_env_migration() {
        use std::env;

        // save original values
        let orig_rs = env::var("RAILSCALE_TEST_VAR").ok();
        let orig_hs = env::var("HEADSCALE_TEST_VAR").ok();

        // SAFETY: test runs single-threaded, safe to manipulate env vars
        unsafe {
            // clean slate
            env::remove_var("RAILSCALE_TEST_VAR");
            env::remove_var("HEADSCALE_TEST_VAR");

            // set only headscale_*
            env::set_var("HEADSCALE_TEST_VAR", "headscale_value");
        }

        apply_headscale_env_migration();

        // railscale_* should now be set
        assert_eq!(
            env::var("RAILSCALE_TEST_VAR").ok(),
            Some("headscale_value".to_string())
        );

        // SAFETY: test cleanup, single-threaded
        unsafe {
            // restore original values
            match orig_rs {
                Some(v) => env::set_var("RAILSCALE_TEST_VAR", v),
                None => env::remove_var("RAILSCALE_TEST_VAR"),
            }
            match orig_hs {
                Some(v) => env::set_var("HEADSCALE_TEST_VAR", v),
                None => env::remove_var("HEADSCALE_TEST_VAR"),
            }
        }
    }
}
