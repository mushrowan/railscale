//! the `serve` subcommand - runs the control server

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::{Config, EmbeddedDerpRuntime};
use tokio::net::TcpListener;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::derp_server::{self, DerpListenerConfig, EmbeddedDerpOptions};

/// run the railscale control server
#[derive(Args, Debug)]
pub struct ServeCommand {
    /// database url (sqlite:// or postgres://)
    #[arg(long, env = "RAILSCALE_DATABASE_URL")]
    database_url: Option<String>,

    /// address to listen on
    #[arg(long, default_value = "0.0.0.0:8080", env = "RAILSCALE_LISTEN_ADDR")]
    listen_addr: String,

    /// server url (for client configuration)
    #[arg(
        long,
        default_value = "http://127.0.0.1:8080",
        env = "RAILSCALE_SERVER_URL"
    )]
    server_url: String,

    /// path to policy file (json grants)
    #[arg(long, env = "RAILSCALE_POLICY_FILE")]
    policy_file: Option<PathBuf>,

    /// path to Noise protocol private key
    #[arg(
        long,
        default_value = "/var/lib/railscale/noise_private.key",
        env = "RAILSCALE_NOISE_KEY"
    )]
    noise_key_path: PathBuf,

    /// base domain for MagicDNS
    #[arg(long, default_value = "railscale.net", env = "RAILSCALE_BASE_DOMAIN")]
    base_domain: String,

    /// ipv4 prefix (cidr)
    #[arg(long, default_value = "100.64.0.0/10", env = "RAILSCALE_PREFIX_V4")]
    prefix_v4: String,

    /// ipv6 prefix (cidr)
    #[arg(
        long,
        default_value = "fd7a:115c:a1e0::/48",
        env = "RAILSCALE_PREFIX_V6"
    )]
    prefix_v6: String,

    /// log level
    #[arg(long, default_value = "info", env = "RAILSCALE_LOG_LEVEL")]
    log_level: String,

    /// enable embedded derp relay server
    #[arg(long, default_value_t = false, env = "RAILSCALE_DERP_EMBEDDED_ENABLED")]
    derp_embedded_enabled: bool,

    /// derp region id to advertise
    #[arg(long, env = "RAILSCALE_DERP_REGION_ID")]
    derp_region_id: Option<i32>,

    /// derp region name to advertise
    #[arg(long, env = "RAILSCALE_DERP_REGION_NAME")]
    derp_region_name: Option<String>,

    /// derp listener address (host:port)
    #[arg(long, env = "RAILSCALE_DERP_LISTEN_ADDR")]
    derp_listen_addr: Option<String>,

    /// hostname or IP advertised to clients for derp
    #[arg(long, env = "RAILSCALE_DERP_ADVERTISE_HOST")]
    derp_advertise_host: Option<String>,

    /// port advertised to clients for derp
    #[arg(long, env = "RAILSCALE_DERP_ADVERTISE_PORT")]
    derp_advertise_port: Option<u16>,

    /// derp TLS certificate path
    #[arg(long, env = "RAILSCALE_DERP_CERT_PATH")]
    derp_cert_path: Option<PathBuf>,

    /// derp TLS private key path (PEM)
    #[arg(long, env = "RAILSCALE_DERP_TLS_KEY_PATH")]
    derp_tls_key_path: Option<PathBuf>,

    /// derp protocol private key path (curve25519)
    #[arg(long, env = "RAILSCALE_DERP_PRIVATE_KEY_PATH")]
    derp_private_key_path: Option<PathBuf>,
}

impl ServeCommand {
    /// convert cli arguments into a Config struct
    fn into_config(self) -> Result<Config> {
        let database = if let Some(db_url) = self.database_url {
            if db_url.starts_with("postgres://") {
                railscale_types::DatabaseConfig {
                    db_type: "postgres".to_string(),
                    connection_string: db_url,
                }
            } else if let Some(path) = db_url.strip_prefix("sqlite://") {
                railscale_types::DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    connection_string: path.to_string(),
                }
            } else {
                bail!("database URL must start with sqlite:// or postgres://");
            }
        } else {
            railscale_types::DatabaseConfig::default()
        };

        let mut config = Config {
            listen_addr: self.listen_addr,
            server_url: self.server_url,
            noise_private_key_path: self.noise_key_path,
            base_domain: self.base_domain,
            prefix_v4: Some(self.prefix_v4.parse().context("invalid IPv4 prefix")?),
            prefix_v6: Some(self.prefix_v6.parse().context("invalid IPv6 prefix")?),
            database,
            ..Default::default()
        };

        config.derp.embedded_derp.enabled = self.derp_embedded_enabled;
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
        // initialize logging
        let log_level = match self.log_level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        };

        let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
        tracing::subscriber::set_global_default(subscriber)?;

        info!("starting railscale...");

        // load policy if provided
        let policy = if let Some(policy_path) = &self.policy_file {
            info!("Loading policy from {:?}", policy_path);
            let policy_content = std::fs::read_to_string(policy_path)
                .with_context(|| format!("failed to read policy file: {:?}", policy_path))?;
            serde_json::from_str::<Policy>(&policy_content)
                .context("failed to parse policy file")?
        } else {
            warn!("No policy file provided, using empty policy (deny-all)");
            Policy { grants: vec![] }
        };

        let grants = GrantsEngine::new(policy);
        info!("Loaded policy with {} grants", grants.policy().grants.len());

        // load configuration
        let config = self.into_config()?;
        info!("Database: {}", config.database.connection_string);
        info!("Listen address: {}", config.listen_addr);
        info!("Server url: {}", config.server_url);

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
            info!("Setting up embedded derp server...");

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
            info!("derp keypair loaded");

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

            // parse listen address and spawn derp listener
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

        // build router
        let notifier = crate::StateNotifier::new();
        let app =
            crate::create_app(db, grants, config.clone(), None, notifier, Some(keypair)).await;

        // parse listen address
        let addr: SocketAddr = config
            .listen_addr
            .parse()
            .context("invalid listen address")?;

        info!("starting http server on {}", addr);

        // start server
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await.context("server error")?;

        Ok(())
    }
}

/// extract hostname from a url, stripping scheme and port
fn extract_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// extract port from an address string like "0.0.0.0:3340"
fn extract_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}
