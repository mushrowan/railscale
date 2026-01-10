//! railscale - Tailscale control server in Rust.
//!
//! a reimplementation of headscale focusing on:
//! - Grants-based access control (instead of ACLs)
//! - Modern Rust idioms
//! - Clean, testable architecture

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;
use tokio::net::TcpListener;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

/// railscale - Tailscale control server in Rust
#[derive(Parser, Debug)]
#[command(name = "railscale")]
#[command(about = "Self-hosted Tailscale control server", long_about = None)]
struct Cli {
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

    /// path to noise protocol private key
    #[arg(
        long,
        default_value = "/var/lib/railscale/noise_private.key",
        env = "RAILSCALE_NOISE_KEY"
    )]
    noise_key_path: PathBuf,

    /// base domain for magicdns
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
}

impl Cli {
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

        let config = Config {
            listen_addr: self.listen_addr,
            server_url: self.server_url,
            noise_private_key_path: self.noise_key_path,
            base_domain: self.base_domain,
            prefix_v4: Some(self.prefix_v4.parse().context("invalid IPv4 prefix")?),
            prefix_v6: Some(self.prefix_v6.parse().context("invalid IPv6 prefix")?),
            database,
            ..Default::default()
        };

        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
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

    // load policy if provided
    let policy = if let Some(policy_path) = &cli.policy_file {
        info!("Loading policy from {:?}", policy_path);
        let policy_content = std::fs::read_to_string(policy_path)
            .with_context(|| format!("failed to read policy file: {:?}", policy_path))?;
        serde_json::from_str::<Policy>(&policy_content).context("failed to parse policy file")?
    } else {
        warn!("No policy file provided, using empty policy (deny-all)");
        Policy { grants: vec![] }
    };

    let grants = GrantsEngine::new(policy);
    info!("Loaded policy with {} grants", grants.policy().grants.len());

    // load configuration
    let config = cli.into_config()?;
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
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create database directory: {:?}", parent))?;
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
    let keypair = railscale::load_or_generate_noise_keypair(&config.noise_private_key_path)
        .await
        .with_context(|| {
            format!(
                "failed to load/generate noise keypair: {:?}",
                config.noise_private_key_path
            )
        })?;
    info!("Noise public key loaded ({} bytes)", keypair.public.len());

    // build router
    let notifier = railscale::StateNotifier::new();
    let app =
        railscale::create_app(db, grants, config.clone(), None, notifier, Some(keypair)).await;

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
