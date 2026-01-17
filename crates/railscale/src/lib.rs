//! railscale library - HTTP handlers and application setup.
//!this crate provides the http server and handlers for the railscale control server:
//! - [`handlers`]: http request handlers for tailscale protocol endpoints
//! - [`cli`]: Command-line interface implementation
//! - [`oidc`]: OpenID Connect authentication provider
//! - [`derp`]: derp relay map management
//! - [`derp_server`]: Embedded derp relay server
//! - [`resolver`]: Grants-based access control resolver
//! - [`resolver`]: Grants-based access control resolver

#![warn(missing_docs)]

/// embedded derp relay server implementation
pub mod cli;
/// openID Connect authentication provider
pub mod derp;
/// embedded derp relay server implementation.
pub mod derp_server;
mod dns;
/// http request handlers for tailscale protocol endpoints.
pub mod handlers;
mod noise_stream;
mod notifier;
/// openid connect authentication provider.
pub mod oidc;
/// grants-based access control resolver.
pub mod resolver;

pub use derp::{
    DerpError, fetch_derp_map_from_url, generate_derp_map, load_derp_map_from_path, merge_derp_maps,
};
pub use noise_stream::NoiseStream;
pub use notifier::StateNotifier;
pub use railscale_proto::Keypair;

use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use railscale_db::{Database, IpAllocator, RailscaleDb};
use railscale_grants::GrantsEngine;
use railscale_types::Config;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// database connection for persistent storage
#[derive(Clone)]
pub struct AppState {
    /// oidc authentication provider (None if oidc is disabled)
    pub db: RailscaleDb,
    /// grants engine for access control evaluation.
    pub grants: GrantsEngine,
    /// server configuration.
    pub config: Config,
    /// oidc authentication provider (none if oidc is disabled).
    pub oidc: Option<oidc::AuthProviderOidc>,
    /// notifier for broadcasting state changes to connected clients.
    pub notifier: StateNotifier,
    /// ip address allocator for new nodes.
    pub ip_allocator: Arc<Mutex<IpAllocator>>,
    /// server's noise public key for ts2021 protocol.
    pub noise_public_key: Vec<u8>,
    /// server's noise private key for ts2021 protocol handshakes.
    pub noise_private_key: Vec<u8>,
}

/// load a noise keypair from file, or generate and save a new one.
///
/// if the file exists, reads the 64-byte keypair (32 private + 32 public).
/// if the file does not exist, generates a new keypair and saves it.
///
/// # Arguments
/// * `path` - Path to the key file
///
/// # Returns
/// the loaded or generated keypair.
pub async fn load_or_generate_noise_keypair(path: &Path) -> std::io::Result<Keypair> {
    if path.exists() {
        // load existing key
        let data = fs::read(path).await?;
        if data.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("noise key file should be 64 bytes, got {}", data.len()),
            ));
        }
        Ok(Keypair {
            private: data[..32].to_vec(),
            public: data[32..].to_vec(),
        })
    } else {
        // generate new keypair
        let keypair = railscale_proto::generate_keypair()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // write keypair: private (32 bytes) + public (32 bytes)
        let mut file = fs::File::create(path).await?;
        file.write_all(&keypair.private).await?;
        file.write_all(&keypair.public).await?;
        file.sync_all().await?;

        Ok(keypair)
    }
}

/// create the axum application with all routes.
///
/// if `keypair` is none, a new keypair will be generated (not persisted).
pub async fn create_app(
    db: RailscaleDb,
    grants: GrantsEngine,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
) -> Router {
    // generate keypair if not provided
    let keypair = keypair.unwrap_or_else(|| {
        railscale_proto::generate_keypair().expect("failed to generate noise keypair")
    });

    // initialize ip allocator with configured prefixes
    let mut ip_allocator = IpAllocator::new(config.prefix_v4, config.prefix_v6);

    // load already-allocated ips from the database
    if let Ok(nodes) = db.list_nodes().await {
        let allocated_ips: Vec<std::net::IpAddr> = nodes
            .iter()
            .flat_map(|n| [n.ipv4, n.ipv6])
            .flatten()
            .collect();
        ip_allocator.load_allocated(allocated_ips);
    }

    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
        ip_allocator: Arc::new(Mutex::new(ip_allocator)),
        noise_public_key: keypair.public,
        noise_private_key: keypair.private,
    };

    Router::new()
        .route("/key", get(handlers::key))
        .route(
            "/ts2021",
            get(handlers::ts2021).post(handlers::ts2021_http_upgrade),
        )
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .route(
            "/register/{registration_id}",
            get(handlers::oidc::register_redirect),
        )
        .route("/oidc/callback", get(handlers::oidc::oidc_callback))
        .with_state(state)
}
