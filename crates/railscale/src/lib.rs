//! railscale library - HTTP handlers and application setup.

mod derp;
mod dns;
pub mod handlers;
mod notifier;
pub mod oidc;
pub mod resolver;

pub use notifier::StateNotifier;
pub use railscale_proto::Keypair;

use axum::{
    Router,
    routing::{get, post},
};
use railscale_db::RailscaleDb;
use railscale_grants::GrantsEngine;
use railscale_types::Config;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: RailscaleDb,
    pub grants: GrantsEngine,
    pub config: Config,
    pub oidc: Option<oidc::AuthProviderOidc>,
    pub notifier: StateNotifier,
    /// server's noise public key for ts2021 protocol.
    pub noise_public_key: Vec<u8>,
    /// server's noise private key for ts2021 protocol handshakes.
    pub noise_private_key: Vec<u8>,
}

/// if the file does not exist, generates a new keypair and saves it
///
/// # Arguments
/// * `path` - Path to the key file
///
/// # Returns
/// the loaded or generated keypair
///
/// # Returns
//load existing key
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

    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
        noise_public_key: keypair.public,
        noise_private_key: keypair.private,
    };

    Router::new()
        .route("/key", get(handlers::key))
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .route(
            "/register/{registration_id}",
            get(handlers::oidc::register_redirect),
        )
        .route("/oidc/callback", get(handlers::oidc::oidc_callback))
        .with_state(state)
}
