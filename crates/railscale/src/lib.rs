//! railscale library - HTTP handlers and application setup.

mod derp;
mod dns;
pub mod handlers;
mod notifier;
pub mod oidc;
pub mod resolver;

pub use notifier::StateNotifier;

use axum::{
    Router,
    routing::{get, post},
};
use railscale_db::RailscaleDb;
use railscale_grants::GrantsEngine;
use railscale_types::Config;

/// application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: RailscaleDb,
    pub grants: GrantsEngine,
    pub config: Config,
    pub oidc: Option<oidc::AuthProviderOidc>,
    pub notifier: StateNotifier,
    /// if `noise_public_key` is None, a new keypair will be generated
    pub noise_public_key: Vec<u8>,
}

/// create the axum application with all routes.
///
/// if `noise_public_key` is none, a new keypair will be generated.
pub async fn create_app(
    db: RailscaleDb,
    grants: GrantsEngine,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    noise_public_key: Option<Vec<u8>>,
) -> Router {
    // generate keypair if not provided
    let noise_public_key = noise_public_key.unwrap_or_else(|| {
        railscale_proto::generate_keypair()
            .expect("failed to generate noise keypair")
            .public
    });

    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
        noise_public_key,
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
