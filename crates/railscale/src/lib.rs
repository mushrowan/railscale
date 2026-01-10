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
}

/// create the axum application with all routes.
pub async fn create_app(
    db: RailscaleDb,
    grants: GrantsEngine,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
) -> Router {
    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
    };

    Router::new()
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .route(
            "/register/{registration_id}",
            get(handlers::oidc::register_redirect),
        )
        .route("/oidc/callback", get(handlers::oidc::oidc_callback))
        .with_state(state)
}
