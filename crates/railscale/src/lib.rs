//! railscale library - HTTP handlers and application setup.

mod derp;
mod dns;
pub mod handlers;
pub mod resolver;

use axum::{Router, routing::post};
use railscale_db::RailscaleDb;
use railscale_grants::GrantsEngine;
use railscale_types::Config;

/// application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: RailscaleDb,
    pub grants: GrantsEngine,
    pub config: Config,
}

/// create the axum application with all routes.
pub async fn create_app(db: RailscaleDb, grants: GrantsEngine, config: Config) -> Router {
    let state = AppState { db, grants, config };

    Router::new()
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .with_state(state)
}
