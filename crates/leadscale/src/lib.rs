//! leadscale library - http handlers and application setup.

pub mod handlers;

use axum::{routing::post, Router};
use leadscale_db::LeadscaleDb;
use leadscale_grants::GrantsEngine;

/// application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: LeadscaleDb,
    pub grants: GrantsEngine,
}

/// create the axum application with all routes.
pub async fn create_app(db: LeadscaleDb, grants: GrantsEngine) -> Router {
    let state = AppState { db, grants };

    Router::new()
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .with_state(state)
}
