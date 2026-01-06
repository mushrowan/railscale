//! leadscale library - http handlers and application setup

pub mod handlers;

use axum::{routing::post, Router};
use leadscale_db::LeadscaleDb;

/// application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: LeadscaleDb,
}

/// create the axum application with all routes
pub async fn create_app(db: LeadscaleDb) -> Router {
    let state = AppState { db };

    Router::new()
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .with_state(state)
}
