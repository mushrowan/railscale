//! health check endpoint handler

use std::time::Duration;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tokio::time::timeout;

use crate::AppState;
use railscale_db::Database;

/// health check response body
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// content-Type for health check responses per RFC 8040
const HEALTH_CONTENT_TYPE: &str = "application/health+json; charset=utf-8";

/// timeout for database ping (1 second, matching headscale)
const PING_TIMEOUT: Duration = Duration::from_secs(1);

/// gET /health - Health check endpoint
///
/// checks database connectivity with a 1-second timeout
/// returns 200 OK with `{"status": "pass"}` if healthy,
/// or 500 Internal Server Error with `{"status": "fail"}` if unhealthy
pub async fn health(State(state): State<AppState>) -> Response {
    let ping_result = timeout(PING_TIMEOUT, state.db.ping()).await;

    let (status_code, health_status) = match ping_result {
        Ok(Ok(())) => (StatusCode::OK, "pass"),
        Ok(Err(_)) | Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "fail"),
    };

    let response = HealthResponse {
        status: health_status,
    };

    (
        status_code,
        [(header::CONTENT_TYPE, HEALTH_CONTENT_TYPE)],
        Json(response),
    )
        .into_response()
}
