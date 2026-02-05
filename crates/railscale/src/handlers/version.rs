//! version endpoint handler

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::AppState;

/// version information response (full)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    /// crate version from Cargo.toml
    pub version: &'static str,
    /// git commit SHA (short)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<&'static str>,
    /// build timestamp (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time: Option<&'static str>,
    /// rust compiler version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc: Option<&'static str>,
    /// whether the git working tree was dirty at build time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

/// GET /version - returns build and version information
pub async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    if state.config.hide_build_metadata {
        Json(VersionResponse {
            version: env!("CARGO_PKG_VERSION"),
            commit: None,
            build_time: None,
            rustc: None,
            dirty: None,
        })
    } else {
        Json(VersionResponse {
            version: env!("CARGO_PKG_VERSION"),
            commit: Some(env!("RAILSCALE_GIT_SHA")),
            build_time: Some(env!("RAILSCALE_BUILD_TIMESTAMP")),
            rustc: Some(env!("RAILSCALE_RUSTC_VERSION")),
            dirty: Some(env!("RAILSCALE_GIT_DIRTY") == "true"),
        })
    }
}
