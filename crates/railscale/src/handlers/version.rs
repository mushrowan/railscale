//! version endpoint handler

use axum::Json;
use serde::Serialize;

/// version information response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    /// crate version from Cargo.toml
    pub version: &'static str,
    /// git commit SHA (short)
    pub commit: &'static str,
    /// build timestamp (RFC 3339)
    pub build_time: &'static str,
    /// rust compiler version
    pub rustc: &'static str,
    /// whether the git working tree was dirty at build time
    pub dirty: bool,
}

/// gET /version - Returns build and version information
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        commit: env!("RAILSCALE_GIT_SHA"),
        build_time: env!("RAILSCALE_BUILD_TIMESTAMP"),
        rustc: env!("RAILSCALE_RUSTC_VERSION"),
        dirty: env!("RAILSCALE_GIT_DIRTY") == "true",
    })
}
