//! derp client verification endpoint handler.
//!
//! # Security Considerations
//! is registered with this control server before allowing relay connections.
//!**This endpoint is intentionally unauthenticated** for compatibility with
//! tailscale's `derper --verify-client-url` flag. The derp server calls this
//!endpoint to check if a client should be allowed to connect
//! **This endpoint is intentionally unauthenticated** for compatibility with
//! ## Deployment Recommendations
//! endpoint to check if a client should be allowed to connect.
//!since this endpoint has no authentication, it should be protected at the
//! network layer:
//!
//! 1. **Firewall rules**: Restrict access to only your derp server IPs
//! 2. **Reverse proxy ACLs**: If behind nginx/caddy, limit by source IP
//!3. **Internal network**: Deploy on a private network segment
//! 1. **Firewall rules**: Restrict access to only your DERP server IPs
//! ## Example nginx configuration
//! 3. **Internal network**: Deploy on a private network segment
//!```nginx
//! location /verify {
//!# Only allow from derp servers
//! allow 10.0.0.0/8;      # Internal network
//! allow 192.168.0.0/16;  # Local network
//! deny all;
//!     allow 10.0.0.0/8;      # Internal network
//! proxy_pass http://localhost:8080;
//! }
//!```
//!     proxy_pass http://localhost:8080;
//! ## Rate limiting
//! ```
//!this endpoint is covered by the protocol route body limit (64KB)
//! for additional protection, consider adding rate limiting at your
//!reverse proxy layer
//! this endpoint is covered by the protocol route body limit (64kb).
//! for additional protection, consider adding rate limiting at your
//! reverse proxy layer.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use railscale_db::Database;
use railscale_types::NodeKey;

/// request body for derp client verification.
///
/// matches `tailcfg.derpadmitclientrequest`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyRequest {
    /// the client's public node key.
    pub node_public: NodeKey,
    /// the client's ip address (informational).
    #[allow(dead_code)]
    pub source: String,
}

/// response for derp client verification.
///
/// matches `tailcfg.derpadmitclientresponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyResponse {
    /// whether to allow this client to connect to the derp server.
    pub allow: bool,
}

/// post /verify - verify a derp client is registered.
///
/// # Security
/// that a client's NodeKey is registered with this control server.
///this endpoint is **intentionally unauthenticated** for derp server
/// compatibility. Protect it via network-layer controls (firewalls,
///reverse proxy ACLs) rather than application-level authentication
/// see module documentation for deployment recommendations
/// compatibility. Protect it via network-layer controls (firewalls,
/// reverse proxy ACLs) rather than application-level authentication.
/// see module documentation for deployment recommendations.
pub async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    // check if the node key exists in the database
    let allow = state
        .db
        .get_node_by_node_key(&request.node_public)
        .await
        .map(|node| node.is_some())
        .unwrap_or(false);

    Json(VerifyResponse { allow })
}
