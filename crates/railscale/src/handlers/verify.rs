//! derp client verification endpoint handler
//!
//! this endpoint is called by derp servers to verify that a client
//! is registered with this control server before allowing relay connections

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use railscale_db::Database;
use railscale_types::NodeKey;

/// request body for derp client verification
///
/// matches `tailcfg.DERPAdmitClientRequest`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyRequest {
    /// the client's public node key
    pub node_public: NodeKey,
    /// the client's ip (informational)
    #[allow(dead_code)]
    pub source: String,
}

/// response for derp client verification
///
/// matches `tailcfg.DERPAdmitClientResponse`
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyResponse {
    /// whether to allow this client to connect to the derp server
    pub allow: bool,
}

/// pOST /verify - Verify a derp client is registered
///
/// called by derp servers with `--verify-clients` enabled to check
/// that a client's NodeKey is registered with this control server
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
