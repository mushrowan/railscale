//! tS2021 protocol handler for tailscale clients
//!
//! this module implements the `/ts2021` endpoint that handles
//! webSocket upgrades and Noise protocol handshakes for the
//! tailscale control protocol

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    response::Response,
};
use serde::Deserialize;

use crate::AppState;

/// query parameters for the /ts2021 endpoint
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Ts2021Params {
    /// base64-encoded Noise handshake initiation message
    #[serde(rename = "X-Tailscale-Handshake")]
    pub handshake: Option<String>,
}

/// handle TS2021 protocol upgrade requests
///
/// this endpoint accepts websocket upgrades and performs the noise
/// protocol handshake to establish an encrypted connection
///
/// if no websocket upgrade header is present, axum's extractor will
/// automatically return a 400 Bad Request with an appropriate message
pub async fn ts2021(
    State(_state): State<AppState>,
    ws: WebSocketUpgrade,
    Query(params): Query<Ts2021Params>,
) -> Response {
    // for now, just accept the upgrade - actual handshake will be implemented next
    let _handshake_data = params.handshake;

    ws.protocols(["tailscale-control-protocol"])
        .on_upgrade(|socket| async move {
            // TODO: perform noise handshake and serve http/2
            let _ = socket;
        })
}
