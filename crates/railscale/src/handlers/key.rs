//! handler for the `/key` endpoint
//!
//! returns the server's Noise public key for TS2021 protocol

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// response for the `/key` endpoint
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse {
    /// server's Noise public key (32 bytes, curve25519)
    pub public_key: Vec<u8>,
}

/// gET /key - Return the server's Noise public key
///
/// this endpoint is used by tailscale clients to obtain the server's
/// static public key before initiating the TS2021 Noise handshake
pub async fn key(State(state): State<AppState>) -> Json<KeyResponse> {
    Json(KeyResponse {
        public_key: state.noise_public_key.clone(),
    })
}
