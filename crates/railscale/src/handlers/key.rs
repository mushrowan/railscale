//! handler for the `/key` endpoint.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::AppState;

/// a zero-valued 32-byte key (all zeros).
const ZERO_KEY: [u8; 32] = [0u8; 32];

/// response for the `/key` endpoint (matches tailscale's `overtlspublickeyresponse`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse {
    /// legacy nacl machine key, always zero for noise clients.
    pub legacy_public_key: String,

    /// server's noise public key (curve25519).
    pub public_key: String,
}

/// format a public key as `"mkey:" + hex(key_bytes)`.
fn format_machine_public_key(key: &[u8]) -> String {
    format!("mkey:{}", hex::encode(key))
}

/// get /key - return the server's noise public key.
pub async fn key(State(state): State<AppState>) -> Json<KeyResponse> {
    let public_key = format_machine_public_key(&state.noise_public_key);
    let key_prefix = &public_key[..14.min(public_key.len())];
    debug!(key_prefix = %key_prefix, "returning noise public key");
    Json(KeyResponse {
        legacy_public_key: format_machine_public_key(&ZERO_KEY),
        public_key,
    })
}
