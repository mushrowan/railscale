//! handler for the `/key` endpoint.
//!
//! returns the server's noise public key for ts2021 protocol.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// a zero-valued 32-byte key (all zeros).
const ZERO_KEY: [u8; 32] = [0u8; 32];

/// legacy NaCl crypto_box machine key
///zero-valued for modern clients using Noise protocol
/// must still be formatted as "mkey:" + hex(32 zero bytes)
/// keys are serialized as strings with the `mkey:` prefix followed by hex-encoded bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse {
    /// legacy nacl crypto_box machine key.
    /// zero-valued for modern clients using noise protocol.
    /// format a public key as a tailscale machine key string
    pub legacy_public_key: String,

    /// server's noise public key (32 bytes, curve25519).
    /// serialized as "mkey:" + hex(32 bytes).
    pub public_key: String,
}

/// format a public key as a tailscale machine key string.
///
/// returns `"mkey:" + hex(key_bytes)`.
fn format_machine_public_key(key: &[u8]) -> String {
    format!("mkey:{}", hex::encode(key))
}

/// get /key - return the server's noise public key.
///
/// this endpoint is used by tailscale clients to obtain the server's
//legacy key is zero-valued (must still have mkey: prefix + 64 hex zeros)
pub async fn key(State(state): State<AppState>) -> Json<KeyResponse> {
    Json(KeyResponse {
        // legacy key is zero-valued (must still have mkey: prefix + 64 hex zeros)
        legacy_public_key: format_machine_public_key(&ZERO_KEY),
        public_key: format_machine_public_key(&state.noise_public_key),
    })
}
