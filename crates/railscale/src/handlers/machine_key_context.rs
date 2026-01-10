//! machine key context for authenticated noise connections.
//!
//! this module provides the [`machinekeycontext`] type that carries the
//! client's machine key (static public key) from the Noise handshake
//! to HTTP handlers.

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use railscale_types::MachineKey;

/// context containing the machine key from the noise handshake.
///
/// this is inserted into request extensions by the ts2021 handler
/// after completing the Noise handshake. Handlers can extract this
/// to get the authenticated machine key without trusting the request body.
#[derive(Debug, Clone)]
pub struct MachineKeyContext(pub MachineKey);

impl MachineKeyContext {
    /// create a new machine key context from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(MachineKey::from_bytes(bytes))
    }

    /// get the machine key.
    pub fn machine_key(&self) -> &MachineKey {
        &self.0
    }
}

impl<S> FromRequestParts<S> for MachineKeyContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<MachineKeyContext>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing machine key context - request must come through ts2021 handler",
        ))
    }
}

/// optional machine key context that returns none when not present.
///
/// use this in handlers that may be called both via ts2021 (with context)
/// and via direct HTTP (without context).
#[derive(Debug, Clone)]
pub struct OptionalMachineKeyContext(pub Option<MachineKeyContext>);

impl<S> FromRequestParts<S> for OptionalMachineKeyContext
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<MachineKeyContext>().cloned()))
    }
}
