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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn from_bytes_creates_context() {
        let bytes = vec![42u8; 32];
        let ctx = MachineKeyContext::from_bytes(bytes.clone());
        assert_eq!(ctx.machine_key().as_bytes(), &bytes);
    }

    #[test]
    fn machine_key_accessor() {
        let key = MachineKey::from_bytes(vec![1u8; 32]);
        let ctx = MachineKeyContext(key.clone());
        assert_eq!(ctx.machine_key(), &key);
    }

    #[test]
    fn context_is_clone() {
        let ctx = MachineKeyContext::from_bytes(vec![7u8; 32]);
        let cloned = ctx.clone();
        assert_eq!(
            ctx.machine_key().as_bytes(),
            cloned.machine_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn extract_from_request_with_extension() {
        let key_bytes = vec![99u8; 32];
        let ctx = MachineKeyContext::from_bytes(key_bytes.clone());

        let mut request = Request::builder().body(()).unwrap();
        request.extensions_mut().insert(ctx);

        let (mut parts, _) = request.into_parts();
        let extracted = MachineKeyContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(extracted.machine_key().as_bytes(), &key_bytes);
    }

    #[tokio::test]
    async fn extract_without_extension_returns_500() {
        let request = Request::builder().body(()).unwrap();
        let (mut parts, _) = request.into_parts();

        let result = MachineKeyContext::from_request_parts(&mut parts, &()).await;
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(msg.contains("missing machine key context"));
    }

    #[tokio::test]
    async fn optional_extract_with_extension() {
        let ctx = MachineKeyContext::from_bytes(vec![55u8; 32]);

        let mut request = Request::builder().body(()).unwrap();
        request.extensions_mut().insert(ctx);

        let (mut parts, _) = request.into_parts();
        let extracted = OptionalMachineKeyContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert!(extracted.0.is_some());
        assert_eq!(
            extracted.0.unwrap().machine_key().as_bytes(),
            &vec![55u8; 32]
        );
    }

    #[tokio::test]
    async fn optional_extract_without_extension_returns_none() {
        let request = Request::builder().body(()).unwrap();
        let (mut parts, _) = request.into_parts();

        let extracted = OptionalMachineKeyContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert!(extracted.0.is_none());
    }
}
