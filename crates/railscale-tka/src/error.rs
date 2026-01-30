//! error types for TKA operations.

use thiserror::Error;

/// errors that can occur during TKA operations.
#[derive(Debug, Error)]
pub enum Error {
    /// invalid key length
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// invalid hash length
    #[error("invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    /// invalid hex encoding
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// cbor encoding/decoding error
    #[error("cbor error: {0}")]
    Cbor(String),

    /// signature verification failed
    #[error("signature verification failed")]
    InvalidSignature,

    /// AUM chain is invalid (prev_aum_hash doesn't match)
    #[error("invalid AUM chain: prev_aum_hash doesn't match current head")]
    InvalidAumChain,

    /// missing required field in AUM
    #[error("missing required AUM field: {0}")]
    MissingAumField(&'static str),

    /// AUM has no signatures
    #[error("AUM has no signatures")]
    MissingSignature,
}
