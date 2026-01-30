//! tailnet key authority (TKA) implementation for railscale.
//!
//! this crate provides types and logic for tailnet lock, including:
//! - cryptographic primitives (ed25519 signing, blake2s hashing)
//! - TKA data structures (AUM, NodeKeySignature, etc.)
//! - signature verification and state management

pub mod aum_hash;
pub mod error;
pub mod nl_key;

pub use aum_hash::AumHash;
pub use error::Error;
pub use nl_key::{NlPrivateKey, NlPublicKey};

/// result type for TKA operations.
pub type Result<T> = std::result::Result<T, Error>;
