//! tailnet key authority (TKA) implementation for railscale.
//!
//! this crate provides types and logic for tailnet lock, including:
//! - cryptographic primitives (ed25519 signing, blake2s hashing)
//! - TKA data structures (AUM, NodeKeySignature, etc.)
//! - signature verification and state management

pub mod aum_hash;
pub mod disablement;
pub mod error;
pub mod key;
pub mod key_id;
pub mod marshaled;
pub mod nl_key;
pub mod signature;

pub use aum_hash::AumHash;
pub use disablement::DisablementSecret;
pub use error::Error;
pub use key::{Key, KeyKind};
pub use key_id::TkaKeyId;
pub use marshaled::{MarshaledAum, MarshaledSignature};
pub use nl_key::{NlPrivateKey, NlPublicKey};
pub use signature::{NodeKeySignature, SigKind};

/// result type for TKA operations.
pub type Result<T> = std::result::Result<T, Error>;
