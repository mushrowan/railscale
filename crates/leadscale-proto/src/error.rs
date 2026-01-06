//! protocol error types.

use thiserror::Error;

/// errors that can occur in protocol operations.
#[derive(Debug, Error)]
pub enum Error {
    /// invalid protocol message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// noise protocol error.
    #[error("noise protocol error: {0}")]
    Noise(String),

    /// unsupported capability version.
    #[error("unsupported capability version: {0}")]
    UnsupportedVersion(u32),

    /// serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// authentication error.
    #[error("authentication error: {0}")]
    Authentication(String),

    /// connection error.
    #[error("connection error: {0}")]
    Connection(String),
}

impl From<snow::Error> for Error {
    fn from(err: snow::Error) -> Self {
        Error::Noise(err.to_string())
    }
}
