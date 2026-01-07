//! error types for leadscale-grants

use thiserror::Error;

/// errors that can occur in leadscale-grants
#[derive(Debug, Error)]
pub enum Error {
    /// failed to parse json policy
    #[error("failed to parse policy JSON: {0}")]
    ParseJson(#[from] serde_json::Error),

    /// invalid grant at given index
    #[error("invalid grant at index {index}: {cause}")]
    InvalidGrant {
        index: usize,
        cause: ValidationError,
    },

    /// failed to parse selector
    #[error("failed to parse selector: {0}")]
    ParseSelector(#[from] ParseError),
}

/// validation errors for grants
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("src cannot be empty")]
    EmptySrc,

    #[error("dst cannot be empty")]
    EmptyDst,

    #[error("grant must have ip or app capabilities")]
    NoCapabilities,

    #[error("via must contain only tags, got: {0}")]
    InvalidVia(String),
}

/// parse errors for selectors and capabilities
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unknown autogroup: {0}")]
    UnknownAutogroup(String),

    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("unknown selector format: {0}")]
    UnknownSelector(String),

    #[error("invalid port number")]
    InvalidPort,

    #[error("unknown protocol: {0}")]
    UnknownProtocol(String),
}

/// result type for leadscale-grants operations
pub type Result<T> = std::result::Result<T, Error>;
