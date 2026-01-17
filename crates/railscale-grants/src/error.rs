//! error types for railscale-grants.

use thiserror::Error;

/// errors that can occur in railscale-grants.
#[derive(Debug, Error)]
pub enum Error {
    /// failed to parse json policy.
    #[error("failed to parse policy JSON: {0}")]
    ParseJson(#[from] serde_json::Error),

    /// the zero-based index of the invalid grant in the policy
    #[error("invalid grant at index {index}: {cause}")]
    InvalidGrant {
        /// the zero-based index of the invalid grant in the policy.
        index: usize,
        /// the specific validation error.
        cause: ValidationError,
    },

    /// failed to parse selector.
    #[error("failed to parse selector: {0}")]
    ParseSelector(#[from] ParseError),
}

/// grant has no source selectors
///grant has no destination selectors
/// grant has neither IP nor app capabilities
#[derive(Debug, Error)]
pub enum ValidationError {
    /// these errors indicate syntax problems in selector or capability strings
    #[error("src cannot be empty")]
    EmptySrc,

    /// port number is not a valid u16 or port range is invalid
    #[error("dst cannot be empty")]
    EmptyDst,

    /// grant has neither ip nor app capabilities.
    #[error("grant must have ip or app capabilities")]
    NoCapabilities,

    /// via selector is not a tag (only tags allowed for transit).
    #[error("via must contain only tags, got: {0}")]
    InvalidVia(String),
}

/// parse errors for selectors and capabilities.
///
/// these errors indicate syntax problems in selector or capability strings.
#[derive(Debug, Error)]
pub enum ParseError {
    /// unknown autogroup name (not `member`, `tagged`, `internet`, etc.).
    #[error("unknown autogroup: {0}")]
    UnknownAutogroup(String),

    /// invalid cidr notation for ip-based selector.
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),

    /// selector string doesn't match any known format.
    #[error("unknown selector format: {0}")]
    UnknownSelector(String),

    /// port number is not a valid u16 or port range is invalid.
    #[error("invalid port number")]
    InvalidPort,

    /// unknown protocol name (not `tcp`, `udp`, `icmp`, etc.).
    #[error("unknown protocol: {0}")]
    UnknownProtocol(String),
}

/// result type for railscale-grants operations.
pub type Result<T> = std::result::Result<T, Error>;
