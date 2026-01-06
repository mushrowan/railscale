//! error types for leadscale-types

use thiserror::Error;

/// errors that can occur in leadscale-types
#[derive(Debug, Error)]
pub enum Error {
    /// node addresses are invalid
    #[error("failed to parse node addresses")]
    NodeAddressesInvalid,

    /// hostname exceeds maximum length
    #[error("hostname too long, cannot exceed 255 ASCII chars")]
    HostnameTooLong,

    /// node has no given name
    #[error("node has no given name")]
    NodeHasNoGivenName,

    /// node user has no name
    #[error("node user has no name")]
    NodeUserHasNoName,

    /// cannot remove all tags from a tagged node
    #[error("cannot remove all tags from node")]
    CannotRemoveAllTags,

    /// invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// invalid ip
    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// configuration error
    #[error("configuration error: {0}")]
    Config(String),
}
