//! state management error types

use thiserror::Error;

/// errors that can occur in state operations
#[derive(Debug, Error)]
pub enum Error {
    /// node not found
    #[error("node not found: {0}")]
    NodeNotFound(String),

    /// user not found
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// invalid node view
    #[error("invalid node view")]
    InvalidNodeView,

    /// database error
    #[error("database error: {0}")]
    Database(String),

    /// policy error
    #[error("policy error: {0}")]
    Policy(String),

    /// feature not yet implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),
}
