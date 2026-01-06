//! db error types

use thiserror::Error;

/// database operation errors
#[derive(Debug, Error)]
pub enum Error {
    /// entity not found
    #[error("not found: {0}")]
    NotFound(String),

    /// duplicate key/unique constraint violation
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// invalid data
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// migration error
    #[error("migration error: {0}")]
    Migration(String),

    /// generic
    #[error("database error: {0}")]
    Database(String),
}
