//! database error types.

use thiserror::Error;

/// errors that can occur in database operations.
#[derive(Debug, Error)]
pub enum Error {
    /// entity not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// duplicate key/unique constraint violation.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// invalid data.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// migration error.
    #[error("migration error: {0}")]
    Migration(String),

    /// generic database error.
    #[error("database error: {0}")]
    Database(String),
}

impl From<sea_orm::DbErr> for Error {
    fn from(err: sea_orm::DbErr) -> Self {
        match &err {
            sea_orm::DbErr::RecordNotFound(msg) => Error::NotFound(msg.clone()),
            sea_orm::DbErr::Conn(e) => Error::Connection(e.to_string()),
            sea_orm::DbErr::ConnectionAcquire(e) => Error::Connection(e.to_string()),
            _ => Error::Database(err.to_string()),
        }
    }
}
