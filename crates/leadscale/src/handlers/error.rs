//! api error handling for http handlers

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// api error type for handler responses
#[derive(Debug)]
pub enum ApiError {
    /// internal server error (500)
    Internal(String),
    /// unauthorized error (401)
    Unauthorized(String),
    /// not found error (404)
    NotFound(String),
}

impl ApiError {
    /// create internal server error from any error type
    pub fn internal(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }

    /// create unauthorized error
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    /// create not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };
        (status, message).into_response()
    }
}

/// extension trait for converting results to apierror
pub trait ResultExt<T> {
    /// convert error to internal server error
    fn map_internal(self) -> Result<T, ApiError>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn map_internal(self) -> Result<T, ApiError> {
        self.map_err(ApiError::internal)
    }
}

/// extension trait for converting options to apierror
pub trait OptionExt<T> {
    /// convert none to unauthorized error
    fn or_unauthorized(self, msg: &str) -> Result<T, ApiError>;
    /// convert none to not found error
    fn or_not_found(self, msg: &str) -> Result<T, ApiError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_unauthorized(self, msg: &str) -> Result<T, ApiError> {
        self.ok_or_else(|| ApiError::unauthorized(msg))
    }

    fn or_not_found(self, msg: &str) -> Result<T, ApiError> {
        self.ok_or_else(|| ApiError::not_found(msg))
    }
}
