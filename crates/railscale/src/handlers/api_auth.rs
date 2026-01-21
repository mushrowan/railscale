//! api key authentication for REST endpoints
//!
//! this module provides Bearer token authentication for the admin REST api
//! api keys use a split-token pattern: `rsapi_{selector}_{verifier}`
//!
//! ## Authentication Flow
//!
//! 1. Extract `Authorization: Bearer <token>` header
//! 2. Parse token to extract selector
//! 3. Look up api key by selector in database
//! 4. Verify the token against stored hash (constant-time)
//! 5. Check expiration and soft-delete status
//! 6. Update `last_used_at` timestamp

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
};
use railscale_db::Database;
use railscale_types::{ApiKey, User, UserId};

use crate::AppState;

/// authentication method for the api
/// future-proofs for SSO/oidc authentication
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// authenticated via api key
    ApiKey {
        /// the api key id
        key_id: u64,
        /// the user id who owns this key
        user_id: UserId,
    },
    // future: OidcToken { subject: String, issuer: String },
}

/// context for authenticated api requests
///
/// this is extracted from the `Authorization: Bearer <token>` header
/// and contains information about the authenticated user
#[derive(Debug, Clone)]
pub struct ApiKeyContext {
    /// how the user authenticated
    pub method: AuthMethod,
    /// the authenticated user
    pub user: User,
    /// the api key used (for auditing)
    pub api_key: ApiKey,
}

impl ApiKeyContext {
    /// get the user id
    pub fn user_id(&self) -> UserId {
        self.user.id
    }
}

/// error type for api authentication failures
#[derive(Debug)]
pub enum ApiAuthError {
    /// missing Authorization header
    MissingHeader,
    /// invalid Authorization header format
    InvalidHeader,
    /// invalid token format
    InvalidToken,
    /// token not found or invalid
    InvalidCredentials,
    /// token has expired
    Expired,
    /// database error
    Internal(String),
}

impl ApiAuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingHeader | Self::InvalidHeader | Self::InvalidToken => {
                StatusCode::UNAUTHORIZED
            }
            Self::InvalidCredentials | Self::Expired => StatusCode::UNAUTHORIZED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::MissingHeader => "missing Authorization header",
            Self::InvalidHeader => "invalid Authorization header format",
            Self::InvalidToken => "invalid token format",
            Self::InvalidCredentials => "invalid credentials",
            Self::Expired => "token has expired",
            Self::Internal(_) => "internal server error",
        }
    }
}

impl axum::response::IntoResponse for ApiAuthError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let message = self.message().to_string();
        (status, message).into_response()
    }
}

/// parse a Bearer token from the Authorization header
fn parse_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ").map(str::trim)
}

/// extract the selector from an api key token
/// token format: `rsapi_{selector}_{verifier}`
fn extract_selector(token: &str) -> Option<&str> {
    let without_prefix = token.strip_prefix("rsapi_")?;
    let (selector, _verifier) = without_prefix.split_once('_')?;
    Some(selector)
}

impl FromRequestParts<AppState> for ApiKeyContext {
    type Rejection = ApiAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // extract Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(ApiAuthError::MissingHeader)?
            .to_str()
            .map_err(|_| ApiAuthError::InvalidHeader)?;

        // parse Bearer token
        let token = parse_bearer_token(auth_header).ok_or(ApiAuthError::InvalidHeader)?;

        // extract selector from token
        let selector = extract_selector(token).ok_or(ApiAuthError::InvalidToken)?;

        // look up api key by selector
        let api_key = state
            .db
            .get_api_key_by_selector(selector)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or(ApiAuthError::InvalidCredentials)?;

        // verify the token
        if !api_key.verify(token) {
            return Err(ApiAuthError::InvalidCredentials);
        }

        // check expiration
        if api_key.is_expired() {
            return Err(ApiAuthError::Expired);
        }

        // get the user
        let user = state
            .db
            .get_user(api_key.user_id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or(ApiAuthError::InvalidCredentials)?;

        // update last_used_at (fire and forget)
        let db = state.db.clone();
        let key_id = api_key.id;
        tokio::spawn(async move {
            let _ = db.touch_api_key(key_id).await;
        });

        Ok(ApiKeyContext {
            method: AuthMethod::ApiKey {
                key_id: api_key.id,
                user_id: api_key.user_id,
            },
            user,
            api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bearer_token_valid() {
        assert_eq!(parse_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(
            parse_bearer_token("Bearer rsapi_selector_verifier"),
            Some("rsapi_selector_verifier")
        );
    }

    #[test]
    fn test_parse_bearer_token_with_whitespace() {
        assert_eq!(parse_bearer_token("Bearer  abc123 "), Some("abc123"));
    }

    #[test]
    fn test_parse_bearer_token_invalid() {
        assert_eq!(parse_bearer_token("Basic abc123"), None);
        assert_eq!(parse_bearer_token("bearer abc123"), None); // case sensitive
        assert_eq!(parse_bearer_token("Bearerabc123"), None); // no space
        assert_eq!(parse_bearer_token(""), None);
    }

    #[test]
    fn test_extract_selector_valid() {
        assert_eq!(extract_selector("rsapi_abc123_xyz789"), Some("abc123"));
        assert_eq!(
            extract_selector("rsapi_0123456789abcdef_fedcba9876543210"),
            Some("0123456789abcdef")
        );
    }

    #[test]
    fn test_extract_selector_invalid() {
        assert_eq!(extract_selector("rsapi_"), None); // no verifier
        assert_eq!(extract_selector("rsapi_abc123"), None); // no underscore after selector
        assert_eq!(extract_selector("abc_123_456"), None); // wrong prefix
        assert_eq!(extract_selector(""), None);
    }

    #[test]
    fn test_api_auth_error_status_codes() {
        assert_eq!(
            ApiAuthError::MissingHeader.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiAuthError::InvalidHeader.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiAuthError::InvalidToken.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiAuthError::InvalidCredentials.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiAuthError::Expired.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiAuthError::Internal("err".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
