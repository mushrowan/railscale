//! api error handling for http handlers.

use axum::{
    Json,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::error;

/// api error type for handler responses.
#[derive(Debug)]
pub enum ApiError {
    /// internal server error (500). The string is logged but NOT exposed to clients.
    Internal(String),
    /// unauthorized error (401).
    Unauthorized(String),
    /// not found error (404).
    NotFound(String),
    /// bad request error (400).
    BadRequest(String),
    /// forbidden error (403).
    Forbidden(String),
    /// conflict error (409).
    Conflict(String),
}

impl ApiError {
    /// create an internal server error from any error type.
    /// the error is logged but a generic message is returned to clients.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        error!(error = %e, "Internal server error");
        Self::Internal(e.to_string())
    }

    /// create an unauthorized error.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    /// create a not found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// create a bad request error.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// create a forbidden error (e.g., invalid credentials).
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    /// create a conflict error (e.g., resource already exists).
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_label, message) = match self {
            // don't expose internal error details to clients
            ApiError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
                "internal server error".to_string(),
            ),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not found", msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad request", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
        };
        (
            status,
            Json(json!({ "error": error_label, "message": message })),
        )
            .into_response()
    }
}

/// json extractor that returns ApiError on deserialization failure
/// instead of axum's default plain text rejection
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => Err(ApiError::bad_request(rejection.body_text())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::header::CONTENT_TYPE;

    async fn response_json(error: ApiError) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .expect("should have content-type")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            ct.contains("application/json"),
            "content-type should be application/json, got: {ct}"
        );
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_bad_request_returns_json() {
        let (status, json) = response_json(ApiError::bad_request("invalid field")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "bad request");
        assert_eq!(json["message"], "invalid field");
    }

    #[tokio::test]
    async fn test_not_found_returns_json() {
        let (status, json) = response_json(ApiError::not_found("user 42 not found")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"], "not found");
        assert_eq!(json["message"], "user 42 not found");
    }

    #[tokio::test]
    async fn test_unauthorized_returns_json() {
        let (status, json) = response_json(ApiError::unauthorized("bad token")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(json["message"], "bad token");
    }

    #[tokio::test]
    async fn test_forbidden_returns_json() {
        let (status, json) = response_json(ApiError::forbidden("access denied")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"], "forbidden");
        assert_eq!(json["message"], "access denied");
    }

    #[tokio::test]
    async fn test_conflict_returns_json() {
        let (status, json) = response_json(ApiError::conflict("already exists")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"], "conflict");
        assert_eq!(json["message"], "already exists");
    }

    #[tokio::test]
    async fn test_json_body_rejection_returns_json_error() {
        use axum::body::Body;
        use axum::{Router, routing::post};
        use http::Request;

        #[derive(serde::Deserialize)]
        struct Payload {
            #[allow(dead_code)]
            id: i64,
        }

        async fn handler(JsonBody(_payload): JsonBody<Payload>) -> &'static str {
            "ok"
        }

        let app = Router::new().route("/test", post(handler));

        // send string where int expected
        let req = Request::builder()
            .method("POST")
            .uri("/test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id": "not_a_number"}"#))
            .unwrap();

        let response = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let ct = response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            ct.contains("application/json"),
            "json rejection should return application/json, got: {ct}"
        );

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "bad request");
    }

    #[tokio::test]
    async fn test_internal_hides_details_in_json() {
        let (status, json) = response_json(ApiError::Internal("db connection failed".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "internal server error");
        assert_eq!(json["message"], "internal server error");
        // must not leak internal details
        let body = json.to_string();
        assert!(
            !body.contains("db connection"),
            "internal details should not be exposed"
        );
    }
}

/// extension trait for converting results to apierror.
pub trait ResultExt<T> {
    /// convert an error to an internal server error.
    fn map_internal(self) -> Result<T, ApiError>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn map_internal(self) -> Result<T, ApiError> {
        self.map_err(ApiError::internal)
    }
}

/// extension trait for converting options to apierror.
pub trait OptionExt<T> {
    /// convert none to an unauthorized error.
    fn or_unauthorized(self, msg: &str) -> Result<T, ApiError>;
    /// convert none to a not found error.
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
