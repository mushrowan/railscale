//! handlers for oidc authentication endpoints.

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use railscale_types::RegistrationId;
use serde::Deserialize;

use super::{ApiError, ResultExt};
use crate::AppState;

/// get /register/{registration_id}
/// redirects to oidc provider's authorization url.
pub async fn register_redirect(
    State(state): State<AppState>,
    Path(registration_id_str): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC not configured"))?;

    let registration_id = RegistrationId::from_string(&registration_id_str)
        .map_err(|e| ApiError::bad_request(format!("invalid registration ID: {}", e)))?;

    let (auth_url, _csrf_token, _nonce) = oidc.authorization_url(registration_id);

    Ok(Redirect::to(&auth_url))
}

/// query parameters for oidc callback.
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    pub code: String,
    pub state: String,
}

/// get /oidc/callback?code=...&state=...
/// processes oidc callback, creates/updates user and node.
pub async fn oidc_callback(
    State(state): State<AppState>,
    Query(params): Query<OidcCallbackParams>,
) -> Result<impl IntoResponse, ApiError> {
    use openidconnect::{AuthorizationCode, TokenResponse};
    use railscale_db::Database;

    let oidc = state
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC not configured"))?;

    // retrieve registration info from cache
    let reg_info = oidc
        .get_registration_info(&params.state)
        .ok_or_else(|| ApiError::bad_request("invalid or expired state"))?;

    // exchange authorization code for tokens
    let token_response = oidc
        .exchange_code(AuthorizationCode::new(params.code), reg_info.pkce_verifier)
        .await
        .map_err(ApiError::internal)?;

    // extract id token and verify it
    let id_token = token_response
        .id_token()
        .ok_or_else(|| ApiError::internal("no ID token in response"))?;

    // verify the id token and extract claims
    let claims = oidc
        .verify_id_token(id_token, &reg_info.nonce)
        .map_err(ApiError::unauthorized)?;

    // validate claims against configuration
    crate::oidc::validate_oidc_claims(oidc.config(), &claims)
        .map_err(|e| ApiError::unauthorized(format!("authorization failed: {}", e)))?;

    // get or create user
    let provider_identifier = claims.identifier();
    let user = state
        .db
        .get_user_by_oidc_identifier(&provider_identifier)
        .await
        .map_internal()?;

    let _user = if let Some(user) = user {
        // user exists, return it
        user
    } else {
        // create new user
        use railscale_types::{User, UserId};
        let new_user = User {
            id: UserId(0), // Will be assigned by database
            name: claims.preferred_username.clone(),
            display_name: Some(claims.display_name().to_string()),
            email: Some(claims.email.clone()),
            provider_identifier: Some(provider_identifier),
            provider: Some("oidc".to_string()),
            profile_pic_url: if claims.picture.is_empty() {
                None
            } else {
                Some(claims.picture.clone())
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.db.create_user(&new_user).await.map_internal()?
    };

    // return success html
    Ok(Html(
        r#"<html>
<head><title>Authentication Successful</title></head>
<body>
<h1>Authentication Successful</h1>
<p>You have successfully authenticated. You can close this window and return to the Tailscale client.</p>
</body>
</html>"#,
    ))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use railscale_db::RailscaleDb;
    use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
    use railscale_types::RegistrationId;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_register_redirect_without_oidc() {
        // set up test database
        let db = RailscaleDb::new_in_memory().await.unwrap();

        // create grants engine with wildcard policy
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        let grants = GrantsEngine::new(policy);

        // create app without OIDC
        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db,
            grants,
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        // generate a test registration id
        let reg_id = RegistrationId::new([1u8; 32]);
        let reg_id_str = reg_id.to_string();

        // send request
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/register/{}", reg_id_str))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // should get an error since oidc is not configured
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_oidc_callback_without_oidc() {
        // set up test database
        let db = RailscaleDb::new_in_memory().await.unwrap();

        // create grants engine with wildcard policy
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        let grants = GrantsEngine::new(policy);

        // create app without OIDC
        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db,
            grants,
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        // send callback request with code and state
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oidc/callback?code=test_code&state=test_state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // should get an error since oidc is not configured
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
