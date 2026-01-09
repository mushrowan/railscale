//! handlers for oidc authentication endpoints

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use railscale_types::RegistrationId;

use super::ApiError;
use crate::AppState;

/// get /register/{registration_id}
/// redirects to oidc provider's authorization url
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

        // create app without oidc
        let config = railscale_types::Config::default();
        let app = crate::create_app(db, grants, config, None).await;

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
}
