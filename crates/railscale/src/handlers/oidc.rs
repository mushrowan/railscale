//! handlers for oidc authentication endpoints.

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use railscale_types::RegistrationId;
use serde::Deserialize;

use super::{ApiError, ResultExt};
use crate::AppState;

/// response type for register_redirect - either redirect or html.
pub enum RegisterRedirectResponse {
    /// redirect to oidc provider.
    Redirect(Redirect),
    /// html page for manual registration (when oidc not configured).
    Html(Html<String>),
}

impl IntoResponse for RegisterRedirectResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            RegisterRedirectResponse::Redirect(r) => r.into_response(),
            RegisterRedirectResponse::Html(h) => h.into_response(),
        }
    }
}

/// get /register/{registration_id}
/// redirects to oidc provider, or shows manual registration page if oidc not configured.
pub async fn register_redirect(
    State(state): State<AppState>,
    Path(registration_id_str): Path<String>,
) -> Result<RegisterRedirectResponse, ApiError> {
    let registration_id = RegistrationId::from_string(&registration_id_str)
        .map_err(|e| ApiError::bad_request(format!("invalid registration ID: {}", e)))?;

    // if oidc is configured, redirect to it
    if let Some(oidc) = state.oidc.as_ref() {
        let (auth_url, _csrf_token, _nonce) = oidc.authorization_url(registration_id);
        return Ok(RegisterRedirectResponse::Redirect(Redirect::to(&auth_url)));
    }

    // otherwise show manual registration page
    let html = super::templates::manual_registration_page(&registration_id_str);
    Ok(RegisterRedirectResponse::Html(Html(html)))
}

/// query parameters for oidc callback.
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    /// the authorization code from the identity provider.
    pub code: String,
    /// the state parameter for csrf protection.
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

    // retrieve and remove registration info from cache (one-time use)
    // this prevents replay attacks by invalidating the state after use
    let reg_info = oidc
        .remove_registration_info(&params.state)
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
    let existing_user = state
        .db
        .get_user_by_oidc_identifier(&provider_identifier)
        .await
        .map_internal()?;

    let user = if let Some(mut user) = existing_user {
        // user exists - sync oidc groups if they've changed
        if user.oidc_groups != claims.groups {
            tracing::debug!(
                user_id = %user.id,
                old_groups = ?user.oidc_groups,
                new_groups = ?claims.groups,
                "syncing OIDC groups on re-login"
            );
            user.oidc_groups = claims.groups.clone();
            user.updated_at = chrono::Utc::now();
            state.db.update_user(&user).await.map_internal()?
        } else {
            user
        }
    } else {
        // create new user with OIDC groups
        use railscale_types::{User, UserId, Username};

        // sanitise username from oidc claims, falling back to email local part
        let sanitised_name = Username::sanitise(&claims.preferred_username)
            .or_else(|| {
                // try email local part (before @)
                let email_local = claims.email.split('@').next().unwrap_or("");
                Username::sanitise(email_local)
            })
            .map(|u| u.into_inner())
            .unwrap_or_else(|| "user".to_string());

        let new_user = User {
            id: UserId(0), // Will be assigned by database
            name: sanitised_name,
            display_name: Some(claims.display_name().to_string()),
            email: Some(claims.email.clone()),
            provider_identifier: Some(provider_identifier),
            provider: Some("oidc".to_string()),
            profile_pic_url: if claims.picture.is_empty() {
                None
            } else {
                Some(claims.picture.clone())
            },
            oidc_groups: claims.groups.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        state.db.create_user(&new_user).await.map_internal()?
    };

    // look up the pending registration and complete node registration if found
    if let Some(pending) = state.pending_registrations.get(&reg_info.registration_id) {
        // allocate ip addresses for the new node
        let (ipv4, ipv6) = {
            let mut allocator = state.ip_allocator.lock().await;
            allocator
                .allocate()
                .map_err(|e| ApiError::internal(e.to_string()))?
        };

        // create the node with sanitised hostname
        use railscale_types::NodeName;

        let raw_hostname = pending
            .hostinfo
            .as_ref()
            .and_then(|h| h.hostname.clone())
            .unwrap_or_default();

        // sanitise hostname for dns compatibility, falling back to "node"
        let hostname = NodeName::sanitise(&raw_hostname)
            .map(|n| n.into_inner())
            .unwrap_or_else(|| "node".to_string());

        let now = chrono::Utc::now();
        let node = railscale_types::Node {
            id: railscale_types::NodeId(0),
            machine_key: pending.machine_key.clone(),
            node_key: pending.node_key.clone(),
            disco_key: Default::default(),
            ipv4,
            ipv6,
            endpoints: vec![],
            hostinfo: pending.hostinfo.clone(),
            hostname: hostname.clone(),
            given_name: hostname,
            user_id: Some(user.id),
            register_method: railscale_types::RegisterMethod::Oidc,
            tags: vec![],
            auth_key_id: None,
            ephemeral: false,
            last_seen: None,
            last_seen_country: None,
            expiry: None,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
            posture_attributes: std::collections::HashMap::new(),
            nl_public_key: None,
        };

        let node = state.db.create_node(&node).await.map_internal()?;

        // notify streaming clients that a new node has been added
        state.notifier.notify_state_changed();

        // complete the pending registration
        let completed = crate::oidc::CompletedRegistration {
            node,
            user: user.clone(),
        };
        pending.complete(completed).await;
    }
    // if no pending registration found, the user was created but no node.
    // this can happen if someone directly accesses the oidc auth url.

    // return success html
    Ok(Html(super::templates::OIDC_SUCCESS_PAGE))
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
    async fn test_register_redirect_without_oidc_shows_manual_page() {
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

        // should return 200 with html page showing manual registration instructions
        assert_eq!(response.status(), StatusCode::OK);

        // check the response body contains the registration instructions
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("Complete Your Registration"),
            "should show registration page"
        );
        assert!(
            body_str.contains("railscale nodes approve"),
            "should show CLI command"
        );
        assert!(
            body_str.contains(&reg_id_str),
            "should include registration ID"
        );
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
