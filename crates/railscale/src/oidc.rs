//! oidc authentication provider.

use std::time::Duration;

use moka::sync::Cache;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreTokenResponse},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use railscale_types::{OidcClaims, OidcConfig, PkceMethod, RegistrationId};

/// information stored in the registration cache during OIDC flow.
#[derive(Clone, Debug)]
pub struct RegistrationInfo {
    /// pKCE verifier (if PKCE is enabled)
    pub registration_id: RegistrationId,
    /// pkce verifier (if pkce is enabled).
    pub pkce_verifier: Option<String>,
}

/// oidc client configuration
pub struct AuthProviderOidc {
    /// configuration from the user
    client: CoreClient,
    /// cache for in-flight registration sessions
    config: OidcConfig,
    /// cache for in-flight registration sessions.
    /// maps CSRF state -> registration info.
    registration_cache: Cache<String, RegistrationInfo>,
}

impl AuthProviderOidc {
    /// this will perform oidc discovery to fetch the provider metadata
    ///
    //parse the issuer url
    pub async fn new(config: OidcConfig, server_url: &str) -> Result<Self, String> {
        // parse the issuer url
        let issuer_url =
            IssuerUrl::new(config.issuer.clone()).map_err(|e| format!("invalid issuer: {}", e))?;

        // perform oidc discovery
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
            .await
            .map_err(|e| format!("OIDC discovery failed: {}", e))?;

        // set up the oauth2 client
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/oidc/callback", server_url.trim_end_matches('/')))
                .map_err(|e| format!("invalid redirect URL: {}", e))?,
        );

        // create registration cache with 15 minute TTL
        let registration_cache = Cache::builder()
            .time_to_live(Duration::from_secs(900))
            .build();

        Ok(Self {
            client,
            config,
            registration_cache,
        })
    }

    /// this stores the registration info in the cache and returns the url
    ///to redirect the user to for authentication
    /// this stores the registration info in the cache and returns the URL
    /// to redirect the user to for authentication.
    pub fn authorization_url(
        &self,
        registration_id: RegistrationId,
    ) -> (String, CsrfToken, Option<Nonce>) {
        let mut auth_req = self.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        // add requested scopes
        for scope in &self.config.scope {
            auth_req = auth_req.add_scope(Scope::new(scope.clone()));
        }

        // add extra parameters
        for (key, value) in &self.config.extra_params {
            auth_req = auth_req.add_extra_param(key, value);
        }

        // handle pkce if enabled
        let reg_info = if self.config.pkce.enabled {
            let (challenge, verifier) = match self.config.pkce.method {
                PkceMethod::S256 => PkceCodeChallenge::new_random_sha256(),
                // so we'll just use SHA256 for now (most secure anyway)
                // the openidconnect crate doesn't have a direct "plain" method,
                // so we'll just use SHA256 for now (most secure anyway)
                PkceMethod::Plain => PkceCodeChallenge::new_random_sha256(),
            };

            auth_req = auth_req.set_pkce_challenge(challenge);

            RegistrationInfo {
                registration_id,
                pkce_verifier: Some(verifier.secret().to_string()),
            }
        } else {
            RegistrationInfo {
                registration_id,
                pkce_verifier: None,
            }
        };

        let (url, csrf_token, nonce) = auth_req.url();

        // store registration info in cache
        self.registration_cache
            .insert(csrf_token.secret().to_string(), reg_info);

        (url.to_string(), csrf_token, Some(nonce))
    }

    /// retrieve registration info from the cache using the CSRF state.
    pub fn get_registration_info(&self, state: &str) -> Option<RegistrationInfo> {
        self.registration_cache.get(state)
    }

    /// exchange the authorization code for tokens.
    pub async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: Option<String>,
    ) -> Result<CoreTokenResponse, String> {
        let mut token_req = self.client.exchange_code(code);

        if let Some(verifier) = pkce_verifier {
            token_req = token_req.set_pkce_verifier(PkceCodeVerifier::new(verifier));
        }

        token_req
            .request_async(async_http_client)
            .await
            .map_err(|e| format!("token exchange failed: {}", e))
    }
}

/// validate OIDC claims against configured filters.
///
/// returns Ok(()) if the user is authorized, or Err with a reason if not.
pub fn validate_oidc_claims(config: &OidcConfig, claims: &OidcClaims) -> Result<(), String> {
    // always check groups first (if configured)
    if !config.allowed_groups.is_empty() {
        let has_allowed_group = config
            .allowed_groups
            .iter()
            .any(|group| claims.groups.contains(group));

        if !has_allowed_group {
            return Err("user is not in any allowed group".to_string());
        }
    }

    // check email verification requirement
    let trust_email = !config.email_verified_required || claims.email_verified;

    // if we have email-based tests, check email verification
    let has_email_tests = !config.allowed_domains.is_empty() || !config.allowed_users.is_empty();
    if !trust_email && has_email_tests {
        return Err("email is not verified".to_string());
    }

    // check allowed domains
    if !config.allowed_domains.is_empty() {
        let email_domain = claims
            .email
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("");

        if !config.allowed_domains.iter().any(|d| d == email_domain) {
            return Err(format!(
                "email domain '{}' is not in allowed domains",
                email_domain
            ));
        }
    }

    // check allowed users
    if !config.allowed_users.is_empty() {
        if !config.allowed_users.iter().any(|u| u == &claims.email) {
            return Err(format!(
                "email '{}' is not in allowed users",
                claims.email
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::{PkceConfig, PkceMethod};

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://sso.example.com".to_string(),
            client_id: "railscale".to_string(),
            client_secret: "secret".to_string(),
            scope: vec!["openid".to_string()],
            email_verified_required: false,
            pkce: PkceConfig {
                enabled: false,
                method: PkceMethod::S256,
            },
            allowed_domains: vec![],
            allowed_users: vec![],
            allowed_groups: vec![],
            expiry_secs: 180 * 24 * 3600,
            use_expiry_from_token: false,
            extra_params: std::collections::HashMap::new(),
        }
    }

    fn test_claims() -> OidcClaims {
        OidcClaims {
            sub: "user123".to_string(),
            iss: "https://sso.example.com".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            preferred_username: "alice".to_string(),
            name: "Alice Smith".to_string(),
            picture: String::new(),
            groups: vec!["users".to_string()],
        }
    }

    #[test]
    fn test_validate_no_filters_allows_all() {
        let config = test_config();
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_allowed_domain_success() {
        let mut config = test_config();
        config.allowed_domains = vec!["example.com".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_allowed_domain_failure() {
        let mut config = test_config();
        config.allowed_domains = vec!["other.com".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_err());
    }

    #[test]
    fn test_validate_allowed_users_success() {
        let mut config = test_config();
        config.allowed_users = vec!["alice@example.com".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_allowed_users_failure() {
        let mut config = test_config();
        config.allowed_users = vec!["bob@example.com".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_err());
    }

    #[test]
    fn test_validate_allowed_groups_success() {
        let mut config = test_config();
        config.allowed_groups = vec!["users".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_allowed_groups_failure() {
        let mut config = test_config();
        config.allowed_groups = vec!["admins".to_string()];
        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_err());
    }

    #[test]
    fn test_validate_email_verification_required_success() {
        let mut config = test_config();
        config.email_verified_required = true;
        config.allowed_domains = vec!["example.com".to_string()];

        let mut claims = test_claims();
        claims.email_verified = true;

        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_email_verification_required_failure() {
        let mut config = test_config();
        config.email_verified_required = true;
        config.allowed_domains = vec!["example.com".to_string()];

        let mut claims = test_claims();
        claims.email_verified = false;

        assert!(validate_oidc_claims(&config, &claims).is_err());
    }

    #[test]
    fn test_validate_multiple_filters() {
        let mut config = test_config();
        config.allowed_domains = vec!["example.com".to_string()];
        config.allowed_groups = vec!["users".to_string()];

        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_ok());
    }

    #[test]
    fn test_validate_multiple_filters_failure() {
        let mut config = test_config();
        config.allowed_domains = vec!["example.com".to_string()];
        config.allowed_groups = vec!["admins".to_string()]; // Wrong group

        let claims = test_claims();
        assert!(validate_oidc_claims(&config, &claims).is_err());
    }
}
