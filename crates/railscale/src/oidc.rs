//! oidc authentication provider.

use std::time::Duration;

use moka::sync::Cache;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreTokenResponse},
    reqwest,
};
use railscale_types::{OidcClaims, OidcConfig, PkceMethod, RegistrationId};

use railscale_types::{HostInfo, MachineKey, Node, NodeKey, User};
use tokio::sync::oneshot;

/// information stored in the registration cache during OIDC flow.
#[derive(Clone, Debug)]
pub struct RegistrationInfo {
    /// the registration ID from the tailscale client.
    pub registration_id: RegistrationId,
    /// pkce verifier (if pkce is enabled).
    pub pkce_verifier: Option<String>,
    /// nonce for ID token verification.
    pub nonce: String,
}

/// and wait for the oidc callback to complete the registration
///
/// the node's public key
/// and wait for the OIDC callback to complete the registration.
pub struct PendingRegistration {
    /// the node's public key.
    pub node_key: NodeKey,
    /// the machine's public key (from noise handshake).
    pub machine_key: MachineKey,
    /// wrapped in Option to allow taking ownership when sending
    pub hostinfo: Option<HostInfo>,
    /// channel to notify when registration completes.
    /// wrapped in option to allow taking ownership when sending.
    pub completion_tx: Option<oneshot::Sender<CompletedRegistration>>,
}

/// the newly created node
#[derive(Debug, Clone)]
pub struct CompletedRegistration {
    /// the newly created node.
    pub node: Node,
    /// the user who authenticated.
    pub user: User,
}

/// oidc authentication provider.
///
/// stores OIDC configuration and provider metadata, building the client on demand
/// to avoid complex type-state issues with the openidconnect crate.
#[derive(Clone)]
pub struct AuthProviderOidc {
    /// provider metadata from OIDC discovery.
    provider_metadata: CoreProviderMetadata,
    /// oauth2 client id.
    client_id: ClientId,
    /// oauth2 client secret.
    client_secret: ClientSecret,
    /// redirect URL for OAuth callbacks.
    redirect_url: RedirectUrl,
    /// http client for async requests.
    http_client: reqwest::Client,
    /// configuration from the user.
    config: OidcConfig,
    /// cache for in-flight registration sessions.
    /// maps CSRF state -> registration info.
    registration_cache: Cache<String, RegistrationInfo>,
}

impl AuthProviderOidc {
    /// create a new OIDC provider from configuration.
    ///
    /// this will perform OIDC discovery to fetch the provider metadata.
    pub async fn new(config: OidcConfig, server_url: &str) -> Result<Self, String> {
        // create HTTP client for async requests
        // disable redirects to prevent ssrf vulnerabilities
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {}", e))?;

        // parse the issuer url
        let issuer_url =
            IssuerUrl::new(config.issuer.clone()).map_err(|e| format!("invalid issuer: {}", e))?;

        // parse the redirect url
        let redirect_url = RedirectUrl::new(format!(
            "{}/oidc/callback",
            server_url.trim_end_matches('/')
        ))
        .map_err(|e| format!("invalid redirect URL: {}", e))?;

        // perform oidc discovery
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| format!("OIDC discovery failed: {}", e))?;

        // create registration cache with 15 minute TTL
        let registration_cache = Cache::builder()
            .time_to_live(Duration::from_secs(900))
            .build();

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(config.client_id.clone()),
            client_secret: ClientSecret::new(config.client_secret.clone()),
            redirect_url,
            http_client,
            config,
            registration_cache,
        })
    }

    /// generate an authorization URL for a registration session.
    ///
    /// this stores the registration info in the cache and returns the URL
    /// to redirect the user to for authentication.
    pub fn authorization_url(
        &self,
        registration_id: RegistrationId,
    ) -> (String, CsrfToken, Option<Nonce>) {
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone());

        let mut auth_req = client.authorize_url(
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
        let pkce_verifier = if self.config.pkce.enabled {
            let (challenge, verifier) = match self.config.pkce.method {
                PkceMethod::S256 => PkceCodeChallenge::new_random_sha256(),
                // plain method is handled by not applying sha256 transformation
                // the openidconnect crate doesn't have a direct "plain" method,
                // so we'll just use SHA256 for now (most secure anyway)
                PkceMethod::Plain => PkceCodeChallenge::new_random_sha256(),
            };

            auth_req = auth_req.set_pkce_challenge(challenge);
            Some(verifier.secret().to_string())
        } else {
            None
        };

        let (url, csrf_token, nonce) = auth_req.url();

        let reg_info = RegistrationInfo {
            registration_id,
            pkce_verifier,
            nonce: nonce.secret().to_string(),
        };

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
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_url.clone());

        let mut token_req = client
            .exchange_code(code)
            .map_err(|e| format!("token endpoint not configured: {:?}", e))?;

        if let Some(verifier) = pkce_verifier {
            token_req = token_req.set_pkce_verifier(PkceCodeVerifier::new(verifier));
        }

        token_req
            .request_async(&self.http_client)
            .await
            .map_err(|e| format!("token exchange failed: {}", e))
    }

    /// get the OIDC configuration.
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// verify an ID token and extract claims.
    pub fn verify_id_token(
        &self,
        id_token: &openidconnect::IdToken<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        nonce: &str,
    ) -> Result<OidcClaims, String> {
        use openidconnect::Nonce;
        use openidconnect::core::CoreIdTokenVerifier;

        // create verifier for ID token validation
        let verifier = CoreIdTokenVerifier::new_confidential_client(
            self.client_id.clone(),
            self.client_secret.clone(),
            self.provider_metadata.issuer().clone(),
            self.provider_metadata.jwks().clone(),
        );

        // verify the id token with the nonce
        let verified_claims = id_token
            .claims(&verifier, &Nonce::new(nonce.to_string()))
            .map_err(|e| format!("ID token verification failed: {}", e))?;

        // convert to our oidcclaims type
        serde_json::from_value(
            serde_json::to_value(verified_claims)
                .map_err(|e| format!("failed to serialize claims: {}", e))?,
        )
        .map_err(|e| format!("failed to parse claims: {}", e))
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
    if !config.allowed_users.is_empty() && !config.allowed_users.iter().any(|u| u == &claims.email)
    {
        return Err(format!("email '{}' is not in allowed users", claims.email));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::{PkceConfig, PkceMethod};

    #[test]
    fn test_pending_registration_stores_node_info() {
        use railscale_types::{MachineKey, NodeKey};
        use tokio::sync::oneshot;

        let node_key = NodeKey::from_bytes(vec![1; 32]);
        let machine_key = MachineKey::from_bytes(vec![2; 32]);
        let (tx, _rx) = oneshot::channel();

        let pending = PendingRegistration {
            node_key: node_key.clone(),
            machine_key: machine_key.clone(),
            hostinfo: None,
            completion_tx: Some(tx),
        };

        assert_eq!(pending.node_key, node_key);
        assert_eq!(pending.machine_key, machine_key);
    }

    #[test]
    fn test_completed_registration_stores_node_and_user() {
        use railscale_types::test_utils::TestNodeBuilder;
        use railscale_types::{User, UserId};

        let node = TestNodeBuilder::new(1).build();
        let user = User {
            id: UserId(1),
            name: "alice".to_string(),
            display_name: Some("Alice".to_string()),
            email: Some("alice@example.com".to_string()),
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let completed = CompletedRegistration {
            node: node.clone(),
            user: user.clone(),
        };

        assert_eq!(completed.node.id, node.id);
        assert_eq!(completed.user.id, user.id);
    }

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
