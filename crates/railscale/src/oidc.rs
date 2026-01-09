//! oidc authentication provider

use railscale_types::{OidcClaims, OidcConfig};

/// validate oidc claims against configured filters
///
/// returns Ok(()) if the user is authorized, or Err with a reason if not
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
