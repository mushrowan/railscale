//! oidc authentication types.

use serde::{Deserialize, Serialize};

/// unique identifier for an OIDC registration session.
///
/// the registration id is used to correlate the oidc callback with the
/// initial registration request from a tailscale client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegistrationId([u8; 32]);

impl RegistrationId {
    /// create a new registration ID from random bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// generate a new random registration ID.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// create a registration ID from a base64url-encoded string.
    pub fn from_string(s: &str) -> Result<Self, String> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| format!("invalid base64: {}", e))?;

        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// encode as a base64url string.
    pub fn encode(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    /// get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for RegistrationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

/// oidc claims from the id token and userinfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// subject - unique identifier for the user from the provider.
    pub sub: String,

    /// issuer - the OIDC provider URL.
    pub iss: String,

    /// email address.
    #[serde(default)]
    pub email: String,

    /// whether the email has been verified by the provider.
    #[serde(default)]
    pub email_verified: bool,

    /// preferred username.
    #[serde(default)]
    pub preferred_username: String,

    /// display name.
    #[serde(default)]
    pub name: String,

    /// profile picture URL.
    #[serde(default)]
    pub picture: String,

    /// group memberships.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl OidcClaims {
    /// get a unique identifier for this user.
    ///
    /// this combines the issuer and subject to create a stable identifier
    /// that won't change even if the user's email or username changes.
    pub fn identifier(&self) -> String {
        format!("{}:{}", self.iss, self.sub)
    }

    /// get a display name, falling back to email or username.
    pub fn display_name(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else if !self.email.is_empty() {
            &self.email
        } else if !self.preferred_username.is_empty() {
            &self.preferred_username
        } else {
            &self.sub
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_id_roundtrip() {
        let bytes = [1u8; 32];
        let id = RegistrationId::new(bytes);
        let s = id.encode();
        let id2 = RegistrationId::from_string(&s).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_registration_id_invalid_length() {
        let result = RegistrationId::from_string("YQ"); // "a" in base64
        assert!(result.is_err());
    }

    #[test]
    fn test_oidc_claims_identifier() {
        let claims = OidcClaims {
            sub: "user123".to_string(),
            iss: "https://sso.example.com".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            preferred_username: "alice".to_string(),
            name: "Alice Smith".to_string(),
            picture: "https://example.com/avatar.jpg".to_string(),
            groups: vec!["admins".to_string()],
        };

        assert_eq!(claims.identifier(), "https://sso.example.com:user123");
    }

    #[test]
    fn test_oidc_claims_display_name_priority() {
        let mut claims = OidcClaims {
            sub: "user123".to_string(),
            iss: "https://sso.example.com".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            preferred_username: "alice".to_string(),
            name: "Alice Smith".to_string(),
            picture: String::new(),
            groups: vec![],
        };

        assert_eq!(claims.display_name(), "Alice Smith");

        claims.name = String::new();
        assert_eq!(claims.display_name(), "alice@example.com");

        claims.email = String::new();
        assert_eq!(claims.display_name(), "alice");

        claims.preferred_username = String::new();
        assert_eq!(claims.display_name(), "user123");
    }
}
