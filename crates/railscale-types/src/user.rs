//! user type representing a tailscale user/namespace.
//!
//! in railscale (like headscale), users are "bubbles" or namespaces
//! that contain nodes. Users can be created via CLI or OIDC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// unique identifier for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u64);

impl UserId {
    /// the special user id for tagged devices.
    ///
    /// tagged nodes don't belong to a real user - the tag is their identity.
    /// this id is used when rendering tagged nodes in the tailscale protocol.
    pub const TAGGED_DEVICES: UserId = UserId(2147455555);
}

impl From<u64> for UserId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// a railscale user representing a namespace for nodes.
///
/// users can own nodes (non-tagged devices) or create preauthkeys
/// that register tagged devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// unique identifier.
    pub id: UserId,

    /// username - used if email is empty.
    /// unique if provider_identifier is not set.
    pub name: String,

    /// display name - typically the user's full name.
    pub display_name: Option<String>,

    /// email address from oidc.
    pub email: Option<String>,

    /// provider identifier from oidc (combination of `iss` and `sub` claims).
    /// unique if set.
    pub provider_identifier: Option<String>,

    /// provider origin (e.g., "oidc", "cli").
    pub provider: Option<String>,

    /// oidc group memberships synced from the identity provider
    pub profile_pic_url: Option<String>,

    /// when resolving grants, these are optionally prefixed via `group_prefix` config
    ///
    /// these are the raw group names from the oidc `groups` claim.
    /// when resolving grants, these are optionally prefixed via `group_prefix` config.
    #[serde(default)]
    pub oidc_groups: Vec<String>,

    /// when the user was created.
    pub created_at: DateTime<Utc>,

    /// when the user was last updated.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// create a new user with the given name.
    pub fn new(id: UserId, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            display_name: None,
            email: None,
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            oidc_groups: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// returns the username to use for display and policy evaluation.
    ///
    /// priority: email > name > provider_identifier > id
    pub fn username(&self) -> &str {
        self.email
            .as_deref()
            .or(Some(&self.name))
            .filter(|s| !s.is_empty())
            .or(self.provider_identifier.as_deref())
            .unwrap_or_else(|| {
                // fallback to id string - this is a bit awkward but matches go behavior
                Box::leak(self.id.to_string().into_boxed_str())
            })
    }

    /// returns the display name or falls back to username.
    pub fn display(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.username())
    }

    /// returns the tagged devices sentinel user.
    ///
    /// this is used in mapresponse for tagged nodes.
    pub fn tagged_devices() -> Self {
        Self {
            id: UserId::TAGGED_DEVICES,
            name: "tagged-devices".to_string(),
            display_name: Some("Tagged Devices".to_string()),
            email: None,
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            oidc_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl Default for User {
    fn default() -> Self {
        Self::new(UserId(0), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_username_priority() {
        let mut user = User::new(UserId(1), "testuser".to_string());

        // name only
        assert_eq!(user.username(), "testuser");

        // email takes priority
        user.email = Some("test@example.com".to_string());
        assert_eq!(user.username(), "test@example.com");
    }

    #[test]
    fn test_user_display() {
        let mut user = User::new(UserId(1), "testuser".to_string());
        assert_eq!(user.display(), "testuser");

        user.display_name = Some("Test User".to_string());
        assert_eq!(user.display(), "Test User");
    }

    #[test]
    fn test_tagged_devices_id() {
        assert_eq!(UserId::TAGGED_DEVICES.0, 2147455555);
    }

    #[test]
    fn test_user_oidc_groups() {
        let mut user = User::new(UserId(1), "testuser".to_string());
        assert!(user.oidc_groups.is_empty());

        user.oidc_groups = vec!["engineering".to_string(), "admins".to_string()];
        assert_eq!(user.oidc_groups.len(), 2);
        assert!(user.oidc_groups.contains(&"engineering".to_string()));
    }

    #[test]
    fn test_user_serde_with_oidc_groups() {
        let mut user = User::new(UserId(1), "testuser".to_string());
        user.oidc_groups = vec!["group1".to_string()];

        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("oidc_groups"));
        assert!(json.contains("group1"));

        let parsed: User = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.oidc_groups, vec!["group1".to_string()]);
    }

    #[test]
    fn test_user_serde_without_oidc_groups() {
        // ensure backwards compatibility - oidc_groups defaults to empty
        let json = r#"{"id":1,"name":"test","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert!(user.oidc_groups.is_empty());
    }
}
