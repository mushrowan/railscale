//! convert headscale users to railscale users

use chrono::{DateTime, Utc};
use serde::Deserialize;

use railscale_types::{User, UserId};

/// a user row from headscale's sqlite database
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "cli", derive(sqlx::FromRow))]
pub struct HeadscaleUser {
    pub id: i64,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub provider_identifier: Option<String>,
    pub provider: Option<String>,
    pub profile_pic_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// convert a headscale user to a railscale user
pub fn convert_user(hs: &HeadscaleUser) -> User {
    let name = match (&hs.name, &hs.email) {
        (Some(n), _) if !n.is_empty() => n.clone(),
        (_, Some(email)) => email.split('@').next().unwrap_or("user").to_string(),
        _ => format!("user-{}", hs.id),
    };

    User {
        id: UserId::from(hs.id),
        name,
        display_name: hs.display_name.clone(),
        email: hs.email.clone(),
        provider_identifier: hs.provider_identifier.clone(),
        provider: hs.provider.clone(),
        profile_pic_url: hs.profile_pic_url.clone(),
        oidc_groups: Vec::new(),
        created_at: hs.created_at,
        updated_at: hs.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc_user() -> HeadscaleUser {
        HeadscaleUser {
            id: 14,
            name: String::new().into(),
            display_name: Some("Ro".into()),
            email: Some("ro@example.com".into()),
            provider_identifier: Some("https://accounts.example.com/user-14".into()),
            provider: Some("oidc".into()),
            profile_pic_url: Some("https://example.com/pic.jpg".into()),
            created_at: "2026-01-28T16:35:36Z".parse().unwrap(),
            updated_at: "2026-02-25T09:26:42Z".parse().unwrap(),
        }
    }

    fn service_user() -> HeadscaleUser {
        HeadscaleUser {
            id: 2,
            name: Some("machines".into()),
            display_name: None,
            email: Some("infra@example.com".into()),
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            created_at: "2025-10-06T09:14:57Z".parse().unwrap(),
            updated_at: "2025-10-06T09:14:57Z".parse().unwrap(),
        }
    }

    #[test]
    fn convert_oidc_user() {
        let hs = oidc_user();
        let user = convert_user(&hs);

        assert_eq!(user.id, UserId::from(14i64));
        assert_eq!(user.display_name.as_deref(), Some("Ro"));
        assert_eq!(user.email.as_deref(), Some("ro@example.com"));
        assert_eq!(
            user.provider_identifier.as_deref(),
            Some("https://accounts.example.com/user-14")
        );
        assert_eq!(user.provider.as_deref(), Some("oidc"));
        assert_eq!(
            user.profile_pic_url.as_deref(),
            Some("https://example.com/pic.jpg")
        );
        assert!(user.oidc_groups.is_empty());
    }

    #[test]
    fn convert_service_user() {
        let hs = service_user();
        let user = convert_user(&hs);

        assert_eq!(user.id, UserId::from(2i64));
        assert_eq!(user.name, "machines");
        assert_eq!(user.email.as_deref(), Some("infra@example.com"));
        assert!(user.provider_identifier.is_none());
        assert!(user.provider.is_none());
    }

    #[test]
    fn preserves_timestamps() {
        let hs = oidc_user();
        let user = convert_user(&hs);

        assert_eq!(user.created_at, hs.created_at);
        assert_eq!(user.updated_at, hs.updated_at);
    }

    #[test]
    fn empty_name_uses_email_prefix() {
        let hs = HeadscaleUser {
            id: 20,
            name: None,
            display_name: None,
            email: Some("esme@example.com".into()),
            provider_identifier: None,
            provider: Some("oidc".into()),
            profile_pic_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let user = convert_user(&hs);

        // should derive a name from the email prefix
        assert_eq!(user.name, "esme");
    }

    #[test]
    fn no_name_no_email_uses_id() {
        let hs = HeadscaleUser {
            id: 99,
            name: None,
            display_name: None,
            email: None,
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let user = convert_user(&hs);

        assert_eq!(user.name, "user-99");
    }
}
