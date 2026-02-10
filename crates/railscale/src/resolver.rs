use railscale_grants::UserResolver;
use railscale_types::{OidcGroupPrefix, User, UserId};
use std::collections::HashMap;

/// resolves user identity and group membership for map responses.
///
/// constructed in the map handler with users from the database and
/// policy groups. groups are resolved from two sources:
/// 1. policy file groups (email-based membership)
/// 2. oidc groups (synced from identity provider claims)
pub struct MapUserResolver {
    users: HashMap<UserId, User>,
    /// maps group name (with "group:" prefix) to list of member emails.
    groups: HashMap<String, Vec<String>>,
    /// optional prefix to apply to oidc group names.
    oidc_group_prefix: Option<OidcGroupPrefix>,
}

impl MapUserResolver {
    /// create a new resolver from a list of users.
    ///
    /// use `with_groups()` to also include policy-defined groups.
    pub fn new(users: Vec<User>) -> Self {
        let users = users.into_iter().map(|u| (u.id, u)).collect();
        Self {
            users,
            groups: HashMap::new(),
            oidc_group_prefix: None,
        }
    }

    /// create a new resolver with users, policy groups, and oidc configuration.
    ///
    /// groups should be a mapping from group name (e.g., "group:engineering")
    /// to a list of member email addresses.
    ///
    /// the `oidc_group_prefix` is applied to oidc group names when resolving
    /// group membership. For example, with prefix "oidc-", an OIDC group
    /// "engineering" becomes "oidc-engineering" for matching against
    /// `group:oidc-engineering` in grants.
    pub fn with_groups(
        users: Vec<User>,
        groups: HashMap<String, Vec<String>>,
        oidc_group_prefix: Option<OidcGroupPrefix>,
    ) -> Self {
        let users = users.into_iter().map(|u| (u.id, u)).collect();
        Self {
            users,
            groups,
            oidc_group_prefix,
        }
    }
}

impl UserResolver for MapUserResolver {
    fn resolve_user(&self, user_id: &UserId) -> Option<String> {
        self.users.get(user_id).map(|u| u.username().to_string())
    }

    fn resolve_groups(&self, user_id: &UserId) -> Vec<String> {
        let user = match self.users.get(user_id) {
            Some(u) => u,
            None => return Vec::new(),
        };

        let mut result = Vec::new();

        // 2. Add policy groups (email-based membership)
        for oidc_group in &user.oidc_groups {
            let group_name = match &self.oidc_group_prefix {
                Some(prefix) => prefix.apply(oidc_group),
                None => oidc_group.clone(),
            };
            result.push(group_name);
        }

        // 2. Add policy groups (email-based membership)
        if let Some(email) = &user.email {
            let email_lower = email.to_lowercase();
            for (group_name, members) in &self.groups {
                // strip "group:" prefix for the returned group name
                let name = group_name.strip_prefix("group:").unwrap_or(group_name);
                // check if user's email is in the member list (case-insensitive)
                if members.iter().any(|m| m.to_lowercase() == email_lower) {
                    // avoid duplicates if oidc group matches policy group
                    if !result.contains(&name.to_string()) {
                        result.push(name.to_string());
                    }
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(id: u64, name: &str, email: Option<&str>) -> User {
        let mut user = User::new(UserId(id), name.to_string());
        user.email = email.map(String::from);
        user
    }

    fn make_user_with_oidc_groups(
        id: u64,
        name: &str,
        email: Option<&str>,
        oidc_groups: Vec<&str>,
    ) -> User {
        let mut user = make_user(id, name, email);
        user.oidc_groups = oidc_groups.into_iter().map(String::from).collect();
        user
    }

    #[test]
    fn test_resolve_groups_with_policy_groups() {
        let users = vec![
            make_user(1, "alice", Some("alice@example.com")),
            make_user(2, "bob", Some("bob@example.com")),
            make_user(3, "eve", Some("eve@example.com")),
        ];

        let mut groups = HashMap::new();
        groups.insert(
            "group:engineering".to_string(),
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string(),
            ],
        );
        groups.insert(
            "group:admins".to_string(),
            vec!["alice@example.com".to_string()],
        );

        let resolver = MapUserResolver::with_groups(users, groups, None);

        // alice is in both groups
        let alice_groups = resolver.resolve_groups(&UserId(1));
        assert!(alice_groups.contains(&"engineering".to_string()));
        assert!(alice_groups.contains(&"admins".to_string()));
        assert_eq!(alice_groups.len(), 2);

        // bob is only in engineering
        let bob_groups = resolver.resolve_groups(&UserId(2));
        assert!(bob_groups.contains(&"engineering".to_string()));
        assert!(!bob_groups.contains(&"admins".to_string()));
        assert_eq!(bob_groups.len(), 1);

        // eve is in no groups
        let eve_groups = resolver.resolve_groups(&UserId(3));
        assert!(eve_groups.is_empty());
    }

    #[test]
    fn test_resolve_groups_case_insensitive() {
        let users = vec![make_user(1, "alice", Some("Alice@Example.COM"))];

        let mut groups = HashMap::new();
        groups.insert(
            "group:team".to_string(),
            vec!["alice@example.com".to_string()],
        );

        let resolver = MapUserResolver::with_groups(users, groups, None);
        let alice_groups = resolver.resolve_groups(&UserId(1));
        assert_eq!(alice_groups, vec!["team".to_string()]);
    }

    #[test]
    fn test_resolve_groups_no_email() {
        let users = vec![make_user(1, "nomail", None)];

        let mut groups = HashMap::new();
        groups.insert(
            "group:team".to_string(),
            vec!["someone@example.com".to_string()],
        );

        let resolver = MapUserResolver::with_groups(users, groups, None);
        let groups = resolver.resolve_groups(&UserId(1));
        assert!(groups.is_empty());
    }

    #[test]
    fn test_resolve_groups_unknown_user() {
        let resolver = MapUserResolver::new(vec![]);
        let groups = resolver.resolve_groups(&UserId(999));
        assert!(groups.is_empty());
    }

    #[test]
    fn test_resolve_oidc_groups_without_prefix() {
        let users = vec![make_user_with_oidc_groups(
            1,
            "alice",
            Some("alice@example.com"),
            vec!["engineering", "devops"],
        )];

        let resolver = MapUserResolver::with_groups(users, HashMap::new(), None);
        let alice_groups = resolver.resolve_groups(&UserId(1));

        assert!(alice_groups.contains(&"engineering".to_string()));
        assert!(alice_groups.contains(&"devops".to_string()));
        assert_eq!(alice_groups.len(), 2);
    }

    #[test]
    fn test_resolve_oidc_groups_with_prefix() {
        let users = vec![make_user_with_oidc_groups(
            1,
            "alice",
            Some("alice@example.com"),
            vec!["engineering", "devops"],
        )];

        let prefix = OidcGroupPrefix::new("oidc-").unwrap();
        let resolver = MapUserResolver::with_groups(users, HashMap::new(), Some(prefix));
        let alice_groups = resolver.resolve_groups(&UserId(1));

        assert!(alice_groups.contains(&"oidc-engineering".to_string()));
        assert!(alice_groups.contains(&"oidc-devops".to_string()));
        assert_eq!(alice_groups.len(), 2);
    }

    #[test]
    fn test_resolve_combined_oidc_and_policy_groups() {
        let users = vec![make_user_with_oidc_groups(
            1,
            "alice",
            Some("alice@example.com"),
            vec!["engineering"], // OIDC group
        )];

        let mut policy_groups = HashMap::new();
        policy_groups.insert(
            "group:admins".to_string(),
            vec!["alice@example.com".to_string()],
        );

        let resolver = MapUserResolver::with_groups(users, policy_groups, None);
        let alice_groups = resolver.resolve_groups(&UserId(1));

        // should have both oidc and policy groups
        assert!(alice_groups.contains(&"engineering".to_string())); // OIDC
        assert!(alice_groups.contains(&"admins".to_string())); // Policy
        assert_eq!(alice_groups.len(), 2);
    }

    #[test]
    fn test_resolve_groups_no_duplicates() {
        // user has oidc group that matches a policy group they're also in
        let users = vec![make_user_with_oidc_groups(
            1,
            "alice",
            Some("alice@example.com"),
            vec!["engineering"], // OIDC group
        )];

        let mut policy_groups = HashMap::new();
        policy_groups.insert(
            "group:engineering".to_string(), // Same name as OIDC group
            vec!["alice@example.com".to_string()],
        );

        let resolver = MapUserResolver::with_groups(users, policy_groups, None);
        let alice_groups = resolver.resolve_groups(&UserId(1));

        // should only appear once
        assert_eq!(
            alice_groups.iter().filter(|g| *g == "engineering").count(),
            1
        );
    }
}
