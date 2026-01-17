use railscale_grants::UserResolver;
use railscale_types::{User, UserId};
use std::collections::HashMap;

/// a userresolver that uses an in-memory map of users and policy-defined groups.
///
/// use `with_groups()` to also include policy-defined groups
/// have the list of users loaded from the database and the policy groups.
pub struct MapUserResolver {
    users: HashMap<UserId, User>,
    /// maps group name (with "group:" prefix) to list of member emails.
    groups: HashMap<String, Vec<String>>,
}

impl MapUserResolver {
    /// groups should be a mapping from group name (e.g., "group:engineering")
    ///to a list of member email addresses
    /// use `with_groups()` to also include policy-defined groups.
    pub fn new(users: Vec<User>) -> Self {
        let users = users.into_iter().map(|u| (u.id, u)).collect();
        Self {
            users,
            groups: HashMap::new(),
        }
    }

    /// create a new resolver with users and policy groups.
    ///
    /// groups should be a mapping from group name (e.g., "group:engineering")
    /// to a list of member email addresses.
    pub fn with_groups(users: Vec<User>, groups: HashMap<String, Vec<String>>) -> Self {
        let users = users.into_iter().map(|u| (u.id, u)).collect();
        Self { users, groups }
    }
}

impl UserResolver for MapUserResolver {
    fn resolve_user(&self, user_id: &UserId) -> Option<String> {
        self.users.get(user_id).map(|u| u.username().to_string())
    }

    fn resolve_groups(&self, user_id: &UserId) -> Vec<String> {
        // get the user's email - if no email, they can't be in any policy groups
        let user = match self.users.get(user_id) {
            Some(u) => u,
            None => return Vec::new(),
        };

        let email = match &user.email {
            Some(e) => e.to_lowercase(),
            None => return Vec::new(),
        };

        // find all groups where this user's email is a member
        self.groups
            .iter()
            .filter_map(|(group_name, members)| {
                // strip "group:" prefix for the returned group name
                let name = group_name.strip_prefix("group:").unwrap_or(group_name);
                // check if user's email is in the member list (case-insensitive)
                if members.iter().any(|m| m.to_lowercase() == email) {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect()
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

        let resolver = MapUserResolver::with_groups(users, groups);

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

        let resolver = MapUserResolver::with_groups(users, groups);
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

        let resolver = MapUserResolver::with_groups(users, groups);
        let groups = resolver.resolve_groups(&UserId(1));
        assert!(groups.is_empty());
    }

    #[test]
    fn test_resolve_groups_unknown_user() {
        let resolver = MapUserResolver::new(vec![]);
        let groups = resolver.resolve_groups(&UserId(999));
        assert!(groups.is_empty());
    }
}
