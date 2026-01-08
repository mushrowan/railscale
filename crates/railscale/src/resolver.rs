use railscale_grants::UserResolver;
use railscale_types::{User, UserId};
use std::collections::HashMap;

/// a userresolver that uses an in-memory map of users.
///
/// this is typically constructed in the map handler where we already
/// have the list of users loaded from the database.
pub struct MapUserResolver {
    users: HashMap<UserId, User>,
}

impl MapUserResolver {
    /// create a new resolver from a list of users.
    pub fn new(users: Vec<User>) -> Self {
        let users = users.into_iter().map(|u| (u.id, u)).collect();
        Self { users }
    }
}

impl UserResolver for MapUserResolver {
    fn resolve_user(&self, user_id: &UserId) -> Option<String> {
        self.users.get(user_id).map(|u| u.username().to_string())
    }

    fn resolve_groups(&self, _user_id: &UserId) -> Vec<String> {
        // TODO: implement groups in db
        // for now, return empty list
        Vec::new()
    }
}
