//! input validation for api v1 endpoints.

use super::super::ApiError;

/// maximum length for usernames (dns-safe).
pub const MAX_USERNAME_LEN: usize = 63;

/// maximum length for node names (dns-safe).
pub const MAX_NODE_NAME_LEN: usize = 63;

/// validate a username for api operations.
///
/// usernames must be:
/// - 1-63 characters long
/// - Lowercase alphanumeric with hyphens
/// - Not start or end with a hyphen
pub fn validate_username(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("username cannot be empty"));
    }
    if name.len() > MAX_USERNAME_LEN {
        return Err(ApiError::bad_request(format!(
            "username too long (max {} characters)",
            MAX_USERNAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::bad_request(
            "username must contain only lowercase letters, digits, and hyphens",
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ApiError::bad_request(
            "username cannot start or end with a hyphen",
        ));
    }
    Ok(())
}

/// validate a node name for api operations.
///
/// node names follow the same rules as usernames.
pub fn validate_node_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("node name cannot be empty"));
    }
    if name.len() > MAX_NODE_NAME_LEN {
        return Err(ApiError::bad_request(format!(
            "node name too long (max {} characters)",
            MAX_NODE_NAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::bad_request(
            "node name must contain only lowercase letters, digits, and hyphens",
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ApiError::bad_request(
            "node name cannot start or end with a hyphen",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice-bob").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn test_invalid_usernames() {
        assert!(validate_username("").is_err());
        assert!(validate_username("Alice").is_err()); // uppercase
        assert!(validate_username("-alice").is_err()); // starts with hyphen
        assert!(validate_username("alice-").is_err()); // ends with hyphen
        assert!(validate_username("alice_bob").is_err()); // underscore not allowed
        assert!(validate_username("alice@example.com").is_err()); // @ not allowed
        assert!(validate_username(&"a".repeat(64)).is_err()); // too long
    }

    #[test]
    fn test_valid_node_names() {
        assert!(validate_node_name("mynode").is_ok());
        assert!(validate_node_name("my-node").is_ok());
        assert!(validate_node_name("node123").is_ok());
    }

    #[test]
    fn test_invalid_node_names() {
        assert!(validate_node_name("").is_err());
        assert!(validate_node_name("MyNode").is_err()); // uppercase
        assert!(validate_node_name("-node").is_err()); // starts with hyphen
    }
}
