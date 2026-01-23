//! input validation for api v1 endpoints

use super::super::ApiError;

/// maximum length for usernames (dns-safe)
pub const MAX_USERNAME_LEN: usize = 63;

/// maximum length for node names (dns-safe)
pub const MAX_NODE_NAME_LEN: usize = 63;

/// maximum number of tags per entity
pub const MAX_TAGS: usize = 100;

/// maximum length for a tag name (after "tag:" prefix)
pub const MAX_TAG_NAME_LEN: usize = 50;

/// validate a username for api operations
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

/// validate a node name for api operations
///
/// node names follow the same rules as usernames
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

/// validate a tag name
///
/// tags must:
/// - Start with "tag:"
/// - Have a name portion of 1-50 lowercase alphanumeric characters (with hyphens/underscores)
pub fn validate_tag(tag: &str) -> Result<(), ApiError> {
    if !tag.starts_with("tag:") {
        return Err(ApiError::bad_request("tag must start with 'tag:'"));
    }
    let name = &tag[4..];
    if name.is_empty() {
        return Err(ApiError::bad_request("tag name cannot be empty"));
    }
    if name.len() > MAX_TAG_NAME_LEN {
        return Err(ApiError::bad_request(format!(
            "tag name too long (max {} characters)",
            MAX_TAG_NAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ApiError::bad_request(
            "tag name must be lowercase alphanumeric with hyphens or underscores",
        ));
    }
    Ok(())
}

/// validate a list of tags
pub fn validate_tags(tags: &[String]) -> Result<(), ApiError> {
    if tags.len() > MAX_TAGS {
        return Err(ApiError::bad_request(format!(
            "too many tags (max {})",
            MAX_TAGS
        )));
    }
    for tag in tags {
        validate_tag(tag)?;
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
    fn test_valid_tags() {
        assert!(validate_tag("tag:server").is_ok());
        assert!(validate_tag("tag:web-server").is_ok());
        assert!(validate_tag("tag:db_server").is_ok());
        assert!(validate_tag("tag:prod123").is_ok());
    }

    #[test]
    fn test_invalid_tags() {
        assert!(validate_tag("server").is_err()); // missing prefix
        assert!(validate_tag("tag:").is_err()); // empty name
        assert!(validate_tag("tag:Server").is_err()); // uppercase
        assert!(validate_tag(&format!("tag:{}", "a".repeat(51))).is_err()); // too long
    }

    #[test]
    fn test_tags_limit() {
        let tags: Vec<String> = (0..MAX_TAGS).map(|i| format!("tag:t{}", i)).collect();
        assert!(validate_tags(&tags).is_ok());

        let too_many: Vec<String> = (0..=MAX_TAGS).map(|i| format!("tag:t{}", i)).collect();
        assert!(validate_tags(&too_many).is_err());
    }
}
