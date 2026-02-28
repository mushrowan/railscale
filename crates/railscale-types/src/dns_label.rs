//! shared validation logic for dns-label-like strings.
//!
//! used by [`Username`] and [`NodeName`] which share identical rules:
//! - 1 to `max_len` characters
//! - lowercase alphanumeric and hyphens only
//! - no leading or trailing hyphens

/// errors from dns label validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsLabelError {
    Empty,
    TooLong(usize),
    InvalidCharacters,
    InvalidHyphenPosition,
}

/// validate a string as a dns label.
pub fn validate(s: &str, max_len: usize) -> Result<(), DnsLabelError> {
    if s.is_empty() {
        return Err(DnsLabelError::Empty);
    }

    if s.len() > max_len {
        return Err(DnsLabelError::TooLong(s.len()));
    }

    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(DnsLabelError::InvalidCharacters);
    }

    if s.starts_with('-') || s.ends_with('-') {
        return Err(DnsLabelError::InvalidHyphenPosition);
    }

    Ok(())
}

/// sanitise an arbitrary string into a valid dns label.
///
/// returns `None` if the result would be empty.
pub fn sanitise(s: &str, max_len: usize) -> Option<String> {
    let sanitised: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();

    let mut result = String::new();
    let mut last_was_hyphen = true; // treat start as if preceded by hyphen
    for c in sanitised.chars() {
        if c == '-' {
            if !last_was_hyphen && result.len() < max_len {
                result.push(c);
                last_was_hyphen = true;
            }
        } else if result.len() < max_len {
            result.push(c);
            last_was_hyphen = false;
        }
    }

    while result.ends_with('-') {
        result.pop();
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid() {
        assert!(validate("hello", 63).is_ok());
        assert!(validate("a-b-c", 63).is_ok());
        assert!(validate("a", 63).is_ok());
        assert!(validate("123", 63).is_ok());
    }

    #[test]
    fn test_validate_empty() {
        assert_eq!(validate("", 63), Err(DnsLabelError::Empty));
    }

    #[test]
    fn test_validate_too_long() {
        let long = "a".repeat(64);
        assert_eq!(validate(&long, 63), Err(DnsLabelError::TooLong(64)));
        assert!(validate(&"a".repeat(63), 63).is_ok());
    }

    #[test]
    fn test_validate_invalid_chars() {
        assert_eq!(validate("Hello", 63), Err(DnsLabelError::InvalidCharacters));
        assert_eq!(
            validate("has_underscore", 63),
            Err(DnsLabelError::InvalidCharacters)
        );
    }

    #[test]
    fn test_validate_hyphens() {
        assert_eq!(
            validate("-start", 63),
            Err(DnsLabelError::InvalidHyphenPosition)
        );
        assert_eq!(
            validate("end-", 63),
            Err(DnsLabelError::InvalidHyphenPosition)
        );
    }

    #[test]
    fn test_sanitise_basic() {
        assert_eq!(sanitise("hello", 63).unwrap(), "hello");
        assert_eq!(sanitise("Hello World", 63).unwrap(), "hello-world");
        assert_eq!(sanitise("a@b.c", 63).unwrap(), "a-b-c");
    }

    #[test]
    fn test_sanitise_collapse_hyphens() {
        assert_eq!(sanitise("a---b", 63).unwrap(), "a-b");
    }

    #[test]
    fn test_sanitise_trim_hyphens() {
        assert_eq!(sanitise("---hello---", 63).unwrap(), "hello");
    }

    #[test]
    fn test_sanitise_empty() {
        assert!(sanitise("", 63).is_none());
        assert!(sanitise("@@@", 63).is_none());
    }
}
