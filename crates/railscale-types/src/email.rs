//! validated email address type
//!
//! uses the `email_address` crate for RFC-compliant validation

use std::fmt;
use std::str::FromStr;

use email_address::EmailAddress;
use serde::{Deserialize, Serialize};

/// a validated email address
///
/// wraps `email_address::emailaddress` to provide rfc-compliant validation
/// with serde integration that validates during deserialisation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(EmailAddress);

impl Email {
    /// create a new Email, validating the format
    pub fn new(s: &str) -> Result<Self, EmailError> {
        let addr = EmailAddress::from_str(s).map_err(|_| EmailError::Invalid)?;
        Ok(Self(addr))
    }

    /// get the email as a string slice
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// consume the Email and return the inner string
    pub fn into_inner(self) -> String {
        self.0.to_string()
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Email::new(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

/// error type for email validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailError {
    /// email format is invalid
    Invalid,
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailError::Invalid => write!(f, "invalid email format"),
        }
    }
}

impl std::error::Error for EmailError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(Email::new("user@example.com").is_ok());
        assert!(Email::new("user.name@example.com").is_ok());
        assert!(Email::new("user+tag@example.com").is_ok());
        assert!(Email::new("user@subdomain.example.com").is_ok());
    }

    #[test]
    fn test_invalid_emails() {
        assert!(Email::new("").is_err());
        assert!(Email::new("not-an-email").is_err());
        assert!(Email::new("@example.com").is_err());
        assert!(Email::new("user@").is_err());
        assert!(Email::new("user@.com").is_err());
    }

    #[test]
    fn test_email_accessors() {
        let email = Email::new("user@example.com").unwrap();
        assert_eq!(email.as_str(), "user@example.com");
        assert_eq!(email.to_string(), "user@example.com");
    }

    #[test]
    fn test_into_inner() {
        let email = Email::new("user@example.com").unwrap();
        assert_eq!(email.into_inner(), "user@example.com");
    }

    #[test]
    fn test_serde_roundtrip() {
        let email = Email::new("user@example.com").unwrap();
        let json = serde_json::to_string(&email).unwrap();
        assert_eq!(json, "\"user@example.com\"");

        let parsed: Email = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, email);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<Email, _> = serde_json::from_str("\"not-an-email\"");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid email format"));
    }

    #[test]
    fn test_from_str() {
        let email: Email = "user@example.com".parse().unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }
}
