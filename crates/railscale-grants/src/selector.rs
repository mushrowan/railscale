//! selector types for matching sources and destinations in grants

use ipnet::IpNet;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ParseError;

/// a selector that can match nodes in src or dst fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// wildcard - matches all nodes in the tailnet
    Wildcard,
    /// user email (e.g., "user@example.com")
    User(String),
    /// group reference (e.g., "group:engineering")
    Group(String),
    /// tag reference (e.g., "tag:server")
    Tag(String),
    /// autogroup (e.g., "autogroup:admin", "autogroup:tagged")
    Autogroup(Autogroup),
    /// cIDR range (e.g., "192.168.1.0/24")
    Cidr(IpNet),
}

impl Serialize for Selector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            Selector::Wildcard => "*".to_string(),
            Selector::User(u) => u.clone(),
            Selector::Group(g) => format!("group:{}", g),
            Selector::Tag(t) => format!("tag:{}", t),
            Selector::Autogroup(ag) => format!("autogroup:{}", autogroup_name(*ag)),
            Selector::Cidr(net) => net.to_string(),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Selector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Selector::parse(&s).map_err(de::Error::custom)
    }
}

fn autogroup_name(ag: Autogroup) -> &'static str {
    match ag {
        Autogroup::Admin => "admin",
        Autogroup::Member => "member",
        Autogroup::Owner => "owner",
        Autogroup::Tagged => "tagged",
        Autogroup::Shared => "shared",
        Autogroup::Internet => "internet",
        Autogroup::SelfDevices => "self",
    }
}

/// built-in autogroups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Autogroup {
    /// all admin users
    Admin,
    /// all member users
    Member,
    /// all owner users
    Owner,
    /// all tagged devices
    Tagged,
    /// all shared device users
    Shared,
    /// internet via exit nodes (dst only)
    Internet,
    /// user's own devices (dst only)
    #[serde(rename = "self")]
    SelfDevices,
}

impl Selector {
    /// parse a selector from a string
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        match s {
            "*" => Ok(Selector::Wildcard),
            s if s.starts_with("tag:") => {
                Ok(Selector::Tag(s.strip_prefix("tag:").unwrap().to_string()))
            }
            s if s.starts_with("group:") => {
                Ok(Selector::Group(s.strip_prefix("group:").unwrap().to_string()))
            }
            s if s.starts_with("autogroup:") => {
                let name = s.strip_prefix("autogroup:").unwrap();
                let autogroup = match name {
                    "admin" => Autogroup::Admin,
                    "member" => Autogroup::Member,
                    "owner" => Autogroup::Owner,
                    "tagged" => Autogroup::Tagged,
                    "shared" => Autogroup::Shared,
                    "internet" => Autogroup::Internet,
                    "self" => Autogroup::SelfDevices,
                    _ => return Err(ParseError::UnknownAutogroup(name.to_string())),
                };
                Ok(Selector::Autogroup(autogroup))
            }
            s if s.contains('@') => Ok(Selector::User(s.to_string())),
            s if s.contains('/') => {
                // try to parse as cidr
                let net: IpNet = s.parse().map_err(|_| ParseError::InvalidCidr(s.to_string()))?;
                Ok(Selector::Cidr(net))
            }
            other => Err(ParseError::UnknownSelector(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wildcard() {
        let selector = Selector::parse("*").unwrap();
        assert_eq!(selector, Selector::Wildcard);
    }

    #[test]
    fn test_parse_tag() {
        let selector = Selector::parse("tag:web").unwrap();
        assert_eq!(selector, Selector::Tag("web".to_string()));
    }

    #[test]
    fn test_parse_autogroup_tagged() {
        let selector = Selector::parse("autogroup:tagged").unwrap();
        assert_eq!(selector, Selector::Autogroup(Autogroup::Tagged));
    }

    #[test]
    fn test_parse_autogroup_admin() {
        let selector = Selector::parse("autogroup:admin").unwrap();
        assert_eq!(selector, Selector::Autogroup(Autogroup::Admin));
    }

    #[test]
    fn test_parse_cidr() {
        let selector = Selector::parse("192.168.1.0/24").unwrap();
        match selector {
            Selector::Cidr(net) => {
                assert_eq!(net.to_string(), "192.168.1.0/24");
            }
            _ => panic!("Expected CIDR selector"),
        }
    }

    #[test]
    fn test_parse_user() {
        let selector = Selector::parse("user@example.com").unwrap();
        assert_eq!(selector, Selector::User("user@example.com".to_string()));
    }

    #[test]
    fn test_parse_group() {
        let selector = Selector::parse("group:engineering").unwrap();
        assert_eq!(selector, Selector::Group("engineering".to_string()));
    }

    #[test]
    fn test_parse_unknown_autogroup() {
        let result = Selector::parse("autogroup:unknown");
        assert!(result.is_err());
    }
}
