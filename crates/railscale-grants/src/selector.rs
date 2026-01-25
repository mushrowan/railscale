//! selector types for matching sources and destinations in grants.

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::ParseError;

/// a selector that can match nodes in src or dst fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// wildcard - matches all nodes in the tailnet.
    Wildcard,
    /// user email (e.g., "user@example.com").
    User(String),
    /// group reference (e.g., "group:engineering").
    Group(String),
    /// tag reference (e.g., "tag:server").
    Tag(String),
    /// autogroup (e.g., "autogroup:admin", "autogroup:tagged").
    Autogroup(Autogroup),
    /// cidr range (e.g., "192.168.1.0/24").
    Cidr(IpNet),
}

impl Serialize for Selector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Selector::Wildcard => serializer.serialize_str("*"),
            Selector::User(u) => serializer.serialize_str(u),
            Selector::Group(g) => serializer.serialize_str(&format!("group:{}", g)),
            Selector::Tag(t) => serializer.serialize_str(&format!("tag:{}", t)),
            Selector::Autogroup(ag) => {
                serializer.serialize_str(&format!("autogroup:{}", autogroup_name(*ag)))
            }
            Selector::Cidr(net) => serializer.serialize_str(&net.to_string()),
        }
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
        Autogroup::NonRoot => "nonroot",
    }
}

/// built-in autogroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Autogroup {
    /// all admin users.
    Admin,
    /// all member users.
    Member,
    /// all owner users.
    Owner,
    /// all tagged devices.
    Tagged,
    /// all shared device users.
    Shared,
    /// internet via exit nodes (dst only).
    Internet,
    /// user's own devices (dst only).
    #[serde(rename = "self")]
    SelfDevices,
    /// any user except root (ssh users only)
    #[serde(rename = "nonroot")]
    NonRoot,
}

impl Selector {
    /// parse a selector from a string.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        match s {
            "*" => Ok(Selector::Wildcard),
            s if s.starts_with("tag:") => Ok(Selector::Tag(s[4..].to_string())),
            s if s.starts_with("group:") => Ok(Selector::Group(s[6..].to_string())),
            s if s.starts_with("autogroup:") => {
                let name = &s[10..];
                let autogroup = match name {
                    "admin" => Autogroup::Admin,
                    "member" => Autogroup::Member,
                    "owner" => Autogroup::Owner,
                    "tagged" => Autogroup::Tagged,
                    "shared" => Autogroup::Shared,
                    "internet" => Autogroup::Internet,
                    "self" => Autogroup::SelfDevices,
                    "nonroot" => Autogroup::NonRoot,
                    _ => return Err(ParseError::UnknownAutogroup(name.to_string())),
                };
                Ok(Selector::Autogroup(autogroup))
            }
            s if s.contains('@') => Ok(Selector::User(s.to_string())),
            s if s.contains('/') => {
                // try to parse as cidr
                let net: IpNet = s
                    .parse()
                    .map_err(|_| ParseError::InvalidCidr(s.to_string()))?;
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
    fn test_parse_autogroup_nonroot() {
        let selector = Selector::parse("autogroup:nonroot").unwrap();
        assert_eq!(selector, Selector::Autogroup(Autogroup::NonRoot));
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid tag names (lowercase alphanumeric + hyphens/underscores)
    fn tag_name_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,49}".prop_map(|s| s)
    }

    // strategy for valid group names
    fn group_name_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,49}".prop_map(|s| s)
    }

    // strategy for valid email-like strings
    fn email_strategy() -> impl Strategy<Value = String> {
        "[a-z]{1,10}@[a-z]{1,10}\\.[a-z]{2,4}".prop_map(|s| s)
    }

    // strategy for valid cidr strings
    fn cidr_v4_strategy() -> impl Strategy<Value = String> {
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32)
            .prop_map(|(a, b, c, d, prefix)| format!("{}.{}.{}.{}/{}", a, b, c, d, prefix))
    }

    // strategy for valid autogroup names
    fn autogroup_strategy() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("admin"),
            Just("member"),
            Just("owner"),
            Just("tagged"),
            Just("shared"),
            Just("internet"),
            Just("self"),
            Just("nonroot"),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn wildcard_roundtrips(s in Just("*".to_string())) {
            let selector = Selector::parse(&s).unwrap();
            prop_assert_eq!(&selector, &Selector::Wildcard);
            // roundtrip through serde
            let json = serde_json::to_string(&selector).unwrap();
            let parsed: Selector = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, selector);
        }

        #[test]
        fn tag_roundtrips(name in tag_name_strategy()) {
            let input = format!("tag:{}", name);
            let selector = Selector::parse(&input).unwrap();
            prop_assert_eq!(&selector, &Selector::Tag(name.clone()));
            // roundtrip through serde
            let json = serde_json::to_string(&selector).unwrap();
            let parsed: Selector = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, selector);
        }

        #[test]
        fn group_roundtrips(name in group_name_strategy()) {
            let input = format!("group:{}", name);
            let selector = Selector::parse(&input).unwrap();
            prop_assert_eq!(&selector, &Selector::Group(name.clone()));
            // roundtrip through serde
            let json = serde_json::to_string(&selector).unwrap();
            let parsed: Selector = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, selector);
        }

        #[test]
        fn autogroup_roundtrips(name in autogroup_strategy()) {
            let input = format!("autogroup:{}", name);
            let selector = Selector::parse(&input).unwrap();
            // roundtrip through serde
            let json = serde_json::to_string(&selector).unwrap();
            let parsed: Selector = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, selector);
        }

        #[test]
        fn user_roundtrips(email in email_strategy()) {
            let selector = Selector::parse(&email).unwrap();
            prop_assert_eq!(&selector, &Selector::User(email.clone()));
            // roundtrip through serde
            let json = serde_json::to_string(&selector).unwrap();
            let parsed: Selector = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed, selector);
        }

        #[test]
        fn cidr_roundtrips(cidr in cidr_v4_strategy()) {
            // NOTE: cidr parsing may normalize the network address
            if let Ok(selector) = Selector::parse(&cidr)
                && let Selector::Cidr(net) = &selector
            {
                // roundtrip through serde
                let json = serde_json::to_string(&selector).unwrap();
                let parsed: Selector = serde_json::from_str(&json).unwrap();
                // verify it's still a cidr
                prop_assert!(matches!(parsed, Selector::Cidr(_)));
                if let Selector::Cidr(parsed_net) = parsed {
                    prop_assert_eq!(net.network(), parsed_net.network());
                    prop_assert_eq!(net.prefix_len(), parsed_net.prefix_len());
                }
            }
        }

        #[test]
        fn arbitrary_string_never_panics(s in ".*") {
            // parsing arbitrary strings should never panic
            let _ = Selector::parse(&s);
        }

        #[test]
        fn invalid_autogroup_rejected(name in "[a-z]{1,20}") {
            // skip valid autogroup names
            if !["admin", "member", "owner", "tagged", "shared", "internet", "self", "nonroot"]
                .contains(&name.as_str())
            {
                let input = format!("autogroup:{}", name);
                let result = Selector::parse(&input);
                prop_assert!(result.is_err());
            }
        }
    }
}
