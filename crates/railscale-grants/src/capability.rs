//! network and application capability types

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ParseError;

/// network capability - what ports/protocols are allowed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkCapability {
    /// wildcard - all tcp, udp, icmp
    Wildcard,
    /// single port (any protocol)
    Port(u16),
    /// port range (any protocol)
    PortRange { start: u16, end: u16 },
    /// protocol-specific port
    ProtocolPort { protocol: Protocol, port: u16 },
    /// protocol-specific port range
    ProtocolPortRange {
        protocol: Protocol,
        start: u16,
        end: u16,
    },
    /// protocol wildcard (all ports)
    ProtocolWildcard { protocol: Protocol },
}

impl Serialize for NetworkCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            NetworkCapability::Wildcard => "*".to_string(),
            NetworkCapability::Port(p) => p.to_string(),
            NetworkCapability::PortRange { start, end } => format!("{}-{}", start, end),
            NetworkCapability::ProtocolPort { protocol, port } => {
                format!("{}:{}", protocol_name(*protocol), port)
            }
            NetworkCapability::ProtocolPortRange {
                protocol,
                start,
                end,
            } => format!("{}:{}-{}", protocol_name(*protocol), start, end),
            NetworkCapability::ProtocolWildcard { protocol } => {
                format!("{}:*", protocol_name(*protocol))
            }
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for NetworkCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NetworkCapability::parse(&s).map_err(de::Error::custom)
    }
}

fn protocol_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Gre => "gre",
        Protocol::Esp => "esp",
        Protocol::Ah => "ah",
        Protocol::Sctp => "sctp",
        Protocol::Igmp => "igmp",
        Protocol::Ipv4 => "ipv4",
    }
}

/// network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Gre,
    Esp,
    Ah,
    Sctp,
    Igmp,
    Ipv4,
}

impl Protocol {
    /// get the IANA protocol number
    pub fn number(&self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::Igmp => 2,
            Protocol::Ipv4 => 4,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Gre => 47,
            Protocol::Esp => 50,
            Protocol::Ah => 51,
            Protocol::Sctp => 132,
        }
    }
}

impl NetworkCapability {
    /// parse from string like "*", "443", "80-443", "tcp:443", "tcp:80-443"
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        if s == "*" {
            return Ok(NetworkCapability::Wildcard);
        }

        if let Some((proto_str, rest)) = s.split_once(':') {
            let protocol = parse_protocol(proto_str)?;
            if rest == "*" {
                return Ok(NetworkCapability::ProtocolWildcard { protocol });
            }
            if let Some((start, end)) = rest.split_once('-') {
                let start: u16 = start.parse().map_err(|_| ParseError::InvalidPort)?;
                let end: u16 = end.parse().map_err(|_| ParseError::InvalidPort)?;
                return Ok(NetworkCapability::ProtocolPortRange {
                    protocol,
                    start,
                    end,
                });
            }
            let port: u16 = rest.parse().map_err(|_| ParseError::InvalidPort)?;
            return Ok(NetworkCapability::ProtocolPort { protocol, port });
        }

        if let Some((start, end)) = s.split_once('-') {
            let start: u16 = start.parse().map_err(|_| ParseError::InvalidPort)?;
            let end: u16 = end.parse().map_err(|_| ParseError::InvalidPort)?;
            return Ok(NetworkCapability::PortRange { start, end });
        }

        let port: u16 = s.parse().map_err(|_| ParseError::InvalidPort)?;
        Ok(NetworkCapability::Port(port))
    }

    /// check if this capability allows a given protocol/port combination
    pub fn allows(&self, proto: Protocol, port: u16) -> bool {
        match self {
            NetworkCapability::Wildcard => true,
            NetworkCapability::Port(p) => port == *p,
            NetworkCapability::PortRange { start, end } => port >= *start && port <= *end,
            NetworkCapability::ProtocolPort {
                protocol,
                port: p,
            } => *protocol == proto && port == *p,
            NetworkCapability::ProtocolPortRange {
                protocol,
                start,
                end,
            } => *protocol == proto && port >= *start && port <= *end,
            NetworkCapability::ProtocolWildcard { protocol } => *protocol == proto,
        }
    }
}

fn parse_protocol(s: &str) -> Result<Protocol, ParseError> {
    match s {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "gre" => Ok(Protocol::Gre),
        "esp" => Ok(Protocol::Esp),
        "ah" => Ok(Protocol::Ah),
        "sctp" => Ok(Protocol::Sctp),
        "igmp" => Ok(Protocol::Igmp),
        "ipv4" => Ok(Protocol::Ipv4),
        _ => Err(ParseError::UnknownProtocol(s.to_string())),
    }
}

/// application capability - opaque json parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCapability {
    /// capability name (e.g., "tailscale.com/cap/drive")
    pub name: String,
    /// parameters - opaque json values
    pub params: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wildcard() {
        let cap = NetworkCapability::parse("*").unwrap();
        assert_eq!(cap, NetworkCapability::Wildcard);
    }

    #[test]
    fn test_parse_port() {
        let cap = NetworkCapability::parse("443").unwrap();
        assert_eq!(cap, NetworkCapability::Port(443));
    }

    #[test]
    fn test_parse_port_range() {
        let cap = NetworkCapability::parse("80-443").unwrap();
        assert_eq!(
            cap,
            NetworkCapability::PortRange {
                start: 80,
                end: 443
            }
        );
    }

    #[test]
    fn test_parse_protocol_port() {
        let cap = NetworkCapability::parse("tcp:443").unwrap();
        assert_eq!(
            cap,
            NetworkCapability::ProtocolPort {
                protocol: Protocol::Tcp,
                port: 443
            }
        );
    }

    #[test]
    fn test_parse_protocol_port_range() {
        let cap = NetworkCapability::parse("tcp:80-443").unwrap();
        assert_eq!(
            cap,
            NetworkCapability::ProtocolPortRange {
                protocol: Protocol::Tcp,
                start: 80,
                end: 443
            }
        );
    }

    #[test]
    fn test_parse_protocol_wildcard() {
        let cap = NetworkCapability::parse("icmp:*").unwrap();
        assert_eq!(
            cap,
            NetworkCapability::ProtocolWildcard {
                protocol: Protocol::Icmp
            }
        );
    }

    #[test]
    fn test_allows_wildcard() {
        let cap = NetworkCapability::Wildcard;
        assert!(cap.allows(Protocol::Tcp, 443));
        assert!(cap.allows(Protocol::Udp, 53));
        assert!(cap.allows(Protocol::Icmp, 0));
    }

    #[test]
    fn test_allows_port() {
        let cap = NetworkCapability::Port(443);
        assert!(cap.allows(Protocol::Tcp, 443));
        assert!(cap.allows(Protocol::Udp, 443));
        assert!(!cap.allows(Protocol::Tcp, 80));
    }

    #[test]
    fn test_allows_port_range() {
        let cap = NetworkCapability::PortRange {
            start: 80,
            end: 443,
        };
        assert!(cap.allows(Protocol::Tcp, 80));
        assert!(cap.allows(Protocol::Tcp, 443));
        assert!(cap.allows(Protocol::Tcp, 200));
        assert!(!cap.allows(Protocol::Tcp, 79));
        assert!(!cap.allows(Protocol::Tcp, 444));
    }

    #[test]
    fn test_allows_protocol_port() {
        let cap = NetworkCapability::ProtocolPort {
            protocol: Protocol::Tcp,
            port: 443,
        };
        assert!(cap.allows(Protocol::Tcp, 443));
        assert!(!cap.allows(Protocol::Udp, 443));
        assert!(!cap.allows(Protocol::Tcp, 80));
    }

    #[test]
    fn test_allows_protocol_wildcard() {
        let cap = NetworkCapability::ProtocolWildcard {
            protocol: Protocol::Icmp,
        };
        assert!(cap.allows(Protocol::Icmp, 0));
        assert!(cap.allows(Protocol::Icmp, 8));
        assert!(!cap.allows(Protocol::Tcp, 80));
    }

    #[test]
    fn test_protocol_numbers() {
        assert_eq!(Protocol::Tcp.number(), 6);
        assert_eq!(Protocol::Udp.number(), 17);
        assert_eq!(Protocol::Icmp.number(), 1);
    }
}
