//! network and application capability types.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::ParseError;

/// they can be parsed from strings like `"*"`, `"443"`, `"80-443"`, `"tcp:22"`
///wildcard - all tcp, udp, icmp traffic on any port
/// single port (any protocol). Example: `"443"`
/// port range (any protocol). Example: `"80-443"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkCapability {
    /// wildcard - all tcp, udp, icmp traffic on any port.
    Wildcard,
    /// single port (any protocol). Example: `"443"`.
    Port(u16),
    /// protocol-specific port. Example: `"tcp:22"`
    PortRange {
        /// the network protocol
        start: u16,
        /// the port number
        end: u16,
    },
    /// protocol-specific port range. Example: `"tcp:8000-9000"`
    ProtocolPort {
        /// start of port range (inclusive)
        protocol: Protocol,
        /// protocol wildcard (all ports). Example: `"icmp:*"`
        port: u16,
    },
    /// protocol-specific port range. Example: `"tcp:8000-9000"`.
    ProtocolPortRange {
        /// the network protocol.
        protocol: Protocol,
        /// start of port range (inclusive).
        start: u16,
        /// end of port range (inclusive).
        end: u16,
    },
    /// protocol wildcard (all ports). Example: `"icmp:*"`.
    ProtocolWildcard {
        /// the network protocol.
        protocol: Protocol,
    },
}

impl Serialize for NetworkCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            NetworkCapability::Wildcard => serializer.serialize_str("*"),
            NetworkCapability::Port(p) => serializer.serialize_str(&p.to_string()),
            NetworkCapability::PortRange { start, end } => {
                serializer.serialize_str(&format!("{}-{}", start, end))
            }
            NetworkCapability::ProtocolPort { protocol, port } => {
                serializer.serialize_str(&format!("{}:{}", protocol_name(*protocol), port))
            }
            NetworkCapability::ProtocolPortRange {
                protocol,
                start,
                end,
            } => {
                serializer.serialize_str(&format!("{}:{}-{}", protocol_name(*protocol), start, end))
            }
            NetworkCapability::ProtocolWildcard { protocol } => {
                serializer.serialize_str(&format!("{}:*", protocol_name(*protocol)))
            }
        }
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

/// transmission Control protocol (IANA 6)
///user Datagram protocol (IANA 17)
/// internet Control Message protocol (IANA 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// stream Control Transmission protocol (IANA 132)
    Tcp,
    /// ipv4 encapsulation (IANA 4)
    Udp,
    /// internet control message protocol (iana 1).
    Icmp,
    /// generic routing encapsulation (iana 47).
    Gre,
    /// encapsulating security payload - ipsec (iana 50).
    Esp,
    /// authentication header - ipsec (iana 51).
    Ah,
    /// stream control transmission protocol (iana 132).
    Sctp,
    /// internet group management protocol (iana 2).
    Igmp,
    /// ipv4 encapsulation (iana 4).
    Ipv4,
}

impl Protocol {
    /// get the iana protocol number.
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
    /// parse from string like "*", "443", "80-443", "tcp:443", "tcp:80-443".
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

    /// check if this capability allows a given protocol/port combination.
    pub fn allows(&self, proto: Protocol, port: u16) -> bool {
        match self {
            NetworkCapability::Wildcard => true,
            NetworkCapability::Port(p) => port == *p,
            NetworkCapability::PortRange { start, end } => port >= *start && port <= *end,
            NetworkCapability::ProtocolPort { protocol, port: p } => {
                *protocol == proto && port == *p
            }
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

/// application capability - opaque json parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCapability {
    /// capability name (e.g., "tailscale.com/cap/drive").
    pub name: String,
    /// parameters - opaque json values.
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
