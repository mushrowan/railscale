//! rate limiting utilities with proxy-aware IP extraction.
//!
//! this module provides a secure key extractor for rate limiting that
//! properly handles X-Forwarded-For headers when behind a trusted proxy.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::Request;
use ipnet::IpNet;
use tower_governor::key_extractor::KeyExtractor;

/// rate limit parameters computed from requests-per-minute config.
pub struct RateLimitParams {
    /// interval between token replenishments in milliseconds.
    pub replenish_interval_ms: u64,
    /// burst size (max tokens).
    pub burst_size: u32,
}

impl RateLimitParams {
    /// compute rate limit params from requests-per-minute.
    ///
    /// burst is ~10 seconds worth of requests, capped at 5-50.
    pub fn from_requests_per_minute(rpm: u32) -> Self {
        let replenish_interval_ms = if rpm > 0 { 60_000 / rpm as u64 } else { 1000 };
        let burst_size = (rpm / 6).clamp(5, 50);
        Self {
            replenish_interval_ms,
            burst_size,
        }
    }
}

/// a rate limit key extractor that securely handles reverse proxy setups
///
/// when a request comes from a trusted proxy IP, the client IP is extracted
/// from the X-Forwarded-For header. Otherwise, the peer IP is used directly
///
/// this prevents IP spoofing attacks where untrusted clients send fake
/// x-Forwarded-For headers to bypass rate limiting
#[derive(Clone)]
pub struct TrustedProxyKeyExtractor {
    /// parsed trusted proxy networks/IPs
    trusted_networks: Arc<Vec<IpNet>>,
}

impl TrustedProxyKeyExtractor {
    /// create a new extractor with the given trusted proxy addresses
    ///
    /// accepts ips and cidr ranges (e.g., "127.0.0.1", "10.0.0.0/8")
    pub fn new(trusted_proxies: &[String]) -> Self {
        let trusted_networks: Vec<IpNet> = trusted_proxies
            .iter()
            .filter_map(|s| {
                // try parsing as cidr first, then as a single IP
                s.parse::<IpNet>().ok().or_else(|| {
                    s.parse::<IpAddr>().ok().map(|ip| {
                        // convert single IP to /32 or /128 network
                        match ip {
                            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
                        }
                    })
                })
            })
            .collect();

        Self {
            trusted_networks: Arc::new(trusted_networks),
        }
    }

    /// check if an ip is from a trusted proxy
    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_networks.iter().any(|net| net.contains(&ip))
    }

    /// extract client IP from X-Forwarded-For header
    ///
    /// the header format is: `X-Forwarded-For: client, proxy1, proxy2, ...`
    /// we want the leftmost (client) IP
    fn extract_forwarded_ip<T>(&self, request: &Request<T>) -> Option<IpAddr> {
        let header_value = request.headers().get("x-forwarded-for")?;
        let header_str = header_value.to_str().ok()?;

        // take the first (leftmost) IP - this is the original client
        let first_ip_str = header_str.split(',').next()?.trim();
        first_ip_str.parse::<IpAddr>().ok()
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, tower_governor::GovernorError> {
        // get the peer IP from ConnectInfo
        let connect_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);

        let peer_ip = connect_info
            .map(|addr| addr.ip())
            .ok_or(tower_governor::GovernorError::UnableToExtractKey)?;

        // if the peer is a trusted proxy, try to get the real client IP
        if self.is_trusted_proxy(peer_ip) {
            if let Some(forwarded_ip) = self.extract_forwarded_ip(request) {
                return Ok(forwarded_ip);
            }
        }

        // either not from a trusted proxy, or no valid X-Forwarded-For header
        Ok(peer_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_proxy_parsing() {
        let extractor = TrustedProxyKeyExtractor::new(&[
            "127.0.0.1".to_string(),
            "10.0.0.0/8".to_string(),
            "::1".to_string(),
            "fd00::/8".to_string(),
        ]);

        assert!(extractor.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(extractor.is_trusted_proxy("10.1.2.3".parse().unwrap()));
        assert!(extractor.is_trusted_proxy("10.255.255.255".parse().unwrap()));
        assert!(extractor.is_trusted_proxy("::1".parse().unwrap()));
        assert!(extractor.is_trusted_proxy("fd00::1".parse().unwrap()));

        assert!(!extractor.is_trusted_proxy("192.168.1.1".parse().unwrap()));
        assert!(!extractor.is_trusted_proxy("8.8.8.8".parse().unwrap()));
        assert!(!extractor.is_trusted_proxy("::2".parse().unwrap()));
    }

    #[test]
    fn test_empty_trusted_proxies() {
        let extractor = TrustedProxyKeyExtractor::new(&[]);

        // nothing should be trusted
        assert!(!extractor.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(!extractor.is_trusted_proxy("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_invalid_proxy_entries_ignored() {
        let extractor = TrustedProxyKeyExtractor::new(&[
            "127.0.0.1".to_string(),
            "not-an-ip".to_string(),
            "also/invalid".to_string(),
            "10.0.0.0/8".to_string(),
        ]);

        // valid entries should work
        assert!(extractor.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        assert!(extractor.is_trusted_proxy("10.1.2.3".parse().unwrap()));
    }
}
