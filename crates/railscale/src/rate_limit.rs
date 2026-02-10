//! rate limiting utilities with proxy-aware IP extraction.
//!
//! this module provides a secure key extractor for rate limiting that
//! properly handles X-Forwarded-For headers when behind a trusted proxy.
//! also provides IP allowlist filtering for restricted endpoints.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
        let replenish_interval_ms = if rpm > 0 {
            (60_000u64 / rpm as u64).max(1)
        } else {
            1000
        };
        let burst_size = (rpm / 6).clamp(5, 50);
        Self {
            replenish_interval_ms,
            burst_size,
        }
    }
}

/// simple IP key extractor that handles missing ConnectInfo gracefully.
///
/// uses the peer IP from ConnectInfo, or falls back to a default IP
/// when ConnectInfo is unavailable (e.g., in tests).
#[derive(Clone, Default)]
pub struct SimpleIpKeyExtractor;

impl KeyExtractor for SimpleIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, tower_governor::GovernorError> {
        let connect_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        // use peer IP if available, otherwise fall back to localhost
        // (missing ConnectInfo only happens in tests)
        Ok(connect_info.unwrap_or(IpAddr::from([127, 0, 0, 1])))
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
        if self.is_trusted_proxy(peer_ip)
            && let Some(forwarded_ip) = self.extract_forwarded_ip(request)
        {
            return Ok(forwarded_ip);
        }

        // either not from a trusted proxy, or no valid X-Forwarded-For header
        Ok(peer_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_params_zero_rpm() {
        let params = RateLimitParams::from_requests_per_minute(0);
        assert_eq!(params.replenish_interval_ms, 1000);
        assert_eq!(params.burst_size, 5);
    }

    #[test]
    fn test_rate_limit_params_extreme_rpm() {
        // very high RPM should not produce zero interval
        let params = RateLimitParams::from_requests_per_minute(1_000_000);
        assert!(
            params.replenish_interval_ms >= 1,
            "interval must be at least 1ms to avoid governor panic"
        );
        assert!(params.burst_size >= 5);
    }

    #[test]
    fn test_rate_limit_params_normal_rpm() {
        let params = RateLimitParams::from_requests_per_minute(60);
        assert_eq!(params.replenish_interval_ms, 1000); // 60_000 / 60
        assert_eq!(params.burst_size, 10); // 60 / 6
    }

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

    #[test]
    fn test_ip_allowlist_filter() {
        let filter =
            IpAllowlistFilter::new(&["10.0.0.0/8".to_string(), "192.168.1.100".to_string()]);

        assert!(filter.is_allowed("10.1.2.3".parse().unwrap()));
        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.1.101".parse().unwrap()));
        assert!(!filter.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_empty_allows_none() {
        let filter = IpAllowlistFilter::new(&[]);
        // empty filter allows nothing (should not be used - check before applying)
        assert!(!filter.is_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_extract_client_ip_from_xff_when_trusted() {
        let filter = IpAllowlistFilter::new(&["10.0.0.0/8".to_string()])
            .with_trusted_proxies(&["192.168.1.1".to_string()]);

        // request from trusted proxy with XFF header containing an allowed IP
        let mut req = Request::builder()
            .header("x-forwarded-for", "10.5.5.5, 192.168.1.1")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 1, 1], 1234))));

        let client_ip = filter.extract_client_ip(&req);
        assert_eq!(
            client_ip,
            Some("10.5.5.5".parse().unwrap()),
            "should extract client IP from XFF when peer is trusted proxy"
        );
    }

    #[test]
    fn test_ip_allowlist_ignores_xff_from_untrusted_peer() {
        let filter = IpAllowlistFilter::new(&["10.0.0.0/8".to_string()])
            .with_trusted_proxies(&["192.168.1.1".to_string()]);

        // request from untrusted peer with spoofed XFF header
        let mut req = Request::builder()
            .header("x-forwarded-for", "10.5.5.5")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([8, 8, 8, 8], 1234))));

        let client_ip = filter.extract_client_ip(&req);
        assert_eq!(
            client_ip,
            Some("8.8.8.8".parse().unwrap()),
            "should use peer IP when not from trusted proxy"
        );
    }

    #[test]
    fn test_ip_allowlist_no_trusted_proxies_uses_peer_ip() {
        let filter = IpAllowlistFilter::new(&["10.0.0.0/8".to_string()]);

        // no trusted proxies configured, XFF should be ignored
        let mut req = Request::builder()
            .header("x-forwarded-for", "10.5.5.5")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([8, 8, 8, 8], 1234))));

        let client_ip = filter.extract_client_ip(&req);
        assert_eq!(
            client_ip,
            Some("8.8.8.8".parse().unwrap()),
            "should use peer IP when no trusted proxies configured"
        );
    }
}

/// IP allowlist filter for restricting endpoint access.
///
/// when applied, only requests from IPs matching the allowlist are permitted.
/// supports trusted proxy configuration for X-Forwarded-For extraction.
#[derive(Clone)]
pub struct IpAllowlistFilter {
    /// parsed allowed networks/IPs
    allowed_networks: Arc<Vec<IpNet>>,
    /// trusted proxy networks for XFF extraction
    trusted_networks: Arc<Vec<IpNet>>,
}

impl IpAllowlistFilter {
    /// create a new filter with the given allowed addresses.
    ///
    /// accepts IPs and CIDR ranges (e.g., "127.0.0.1", "10.0.0.0/8").
    pub fn new(allowed_ips: &[String]) -> Self {
        Self {
            allowed_networks: Arc::new(parse_ip_list(allowed_ips)),
            trusted_networks: Arc::new(Vec::new()),
        }
    }

    /// add trusted proxy addresses for X-Forwarded-For extraction.
    ///
    /// when a request arrives from a trusted proxy, the client IP is
    /// extracted from the X-Forwarded-For header instead of using the peer IP.
    pub fn with_trusted_proxies(mut self, trusted_proxies: &[String]) -> Self {
        self.trusted_networks = Arc::new(parse_ip_list(trusted_proxies));
        self
    }

    /// check if an IP is in the allowlist.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.allowed_networks.iter().any(|net| net.contains(&ip))
    }

    /// extract the client IP from a request, respecting trusted proxies.
    ///
    /// if the peer IP is from a trusted proxy, extracts the client IP from
    /// the X-Forwarded-For header. otherwise, returns the peer IP directly.
    pub fn extract_client_ip<T>(&self, request: &Request<T>) -> Option<IpAddr> {
        let peer_ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())?;

        // if peer is a trusted proxy, try to extract real client IP from XFF
        if self
            .trusted_networks
            .iter()
            .any(|net| net.contains(&peer_ip))
            && let Some(xff) = request.headers().get("x-forwarded-for")
            && let Ok(xff_str) = xff.to_str()
            && let Some(first_ip) = xff_str.split(',').next()
            && let Ok(client_ip) = first_ip.trim().parse::<IpAddr>()
        {
            return Some(client_ip);
        }

        Some(peer_ip)
    }
}

/// parse a list of IP/CIDR strings into IpNet entries.
fn parse_ip_list(ips: &[String]) -> Vec<IpNet> {
    ips.iter()
        .filter_map(|s| {
            s.parse::<IpNet>().ok().or_else(|| {
                s.parse::<IpAddr>().ok().map(|ip| match ip {
                    IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                    IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
                })
            })
        })
        .collect()
}

/// middleware to filter requests by IP allowlist.
///
/// returns 403 Forbidden if the client IP is not in the allowlist.
/// respects trusted proxy configuration for X-Forwarded-For extraction.
pub async fn ip_allowlist_middleware(
    State(filter): State<IpAllowlistFilter>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = filter.extract_client_ip(&request);

    match client_ip {
        Some(ip) if filter.is_allowed(ip) => next.run(request).await,
        Some(ip) => {
            tracing::warn!(client_ip = %ip, "verify request from disallowed IP");
            (StatusCode::FORBIDDEN, "IP not in allowlist").into_response()
        }
        None => {
            tracing::warn!("verify request without client IP");
            (StatusCode::FORBIDDEN, "unable to determine client IP").into_response()
        }
    }
}
