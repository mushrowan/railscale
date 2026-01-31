//! geoip resolution for ip:country posture checks

use std::net::IpAddr;

/// resolves IP addresses to country codes
pub trait GeoIpResolver: Send + Sync {
    /// lookup the ISO 3166-1 alpha-2 country code for an IP address
    fn lookup_country(&self, ip: IpAddr) -> Option<String>;
}

/// resolver that returns nothing (for when no geoip database is available)
#[derive(Debug, Default, Clone)]
pub struct NoopGeoIpResolver;

impl GeoIpResolver for NoopGeoIpResolver {
    fn lookup_country(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// mock resolver for testing
    struct MockGeoIpResolver {
        mappings: std::collections::HashMap<IpAddr, String>,
    }

    impl MockGeoIpResolver {
        fn new() -> Self {
            Self {
                mappings: std::collections::HashMap::new(),
            }
        }

        fn add(&mut self, ip: IpAddr, country: &str) {
            self.mappings.insert(ip, country.to_string());
        }
    }

    impl GeoIpResolver for MockGeoIpResolver {
        fn lookup_country(&self, ip: IpAddr) -> Option<String> {
            self.mappings.get(&ip).cloned()
        }
    }

    #[test]
    fn lookup_country_from_known_ip() {
        let mut resolver = MockGeoIpResolver::new();
        resolver.add("8.8.8.8".parse().unwrap(), "US");
        resolver.add("1.1.1.1".parse().unwrap(), "AU");

        assert_eq!(
            resolver.lookup_country("8.8.8.8".parse().unwrap()),
            Some("US".to_string())
        );
        assert_eq!(
            resolver.lookup_country("1.1.1.1".parse().unwrap()),
            Some("AU".to_string())
        );
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let resolver = MockGeoIpResolver::new();
        assert_eq!(
            resolver.lookup_country("192.168.1.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn noop_resolver_returns_none() {
        let resolver = NoopGeoIpResolver;
        assert_eq!(resolver.lookup_country("8.8.8.8".parse().unwrap()), None);
    }
}
