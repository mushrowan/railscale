//! ip allocation for nodes
//!
//! provides efficient ip address allocation by tracking the next candidate
//! index to avoid O(n) scans on each allocation

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::Error;

/// allocates ip addresses for new nodes.
///
/// supports both ipv4 and ipv6 allocation from configured prefixes.
/// tracks the next candidate index to provide amortised O(1) allocation
/// instead of O(n) per allocation
pub struct IpAllocator {
    prefix_v4: Option<IpNet>,
    prefix_v6: Option<IpNet>,
    allocated_v4: HashSet<IpAddr>,
    allocated_v6: HashSet<IpAddr>,
    /// next ipv4 host offset to try (avoids re-scanning from start)
    next_v4_offset: usize,
    /// next ipv6 host count to try (avoids re-scanning from start)
    next_v6_count: u64,
}

impl IpAllocator {
    /// create a new ip allocator with the given prefixes.
    pub fn new(prefix_v4: Option<IpNet>, prefix_v6: Option<IpNet>) -> Self {
        Self {
            prefix_v4,
            prefix_v6,
            allocated_v4: HashSet::new(),
            allocated_v6: HashSet::new(),
            next_v4_offset: 0,
            next_v6_count: 1,
        }
    }

    /// load already-allocated addresses from the database.
    pub fn load_allocated(&mut self, addresses: impl IntoIterator<Item = IpAddr>) {
        for addr in addresses {
            match addr {
                IpAddr::V4(_) => {
                    self.allocated_v4.insert(addr);
                }
                IpAddr::V6(_) => {
                    self.allocated_v6.insert(addr);
                }
            }
        }
    }

    /// allocate a new ipv4 address.
    ///
    /// uses a next-candidate tracking strategy to avoid O(n) scans on each
    /// allocation. amortised cost is O(1) for sequential allocations.
    /// computes addresses arithmetically to avoid materialising all hosts.
    pub fn allocate_v4(&mut self) -> Result<Option<IpAddr>, Error> {
        let Some(prefix) = &self.prefix_v4 else {
            return Ok(None);
        };

        // get base address and compute host count without collecting
        let base = match prefix.network() {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(_) => return Ok(None),
        };

        // host count for prefix (e.g. /24 = 254 hosts, /10 = 4M hosts)
        // hosts() excludes network and broadcast, so count is 2^(32-prefix) - 2
        let prefix_len = prefix.prefix_len();
        if prefix_len >= 31 {
            // /31 and /32 have special semantics, use hosts() for correctness
            let hosts: Vec<IpAddr> = prefix.hosts().collect();
            return self.allocate_v4_from_slice(&hosts);
        }

        let total_hosts = (1u64 << (32 - prefix_len)) - 2;
        if total_hosts == 0 {
            return Err(Error::InvalidData("ipv4 address pool is empty".to_string()));
        }

        // start from next_v4_offset and wrap around if needed
        let start_offset = self.next_v4_offset as u64 % total_hosts;

        for i in 0..total_hosts {
            let offset = (start_offset + i) % total_hosts;
            // +1 to skip network address (base is network, base+1 is first host)
            let ip_u32 = base.wrapping_add((offset + 1) as u32);
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(ip_u32));

            if !self.allocated_v4.contains(&ip) {
                self.allocated_v4.insert(ip);
                // update next offset to the one after this allocation
                self.next_v4_offset = (offset + 1) as usize;
                return Ok(Some(ip));
            }
        }

        Err(Error::InvalidData(
            "ipv4 address pool exhausted".to_string(),
        ))
    }

    /// helper for small prefixes (/31, /32) where hosts() is fine
    fn allocate_v4_from_slice(&mut self, hosts: &[IpAddr]) -> Result<Option<IpAddr>, Error> {
        let total_hosts = hosts.len();
        if total_hosts == 0 {
            return Err(Error::InvalidData("ipv4 address pool is empty".to_string()));
        }

        let start_offset = self.next_v4_offset % total_hosts;

        for i in 0..total_hosts {
            let offset = (start_offset + i) % total_hosts;
            let ip = hosts[offset];

            if !self.allocated_v4.contains(&ip) {
                self.allocated_v4.insert(ip);
                self.next_v4_offset = offset + 1;
                return Ok(Some(ip));
            }
        }

        Err(Error::InvalidData(
            "ipv4 address pool exhausted".to_string(),
        ))
    }

    /// allocate a new ipv6 address.
    ///
    /// uses a next-candidate tracking strategy to avoid o(n) scans on each
    /// allocation. Amortised cost is O(1) for sequential allocations.
    pub fn allocate_v6(&mut self) -> Result<Option<IpAddr>, Error> {
        let Some(prefix) = &self.prefix_v6 else {
            return Ok(None);
        };

        // get base address
        let base = match prefix.network() {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(_) => return Ok(None),
        };

        let segments = base.segments();
        let max_count: u64 = 1_000_000;

        // start from next_v6_count and search for an available address
        let start_count = self.next_v6_count;

        for i in 0..max_count {
            let count = ((start_count - 1 + i) % max_count) + 1;

            let new_segments = [
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                (count >> 16) as u16,
                count as u16,
            ];

            let ip = IpAddr::V6(std::net::Ipv6Addr::from(new_segments));
            if !self.allocated_v6.contains(&ip) {
                self.allocated_v6.insert(ip);
                // update next count to the one after this allocation
                self.next_v6_count = count + 1;
                if self.next_v6_count > max_count {
                    self.next_v6_count = 1;
                }
                return Ok(Some(ip));
            }
        }

        Err(Error::InvalidData(
            "IPv6 address pool exhausted".to_string(),
        ))
    }

    /// allocate both ipv4 and ipv6 addresses for a new node.
    pub fn allocate(&mut self) -> Result<(Option<IpAddr>, Option<IpAddr>), Error> {
        let v4 = self.allocate_v4()?;
        let v6 = self.allocate_v6()?;
        Ok((v4, v6))
    }

    /// release an ip address back to the pool.
    pub fn release(&mut self, addr: IpAddr) {
        match addr {
            IpAddr::V4(_) => {
                self.allocated_v4.remove(&addr);
            }
            IpAddr::V6(_) => {
                self.allocated_v6.remove(&addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_v4() {
        let prefix: IpNet = "100.64.0.0/30".parse().unwrap();
        let mut allocator = IpAllocator::new(Some(prefix), None);

        let ip1 = allocator.allocate_v4().unwrap();
        assert!(ip1.is_some());

        let ip2 = allocator.allocate_v4().unwrap();
        assert!(ip2.is_some());
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_allocate_v4_large_prefix() {
        // /16 has 65534 hosts - this would OOM if we collected all hosts
        let prefix: IpNet = "100.64.0.0/16".parse().unwrap();
        let mut allocator = IpAllocator::new(Some(prefix), None);

        // allocate first address
        let ip1 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip1.to_string(), "100.64.0.1");

        // allocate second address
        let ip2 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip2.to_string(), "100.64.0.2");

        // allocate a bunch more to verify arithmetic works
        for _ in 0..100 {
            let ip = allocator.allocate_v4().unwrap();
            assert!(ip.is_some());
        }
    }

    #[test]
    fn test_allocate_v4_default_prefix() {
        // default tailscale prefix is /10 (4M hosts) - must not OOM
        let prefix: IpNet = "100.64.0.0/10".parse().unwrap();
        let mut allocator = IpAllocator::new(Some(prefix), None);

        let ip1 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip1.to_string(), "100.64.0.1");

        let ip2 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip2.to_string(), "100.64.0.2");
    }

    #[test]
    fn test_release() {
        // /30 has only 2 usable hosts: .1 and .2
        let prefix: IpNet = "100.64.0.0/30".parse().unwrap();
        let mut allocator = IpAllocator::new(Some(prefix), None);

        // allocate both addresses
        let ip1 = allocator.allocate_v4().unwrap().unwrap();
        let ip2 = allocator.allocate_v4().unwrap().unwrap();
        assert_ne!(ip1, ip2);

        // pool should be exhausted
        assert!(allocator.allocate_v4().is_err());

        // release one and reallocate - should get it back
        allocator.release(ip1);
        let ip3 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip1, ip3);
    }
}
