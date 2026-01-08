//! ip address allocation for nodes.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::Error;

/// allocates ip addresses for new nodes.
///
/// supports both ipv4 and ipv6 allocation from configured prefixes.
pub struct IpAllocator {
    prefix_v4: Option<IpNet>,
    prefix_v6: Option<IpNet>,
    allocated_v4: HashSet<IpAddr>,
    allocated_v6: HashSet<IpAddr>,
}

impl IpAllocator {
    /// create a new ip allocator with the given prefixes.
    pub fn new(prefix_v4: Option<IpNet>, prefix_v6: Option<IpNet>) -> Self {
        Self {
            prefix_v4,
            prefix_v6,
            allocated_v4: HashSet::new(),
            allocated_v6: HashSet::new(),
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
    pub fn allocate_v4(&mut self) -> Result<Option<IpAddr>, Error> {
        let Some(prefix) = &self.prefix_v4 else {
            return Ok(None);
        };

        // simple sequential allocation
        // TODO: implement more sophisticated allocation strategy
        for addr in prefix.hosts() {
            let ip = IpAddr::V4(match addr {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => continue,
            });
            if !self.allocated_v4.contains(&ip) {
                self.allocated_v4.insert(ip);
                return Ok(Some(ip));
            }
        }

        Err(Error::InvalidData(
            "IPv4 address pool exhausted".to_string(),
        ))
    }

    /// allocate a new ipv6 address.
    pub fn allocate_v6(&mut self) -> Result<Option<IpAddr>, Error> {
        let Some(prefix) = &self.prefix_v6 else {
            return Ok(None);
        };

        // for ipv6, we typically use the last 64 bits for host addressing
        // this is a simplified implementation
        // TODO: implement proper ipv6 allocation with node id embedding
        let mut count: u64 = 1;
        loop {
            if count > 1_000_000 {
                return Err(Error::InvalidData(
                    "IPv6 address pool exhausted".to_string(),
                ));
            }

            // get base address and add count
            let base = match prefix.network() {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(_) => return Ok(None),
            };

            let segments = base.segments();
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
                return Ok(Some(ip));
            }

            count += 1;
        }
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
    fn test_release() {
        let prefix: IpNet = "100.64.0.0/30".parse().unwrap();
        let mut allocator = IpAllocator::new(Some(prefix), None);

        let ip1 = allocator.allocate_v4().unwrap().unwrap();
        allocator.release(ip1);

        let ip2 = allocator.allocate_v4().unwrap().unwrap();
        assert_eq!(ip1, ip2);
    }
}
