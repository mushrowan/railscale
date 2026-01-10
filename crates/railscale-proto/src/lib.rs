//! tailscale protocol implementation for railscale.
//!
//! this crate handles:
//! - noise protocol for secure communication
//! - maprequest/mapresponse handling
//! - node registration protocol
//! - derp integration

mod error;
mod map_request;
mod noise;

pub use error::Error;
pub use map_request::{
    DerpMap, DerpNode, DerpRegion, DnsConfig, FilterRule, MapRequest, MapResponse, MapResponseNode,
    PortRange, UserProfile,
};
pub use noise::{generate_keypair, NoiseHandshake, NoiseTransport};

/// result type for protocol operations.
pub type Result<T> = std::result::Result<T, Error>;

use serde::{Deserialize, Serialize};

/// protocol version / capability version.
///
/// this represents the tailscale client capability version.
/// different versions support different features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityVersion(pub u32);

impl CapabilityVersion {
    /// minimum supported capability version.
    pub const MIN: CapabilityVersion = CapabilityVersion(68);

    /// current capability version.
    pub const CURRENT: CapabilityVersion = CapabilityVersion(106);
}

impl Default for CapabilityVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}
