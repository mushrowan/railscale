//! tailscale protocol implementation for railscale.
//!
//! this crate handles:
//! - noise protocol for secure communication
//! - maprequest/mapresponse handling
//! - node registration protocol
//! - derp integration

#![warn(missing_docs)]

mod error;
mod map_request;
mod noise;
mod ssh;
mod tka;

pub use error::Error;
pub use map_request::{
    DerpMap, DerpNode, DerpRegion, DnsConfig, DnsResolver, FilterRule, MapRequest, MapResponse,
    MapResponseNode, NetPortRange, PortRange, UserProfile,
};
pub use noise::{NoiseHandshake, NoiseTransport, generate_keypair};
pub use snow::Keypair;
pub use ssh::{SshAction, SshPolicy, SshPrincipal, SshRecorderFailureAction, SshRule};
pub use tka::TkaInfo;

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
