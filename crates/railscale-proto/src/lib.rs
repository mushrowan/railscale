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
    AppConnectorAttr, CAP_APP_CONNECTORS, CAP_DNS_SUBDOMAIN_RESOLVE, CAP_FILE_SHARING,
    CAP_SSH_ENV_VARS, CAP_STORE_APPC_ROUTES, CapGrant, DerpMap, DerpNode, DerpRegion, DnsConfig,
    DnsResolver, FilterRule, MapRequest, MapResponse, MapResponseNode, NetPortRange,
    PEER_CAP_DEBUG_PEER, PEER_CAP_FILE_SEND, PEER_CAP_FILE_SHARING_TARGET, PEER_CAP_INGRESS,
    PEER_CAP_WAKE_ON_LAN, PeerChange, PortRange, SetDNSRequest, SetDNSResponse,
    SetDeviceAttributesRequest, UserProfile,
};
pub use noise::{NoiseHandshake, NoiseTransport, builder as noise_builder, generate_keypair};
pub use snow::Keypair;
pub use ssh::{SshAction, SshPolicy, SshPrincipal, SshRecorderFailureAction, SshRule};
pub use tka::{
    TkaBootstrapRequest, TkaBootstrapResponse, TkaDisableRequest, TkaDisableResponse, TkaInfo,
    TkaInitBeginRequest, TkaInitBeginResponse, TkaInitFinishRequest, TkaInitFinishResponse,
    TkaSignInfo, TkaSubmitSignatureRequest, TkaSubmitSignatureResponse, TkaSyncOfferRequest,
    TkaSyncOfferResponse, TkaSyncSendRequest, TkaSyncSendResponse,
};

/// serde helper for base64-encoded byte vectors.
pub mod base64_bytes {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// serialize bytes as base64.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    /// deserialize base64 to bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        BASE64_STANDARD.decode(&s).map_err(de::Error::custom)
    }
}

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
