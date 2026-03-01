//! tailnet lock (tka) protocol types.

use std::collections::HashMap;

use railscale_tka::{MarshaledAum, MarshaledSignature};
use railscale_types::{NodeId, NodeKey};
use serde::{Deserialize, Serialize};

use crate::CapabilityVersion;

/// control plane's view of tailnet key authority (tka) state.
///
/// transmitted as part of mapresponse. clients use this to determine
/// if they need to sync their local tka state with the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInfo {
    /// hash of the latest aum applied to the authority.
    /// encoded as tka.AUMHash.MarshalText (hex string).
    ///
    /// if head differs from local state, the node should sync via separate rpc.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head: String,

    /// whether control plane believes tka should be disabled.
    ///
    /// if true, node should fetch disablement secret and disable tka locally.
    /// this disambiguates a nil TKAInfo (no change) from disabled state.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

impl TkaInfo {
    /// create a new tka info with a head hash.
    pub fn new(head: impl Into<String>) -> Self {
        Self {
            head: head.into(),
            disabled: false,
        }
    }

    /// create a disabled tka info.
    pub fn disabled() -> Self {
        Self {
            head: String::new(),
            disabled: true,
        }
    }
}

// =============================================================================
// TKA Init RPCs
// =============================================================================

/// request to begin tka initialisation.
///
/// POST /machine/tka/init/begin
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitBeginRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// genesis aum to bootstrap tka state.
    #[serde(rename = "GenesisAUM")]
    pub genesis_aum: MarshaledAum,
}

/// information about a node needing a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSignInfo {
    /// node id requiring signature.
    #[serde(rename = "NodeID")]
    pub node_id: NodeId,

    /// node's wireguard public key.
    pub node_public: NodeKey,

    /// rotation pubkey (raw ed25519) for future key rotations.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_bytes"
    )]
    pub rotation_pubkey: Vec<u8>,
}

/// response from /tka/init/begin.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitBeginResponse {
    /// nodes requiring signatures before tka can be enabled.
    #[serde(default)]
    pub need_signatures: Vec<TkaSignInfo>,
}

/// request to finish tka initialisation.
///
/// POST /machine/tka/init/finish
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitFinishRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// node-key signatures for all nodes (keyed by node id).
    pub signatures: HashMap<u64, MarshaledSignature>,

    /// optional disablement secret for support.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_bytes"
    )]
    pub support_disablement: Vec<u8>,
}

/// response from /tka/init/finish.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInitFinishResponse {}

// =============================================================================
// TKA Bootstrap RPC
// =============================================================================

/// request for tka bootstrap info.
///
/// POST /machine/tka/bootstrap
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaBootstrapRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's current head hash (if tka enabled locally).
    #[serde(default)]
    pub head: String,
}

/// response with tka bootstrap info.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaBootstrapResponse {
    /// genesis aum to initialise tka (if enabling).
    #[serde(
        rename = "GenesisAUM",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub genesis_aum: Option<MarshaledAum>,

    /// disablement secret (if disabling).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_bytes"
    )]
    pub disablement_secret: Vec<u8>,
}

// =============================================================================
// TKA Sync RPCs
// =============================================================================

/// request to offer sync state.
///
/// POST /machine/tka/sync/offer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncOfferRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's head aum hash.
    pub head: String,

    /// ancestor hashes ascending from head.
    #[serde(default)]
    pub ancestors: Vec<String>,
}

/// response with sync offer from control.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncOfferResponse {
    /// control's head aum hash.
    #[serde(default)]
    pub head: String,

    /// control's ancestor hashes.
    #[serde(default)]
    pub ancestors: Vec<String>,

    /// aums the client is missing.
    #[serde(default, rename = "MissingAUMs")]
    pub missing_aums: Vec<MarshaledAum>,
}

/// request to send aums to control.
///
/// POST /machine/tka/sync/send
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncSendRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's head after applying sync-offer aums.
    pub head: String,

    /// aums control is missing.
    #[serde(default, rename = "MissingAUMs")]
    pub missing_aums: Vec<MarshaledAum>,

    /// whether this is an interactive request (admin action).
    #[serde(default)]
    pub interactive: bool,
}

/// response after receiving aums.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSyncSendResponse {
    /// control's head after applying received aums.
    #[serde(default)]
    pub head: String,
}

// =============================================================================
// TKA Disable RPC
// =============================================================================

/// request to disable tka.
///
/// POST /machine/tka/disable
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaDisableRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's head aum hash.
    pub head: String,

    /// disablement secret.
    #[serde(with = "crate::base64_bytes")]
    pub disablement_secret: Vec<u8>,
}

/// response after disabling tka.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaDisableResponse {}

// =============================================================================
// TKA Sign RPC
// =============================================================================

/// request to submit a node-key signature.
///
/// POST /machine/tka/sign
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSubmitSignatureRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// serialized node-key signature.
    pub signature: MarshaledSignature,
}

/// response after submitting signature.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TkaSubmitSignatureResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tka_info_serde_roundtrip() {
        let info = TkaInfo::new("abc123");
        let json = serde_json::to_string(&info).unwrap();
        let parsed: TkaInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn tka_info_json_matches_tailscale_format() {
        // tailscale expects PascalCase: "Head", "Disabled"
        let info = TkaInfo::new("deadbeef");
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Head\""));
        assert!(!json.contains("\"Disabled\"")); // omitted when false
    }

    #[test]
    fn tka_info_disabled_includes_flag() {
        let info = TkaInfo::disabled();
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Disabled\":true"));
    }

    #[test]
    fn tka_info_default_is_empty() {
        let info = TkaInfo::default();
        assert!(info.head.is_empty());
        assert!(!info.disabled);
    }

    #[test]
    fn tka_init_begin_request_serde() {
        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes([0u8; 32]),
            genesis_aum: MarshaledAum::from(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Version\""));
        assert!(json.contains("\"NodeKey\""));
        assert!(json.contains("\"GenesisAUM\""));
        let parsed: TkaInitBeginRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version.0, 106);
    }

    #[test]
    fn tka_sign_info_serde() {
        let info = TkaSignInfo {
            node_id: NodeId::new(42),
            node_public: NodeKey::from_bytes([0u8; 32]),
            rotation_pubkey: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"NodeID\":42"));
        assert!(json.contains("\"RotationPubkey\"")); // base64 encoded
        let parsed: TkaSignInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.node_id.as_u64(), 42);
        assert_eq!(parsed.rotation_pubkey, vec![1, 2, 3, 4]);
    }

    #[test]
    fn tka_init_finish_request_serde() {
        let mut signatures = HashMap::new();
        signatures.insert(1, MarshaledSignature::from(vec![0xaa, 0xbb]));
        let req = TkaInitFinishRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes([0u8; 32]),
            signatures,
            support_disablement: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Signatures\""));
        let parsed: TkaInitFinishRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.signatures.contains_key(&1));
    }

    #[test]
    fn tka_sync_offer_request_serde() {
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes([0u8; 32]),
            head: "abc123".to_string(),
            ancestors: vec!["def456".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Head\":\"abc123\""));
        assert!(json.contains("\"Ancestors\""));
    }

    #[test]
    fn tka_disable_request_serde() {
        let req = TkaDisableRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes([0u8; 32]),
            head: "abc123".to_string(),
            disablement_secret: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"DisablementSecret\""));
        let parsed: TkaDisableRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.disablement_secret, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn tka_bootstrap_response_empty_secret_omitted() {
        let resp = TkaBootstrapResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        // empty secret should be omitted
        assert!(!json.contains("DisablementSecret"));
    }
}
