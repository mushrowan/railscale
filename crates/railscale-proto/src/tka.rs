//! tailnet lock (tka) protocol types.
//!
//! these types are used in mapresponse to communicate tka state to clients.

use serde::{Deserialize, Serialize};

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
}
