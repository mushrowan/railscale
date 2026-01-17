//! cryptographic key types for tailscale protocol.
//!
//! these types wrap the raw key bytes and provide serialization support.
//! keys serialize to tailscale's prefixed hex format (e.g., `"nodekey:abc123..."`).
//! the actual cryptographic operations will be implemented in railscale-proto.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// helper to implement tailscale key serialization with a given prefix.
macro_rules! impl_key_serde {
    ($type:ty, $prefix:expr) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let hex = hex::encode(&self.0);
                let s = format!("{}:{}", $prefix, hex);
                serializer.serialize_str(&s)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let expected_prefix = concat!($prefix, ":");
                let hex_str = s.strip_prefix(expected_prefix).ok_or_else(|| {
                    de::Error::custom(format!(
                        "key must start with '{}', got '{}'",
                        expected_prefix, s
                    ))
                })?;
                let bytes = hex::decode(hex_str)
                    .map_err(|e| de::Error::custom(format!("invalid hex in key: {}", e)))?;
                Ok(Self(bytes))
            }
        }
    };
}

/// machine key - identifies a physical device.
///
/// this key is stable across node key rotations and is used
/// for machine-level authentication.
/// serializes as `"mkey:<64 hex chars>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct MachineKey(Vec<u8>);

impl_key_serde!(MachineKey, "mkey");

impl MachineKey {
    /// create a new machine key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// get the raw bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// returns a short string representation for logging.
    pub fn short_string(&self) -> String {
        if self.0.len() >= 4 {
            format!("mkey:{:02x}{:02x}...", self.0[0], self.0[1])
        } else {
            "mkey:???".to_string()
        }
    }
}

/// node key - identifies a node's current session.
///
/// this key can be rotated and is used for the noise protocol handshake.
/// serializes as `"nodekey:<64 hex chars>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct NodeKey(Vec<u8>);

impl_key_serde!(NodeKey, "nodekey");

impl NodeKey {
    /// create a new node key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// get the raw bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// returns a short string representation for logging.
    pub fn short_string(&self) -> String {
        if self.0.len() >= 4 {
            format!("nodekey:{:02x}{:02x}...", self.0[0], self.0[1])
        } else {
            "nodekey:???".to_string()
        }
    }

    /// check if this is a zero key.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

/// disco key - used for peer discovery (STUN/DERP coordination) or alternatively partying.
/// serializes as `"discokey:<64 hex chars>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DiscoKey(Vec<u8>);

impl_key_serde!(DiscoKey, "discokey");

impl DiscoKey {
    /// create a new disco key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// get the raw bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// returns a short string representation for logging.
    pub fn short_string(&self) -> String {
        if self.0.len() >= 4 {
            format!("discokey:{:02x}{:02x}...", self.0[0], self.0[1])
        } else {
            "discokey:???".to_string()
        }
    }

    /// check if the key is empty (not set).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_key_short_string() {
        let key = MachineKey::from_bytes(vec![0xab, 0xcd, 0xef, 0x12]);
        assert_eq!(key.short_string(), "mkey:abcd...");
    }

    #[test]
    fn test_node_key_short_string() {
        let key = NodeKey::from_bytes(vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(key.short_string(), "nodekey:1234...");
    }

    #[test]
    fn test_disco_key_short_string() {
        let key = DiscoKey::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(key.short_string(), "discokey:dead...");
    }

    #[test]
    fn test_empty_key_short_string() {
        let key = MachineKey::default();
        assert_eq!(key.short_string(), "mkey:???");
    }

    #[test]
    fn test_node_key_serialize() {
        let key = NodeKey::from_bytes(vec![0x02; 32]);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(
            json,
            "\"nodekey:0202020202020202020202020202020202020202020202020202020202020202\""
        );
    }

    #[test]
    fn test_node_key_deserialize() {
        let json = "\"nodekey:0202020202020202020202020202020202020202020202020202020202020202\"";
        let key: NodeKey = serde_json::from_str(json).unwrap();
        assert_eq!(key.as_bytes(), &[0x02; 32]);
    }

    #[test]
    fn test_machine_key_roundtrip() {
        let original = MachineKey::from_bytes(vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90]);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: MachineKey = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_node_key_is_zero() {
        let zero_key = NodeKey::from_bytes(vec![0; 32]);
        assert!(zero_key.is_zero());

        let non_zero_key = NodeKey::from_bytes(vec![0x02; 32]);
        assert!(!non_zero_key.is_zero());
    }

    #[test]
    fn test_key_deserialize_invalid_prefix() {
        let json = "\"wrong:0202020202020202020202020202020202020202020202020202020202020202\"";
        let result: Result<NodeKey, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_disco_key_serialize() {
        // empty DiscoKey serializes to "discokey:" (empty hex)
        // this format is not parseable by tailscale clients (expect 64 hex chars)
        // so we use skip_serializing_if in mapresponsenode to omit empty keys
        let key = DiscoKey::default();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, "\"discokey:\"");
        assert!(key.is_empty());
    }

    #[test]
    fn test_disco_key_is_empty() {
        let empty = DiscoKey::default();
        assert!(empty.is_empty());

        let non_empty = DiscoKey::from_bytes(vec![1, 2, 3]);
        assert!(!non_empty.is_empty());
    }
}
