//! cryptographic key types for tailscale protocol.
//!
//! these types wrap the raw key bytes and provide serialization support.
//! keys serialize to tailscale's prefixed hex format (e.g., `"nodekey:abc123..."`).
//! the actual cryptographic operations are in railscale-proto.
//!
//! all three key types (`MachineKey`, `NodeKey`, `DiscoKey`) share identical
//! structure via `TailscaleKey<P>` parameterised by a prefix marker.

use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// expected key length in bytes (curve25519 keys are 32 bytes).
const KEY_LENGTH: usize = 32;

/// trait for key prefix markers (sealed, not extensible outside this module).
pub trait KeyPrefix: Clone + PartialEq + Eq + std::hash::Hash + Default {
    /// the wire prefix (e.g. "mkey", "nodekey", "discokey")
    const PREFIX: &'static str;
}

/// a tailscale protocol key with a typed prefix.
///
/// generic over the prefix marker to avoid duplicating logic for
/// machine keys, node keys, and disco keys.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TailscaleKey<P: KeyPrefix> {
    bytes: Vec<u8>,
    _prefix: PhantomData<P>,
}

impl<P: KeyPrefix> Default for TailscaleKey<P> {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            _prefix: PhantomData,
        }
    }
}

impl<P: KeyPrefix> TailscaleKey<P> {
    /// create a key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _prefix: PhantomData,
        }
    }

    /// get the raw bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// returns a short string representation for logging.
    pub fn short_string(&self) -> String {
        if self.bytes.len() >= 4 {
            format!(
                "{}:{:02x}{:02x}...",
                P::PREFIX,
                self.bytes[0],
                self.bytes[1]
            )
        } else {
            format!("{}:???", P::PREFIX)
        }
    }

    /// check if the key is empty (not set).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// check if this is a zero key (all bytes are 0).
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl<P: KeyPrefix> fmt::Debug for TailscaleKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})",
            std::any::type_name::<Self>(),
            self.short_string()
        )
    }
}

impl<P: KeyPrefix> Serialize for TailscaleKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex::encode(&self.bytes);
        let s = format!("{}:{}", P::PREFIX, hex);
        serializer.serialize_str(&s)
    }
}

impl<'de, P: KeyPrefix> Deserialize<'de> for TailscaleKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let prefix_colon = format!("{}:", P::PREFIX);
        let hex_str = s.strip_prefix(&prefix_colon).ok_or_else(|| {
            de::Error::custom(format!(
                "key must start with '{}', got '{}'",
                prefix_colon, s
            ))
        })?;
        let bytes = hex::decode(hex_str)
            .map_err(|e| de::Error::custom(format!("invalid hex in key: {}", e)))?;
        if bytes.len() != KEY_LENGTH {
            return Err(de::Error::custom(format!(
                "key must be exactly {} bytes, got {}",
                KEY_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self::from_bytes(bytes))
    }
}

// ── prefix markers ──────────────────────────────────────────────────────

/// marker for machine keys (`mkey:`)
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct MachineKeyPrefix;

impl KeyPrefix for MachineKeyPrefix {
    const PREFIX: &'static str = "mkey";
}

/// marker for node keys (`nodekey:`)
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct NodeKeyPrefix;

impl KeyPrefix for NodeKeyPrefix {
    const PREFIX: &'static str = "nodekey";
}

/// marker for disco keys (`discokey:`)
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct DiscoKeyPrefix;

impl KeyPrefix for DiscoKeyPrefix {
    const PREFIX: &'static str = "discokey";
}

// ── public type aliases ─────────────────────────────────────────────────

/// machine key - identifies a physical device.
///
/// stable across node key rotations. serializes as `"mkey:<64 hex chars>"`.
pub type MachineKey = TailscaleKey<MachineKeyPrefix>;

/// node key - identifies a node's current session.
///
/// rotatable, used for noise handshake. serializes as `"nodekey:<64 hex chars>"`.
pub type NodeKey = TailscaleKey<NodeKeyPrefix>;

/// disco key - used for peer discovery (STUN/DERP coordination) or alternatively partying.
///
/// serializes as `"discokey:<64 hex chars>"`.
pub type DiscoKey = TailscaleKey<DiscoKeyPrefix>;

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn valid_key_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), KEY_LENGTH)
    }

    fn invalid_key_length() -> impl Strategy<Value = usize> {
        (0usize..100).prop_filter("must not be 32", |&len| len != KEY_LENGTH)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn machine_key_serde_roundtrips(bytes in valid_key_bytes()) {
            let key = MachineKey::from_bytes(bytes.clone());
            let json = serde_json::to_string(&key).unwrap();
            prop_assert!(json.contains("mkey:"));
            let parsed: MachineKey = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed.as_bytes(), &bytes[..]);
            prop_assert_eq!(key, parsed);
        }

        #[test]
        fn machine_key_short_string_format(bytes in valid_key_bytes()) {
            let key = MachineKey::from_bytes(bytes);
            let short = key.short_string();
            prop_assert!(short.starts_with("mkey:"));
            prop_assert!(short.ends_with("..."));
        }

        #[test]
        fn node_key_serde_roundtrips(bytes in valid_key_bytes()) {
            let key = NodeKey::from_bytes(bytes.clone());
            let json = serde_json::to_string(&key).unwrap();
            prop_assert!(json.contains("nodekey:"));
            let parsed: NodeKey = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed.as_bytes(), &bytes[..]);
            prop_assert_eq!(key, parsed);
        }

        #[test]
        fn node_key_is_zero_correct(bytes in valid_key_bytes()) {
            let key = NodeKey::from_bytes(bytes.clone());
            let expected_zero = bytes.iter().all(|&b| b == 0);
            prop_assert_eq!(key.is_zero(), expected_zero);
        }

        #[test]
        fn node_key_short_string_format(bytes in valid_key_bytes()) {
            let key = NodeKey::from_bytes(bytes);
            let short = key.short_string();
            prop_assert!(short.starts_with("nodekey:"));
            prop_assert!(short.ends_with("..."));
        }

        #[test]
        fn disco_key_serde_roundtrips(bytes in valid_key_bytes()) {
            let key = DiscoKey::from_bytes(bytes.clone());
            let json = serde_json::to_string(&key).unwrap();
            prop_assert!(json.contains("discokey:"));
            let parsed: DiscoKey = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(parsed.as_bytes(), &bytes[..]);
            prop_assert_eq!(key, parsed);
        }

        #[test]
        fn disco_key_short_string_format(bytes in valid_key_bytes()) {
            let key = DiscoKey::from_bytes(bytes);
            let short = key.short_string();
            prop_assert!(short.starts_with("discokey:"));
            prop_assert!(short.ends_with("..."));
        }

        #[test]
        fn node_key_rejects_invalid_length(len in invalid_key_length()) {
            let hex: String = (0..len).map(|i| format!("{:02x}", (i % 256) as u8)).collect();
            let json = format!("\"nodekey:{}\"", hex);
            let result: Result<NodeKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn machine_key_rejects_invalid_length(len in invalid_key_length()) {
            let hex: String = (0..len).map(|i| format!("{:02x}", (i % 256) as u8)).collect();
            let json = format!("\"mkey:{}\"", hex);
            let result: Result<MachineKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn disco_key_rejects_invalid_length(len in invalid_key_length()) {
            let hex: String = (0..len).map(|i| format!("{:02x}", (i % 256) as u8)).collect();
            let json = format!("\"discokey:{}\"", hex);
            let result: Result<DiscoKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn node_key_rejects_wrong_prefix(bytes in valid_key_bytes(), prefix in "[a-z]{3,8}") {
            prop_assume!(prefix != "nodekey");
            let hex = hex::encode(&bytes);
            let json = format!("\"{}:{}\"", prefix, hex);
            let result: Result<NodeKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn machine_key_rejects_wrong_prefix(bytes in valid_key_bytes(), prefix in "[a-z]{3,8}") {
            prop_assume!(prefix != "mkey");
            let hex = hex::encode(&bytes);
            let json = format!("\"{}:{}\"", prefix, hex);
            let result: Result<MachineKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn disco_key_rejects_wrong_prefix(bytes in valid_key_bytes(), prefix in "[a-z]{3,8}") {
            prop_assume!(prefix != "discokey");
            let hex = hex::encode(&bytes);
            let json = format!("\"{}:{}\"", prefix, hex);
            let result: Result<DiscoKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn node_key_rejects_invalid_hex(bad_hex in "[g-z]{64}") {
            let json = format!("\"nodekey:{}\"", bad_hex);
            let result: Result<NodeKey, _> = serde_json::from_str(&json);
            prop_assert!(result.is_err());
        }
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
        let original = MachineKey::from_bytes(vec![0xab; 32]);
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

    #[test]
    fn test_node_key_rejects_oversized_input() {
        let json = "\"nodekey:020202020202020202020202020202020202020202020202020202020202020202\"";
        let result: Result<NodeKey, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject oversized key");
    }

    #[test]
    fn test_node_key_rejects_undersized_input() {
        let json = "\"nodekey:02020202020202020202020202020202020202020202020202020202020202\"";
        let result: Result<NodeKey, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject undersized key");
    }

    #[test]
    fn test_machine_key_rejects_wrong_size() {
        let json = "\"mkey:0202020202020202020202020202020202020202020202020202020202020202ff\"";
        let result: Result<MachineKey, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject wrong-size key");
    }
}
