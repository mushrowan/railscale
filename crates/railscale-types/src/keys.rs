//! the actual cryptographic operations will be implemented in railscale-proto
//!
//! these types wrap the raw key bytes and provide serialization support.
//! the actual cryptographic operations will be implemented in railscale-proto.

use serde::{Deserialize, Serialize};

/// machine key - identifies a physical device.
///
/// this key is stable across node key rotations and is used
/// for machine-level authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineKey(Vec<u8>);

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

impl Default for MachineKey {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// node key - identifies a node's current session.
///
/// this key can be rotated and is used for the noise protocol handshake.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeKey(Vec<u8>);

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
}

impl Default for NodeKey {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// disco key - used for peer discovery (stun/derp coordination).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiscoKey(Vec<u8>);

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
}

impl Default for DiscoKey {
    fn default() -> Self {
        Self(Vec::new())
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
}
