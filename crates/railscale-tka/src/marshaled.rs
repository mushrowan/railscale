//! opaque CBOR-encoded types for wire transmission.

use base64::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// opaque CBOR-encoded NodeKeySignature.
///
/// this wraps the raw bytes of a CBOR-encoded signature.
/// serializes as base64 in JSON for wire transmission.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MarshaledSignature(Vec<u8>);

impl MarshaledSignature {
    /// returns the raw CBOR bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// returns true if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for MarshaledSignature {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for MarshaledSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MarshaledSignature({} bytes)", self.0.len())
    }
}

impl Serialize for MarshaledSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for MarshaledSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(&s).map_err(de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// opaque CBOR-encoded AUM (Authority Update Message).
///
/// this wraps the raw bytes of a CBOR-encoded AUM.
/// serializes as base64 in JSON for wire transmission.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MarshaledAum(Vec<u8>);

impl MarshaledAum {
    /// returns the raw CBOR bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// returns true if the AUM is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for MarshaledAum {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for MarshaledAum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MarshaledAum({} bytes)", self.0.len())
    }
}

impl Serialize for MarshaledAum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for MarshaledAum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(&s).map_err(de::Error::custom)?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{MarshaledAum, MarshaledSignature};

    // MarshaledSignature tests
    #[test]
    fn marshaled_signature_from_bytes() {
        let bytes = vec![0x01, 0x02, 0x03];
        let sig = MarshaledSignature::from(bytes.clone());
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn marshaled_signature_is_empty() {
        let empty = MarshaledSignature::default();
        assert!(empty.is_empty());

        let non_empty = MarshaledSignature::from(vec![0x01]);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn marshaled_signature_serde_base64_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let sig = MarshaledSignature::from(bytes.clone());
        let json = serde_json::to_string(&sig).unwrap();
        // should be base64 encoded
        assert!(
            json.contains("3q2+7w==") || json.contains("3q2-7w"),
            "json was: {}",
            json
        );
        let parsed: MarshaledSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_bytes(), &bytes);
    }

    // MarshaledAum tests
    #[test]
    fn marshaled_aum_from_bytes() {
        let bytes = vec![0x04, 0x05, 0x06];
        let aum = MarshaledAum::from(bytes.clone());
        assert_eq!(aum.as_bytes(), &bytes);
    }

    #[test]
    fn marshaled_aum_is_empty() {
        let empty = MarshaledAum::default();
        assert!(empty.is_empty());

        let non_empty = MarshaledAum::from(vec![0x01]);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn marshaled_aum_serde_base64_roundtrip() {
        let bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        let aum = MarshaledAum::from(bytes.clone());
        let json = serde_json::to_string(&aum).unwrap();
        let parsed: MarshaledAum = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_bytes(), &bytes);
    }
}
