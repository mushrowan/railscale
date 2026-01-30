//! TKA key identifier type.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, NlPublicKey};

/// length of a TKA key ID in bytes (same as ed25519 public key).
pub const TKA_KEY_ID_LEN: usize = 32;

/// identifies a key in the tailnet key authority.
///
/// this is the raw bytes of the ed25519 public key that can sign TKA operations.
/// serializes as hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TkaKeyId([u8; TKA_KEY_ID_LEN]);

impl TkaKeyId {
    /// returns the key ID as a byte slice.
    pub fn as_bytes(&self) -> &[u8; TKA_KEY_ID_LEN] {
        &self.0
    }
}

impl From<[u8; TKA_KEY_ID_LEN]> for TkaKeyId {
    fn from(bytes: [u8; TKA_KEY_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<&NlPublicKey> for TkaKeyId {
    fn from(key: &NlPublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl TryFrom<&[u8]> for TkaKeyId {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; TKA_KEY_ID_LEN] =
            slice.try_into().map_err(|_| Error::InvalidKeyLength {
                expected: TKA_KEY_ID_LEN,
                actual: slice.len(),
            })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for TkaKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for TkaKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TkaKeyId({})", hex::encode(self.0))
    }
}

impl Serialize for TkaKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for TkaKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        Self::try_from(bytes.as_slice()).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tka_key_id_from_bytes() {
        let bytes = [0xab; TKA_KEY_ID_LEN];
        let id = TkaKeyId::from(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn tka_key_id_try_from_slice_valid() {
        let bytes = [0xcd; TKA_KEY_ID_LEN];
        let id = TkaKeyId::try_from(&bytes[..]).unwrap();
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn tka_key_id_try_from_slice_invalid_length() {
        let short = [0u8; 16];
        let result = TkaKeyId::try_from(&short[..]);
        assert!(result.is_err());
    }

    #[test]
    fn tka_key_id_display_is_hex() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff,
        ];
        let id = TkaKeyId::from(bytes);
        let display = format!("{}", id);
        assert_eq!(
            display,
            "01020304000000000000000000000000000000000000000000000000000000ff"
        );
    }

    #[test]
    fn tka_key_id_serde_roundtrip() {
        let bytes = [0xde; TKA_KEY_ID_LEN];
        let id = TkaKeyId::from(bytes);
        let json = serde_json::to_string(&id).unwrap();
        // should serialize as hex string
        assert!(json.contains("dedede"));
        let parsed: TkaKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn tka_key_id_from_nl_public_key() {
        use crate::NlPrivateKey;
        let pubkey = NlPrivateKey::generate().public_key();
        let id = TkaKeyId::from(&pubkey);
        assert_eq!(id.as_bytes(), pubkey.as_bytes());
    }
}
