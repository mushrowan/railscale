//! AUM hash type - 32-byte BLAKE2s hash identifying an AUM.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::Error;

/// length of an AUM hash in bytes (BLAKE2s-256).
pub const AUM_HASH_LEN: usize = 32;

/// 32-byte BLAKE2s hash identifying an AUM in the TKA log.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AumHash([u8; AUM_HASH_LEN]);

impl AumHash {
    /// returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; AUM_HASH_LEN] {
        &self.0
    }
}

impl From<[u8; AUM_HASH_LEN]> for AumHash {
    fn from(bytes: [u8; AUM_HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for AumHash {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; AUM_HASH_LEN] = slice.try_into().map_err(|_| Error::InvalidHashLength {
            expected: AUM_HASH_LEN,
            actual: slice.len(),
        })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for AumHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for AumHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AumHash({})", hex::encode(self.0))
    }
}

impl Serialize for AumHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for AumHash {
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
    fn aum_hash_from_bytes() {
        let bytes = [0xab; AUM_HASH_LEN];
        let hash = AumHash::from(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn aum_hash_try_from_slice_valid() {
        let bytes = [0xcd; AUM_HASH_LEN];
        let hash = AumHash::try_from(&bytes[..]).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn aum_hash_try_from_slice_invalid_length() {
        let short = [0u8; 16];
        let result = AumHash::try_from(&short[..]);
        assert!(result.is_err());
    }

    #[test]
    fn aum_hash_display_is_hex() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff,
        ];
        let hash = AumHash::from(bytes);
        let display = format!("{}", hash);
        assert_eq!(
            display,
            "01020304000000000000000000000000000000000000000000000000000000ff"
        );
    }

    #[test]
    fn aum_hash_serde_roundtrip() {
        let bytes = [0xde; AUM_HASH_LEN];
        let hash = AumHash::from(bytes);
        let json = serde_json::to_string(&hash).unwrap();
        // should serialize as hex string
        assert!(json.contains("dedede"));
        let parsed: AumHash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn aum_hash_is_copy() {
        let hash = AumHash::from([0x11; AUM_HASH_LEN]);
        let copy = hash; // should copy, not move
        assert_eq!(hash, copy);
    }
}
