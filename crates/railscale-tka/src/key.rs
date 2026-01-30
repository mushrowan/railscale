//! TKA trusted signing key types.

use std::collections::BTreeMap;

use minicbor::{Decode, Encode};

use crate::{Error, TkaKeyId};

/// type of cryptographic key.
///
/// currently only ed25519 is supported (matching tailscale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum KeyKind {
    /// ed25519 signing key.
    #[n(1)]
    Ed25519 = 1,
}

/// a trusted signing key in the TKA.
///
/// CBOR-encoded with integer keys for tailscale compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Key {
    /// the type of key.
    #[n(1)]
    pub kind: KeyKind,

    /// voting weight for quorum decisions.
    #[n(2)]
    pub votes: u32,

    /// the raw public key bytes (32 bytes for ed25519).
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub public: Vec<u8>,

    /// optional metadata (e.g., purpose, created_by).
    /// uses CBOR field index 12 to match tailscale.
    #[n(12)]
    pub meta: Option<BTreeMap<String, String>>,
}

impl Key {
    /// encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        minicbor::decode(bytes).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// get the key ID (the public key bytes as TkaKeyId).
    pub fn id(&self) -> Result<TkaKeyId, Error> {
        TkaKeyId::try_from(self.public.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, KeyKind};
    use crate::NlPrivateKey;
    use std::collections::BTreeMap;

    #[test]
    fn key_kind_values_match_tailscale() {
        assert_eq!(KeyKind::Ed25519 as u8, 1);
    }

    #[test]
    fn key_cbor_roundtrip() {
        let private = NlPrivateKey::generate();
        let pubkey = private.public_key();

        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: pubkey.as_bytes().to_vec(),
            meta: None,
        };

        let encoded = key.to_cbor().unwrap();
        let decoded = Key::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.kind, KeyKind::Ed25519);
        assert_eq!(decoded.votes, 1);
        assert_eq!(decoded.public, key.public);
        assert!(decoded.meta.is_none());
    }

    #[test]
    fn key_cbor_with_metadata() {
        let mut meta = BTreeMap::new();
        meta.insert("purpose".to_string(), "backup".to_string());
        meta.insert("created_by".to_string(), "admin".to_string());

        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 2,
            public: vec![0xab; 32],
            meta: Some(meta.clone()),
        };

        let encoded = key.to_cbor().unwrap();
        let decoded = Key::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.votes, 2);
        assert_eq!(decoded.meta, Some(meta));
    }

    #[test]
    fn key_id_from_key() {
        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: vec![0xcd; 32],
            meta: None,
        };

        let id = key.id().unwrap();
        assert_eq!(id.as_bytes(), &[0xcd; 32]);
    }

    #[test]
    fn key_id_invalid_public_length() {
        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: vec![0xab; 16], // wrong length
            meta: None,
        };

        assert!(key.id().is_err());
    }
}
