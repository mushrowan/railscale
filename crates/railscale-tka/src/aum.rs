//! authority update message (AUM) for TKA log.

use std::collections::BTreeMap;

use blake2::{Blake2s256, Digest};
use minicbor::{Decode, Encode};

use crate::{AumHash, Error, Key, State};

/// type of AUM operation.
///
/// values match tailscale's AUMKind constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum AumKind {
    /// add a new trusted key.
    #[n(1)]
    AddKey = 1,
    /// remove a trusted key.
    #[n(2)]
    RemoveKey = 2,
    /// no-op (used in tests).
    #[n(3)]
    NoOp = 3,
    /// update key metadata/votes.
    #[n(4)]
    UpdateKey = 4,
    /// full state checkpoint.
    #[n(5)]
    Checkpoint = 5,
}

/// signature on an AUM by a trusted key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AumSignature {
    /// the key ID that signed this AUM.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub key_id: Vec<u8>,

    /// the ed25519 signature.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: Vec<u8>,
}

impl AumSignature {
    /// encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        minicbor::decode(bytes).map_err(|e| Error::Cbor(e.to_string()))
    }
}

/// authority update message - an entry in the TKA append-only log.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Aum {
    /// the type of operation.
    #[n(1)]
    pub message_kind: AumKind,

    /// hash of the previous AUM (None for genesis).
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub prev_aum_hash: Option<Vec<u8>>,

    /// key to add (for AddKey).
    #[n(3)]
    pub key: Option<Key>,

    /// key ID to remove/update (for RemoveKey/UpdateKey).
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub key_id: Option<Vec<u8>>,

    /// full state checkpoint (for Checkpoint).
    #[n(5)]
    pub state: Option<State>,

    /// new vote count (for UpdateKey).
    #[n(6)]
    pub votes: Option<u32>,

    /// new metadata (for UpdateKey).
    #[n(7)]
    pub meta: Option<BTreeMap<String, String>>,

    /// signatures from trusted keys.
    /// uses CBOR field index 23 to match tailscale.
    #[n(23)]
    pub signatures: Vec<AumSignature>,
}

impl Aum {
    /// encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        minicbor::decode(bytes).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// compute the hash of this AUM (without signatures).
    pub fn hash(&self) -> Result<AumHash, Error> {
        // hash the AUM without signatures
        let mut copy = self.clone();
        copy.signatures = vec![];

        let cbor = copy.to_cbor()?;
        let hash: [u8; 32] = Blake2s256::digest(&cbor).into();
        Ok(AumHash::from(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::{Aum, AumKind, AumSignature};
    use crate::{Key, KeyKind};

    #[test]
    fn aum_kind_values_match_tailscale() {
        assert_eq!(AumKind::AddKey as u8, 1);
        assert_eq!(AumKind::RemoveKey as u8, 2);
        assert_eq!(AumKind::NoOp as u8, 3);
        assert_eq!(AumKind::UpdateKey as u8, 4);
        assert_eq!(AumKind::Checkpoint as u8, 5);
    }

    #[test]
    fn aum_signature_cbor_roundtrip() {
        let sig = AumSignature {
            key_id: vec![0xab; 32],
            signature: vec![0xcd; 64],
        };

        let encoded = sig.to_cbor().unwrap();
        let decoded = AumSignature::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.key_id, sig.key_id);
        assert_eq!(decoded.signature, sig.signature);
    }

    #[test]
    fn aum_add_key_cbor_roundtrip() {
        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: vec![0x01; 32],
            meta: None,
        };

        let aum = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: Some(vec![0x00; 32]),
            key: Some(key.clone()),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };

        let encoded = aum.to_cbor().unwrap();
        let decoded = Aum::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.message_kind, AumKind::AddKey);
        assert!(decoded.key.is_some());
        assert_eq!(decoded.key.unwrap().public, key.public);
    }

    #[test]
    fn aum_remove_key_cbor_roundtrip() {
        let aum = Aum {
            message_kind: AumKind::RemoveKey,
            prev_aum_hash: Some(vec![0xab; 32]),
            key: None,
            key_id: Some(vec![0xcd; 32]),
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };

        let encoded = aum.to_cbor().unwrap();
        let decoded = Aum::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.message_kind, AumKind::RemoveKey);
        assert_eq!(decoded.key_id, Some(vec![0xcd; 32]));
    }

    #[test]
    fn aum_with_signatures() {
        let sig1 = AumSignature {
            key_id: vec![0x01; 32],
            signature: vec![0x02; 64],
        };
        let sig2 = AumSignature {
            key_id: vec![0x03; 32],
            signature: vec![0x04; 64],
        };

        let aum = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None, // genesis
            key: Some(Key {
                kind: KeyKind::Ed25519,
                votes: 1,
                public: vec![0x01; 32],
                meta: None,
            }),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![sig1, sig2],
        };

        let encoded = aum.to_cbor().unwrap();
        let decoded = Aum::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.signatures.len(), 2);
    }

    #[test]
    fn aum_hash_is_deterministic() {
        let aum = Aum {
            message_kind: AumKind::NoOp,
            prev_aum_hash: Some(vec![0xab; 32]),
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };

        let hash1 = aum.hash().unwrap();
        let hash2 = aum.hash().unwrap();

        assert_eq!(hash1, hash2);
    }
}
