//! node key signature types for TKA.

use minicbor::{Decode, Encode};

use crate::Error;

/// signature type for NodeKeySignature.
///
/// values match tailscale's SigKind constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum SigKind {
    /// direct signature by a TKA key.
    #[n(1)]
    Direct = 1,
    /// rotation signature (wraps a nested signature).
    #[n(2)]
    Rotation = 2,
    /// credential delegation signature.
    #[n(3)]
    Credential = 3,
}

/// a signature authorising a node key in the TKA.
///
/// CBOR-encoded with integer keys for tailscale compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct NodeKeySignature {
    /// the type of signature.
    #[n(1)]
    pub sig_kind: SigKind,

    /// the node public key being authorised (34 bytes: "np" + 32).
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub pubkey: Option<Vec<u8>>,

    /// the TKA key ID for verification (32 bytes).
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub key_id: Option<Vec<u8>>,

    /// the ed25519 signature (64 bytes).
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: Option<Vec<u8>>,

    /// nested signature for rotation.
    #[n(5)]
    pub nested: Option<Box<NodeKeySignature>>,

    /// ed25519 pubkey for rotation (32 bytes).
    #[n(6)]
    #[cbor(with = "minicbor::bytes")]
    pub wrapping_pubkey: Option<Vec<u8>>,
}

impl NodeKeySignature {
    /// encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        minicbor::decode(bytes).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// compute the hash that should be signed (BLAKE2s of CBOR without signature).
    pub fn sig_hash(&self) -> Result<[u8; 32], Error> {
        use blake2::{Blake2s256, Digest};

        let mut copy = self.clone();
        copy.signature = None;

        let cbor = copy.to_cbor()?;
        Ok(Blake2s256::digest(&cbor).into())
    }

    /// create a direct signature over a node key.
    pub fn sign_direct(
        node_pubkey: &[u8],
        tka_key_id: &crate::TkaKeyId,
        tka_private: &crate::NlPrivateKey,
    ) -> Result<Self, Error> {
        let mut sig = Self {
            sig_kind: SigKind::Direct,
            pubkey: Some(node_pubkey.to_vec()),
            key_id: Some(tka_key_id.as_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };

        let hash = sig.sig_hash()?;
        sig.signature = Some(tka_private.sign(&hash).to_vec());

        Ok(sig)
    }

    /// verify this signature against a TKA public key.
    pub fn verify(&self, tka_public: &crate::NlPublicKey) -> Result<(), Error> {
        match self.sig_kind {
            SigKind::Direct => self.verify_direct(tka_public),
            SigKind::Rotation => self.verify_rotation(),
            SigKind::Credential => Err(Error::UnsupportedSigKind),
        }
    }

    fn verify_direct(&self, tka_public: &crate::NlPublicKey) -> Result<(), Error> {
        let hash = self.sig_hash()?;
        let sig_bytes = self.signature.as_ref().ok_or(Error::MissingSignature)?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;

        tka_public.verify(&sig, &hash)
    }

    fn verify_rotation(&self) -> Result<(), Error> {
        // for rotation, verify with the wrapping pubkey from the nested signature
        let nested = self
            .nested
            .as_ref()
            .ok_or(Error::MissingAumField("nested"))?;
        let wrapping_pubkey = nested
            .wrapping_pubkey
            .as_ref()
            .ok_or(Error::MissingAumField("wrapping_pubkey"))?;

        // convert wrapping pubkey to NlPublicKey
        let vk = crate::NlPublicKey::try_from(wrapping_pubkey.as_slice())?;

        let hash = self.sig_hash()?;
        let sig_bytes = self.signature.as_ref().ok_or(Error::MissingSignature)?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;

        vk.verify(&sig, &hash)
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeKeySignature, SigKind};
    use crate::{NlPrivateKey, TkaKeyId};

    #[test]
    fn sig_kind_values_match_tailscale() {
        // tailscale uses 1, 2, 3 (0 is invalid)
        assert_eq!(SigKind::Direct as u8, 1);
        assert_eq!(SigKind::Rotation as u8, 2);
        assert_eq!(SigKind::Credential as u8, 3);
    }

    #[test]
    fn node_key_signature_cbor_roundtrip() {
        let private = NlPrivateKey::generate();
        let pubkey = private.public_key();

        let sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(pubkey.as_bytes().to_vec()),
            key_id: Some(TkaKeyId::from(&pubkey).as_bytes().to_vec()),
            signature: Some(vec![0xab; 64]),
            nested: None,
            wrapping_pubkey: None,
        };

        // encode to CBOR
        let encoded = sig.to_cbor().unwrap();

        // decode from CBOR
        let decoded = NodeKeySignature::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.sig_kind, SigKind::Direct);
        assert_eq!(decoded.pubkey, sig.pubkey);
        assert_eq!(decoded.key_id, sig.key_id);
        assert_eq!(decoded.signature, sig.signature);
    }

    #[test]
    fn node_key_signature_nested_roundtrip() {
        let inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x01; 34]),
            key_id: Some(vec![0x02; 32]),
            signature: Some(vec![0x03; 64]),
            nested: None,
            wrapping_pubkey: None,
        };

        let outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(vec![0x04; 34]),
            key_id: None,
            signature: Some(vec![0x05; 64]),
            nested: Some(Box::new(inner)),
            wrapping_pubkey: Some(vec![0x06; 32]),
        };

        let encoded = outer.to_cbor().unwrap();
        let decoded = NodeKeySignature::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.sig_kind, SigKind::Rotation);
        assert!(decoded.nested.is_some());
        let nested = decoded.nested.unwrap();
        assert_eq!(nested.sig_kind, SigKind::Direct);
    }

    #[test]
    fn node_key_signature_cbor_uses_integer_keys() {
        let sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x01; 34]),
            key_id: None,
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };

        let encoded = sig.to_cbor().unwrap();

        // CBOR map with integer keys should start with map marker
        // followed by integer keys (1, 2, etc), not string keys
        // first byte should be map (0xa0-0xbf for small maps)
        assert!(
            encoded[0] >= 0xa0 && encoded[0] <= 0xbf,
            "expected CBOR map, got {:02x}",
            encoded[0]
        );
    }

    #[test]
    fn sign_direct_and_verify() {
        let tka_private = NlPrivateKey::generate();
        let tka_public = tka_private.public_key();
        let tka_key_id = TkaKeyId::from(&tka_public);

        // simulate a node key (34 bytes: "np" prefix + 32 bytes)
        let node_pubkey = vec![
            b'n', b'p', 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
            0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let sig = NodeKeySignature::sign_direct(&node_pubkey, &tka_key_id, &tka_private).unwrap();

        assert_eq!(sig.sig_kind, SigKind::Direct);
        assert!(sig.signature.is_some());
        assert!(sig.verify(&tka_public).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let tka_private = NlPrivateKey::generate();
        let tka_public = tka_private.public_key();
        let tka_key_id = TkaKeyId::from(&tka_public);

        let other_private = NlPrivateKey::generate();
        let other_public = other_private.public_key();

        let node_pubkey = vec![0xab; 34];

        let sig = NodeKeySignature::sign_direct(&node_pubkey, &tka_key_id, &tka_private).unwrap();

        // verification with wrong key should fail
        assert!(sig.verify(&other_public).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let tka_private = NlPrivateKey::generate();
        let tka_public = tka_private.public_key();
        let tka_key_id = TkaKeyId::from(&tka_public);

        let node_pubkey = vec![0xcd; 34];

        let mut sig =
            NodeKeySignature::sign_direct(&node_pubkey, &tka_key_id, &tka_private).unwrap();

        // tamper with the signature
        if let Some(ref mut s) = sig.signature {
            s[0] ^= 0xff;
        }

        assert!(sig.verify(&tka_public).is_err());
    }
}
