//! network-lock key types (ed25519).

use std::fmt;

use ed25519_consensus::{Signature, SigningKey, VerificationKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// length of ed25519 public key in bytes.
pub const NL_PUBLIC_KEY_LEN: usize = 32;

/// length of ed25519 private key seed in bytes.
pub const NL_PRIVATE_KEY_LEN: usize = 32;

/// network-lock public key (ed25519).
///
/// used for verifying TKA signatures. serializes as `"nlpub:<hex>"` in JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct NlPublicKey(VerificationKey);

impl NlPublicKey {
    /// returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8; NL_PUBLIC_KEY_LEN] {
        // VerificationKey::as_ref returns &[u8], but we know it's always 32 bytes
        self.0
            .as_ref()
            .try_into()
            .expect("ed25519 pubkey is always 32 bytes")
    }

    /// verify a signature over a message.
    pub fn verify(&self, signature: &[u8; 64], message: &[u8]) -> Result<(), Error> {
        let sig = Signature::try_from(signature.as_slice()).map_err(|_| Error::InvalidSignature)?;
        self.0
            .verify(&sig, message)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl TryFrom<&[u8]> for NlPublicKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; NL_PUBLIC_KEY_LEN] =
            slice.try_into().map_err(|_| Error::InvalidKeyLength {
                expected: NL_PUBLIC_KEY_LEN,
                actual: slice.len(),
            })?;
        let key = VerificationKey::try_from(bytes).map_err(|_| Error::InvalidSignature)?;
        Ok(Self(key))
    }
}

impl fmt::Display for NlPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nlpub:{}", hex::encode(self.as_bytes()))
    }
}

impl fmt::Debug for NlPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NlPublicKey({})", hex::encode(self.as_bytes()))
    }
}

impl Serialize for NlPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("nlpub:{}", hex::encode(self.as_bytes())))
    }
}

impl<'de> Deserialize<'de> for NlPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let hex_str = s
            .strip_prefix("nlpub:")
            .ok_or_else(|| de::Error::custom("key must start with 'nlpub:'"))?;
        let bytes = hex::decode(hex_str).map_err(de::Error::custom)?;
        Self::try_from(bytes.as_slice()).map_err(de::Error::custom)
    }
}

/// network-lock private key (ed25519).
///
/// used for signing TKA operations. zeroized on drop for security.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NlPrivateKey {
    #[zeroize(skip)] // SigningKey handles its own zeroization
    key: SigningKey,
}

impl NlPrivateKey {
    /// generate a new random private key.
    pub fn generate() -> Self {
        let seed: [u8; 32] = rand::random();
        Self::from_seed(seed)
    }

    /// create from a 32-byte seed.
    pub fn from_seed(seed: [u8; NL_PRIVATE_KEY_LEN]) -> Self {
        Self {
            key: SigningKey::from(seed),
        }
    }

    /// get the seed bytes for serialization.
    ///
    /// warning: handle with care - this is sensitive key material.
    pub fn to_seed(&self) -> [u8; NL_PRIVATE_KEY_LEN] {
        // SigningKey stores the seed internally - we can get it via as_ref
        let bytes: &[u8] = self.key.as_ref();
        bytes[..NL_PRIVATE_KEY_LEN]
            .try_into()
            .expect("SigningKey seed is always 32 bytes")
    }

    /// get the corresponding public key.
    pub fn public_key(&self) -> NlPublicKey {
        NlPublicKey(self.key.verification_key())
    }

    /// sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nl_public_key_from_bytes_roundtrip() {
        // generate a valid key, then round-trip through bytes
        let original = NlPrivateKey::generate().public_key();
        let bytes = original.as_bytes();
        let restored = NlPublicKey::try_from(&bytes[..]).unwrap();
        assert_eq!(original.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn nl_public_key_try_from_invalid_length() {
        let short = [0u8; 16];
        let result = NlPublicKey::try_from(&short[..]);
        assert!(result.is_err());
    }

    #[test]
    fn nl_public_key_try_from_invalid_point() {
        // not a valid curve point
        let invalid = [0xab; NL_PUBLIC_KEY_LEN];
        let result = NlPublicKey::try_from(&invalid[..]);
        assert!(result.is_err());
    }

    #[test]
    fn nl_public_key_serde_roundtrip() {
        // use a valid ed25519 key (not random bytes)
        let key = NlPrivateKey::generate().public_key();
        let json = serde_json::to_string(&key).unwrap();
        // should serialize with nlpub: prefix
        assert!(json.contains("nlpub:"), "json was: {}", json);
        let parsed: NlPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn nl_public_key_display_has_prefix() {
        let key = NlPrivateKey::generate().public_key();
        let display = format!("{}", key);
        assert!(display.starts_with("nlpub:"));
    }

    #[test]
    fn nl_private_key_generates_valid_keypair() {
        let private = NlPrivateKey::generate();
        let public = private.public_key();
        // public key should be 32 bytes
        assert_eq!(public.as_bytes().len(), NL_PUBLIC_KEY_LEN);
    }

    #[test]
    fn nl_private_key_sign_and_verify() {
        let private = NlPrivateKey::generate();
        let public = private.public_key();
        let message = b"test message";
        let signature = private.sign(message);
        assert!(public.verify(&signature, message).is_ok());
    }

    #[test]
    fn nl_private_key_verify_wrong_message_fails() {
        let private = NlPrivateKey::generate();
        let public = private.public_key();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = private.sign(message);
        assert!(public.verify(&signature, wrong_message).is_err());
    }
}
