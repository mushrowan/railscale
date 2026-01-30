//! disablement secret for TKA.

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// length of a disablement secret in bytes.
pub const DISABLEMENT_SECRET_LEN: usize = 32;

/// salt used for KDF when hashing disablement secrets.
pub const DISABLEMENT_SALT: &[u8] = b"tailscale network-lock disablement salt";

/// a secret used to disable tailnet lock in emergency.
///
/// the raw secret is never stored - only its salted hash.
/// zeroized on drop for security.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DisablementSecret {
    secret: [u8; DISABLEMENT_SECRET_LEN],
}

impl DisablementSecret {
    /// generate a new random disablement secret.
    pub fn generate() -> Self {
        Self {
            secret: rand::random(),
        }
    }

    /// compute the hash of this secret for storage.
    ///
    /// this is what should be stored in the TKA state, not the raw secret.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(DISABLEMENT_SALT);
        hasher.update(self.secret);
        hasher.finalize().into()
    }

    /// verify that this secret matches a stored hash.
    pub fn verify(&self, stored_hash: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        self.hash().ct_eq(stored_hash).into()
    }
}

impl From<[u8; DISABLEMENT_SECRET_LEN]> for DisablementSecret {
    fn from(secret: [u8; DISABLEMENT_SECRET_LEN]) -> Self {
        Self { secret }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disablement_secret_generate_is_random() {
        let s1 = DisablementSecret::generate();
        let s2 = DisablementSecret::generate();
        // extremely unlikely to be equal
        assert_ne!(s1.hash(), s2.hash());
    }

    #[test]
    fn disablement_secret_hash_is_deterministic() {
        let bytes = [0xab; DISABLEMENT_SECRET_LEN];
        let s1 = DisablementSecret::from(bytes);
        let s2 = DisablementSecret::from(bytes);
        assert_eq!(s1.hash(), s2.hash());
    }

    #[test]
    fn disablement_secret_hash_length() {
        let secret = DisablementSecret::generate();
        let hash = secret.hash();
        assert_eq!(hash.len(), 32); // BLAKE2s-256
    }

    #[test]
    fn disablement_secret_verify_correct() {
        let secret = DisablementSecret::generate();
        let hash = secret.hash();
        assert!(secret.verify(&hash));
    }

    #[test]
    fn disablement_secret_verify_wrong_hash() {
        let secret = DisablementSecret::generate();
        let wrong_hash = [0xff; 32];
        assert!(!secret.verify(&wrong_hash));
    }

    #[test]
    fn disablement_secret_from_bytes() {
        let bytes = [0xcd; DISABLEMENT_SECRET_LEN];
        let secret = DisablementSecret::from(bytes);
        // can't directly access bytes (security), but hash should work
        assert_eq!(secret.hash().len(), 32);
    }
}
