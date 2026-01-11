//! the traits for cryptographic implementations that can be used by Noise

use crate::{
    constants::{CIPHERKEYLEN, MAXBLOCKLEN, MAXHASHLEN, TAGLEN},
    Error,
};

/// csprng operations
pub trait Random: Send + Sync {
    /// fill `dest` entirely with random data
    ///
    /// # Errors
    /// returns `Error::Rng` in the event that the provided RNG failed
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error>;
}

/// diffie-hellman operations
pub trait Dh: Send + Sync {
    /// the string that the noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// the length in bytes of a public key for this primitive
    fn pub_len(&self) -> usize;

    /// the length in bytes of a private key for this primitive
    fn priv_len(&self) -> usize;

    /// set the private key
    fn set(&mut self, privkey: &[u8]);

    /// generate a new private key
    ///
    /// # Errors
    /// returns `Error::Rng` in the event that the provided RNG failed
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error>;

    /// get the public key
    fn pubkey(&self) -> &[u8];

    /// get the private key
    fn privkey(&self) -> &[u8];

    /// calculate a Diffie-Hellman exchange
    ///
    /// # Errors
    /// returns `Error::Dh` in the event that the Diffie-Hellman failed
    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error>;

    /// the lenght in bytes of of the DH key exchange. Defaults to the public key
    fn dh_len(&self) -> usize {
        self.pub_len()
    }
}

/// cipher operations
pub trait Cipher: Send + Sync {
    /// the string that the noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// set the key
    fn set(&mut self, key: &[u8; CIPHERKEYLEN]);

    /// encrypt (with associated data) a given plaintext
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize;

    /// decrypt (with associated data) a given ciphertext
    ///
    /// # Errors
    /// returns `Error::Decrypt` in the event that the decryption failed
    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error>;

    /// rekey according to section 4.2 of the noise specification, with a default
    /// implementation guaranteed to be secure for all ciphers
    fn rekey(&mut self) {
        let mut ciphertext = [0; CIPHERKEYLEN + TAGLEN];
        let ciphertext_len = self.encrypt(u64::MAX, &[], &[0; CIPHERKEYLEN], &mut ciphertext);
        assert_eq!(ciphertext_len, ciphertext.len(), "unexpected ciphertext length for rekey");

        // todo(mcginty): use `split_array_ref` once stable to avoid memory inefficiency
        let mut key = [0_u8; CIPHERKEYLEN];
        key.copy_from_slice(&ciphertext[..CIPHERKEYLEN]);

        self.set(&key);
    }
}

/// hashing operations
pub trait Hash: Send + Sync {
    /// the string that the noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// the block length for the primitive
    fn block_len(&self) -> usize;

    /// the final hash digest length for the primitive
    fn hash_len(&self) -> usize;

    /// reset the internal state
    fn reset(&mut self);

    /// provide input to the internal state
    fn input(&mut self, data: &[u8]);

    /// get the resulting hash
    fn result(&mut self, out: &mut [u8]);

    /// calculate HMAC, as specified in the Noise spec
    ///
    /// NOTE: this method clobbers the existing internal state
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= self.block_len(), "unexpectedly large key length for hmac");
        let block_len = self.block_len();
        let hash_len = self.hash_len();
        let mut ipad = [0x36_u8; MAXBLOCKLEN];
        let mut opad = [0x5c_u8; MAXBLOCKLEN];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }
        self.reset();
        self.input(&ipad[..block_len]);
        self.input(data);
        let mut inner_output = [0_u8; MAXHASHLEN];
        self.result(&mut inner_output);
        self.reset();
        self.input(&opad[..block_len]);
        self.input(&inner_output[..hash_len]);
        self.result(out);
    }

    /// derive keys as specified in the Noise spec
    ///
    /// NOTE: this method clobbers the existing internal state
    fn hkdf(
        &mut self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        outputs: usize,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: &mut [u8],
    ) {
        let hash_len = self.hash_len();
        let mut temp_key = [0_u8; MAXHASHLEN];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1_u8], out1);
        if outputs == 1 {
            return;
        }

        let mut in2 = [0_u8; MAXHASHLEN + 1];
        copy_slices!(out1[0..hash_len], &mut in2);
        in2[hash_len] = 2;
        self.hmac(&temp_key, &in2[..=hash_len], out2);
        if outputs == 2 {
            return;
        }

        let mut in3 = [0_u8; MAXHASHLEN + 1];
        copy_slices!(out2[0..hash_len], &mut in3);
        in3[hash_len] = 3;
        self.hmac(&temp_key, &in3[..=hash_len], out3);
    }
}

/// kem operations
#[cfg(feature = "hfs")]
pub trait Kem: Send + Sync {
    /// the string that the noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// the length in bytes of a public key for this primitive
    fn pub_len(&self) -> usize;

    /// the length in bytes the Kem cipherthext for this primitive
    fn ciphertext_len(&self) -> usize;

    /// shared secret length in bytes that this Kem encapsulates
    fn shared_secret_len(&self) -> usize;

    /// generate a new private key
    fn generate(&mut self, rng: &mut dyn Random);

    /// get the public key
    fn pubkey(&self) -> &[u8];

    /// generate a shared secret and encapsulate it using this Kem
    ///
    /// # Errors
    /// returns `Error::Kem` if the public key is invalid
    #[must_use = "returned value includes needed length values for output slices"]
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), Error>;

    /// decapsulate a ciphertext producing a shared secret
    ///
    /// # Errors
    /// returns `Error::Kem` if the ciphertext is invalid
    #[must_use = "returned value includes needed length value for output slice"]
    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, Error>;
}
