//! TKA authority state machine.

use std::collections::HashMap;

use ed25519_consensus::VerificationKey;

use crate::{Aum, AumHash, AumKind, AumSignature, Error, Key, NlPrivateKey, TkaKeyId};

/// TKA authority - manages the append-only log and trusted keys.
#[derive(Debug, Clone)]
pub struct Authority {
    /// current head of the AUM chain
    head: Option<AumHash>,
    /// trusted signing keys indexed by key ID
    keys: HashMap<TkaKeyId, Key>,
}

impl Authority {
    /// create a new authority with a genesis AUM containing the initial key.
    pub fn new_with_genesis(initial_key: Key, signer: &NlPrivateKey) -> Result<Self, Error> {
        let key_id = initial_key.id()?;

        let mut authority = Self {
            head: None,
            keys: HashMap::new(),
        };

        // create genesis AUM
        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(initial_key.clone()),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };

        // for genesis, we sign with the key being added (bootstrap)
        let hash = genesis.hash()?;
        let sig = signer.sign(hash.as_bytes());

        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };

        // add the key first so we can verify the signature
        authority.keys.insert(key_id, initial_key);

        // set the head
        authority.head = Some(signed_genesis.hash()?);

        Ok(authority)
    }

    /// get the current head hash.
    pub fn head(&self) -> Option<&AumHash> {
        self.head.as_ref()
    }

    /// get all trusted keys.
    pub fn keys(&self) -> &HashMap<TkaKeyId, Key> {
        &self.keys
    }

    /// check if a key is trusted.
    pub fn has_key(&self, key_id: &TkaKeyId) -> bool {
        self.keys.contains_key(key_id)
    }

    /// create an AddKey AUM (unsigned).
    pub fn create_add_key_aum(&self, key: Key) -> Aum {
        Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: self.head.map(|h| h.as_bytes().to_vec()),
            key: Some(key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        }
    }

    /// create a RemoveKey AUM (unsigned).
    pub fn create_remove_key_aum(&self, key_id: TkaKeyId) -> Aum {
        Aum {
            message_kind: AumKind::RemoveKey,
            prev_aum_hash: self.head.map(|h| h.as_bytes().to_vec()),
            key: None,
            key_id: Some(key_id.as_bytes().to_vec()),
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        }
    }

    /// sign an AUM with a private key.
    pub fn sign_aum(&self, mut aum: Aum, signer: &NlPrivateKey) -> Result<Aum, Error> {
        let public = signer.public_key();
        let key_id = TkaKeyId::from(&public);

        let hash = aum.hash()?;
        let sig = signer.sign(hash.as_bytes());

        aum.signatures.push(AumSignature {
            key_id: key_id.as_bytes().to_vec(),
            signature: sig.to_vec(),
        });

        Ok(aum)
    }

    /// apply an AUM to the authority state.
    pub fn apply_aum(&mut self, aum: Aum) -> Result<(), Error> {
        // verify the AUM has at least one valid signature from a trusted key
        self.verify_aum_signatures(&aum)?;

        // check prev_aum_hash matches current head
        let expected_prev = self.head.map(|h| h.as_bytes().to_vec());
        if aum.prev_aum_hash != expected_prev {
            return Err(Error::InvalidAumChain);
        }

        // compute hash before consuming fields
        let new_head = aum.hash()?;

        // apply the operation
        match aum.message_kind {
            AumKind::AddKey => {
                let key = aum.key.ok_or(Error::MissingAumField("key"))?;
                let key_id = key.id()?;
                self.keys.insert(key_id, key);
            }
            AumKind::RemoveKey => {
                let key_id_bytes = aum.key_id.ok_or(Error::MissingAumField("key_id"))?;
                let key_id = TkaKeyId::try_from(key_id_bytes.as_slice())?;
                self.keys.remove(&key_id);
            }
            AumKind::NoOp => {
                // nothing to do
            }
            AumKind::UpdateKey => {
                let key_id_bytes = aum.key_id.ok_or(Error::MissingAumField("key_id"))?;
                let key_id = TkaKeyId::try_from(key_id_bytes.as_slice())?;
                if let Some(key) = self.keys.get_mut(&key_id) {
                    if let Some(votes) = aum.votes {
                        key.votes = votes;
                    }
                    if let Some(meta) = aum.meta {
                        key.meta = Some(meta);
                    }
                }
            }
            AumKind::Checkpoint => {
                // for checkpoint, replace entire state
                if let Some(state) = aum.state {
                    self.keys.clear();
                    for key in state.keys {
                        let key_id = key.id()?;
                        self.keys.insert(key_id, key);
                    }
                }
            }
        }

        // update head
        self.head = Some(new_head);

        Ok(())
    }

    /// verify that an AUM has at least one valid signature from a trusted key.
    fn verify_aum_signatures(&self, aum: &Aum) -> Result<(), Error> {
        if aum.signatures.is_empty() {
            return Err(Error::MissingSignature);
        }

        let hash = aum.hash()?;

        for sig in &aum.signatures {
            let key_id = TkaKeyId::try_from(sig.key_id.as_slice())?;

            // check if this key is trusted
            if let Some(key) = self.keys.get(&key_id) {
                // verify the signature
                let vk = VerificationKey::try_from(key.public.as_slice())
                    .map_err(|_| Error::InvalidSignature)?;

                let signature: [u8; 64] = sig
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidSignature)?;

                let ed_sig = ed25519_consensus::Signature::from(signature);

                if vk.verify(&ed_sig, hash.as_bytes()).is_ok() {
                    return Ok(()); // at least one valid signature
                }
            }
        }

        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::Authority;
    use crate::{Key, KeyKind, NlPrivateKey};

    fn make_test_key() -> (NlPrivateKey, Key) {
        let private = NlPrivateKey::generate();
        let public = private.public_key();
        let key = Key {
            kind: KeyKind::Ed25519,
            votes: 1,
            public: public.as_bytes().to_vec(),
            meta: None,
        };
        (private, key)
    }

    #[test]
    fn authority_new_with_genesis() {
        let (private, key) = make_test_key();
        let authority = Authority::new_with_genesis(key.clone(), &private).unwrap();

        assert_eq!(authority.keys().len(), 1);
        assert!(authority.head().is_some());
    }

    #[test]
    fn authority_has_key() {
        let (private, key) = make_test_key();
        let authority = Authority::new_with_genesis(key.clone(), &private).unwrap();

        let key_id = key.id().unwrap();
        assert!(authority.has_key(&key_id));
    }

    #[test]
    fn authority_add_key() {
        let (private1, key1) = make_test_key();
        let mut authority = Authority::new_with_genesis(key1.clone(), &private1).unwrap();

        let (_private2, key2) = make_test_key();

        // create and sign an AddKey AUM
        let aum = authority.create_add_key_aum(key2.clone());
        let signed_aum = authority.sign_aum(aum, &private1).unwrap();

        authority.apply_aum(signed_aum).unwrap();

        assert_eq!(authority.keys().len(), 2);
    }

    #[test]
    fn authority_remove_key() {
        let (private1, key1) = make_test_key();
        let mut authority = Authority::new_with_genesis(key1.clone(), &private1).unwrap();

        let (_private2, key2) = make_test_key();
        let key2_id = key2.id().unwrap();

        // add second key
        let aum = authority.create_add_key_aum(key2.clone());
        let signed_aum = authority.sign_aum(aum, &private1).unwrap();
        authority.apply_aum(signed_aum).unwrap();

        assert_eq!(authority.keys().len(), 2);

        // remove second key (signed by first key)
        let aum = authority.create_remove_key_aum(key2_id);
        let signed_aum = authority.sign_aum(aum, &private1).unwrap();
        authority.apply_aum(signed_aum).unwrap();

        assert_eq!(authority.keys().len(), 1);
        assert!(!authority.has_key(&key2_id));
    }

    #[test]
    fn authority_rejects_unsigned_aum() {
        let (private, key) = make_test_key();
        let mut authority = Authority::new_with_genesis(key.clone(), &private).unwrap();

        let (_, key2) = make_test_key();
        let aum = authority.create_add_key_aum(key2);
        // don't sign it

        let result = authority.apply_aum(aum);
        assert!(result.is_err());
    }

    #[test]
    fn authority_rejects_aum_signed_by_unknown_key() {
        let (private1, key1) = make_test_key();
        let mut authority = Authority::new_with_genesis(key1.clone(), &private1).unwrap();

        let (private_unknown, _) = make_test_key();
        let (_, key2) = make_test_key();

        let aum = authority.create_add_key_aum(key2);
        // sign with unknown key
        let signed_aum = authority.sign_aum(aum, &private_unknown).unwrap();

        let result = authority.apply_aum(signed_aum);
        assert!(result.is_err());
    }
}
