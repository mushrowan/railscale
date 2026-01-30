//! TKA checkpoint state.

use minicbor::{Decode, Encode};

use crate::{Error, Key};

/// TKA state checkpoint.
///
/// contains the full state at a point in the log.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct State {
    /// hash of the last AUM that led to this state.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub last_aum_hash: Option<Vec<u8>>,

    /// hashed disablement secrets.
    #[n(2)]
    pub disablement_secrets: Vec<Vec<u8>>,

    /// trusted signing keys.
    #[n(3)]
    pub keys: Vec<Key>,

    /// state ID nonce (part 1).
    #[n(4)]
    pub state_id_1: Option<u64>,

    /// state ID nonce (part 2).
    #[n(5)]
    pub state_id_2: Option<u64>,
}

impl State {
    /// encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(|e| Error::Cbor(e.to_string()))
    }

    /// decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        minicbor::decode(bytes).map_err(|e| Error::Cbor(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyKind;

    #[test]
    fn state_cbor_roundtrip() {
        let state = State {
            last_aum_hash: Some(vec![0xab; 32]),
            disablement_secrets: vec![vec![0xcd; 32], vec![0xef; 32]],
            keys: vec![Key {
                kind: KeyKind::Ed25519,
                votes: 1,
                public: vec![0x01; 32],
                meta: None,
            }],
            state_id_1: Some(12345),
            state_id_2: Some(67890),
        };

        let encoded = state.to_cbor().unwrap();
        let decoded = State::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.last_aum_hash, state.last_aum_hash);
        assert_eq!(decoded.disablement_secrets.len(), 2);
        assert_eq!(decoded.keys.len(), 1);
        assert_eq!(decoded.state_id_1, Some(12345));
    }
}
