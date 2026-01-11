//! all error types used by Snow operations

use core::fmt;

/// `snow` provides decently detailed errors, exposed as the [`Error`] enum,
/// to allow developers to react to errors in a more actionable way
///
/// *With that said*, security vulnerabilities *can* be introduced by passing
/// along detailed failure information to an attacker. While an effort was
/// made to not make any particularly foolish choices in this regard, we strongly
/// recommend you don't dump the `Debug` output to a user, for example
///
/// this enum is intentionally non-exhasutive to allow new error types to be
/// introduced without causing a breaking api change
///
/// `snow` may eventually add a feature flag and enum variant to only return
/// an "unspecified" error for those who would prefer safety over observability
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// the noise pattern failed to parse
    Pattern(PatternProblem),

    /// initialization failure, at a provided stage
    Init(InitStage),

    /// missing prerequisite material
    Prereq(Prerequisite),

    /// an error in `snow`'s internal state
    State(StateProblem),

    /// invalid input
    Input,

    /// diffie-Hellman agreement failed
    Dh,

    /// decryption failed
    Decrypt,

    /// rNG failed
    Rng,

    /// key-encapsulation failed
    #[cfg(feature = "hfs")]
    Kem,
}

/// the various stages of initialization used to help identify
/// the specific cause of an `Init` error
#[derive(Debug, PartialEq)]
pub enum PatternProblem {
    /// caused by a pattern string that is too short and malformed (e.g. `Noise_NN_25519`)
    TooFewParameters,
    /// caused by a pattern string that is too long (e.g. `Noise_NN_25519_SHA256_SomeOtherThing`)
    TooManyParameters,
    /// the handshake section of the string (e.g. `XXpsk3`) isn't supported. Check for typos
    /// and necessary feature flags
    UnsupportedHandshakeType,
    /// this was a trick choice -- an illusion. The correct answer was `Noise`
    UnsupportedBaseType,
    /// invalid hash type (e.g. `blake2s`)
    /// check that there are no typos and that any feature flags you might need are toggled
    UnsupportedHashType,
    /// invalid DH type (e.g. `25519`)
    /// check that there are no typos and that any feature flags you might need are toggled
    UnsupportedDhType,
    /// invalid cipher type (e.g. `ChaChaPoly`)
    /// check that there are no typos and that any feature flags you might need are toggled
    UnsupportedCipherType,
    /// the PSK position must be a number, and a pretty small one at that
    InvalidPsk,
    /// duplicate modifiers must not be used in the same pattern
    DuplicateModifier,
    /// invalid modifier (e.g. `fallback`)
    /// check that there are no typos and that any feature flags you might need are toggled
    UnsupportedModifier,
    #[cfg(feature = "hfs")]
    /// invalid KEM type
    /// check that there are no typos and that any feature flags you might need are toggled
    UnsupportedKemType,
}

impl From<PatternProblem> for Error {
    fn from(reason: PatternProblem) -> Self {
        Error::Pattern(reason)
    }
}

/// the various stages of initialization used to help identify
/// the specific cause of an `Init` error
#[derive(Debug, PartialEq)]
pub enum InitStage {
    /// provided and received key lengths were not equal
    ValidateKeyLengths,
    /// provided and received preshared key lengths were not equal
    ValidatePskLengths,
    /// two separate cipher algorithms were initialized
    ValidateCipherTypes,
    /// the RNG couldn't be initialized
    GetRngImpl,
    /// the DH implementation couldn't be initialized
    GetDhImpl,
    /// the cipher implementation couldn't be initialized
    GetCipherImpl,
    /// the hash implementation couldn't be initialized
    GetHashImpl,
    #[cfg(feature = "hfs")]
    /// the KEM implementation couldn't be initialized
    GetKemImpl,
    /// the PSK position (specified in the pattern string) isn't valid for the given handshake type
    ValidatePskPosition,
    /// the Builder already has set a value for this parameter, and overwrites are not allowed as
    /// they can introduce subtle security issues
    ParameterOverwrite,
}

impl From<InitStage> for Error {
    fn from(reason: InitStage) -> Self {
        Error::Init(reason)
    }
}

/// a prerequisite that may be missing
#[derive(Debug, PartialEq)]
pub enum Prerequisite {
    /// a local private key wasn't provided when it was needed by the selected pattern
    LocalPrivateKey,
    /// a remote public key wasn't provided when it was needed by the selected pattern
    RemotePublicKey,
}

impl From<Prerequisite> for Error {
    fn from(reason: Prerequisite) -> Self {
        Error::Prereq(reason)
    }
}

/// specific errors in the state machine
#[derive(Debug, PartialEq)]
pub enum StateProblem {
    /// missing key material in the internal handshake state
    MissingKeyMaterial,
    /// preshared key missing in the internal handshake state
    MissingPsk,
    /// you attempted to write a message when it's our turn to read
    NotTurnToWrite,
    /// you attempted to read a message when it's our turn to write
    NotTurnToRead,
    /// you tried to go into transport mode before the handshake was done
    HandshakeNotFinished,
    /// you tried to continue the handshake when it was already done
    HandshakeAlreadyFinished,
    /// you called a method that is only valid if this weren't a one-way handshake
    OneWay,
    /// the nonce counter attempted to go higher than (2^64) - 1
    Exhausted,
}

impl From<StateProblem> for Error {
    fn from(reason: StateProblem) -> Self {
        Error::State(reason)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pattern(reason) => write!(f, "pattern error: {reason:?}"),
            Error::Init(reason) => {
                write!(f, "initialization error: {reason:?}")
            },
            Error::Prereq(reason) => {
                write!(f, "prerequisite error: {reason:?}")
            },
            Error::State(reason) => write!(f, "state error: {reason:?}"),
            Error::Input => write!(f, "input error"),
            Error::Dh => write!(f, "diffie-hellman error"),
            Error::Decrypt => write!(f, "decrypt error"),
            Error::Rng => write!(f, "RNG error"),
            #[cfg(feature = "hfs")]
            Error::Kem => write!(f, "kem error"),
        }
    }
}

impl core::error::Error for Error {}
