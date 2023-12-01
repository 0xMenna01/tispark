// Implementations for app specific commit-reveal scheme
use self::message::{ContractPubKey, ContractSecretKey, ContractSigType};
pub use self::Result as ContractResult;
use crate::tispark_client::{KeyVersionInfo, KeyringVersion};
use core::fmt::Debug;
use ink::primitives::AccountId;
use scale::{Decode, Encode};

pub mod commitment;
pub mod consensus;
pub mod message;
pub mod state;

/// Type alias for the contract's result type.
pub type Result<T> = core::result::Result<T, ContractError>;

pub type ContractServiceId = AccountId;
pub type ServiceId = u32;

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum ContractError {
    DecodeBetResultError,
    DecodeCommitRequestForResultError,
    StateVerificationError,
    PermissionDeniedError,
    BadOrigin,
    CommitmentKeyDerivationError,
    CommitmentEncryptionError,
    ConsensusClientInvalidLogs,
    ConsensusClientInvalidJustifications,
    ConsensusClientInvalidSignatures,
    ConsensusClientInvalidEmergencySignature,
    InvalidConsensusStateConstruct,
    ConsensusClientInvalidStateProof,
    StateValueInvalidMatch,
    InvalidKeysError,
    CommitmentStateError,
    DecodeCommitStateError,
    CommitmentStateInvalidMetadata,
    InvalidInputFormat,
    UntrustedAuthoritiesError,
    GameAlreadyExists,
    InvalidGame,
    InvalidConsensusProof,
}

pub type VersionNumber = u32;

pub enum Versioned {
    Signing,
    Commitment,
}

impl KeyringVersion {
    pub fn new(info: KeyVersionInfo) -> Self {
        KeyringVersion(info)
    }

    pub fn increment(self) -> (Self, ContractSecretKey, ContractPubKey) {
        let new_version = match self.0 {
            KeyVersionInfo::Signature(v) => KeyVersionInfo::Signature(v + 1),
            KeyVersionInfo::Commitment(v) => KeyVersionInfo::Commitment(v + 1),
        };

        let new_keyring = KeyringVersion(new_version);
        let key = pink_extension::ext().derive_sr25519_key(new_keyring.encode().into());
        let pub_key = pink_extension::ext().get_public_key(ContractSigType::Sr25519, &key);

        (new_keyring, key, pub_key)
    }

    pub fn build_keyring_material(
        version: Versioned,
    ) -> (KeyringVersion, ContractSecretKey, ContractPubKey) {
        let version = match version {
            Versioned::Signing => KeyringVersion::new(KeyVersionInfo::Signature(1)),
            Versioned::Commitment => KeyringVersion::new(KeyVersionInfo::Commitment(1)),
        };

        let secret_key = pink_extension::ext().derive_sr25519_key(version.encode().into());
        let pub_key = pink_extension::ext().get_public_key(ContractSigType::Sr25519, &secret_key);

        (version, secret_key, pub_key)
    }
}
