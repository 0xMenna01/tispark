use crate::{
    message::RevealResponse,
    types::{
        commitment::ContractCommitment,
        consensus::AuthorityId,
        message::{
            CommitmentRequest, ResponseStateProofRequest, StateResponseProof, StateVerifyRequest,
        },
        Result as ContractResult,
    },
};
use alloc::vec::Vec;
use core::fmt::Debug;
use ink::primitives::AccountId;
use light_client::{GetResponse, SessionIndex};
use scale::{Decode, Encode};

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum FinalityError {
    PermissionDenied,
    SudoAlreadyRemoved,
    InvalidProof,
    AuthoritiesAlreadyInitialized,
}

#[ink::trait_definition]
pub trait FinalityGadget {
    /// Initialize a permissionless setting for the consensus client, by rotating a committee of authorities
    #[ink(message)]
    fn initialize_permissionless_authorities(
        &mut self,
        next_authorities: Vec<AuthorityId>,
    ) -> Result<(), FinalityError>;

    /// Initialize a permissioned set of authorities for the consensus client
    #[ink(message)]
    fn initialize_permissioned_authorities(
        &mut self,
        authorities: Vec<AuthorityId>,
    ) -> Result<(), FinalityError>;

    /// Updates the list of authorities based on next authorities already stored and stores the new next authorities within a proof.
    #[ink(message)]
    fn update_authorities(
        &mut self,
        next_authorities: Vec<AuthorityId>,
        proof: GetResponse,
    ) -> Result<(), FinalityError>;

    /// Set the next emergency finalizer account (aka sudo)
    #[ink(message)]
    fn update_emergency_finalizer_account(
        &mut self,
        emergency_finalizer: AuthorityId,
    ) -> Result<(), FinalityError>;

    /// Returns the current session, if necessary.
    #[ink(message)]
    fn current_session(&self) -> Option<SessionIndex>;

    /// Returns the current session, if necessary.
    #[ink(message)]
    fn authorities(&self) -> Option<Vec<AccountId>>;

    /// Checks whether the chain is in a permissionless setting
    #[ink(message)]
    fn is_permissionless(&self) -> bool;

    /// Retuns current sudo account. Returns `None` if there isnt't
    #[ink(message)]
    fn sudo(&self) -> Option<AuthorityId>;

    /// Removes sudo account, if some.
    #[ink(message)]
    fn remove_sudo(&mut self) -> Result<(), FinalityError>;
}

#[ink::trait_definition]
pub trait CommitRevealContractManager {
    /// Updates the key material used for key derivation
    #[ink(message)]
    fn update_keyring_material(&mut self) -> ContractResult<()>;

    #[ink(message)]
    fn commit(&self, request: CommitmentRequest) -> ContractResult<ContractCommitment>;

    #[ink(message)]
    fn reveal(&self, request: ResponseStateProofRequest) -> ContractResult<RevealResponse>;
}

#[ink::trait_definition]
pub trait StateTrieManager {
    #[ink(message)]
    fn verify_state(&self, request: StateVerifyRequest) -> StateResponseProof;
}
