use crate::{types::ConsensusContractResult, ConsensusProof, StateTrieResponseProof};
use alloc::vec::Vec;
use core::fmt::Debug;
use ink::primitives::AccountId;
use light_client::{GetResponse, SessionIndex};
use scale::{Decode, Encode};
use utils::types::AuthorityId;

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum FinalityError {
    PermissionDenied,
    SudoAlreadyRemoved,
    InvalidProof,
    AuthoritiesAlreadyInitialized,
    VerificationError,
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

    #[ink(message)]
    fn verify_consensus(&self, request: ConsensusProof) -> ConsensusContractResult<()>;
}

#[ink::trait_definition]
pub trait StateTrieManager {
    #[ink(message)]
    fn verify_state(&self, request: StateTrieResponseProof) -> ConsensusContractResult<Vec<u8>>;
}
