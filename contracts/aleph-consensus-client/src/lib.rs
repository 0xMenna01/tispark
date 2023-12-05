#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod traits;
mod types;

pub use traits::*;
pub use types::*;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod alpeh_consensus_client {
    use super::pink;
    use crate::{
        traits::{FinalityError, FinalityGadget, StateTrieManager},
        types::{ConsensusContractResult, ConsensusProofHandlerBuilder, ContractError},
        ConsensusProof, StateTrieResponseProof,
    };
    use alloc::vec::Vec;
    use pink::PinkEnvironment;
    use utils::types::{AccessControl, AuthorityId, SudoAccount};

    #[ink(storage)]
    pub struct AlephConsensusClient {
        /// List of authorities for the consensus client
        consensus_auth: ConsensusAuthorities,
        /// Sudo account for emergency operations
        sudo: SudoAccount,
    }

    #[derive(Debug)]
    #[ink::storage_item]
    pub struct ConsensusAuthorities {
        authorities: Vec<AuthorityId>,
        next_authorities: Option<Vec<AuthorityId>>,
    }

    impl AlephConsensusClient {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Set sudo account for initializing later on the consensus client authorities
            // It can be removed at later stages for a permissionless setting
            let sudo = pink::env().caller();
            let sudo = SudoAccount::new(Some(sudo));

            // Set an empty set of authorities
            let consensus_auth = ConsensusAuthorities {
                authorities: Default::default(),
                next_authorities: Default::default(),
            };

            Self {
                consensus_auth,
                sudo,
            }
        }

        // Once it is permissionless modify this because the exception can be triggered
        fn sudo(&self) -> AccountId {
            self.sudo
                .get()
                .expect("The sudo account is expected to be initialized")
        }

        fn ensure_owner(&self) -> ConsensusContractResult<()> {
            AccessControl::new(self.sudo.get())
                .caller(pink::env().caller())
                .verify()
                .map_err(|_| ContractError::BadOrigin)
        }
    }

    impl FinalityGadget for AlephConsensusClient {
        /// Initialize a permissionless setting for the consensus client, by rotating a committee of authorities
        // Not implemeneted yet, we are still in a permissioned setting.
        #[ink(message)]
        fn initialize_permissionless_authorities(
            &mut self,
            _next_authorities: Vec<AuthorityId>,
        ) -> Result<(), FinalityError> {
            Ok(())
        }

        /// Initialize a permissioned set of authorities for the consensus client
        #[ink(message)]
        fn initialize_permissioned_authorities(
            &mut self,
            authorities: Vec<AuthorityId>,
        ) -> Result<(), FinalityError> {
            self.ensure_owner()
                .map_err(|_| FinalityError::PermissionDenied)?;

            let mut auth = authorities;
            if self.consensus_auth.authorities.is_empty() {
                self.consensus_auth.authorities.append(&mut auth);
                Ok(())
            } else {
                Err(FinalityError::AuthoritiesAlreadyInitialized)
            }
        }

        /// Updates the list of authorities based on next authorities already stored and stores the new next authorities within a proof.
        // Not implemeneted yet, we are still in a permissioned setting.
        #[ink(message)]
        fn update_authorities(
            &mut self,
            _next_authorities: Vec<AuthorityId>,
            _proof: light_client::GetResponse,
        ) -> Result<(), FinalityError> {
            Ok(())
        }

        /// Set the next emergency finalizer account (aka sudo)
        #[ink(message)]
        fn update_emergency_finalizer_account(
            &mut self,
            emergency_finalizer: AuthorityId,
        ) -> Result<(), FinalityError> {
            self.ensure_owner()
                .map_err(|_| FinalityError::PermissionDenied)?;

            self.sudo.set(emergency_finalizer);
            Ok(())
        }

        /// Returns the current session, if necessary.
        // Returns `None` because we are still in a permissioned setting
        #[ink(message)]
        fn current_session(&self) -> Option<light_client::SessionIndex> {
            None
        }

        /// Returns the current session, if necessary.
        #[ink(message)]
        fn authorities(&self) -> Option<Vec<AccountId>> {
            let auth = self.consensus_auth.authorities.clone();
            if auth.is_empty() {
                None
            } else {
                Some(auth)
            }
        }

        /// Checks whether the chain is in a permissionless setting
        #[ink(message)]
        fn is_permissionless(&self) -> bool {
            self.consensus_auth.next_authorities.is_some()
        }

        /// Retuns current sudo account. Returns `None` if there isnt't
        #[ink(message)]
        fn sudo(&self) -> Option<AuthorityId> {
            self.sudo.get()
        }

        /// Removes sudo account, if some.
        #[ink(message)]
        fn remove_sudo(&mut self) -> Result<(), FinalityError> {
            self.ensure_owner()
                .map_err(|_| FinalityError::PermissionDenied)?;

            self.sudo.remove();
            Ok(())
        }

        #[ink(message)]
        fn verify_consensus(&self, request: ConsensusProof) -> ConsensusContractResult<()> {
            let sudo = self.sudo();

            // Verify the consensus proof
            let state_client_handler = ConsensusProofHandlerBuilder::default()
                .setup_client(
                    self.consensus_auth.authorities.clone(),
                    request.untrusted_auth.clone(),
                    sudo,
                )?
                .consensus_proof(request)
                .build();

            state_client_handler.verify_consensus_state()?;
            Ok(())
        }
    }

    impl StateTrieManager for AlephConsensusClient {
        #[ink(message)]
        fn verify_state(
            &self,
            request: StateTrieResponseProof,
        ) -> ConsensusContractResult<Vec<u8>> {
            Ok(request
                .verify_state()
                .map_err(|_| ContractError::ConsensusClientInvalidStateProof)?)
        }
    }
}
