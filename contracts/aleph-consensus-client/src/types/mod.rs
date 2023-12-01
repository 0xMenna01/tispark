pub use self::Result as ConsensusContractResult;
use alloc::vec::Vec;
use core::fmt::Debug;
use ink::storage::Mapping;
use light_client::{
    consensus::{AlephConsensusLogBuilder, AlephLogs, PhatContractConsensusClient},
    finality::{crypto::AuthorityId as AuthorityPublic, justification},
    ConsensusClient, GetResponse, GetSingleState,
};
use scale::{Decode, Encode};
use tispark_primitives::state_proofs::GetResponseProof;
use utils::types::AuthorityId;

/// Type alias for the contract's result type.
pub type Result<T> = core::result::Result<T, ContractError>;

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum ContractError {
    BadOrigin,
    ConsensusClientInvalidLogs,
    ConsensusClientInvalidJustifications,
    ConsensusClientInvalidSignatures,
    ConsensusClientInvalidEmergencySignature,
    UntrustedAuthoritiesError,
    InvalidKeysError,
    CommitmentStateError,
    ConsensusClientInvalidStateProof,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusState {
    pub block: u32,
    pub extrinsics_root: light_client::Hash,
    pub state_root: light_client::Hash,
    pub parent_hash: light_client::Hash,
    pub logs: AlephLogs,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusProof {
    pub justification: Vec<u8>,
    pub state: ConsensusState,
    pub untrusted_auth: Vec<AuthorityId>,
}

#[derive(Default)]
pub struct ConsensusNotInit;
pub struct AuthoritiesSet(Vec<AuthorityId>, AuthorityId);
pub struct ConsensusInitialized {
    authorities: Vec<AuthorityId>,
    emergency_finalizer: AuthorityId,
    proof: ConsensusProof,
}

pub struct ConsensusProofClientHandler {
    client: PhatContractConsensusClient,
    proof: ConsensusProof,
}

impl ConsensusProofClientHandler {
    pub fn verify_consensus_state(&self) -> Result<light_client::Hash> {
        // Build the consensus state
        let aura_pre_runtime = &self.proof.state.logs.aura_pre_runtime;
        let seal = &self.proof.state.logs.seal;
        let digest = AlephConsensusLogBuilder::logs(aura_pre_runtime, seal)
            .map_err(|_| ContractError::ConsensusClientInvalidLogs)?
            .build();

        let consensus_state = self.client.build_consenus_state(
            self.proof.state.block,
            self.proof.state.extrinsics_root,
            self.proof.state.state_root,
            self.proof.state.parent_hash,
            digest,
        );

        // Decodes Aleph Justification
        let justification =
            justification::backwards_compatible_decode(self.proof.justification.clone())
                .map_err(|_| ContractError::ConsensusClientInvalidJustifications)?;

        match justification {
            // Authority signature set verification
            justification::AlephJustification::CommitteeMultisignature(signatures) => {
                self.client
                    .verify_consensus(consensus_state, signatures)
                    .map_err(|_| ContractError::ConsensusClientInvalidSignatures)?;
            }

            // Emergency finalizer signature verification
            justification::AlephJustification::EmergencySignature(signature) => {
                let verify = self
                    .client
                    .verify_consensus_sudo(consensus_state, signature);
                if !verify {
                    return Err(ContractError::ConsensusClientInvalidEmergencySignature);
                }
            }
        }
        // Returns the block hash that has been validated
        Ok(consensus_state)
    }
}

pub struct ConsensusProofHandlerBuilder<S> {
    state: S,
}

impl Default for ConsensusProofHandlerBuilder<ConsensusNotInit> {
    fn default() -> Self {
        Self {
            state: Default::default(),
        }
    }
}

impl ConsensusProofHandlerBuilder<ConsensusNotInit> {
    pub fn setup_client(
        self,
        authorities: Vec<AuthorityId>,
        untrusted_authorites: Vec<AuthorityId>,
        emergency_finalizer: AuthorityId,
    ) -> Result<ConsensusProofHandlerBuilder<AuthoritiesSet>> {
        if Self::verify_untrasted_authorities(&authorities, &untrusted_authorites) {
            Ok(ConsensusProofHandlerBuilder {
                state: AuthoritiesSet(untrusted_authorites, emergency_finalizer),
            })
        } else {
            Err(ContractError::UntrustedAuthoritiesError)
        }
    }

    fn verify_untrasted_authorities(
        authorities: &[AuthorityId],
        untrusted_authorites: &[AuthorityId],
    ) -> bool {
        if authorities.len() != untrusted_authorites.len() {
            return false;
        } else {
            let mut trusted: Mapping<AuthorityId, bool> = Mapping::new();

            // add each trusted authorities in the map as still not found trusted authorities
            for authority in authorities {
                trusted.insert(authority, &true);
            }
            // verify if each untrasted authority is trusted
            for untrusted in untrusted_authorites {
                let is_trusted = trusted.get(untrusted).is_some_and(|is_trusted| is_trusted);
                if !is_trusted {
                    return false;
                }
            }
            // All untrasted authorities have passed the test
            return true;
        }
    }
}

impl ConsensusProofHandlerBuilder<AuthoritiesSet> {
    pub fn consensus_proof(
        self,
        proof: ConsensusProof,
    ) -> ConsensusProofHandlerBuilder<ConsensusInitialized> {
        let authorities = self.state.0;
        let emergency_finalizer = self.state.1;
        ConsensusProofHandlerBuilder {
            state: ConsensusInitialized {
                authorities,
                emergency_finalizer,
                proof,
            },
        }
    }
}

impl ConsensusProofHandlerBuilder<ConsensusInitialized> {
    pub fn build(self) -> ConsensusProofClientHandler {
        // Convert the authorities into a valid set of Authority Public keys
        let mut authorities = Vec::new();
        self.state.authorities.into_iter().for_each(|key| {
            authorities.push(
                AuthorityPublic::try_from(key.as_ref())
                    .expect("The set of authority keys is expected to be in a valid format"),
            )
        });

        // Convert the emergency finalizer into a valid public key
        let emergency_finalizer =
            AuthorityPublic::try_from(self.state.emergency_finalizer.as_ref())
                .expect("The emergency finalizer is expected to be in a valid format");

        let client = PhatContractConsensusClient::new(authorities, emergency_finalizer);
        let proof = self.state.proof;

        ConsensusProofClientHandler { client, proof }
    }
}

// state verification feature
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct StateTrieResponseProof {
    pub proof: GetResponseProof,
}

impl StateTrieResponseProof {
    pub fn response(&self) -> GetResponse {
        GetResponse(self.proof.clone())
    }

    pub fn new(proof: GetResponseProof) -> Result<Self> {
        let commitment_response = StateTrieResponseProof { proof };
        if commitment_response.response().verify_key_uniquness() {
            Ok(commitment_response)
        } else {
            Err(ContractError::InvalidKeysError)
        }
    }

    pub fn verify_state(&self) -> Result<Vec<u8>> {
        Ok(self
            .response()
            .verify_state()
            .map_err(|_| ContractError::CommitmentStateError)?)
    }
}
