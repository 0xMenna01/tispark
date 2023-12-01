use crate::{state, ServiceId};
use aleph_consensus_client::{ConsensusProof, ConsensusState, StateTrieResponseProof};
use alloc::{string::String, vec, vec::Vec};
use hex::FromHex;
use light_client::consensus::AlephLogs;
use light_client::Hash;
use scale::{Decode, Encode};
use tispark_primitives::{
    commit_reveal::{CommitId, RevealProof},
    state_proofs::{GetResponseProof, HashAlgorithm, Proof, StateCommitment, SubstrateStateProof},
};
use utils::types::AuthorityId;

pub enum Error {
    ParamsConversionError,
    InvalidHash,
    InvalidHex,
}

/// Encoded BetResult that will be encrypted.
/// Before the encryption takes place, the BetResultRequest is encoded once again for compatibility reasons within the tispark library.

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct CommitmentRequest {
    /// Some encoded plaintext value that nedds to be committed
    encoded_result: Vec<u8>,
    /// Some scale encoded metadata associated to the result
    metadata: Vec<u8>,
    service: ServiceId,
}

impl CommitmentRequest {
    pub fn new(encoded_result: Vec<u8>, metadata: Vec<u8>, service: ServiceId) -> Self {
        Self {
            encoded_result,
            metadata,
            service,
        }
    }

    pub fn get_service(&self) -> ServiceId {
        self.service.clone()
    }

    pub fn get(&self) -> (Vec<u8>, Vec<u8>) {
        (self.encoded_result.clone(), self.metadata.clone())
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ResponseStateProofRequest {
    pub meta: StateRequestMetadata,
    pub storage_proof: StorageProofParams,
    pub consensus_proof: ConsensusProofParams,
}

impl TryFrom<ResponseStateProofRequest> for RevealResultRequest {
    type Error = Error;
    fn try_from(value: ResponseStateProofRequest) -> Result<Self, Self::Error> {
        // 1. Build a commitment response proof

        // Encoded Storage proof
        let proof = SubstrateStateProof {
            hasher: HashAlgorithm::Blake2,
            storage_proof: value.storage_proof.proof.clone(),
        }
        .encode();

        let proof = Proof {
            height: value.meta.height,
            proof,
        };

        let root = StateCommitment {
            timestamp: value.meta.timestamp,
            state_root: value.consensus_proof.state_root()?,
        };

        let commit_id = value.meta.commit_hash()?;
        let keys = vec![state::build_storage_key_for_commitment(
            commit_id.as_bytes(),
        )];

        let proof_request =
            StateTrieResponseProof::new(GetResponseProof::new(&keys, &root, &proof)).unwrap();

        // 2. Build a consensus proof
        let state = ConsensusState {
            block: value.consensus_proof.block(),
            extrinsics_root: value.consensus_proof.extrinsics_root()?,
            state_root: value.consensus_proof.state_root()?,
            parent_hash: value.consensus_proof.parent_hash()?,
            logs: value.consensus_proof.logs(),
        };

        let consensus_proof = ConsensusProof {
            justification: value.consensus_proof.justification,
            state,
            untrusted_auth: value.consensus_proof.untrusted_authorites,
        };

        Ok(Self::new(proof_request, consensus_proof, commit_id))
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct StateRequestMetadata {
    pub commit_id: String,
    pub timestamp: u64,
    pub height: u64,
}

impl StateRequestMetadata {
    pub fn commit_hash(&self) -> Result<light_client::Hash, Error> {
        let commit_id = Vec::from_hex(&self.commit_id).map_err(|_| Error::InvalidHash)?;
        Ok(light_client::Hash::from_slice(&commit_id))
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct StorageProofParams {
    pub proof: Vec<Vec<u8>>,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusProofParams {
    pub untrusted_authorites: Vec<AuthorityId>,
    pub justification: Vec<u8>,
    pub consensus_state: ConsensusStateParams,
}

impl ConsensusProofParams {
    pub fn state_root(&self) -> Result<Hash, Error> {
        let state_root =
            Vec::from_hex(&self.consensus_state.state_root).map_err(|_| Error::InvalidHash)?;
        Ok(Hash::from_slice(&state_root))
    }

    pub fn block(&self) -> u32 {
        self.consensus_state.block.clone()
    }

    pub fn extrinsics_root(&self) -> Result<Hash, Error> {
        let extrinsics_hash =
            Vec::from_hex(&self.consensus_state.extrinsics_root).map_err(|_| Error::InvalidHash)?;
        Ok(Hash::from_slice(&extrinsics_hash))
    }

    pub fn parent_hash(&self) -> Result<Hash, Error> {
        let parent_hash =
            Vec::from_hex(&self.consensus_state.parent_hash).map_err(|_| Error::InvalidHash)?;
        Ok(Hash::from_slice(&parent_hash))
    }

    pub fn logs(&self) -> AlephLogs {
        AlephLogs {
            aura_pre_runtime: self.consensus_state.aura_pre_runtime.clone(),
            seal: self.consensus_state.seal.clone(),
        }
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusStateParams {
    pub block: u32,
    pub extrinsics_root: String,
    pub state_root: String,
    pub parent_hash: String,
    pub aura_pre_runtime: String,
    pub seal: String,
}

/// Request to reveal the key binded to a commit
/// The nonce_metadata is used as iv
#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct RevealResultRequest {
    response: StateTrieResponseProof,
    proof: ConsensusProof,
    commit: CommitId,
}

impl RevealResultRequest {
    pub fn new(response: StateTrieResponseProof, proof: ConsensusProof, commit: CommitId) -> Self {
        Self {
            response,
            proof,
            commit,
        }
    }

    pub fn proof(&self) -> ConsensusProof {
        self.proof.clone()
    }

    pub fn response(&self) -> StateTrieResponseProof {
        self.response.clone()
    }

    pub fn commmit(&self) -> Hash {
        self.commit.clone()
    }
}

/// Encoded Reveal
#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct RevealResponse {
    /// The encoded result with the associated metadata
    result: Vec<u8>,
    /// bet commitment proof
    proof: RevealProof,
}

impl RevealResponse {
    pub fn new(result: Vec<u8>, proof: RevealProof) -> Self {
        Self { result, proof }
    }

    pub fn result(&self) -> Vec<u8> {
        self.result.clone()
    }

    pub fn proof(&self) -> RevealProof {
        self.proof.clone()
    }
}
