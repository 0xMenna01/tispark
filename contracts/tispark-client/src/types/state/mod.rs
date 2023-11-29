use crate::types::Result as ContractResult;
use alloc::vec::Vec;
use frame_support::traits::ConstU32;
use light_client::{GetResponse, GetSingleState, Hash};
use scale::{Decode, Encode};
use tispark_primitives::{commit_reveal::SecretKey, state_proofs::GetResponseProof};

use super::ContractError;

pub type Len<const T: u32> = ConstU32<T>;
const MAX_LEN_COMMITMENT: u32 = 2048 / 8;
const LEN_ALGO: u32 = 256 / 8;
const LEN_IV: u32 = 96 / 8;
const MAX_METADATA_LEN: u32 = 512 / 8;

/// commit (encrypted data) and nonce (iv)
pub type Commitment = (Vec<u8>, Vec<u8>);

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct ResultCommitment {
    commitment: Commitment,
    proof: SecretKey,
}

impl ResultCommitment {
    pub fn new(commitment: Commitment, proof: SecretKey) -> Self {
        Self { commitment, proof }
    }

    pub fn nonce(&self) -> &[u8] {
        &self.commitment.1
    }

    pub fn value(&self) -> &[u8] {
        &self.commitment.0
    }

    pub fn key(&self) -> &[u8] {
        &self.proof
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct GetCommitmentResponseProof {
    height: u64,
    commit: Hash,
    proof: GetResponseProof,
}

impl GetCommitmentResponseProof {
    pub fn response(&self) -> GetResponse {
        GetResponse(self.proof.clone())
    }

    pub fn commit(&self) -> Hash {
        self.commit.clone()
    }

    pub fn new(height: u64, commit: Hash, proof: GetResponseProof) -> ContractResult<Self> {
        let commitment_response = GetCommitmentResponseProof {
            height,
            commit,
            proof,
        };
        if commitment_response.response().verify_key_uniquness() {
            Ok(commitment_response)
        } else {
            Err(ContractError::InvalidKeysError)
        }
    }

    pub fn verify_commitment(&self) -> ContractResult<ResultCommitment> {
        let data = self
            .response()
            .verify_state()
            .map_err(|_| ContractError::CommitmentStateError)?;

        let commitment: commit_reveal_pallet::types::TiSparkCommitment<
            Len<MAX_LEN_COMMITMENT>,
            Len<LEN_IV>,
            Len<LEN_ALGO>,
            Len<MAX_METADATA_LEN>,
        > = Decode::decode(&mut &data[..]).map_err(|_| ContractError::DecodeCommitStateError)?;

        Ok(ResultCommitment::new(
            (commitment.get_data(), commitment.get_iv()),
            Vec::new(),
        ))
    }
}
