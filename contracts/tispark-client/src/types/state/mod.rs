use crate::types::Result as ContractResult;
use aleph_consensus_client::{ConsensusContractResult, StateTrieResponseProof};
use alloc::vec::Vec;
use crypto::Twox64Concat;
use frame_support::traits::ConstU32;
use ink::env::call::{ExecutionInput, Selector};
use scale::{Decode, Encode};
use tispark_primitives::commit_reveal::SecretKey;
use utils::ContractRef;

use super::ContractError;

pub type Len<const T: u32> = ConstU32<T>;
const MAX_LEN_COMMITMENT: u32 = 2048 / 8;
const LEN_ALGO: u32 = 256 / 8;
const LEN_IV: u32 = 96 / 8;
const MAX_METADATA_LEN: u32 = 512 / 8;

/// commit (encrypted data) and nonce (iv)
pub type Commitment = (Vec<u8>, Vec<u8>);

pub fn verify_state(
    contract: &ContractRef,
    state: StateTrieResponseProof,
) -> ConsensusContractResult<Vec<u8>> {
    let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!(
        "StateTrieManager::verify_state"
    )))
    .push_arg(state);

    contract.query(exec)
}

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

pub struct CommitmentStateDecoder;

impl CommitmentStateDecoder {
    pub fn decode(encoded: Vec<u8>) -> ContractResult<ResultCommitment> {
        let commitment: commit_reveal_pallet::types::TiSparkCommitment<
            Len<MAX_LEN_COMMITMENT>,
            Len<LEN_IV>,
            Len<LEN_ALGO>,
            Len<MAX_METADATA_LEN>,
        > = Decode::decode(&mut &encoded[..]).map_err(|_| ContractError::DecodeCommitStateError)?;

        Ok(ResultCommitment::new(
            (commitment.get_data(), commitment.get_iv()),
            Vec::new(),
        ))
    }
}

/// TwoxHash of Pallet name CommitReveal
const MODULE: [u8; 16] = [
    0xa4, 0x5f, 0x72, 0x30, 0x93, 0x2f, 0xe9, 0xd5, 0xeb, 0xc8, 0x46, 0xb8, 0x73, 0xec, 0xd5, 0x3f,
];
/// TwoxHash of StorageMape Name PhatContractCommitment
const METHOD: [u8; 16] = [
    0xe2, 0xb9, 0x63, 0x43, 0x2a, 0xe5, 0x50, 0x77, 0x2d, 0xaa, 0x14, 0xb5, 0xf8, 0xe6, 0xe3, 0x97,
];

pub fn build_storage_key_for_commitment(commit: &[u8]) -> Vec<u8> {
    let twox_commit = Twox64Concat::hash(commit);
    [&MODULE[..], &METHOD[..], &twox_commit[..]].concat()
}
