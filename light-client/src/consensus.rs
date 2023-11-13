use crate::{
    finality::{
        crypto::{
            verify, verify_from_contract, AlephSignature, AlephSignatureSet, AuthorityId,
            AuthoritySignature,
        },
        types::NodeIndex,
    },
    BlockHash, BlockNumber, ConsensusClient, ConsensusError, ContractBlakeTwo256, Hash, Header,
    Proof,
};

use alloc::{string::String, vec::Vec};
use codec::{Decode, Encode};
use hex::FromHex;
use scale_info::TypeInfo;
use sp_core::Hasher;
use sp_runtime::{traits::Header as HeaderT, ConsensusEngineId, Digest, DigestItem};

/// The `ConsensusEngineId` of AuRa.
pub const AURA_ENGINE_ID: ConsensusEngineId = *b"aura";

/// The `ConsensusEngineId` of Aleph.
pub const ALEPH_ENGINE_ID: ConsensusEngineId = *b"FRNK";

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, TypeInfo)]
pub struct AlephLogs {
    pub aura_pre_runtime: String,
    pub seal: String,
}

#[allow(dead_code)]
pub struct AlephConsensusLogBuilder {
    aura_pre_runtime: Vec<u8>,
    seal: Vec<u8>,
}

#[allow(dead_code)]
impl AlephConsensusLogBuilder {
    pub fn logs(aura_pre_runtime: &str, seal: &str) -> Result<Self, ConsensusError> {
        let aura_pre_runtime = Vec::from_hex(aura_pre_runtime)
            .map_err(|_| ConsensusError::InvalidAlephLogPreRuntime)?;
        let seal = Vec::from_hex(seal).map_err(|_| ConsensusError::InvalidAlephLogSeal)?;

        Ok(Self {
            aura_pre_runtime,
            seal,
        })
    }

    pub fn build(self) -> Digest {
        let mut logs = Vec::new();
        logs.push(DigestItem::PreRuntime(
            AURA_ENGINE_ID,
            self.aura_pre_runtime,
        ));
        logs.push(DigestItem::Seal(AURA_ENGINE_ID, self.seal));

        Digest { logs }
    }
}

/// AlephBFT consensus client implementation
pub struct AlephConsensusClient {
    authorities: Vec<AuthorityId>,
    // Not yet supported for state verify
    emergency_finalizer: AuthorityId,
}

impl Proof for AlephSignatureSet<AlephSignature> {}

impl ConsensusClient for AlephConsensusClient {
    type ConsensusProof = AlephSignatureSet<AlephSignature>;

    fn verify_consensus(
        &self,
        consensus_state: Hash,
        proof: Self::ConsensusProof,
    ) -> Result<Vec<NodeIndex>, ConsensusError> {
        let mut authorities = Vec::new();

        for (node_index, sign) in proof.into_iter() {
            if let Some(authority_key) = self.authorities.get(node_index.0) {
                if verify(authority_key, &consensus_state.0, &sign) {
                    authorities.push(NodeIndex::from(node_index));
                } else {
                    return Err(ConsensusError::InvalidSignature);
                }
            } else {
                return Err(ConsensusError::MissingAuthorityKey);
            }
        }

        Ok(authorities)
    }
}

#[allow(dead_code)]
impl AlephConsensusClient {
    pub fn new(authorities: Vec<AuthorityId>, emergency_finalizer: AuthorityId) -> Self {
        Self {
            authorities,
            emergency_finalizer,
        }
    }

    /// Verifies the proof of a sudo account
    pub fn verify_consensus_sudo(
        &self,
        consensus_state: BlockHash,
        proof: AuthoritySignature,
    ) -> bool {
        let sign = AlephSignature::from(proof);
        verify(&self.emergency_finalizer, &consensus_state.0, &sign)
    }

    pub fn build_consenus_state(
        &self,
        block: BlockNumber,
        extrinsics_root: Hash,
        state_root: Hash,
        parent_hash: BlockHash,
        digest: Digest,
    ) -> BlockHash {
        Header::new(block, extrinsics_root, state_root, parent_hash, digest).hash()
    }
}

pub struct PhatContractConsensusClient(AlephConsensusClient);

impl ConsensusClient for PhatContractConsensusClient {
    type ConsensusProof = AlephSignatureSet<AlephSignature>;

    fn verify_consensus(
        &self,
        consensus_state: Hash,
        proof: Self::ConsensusProof,
    ) -> Result<Vec<NodeIndex>, ConsensusError> {
        let aleph_client = &self.0;

        let mut authorities = Vec::new();
        for (node_index, sign) in proof.into_iter() {
            if let Some(authority_key) = aleph_client.authorities.get(node_index.0) {
                if verify_from_contract(authority_key, &consensus_state.0, &sign) {
                    authorities.push(NodeIndex::from(node_index));
                } else {
                    return Err(ConsensusError::InvalidSignature);
                }
            } else {
                return Err(ConsensusError::MissingAuthorityKey);
            }
        }

        Ok(authorities)
    }
}

#[allow(dead_code)]
impl PhatContractConsensusClient {
    pub fn new(authorities: Vec<AuthorityId>, emergency_finalizer: AuthorityId) -> Self {
        Self(AlephConsensusClient {
            authorities,
            emergency_finalizer,
        })
    }

    /// Verifies the proof of a sudo account
    pub fn verify_consensus_sudo(
        &self,
        consensus_state: BlockHash,
        proof: AuthoritySignature,
    ) -> bool {
        let alep_client = &self.0;

        let sign = AlephSignature::from(proof);
        verify_from_contract(&alep_client.emergency_finalizer, &consensus_state.0, &sign)
    }

    pub fn build_consenus_state(
        &self,
        block: BlockNumber,
        extrinsics_root: Hash,
        state_root: Hash,
        parent_hash: Hash,
        digest: Digest,
    ) -> Hash {
        ink_hash_header(block, extrinsics_root, state_root, parent_hash, digest)
    }
}

pub fn ink_hash_header(
    block: BlockNumber,
    extrinsics_root: Hash,
    state_root: Hash,
    parent_hash: Hash,
    digest: Digest,
) -> Hash {
    Header::new(block, extrinsics_root, state_root, parent_hash, digest)
        .using_encoded(|consensus_state| ContractBlakeTwo256::hash(consensus_state))
}
