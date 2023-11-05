use crate::{
    finality::crypto::{verify, AlephSignature, AuthorityId, AuthoritySignature, SignatureSet},
    BlockHash, BlockNumber, ConsensusClient, ConsensusError, Hash, Header, Proof, StateRootHash,
};
use aleph_bft_crypto::NodeIndex;
use hex::FromHex;
use scale::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{testing::DigestItem, traits::Header as HeaderT, ConsensusEngineId, Digest};

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

impl Proof for SignatureSet<AlephSignature> {}

impl ConsensusClient for AlephConsensusClient {
    type ConsensusState = BlockHash;
    type ConsensusProof = SignatureSet<AlephSignature>;

    fn verify_consensus(
        &self,
        consensus_state: Self::ConsensusState,
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
        state_root: StateRootHash,
        parent_hash: Hash,
        digest: Digest,
    ) -> BlockHash {
        Header::new(block, extrinsics_root, state_root, parent_hash, digest).hash()
    }
}
