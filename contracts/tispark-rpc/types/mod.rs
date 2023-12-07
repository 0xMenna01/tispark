use self::{chain_state::StorageProofParams, consensus::ConsensusProofParams};
use aleph_consensus_client::{ConsensusProof, ConsensusState, StateTrieResponseProof};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use light_client::Hash;
use pink_extension as pink;
use scale::{Decode, Encode};
use serde::Deserialize;
use tispark_primitives::{
    commit_reveal::CommitId,
    state_proofs::{GetResponseProof, HashAlgorithm, Proof, StateCommitment, SubstrateStateProof},
};

pub mod chain_state;
pub mod consensus;

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum Error {
    BadOrigin,
    RequestFailed,
    InvalidBody,
    InvalidHexData,
    HexStringOutOfBounds,
    DigestItemMissing,
    U32ConversionError,
    InvalidJustificationsFormat,
    AuthoritiesDecodeError,
    InvalidHash,
}

/// Type alias for the contract's result type.
pub type Result<T> = core::result::Result<T, Error>;
pub type CommitIdRequest = Hash;

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct FinalizedBlockHash<'a> {
    pub jsonrpc: &'a str,
    pub result: &'a str,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct SignedBlock<'a> {
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub result: BlockData<'a>,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct BlockData<'a> {
    #[serde(borrow)]
    pub block: Block<'a>,
    pub justifications: Vec<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct Block<'a> {
    #[serde(borrow)]
    pub header: Header<'a>,
    #[serde(borrow)]
    pub extrinsics: Vec<&'a str>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct Header<'a> {
    pub parentHash: &'a str,
    pub number: &'a str,
    pub stateRoot: &'a str,
    pub extrinsicsRoot: &'a str,
    #[serde(borrow)]
    pub digest: Digest<'a>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct Digest<'a> {
    #[serde(borrow)]
    pub logs: Vec<&'a str>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct ReadProof<'a> {
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub result: ReadProofAtFinalizedBlock<'a>,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct ReadProofAtFinalizedBlock<'a> {
    pub at: &'a str,
    #[serde(borrow)]
    pub proof: Vec<&'a str>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct UntrustedAuthorities<'a> {
    pub jsonrpc: &'a str,
    pub result: &'a str,
    pub id: u32,
}

pub struct Utils(());

impl Utils {
    fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
        let content_length = format!("{}", data.len());
        let headers: Vec<(String, String)> = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), content_length),
        ];

        let response = pink::http_post!(rpc_node, data, headers);
        if response.status_code != 200 {
            return Err(Error::RequestFailed);
        }

        let body = response.body;
        Ok(body)
    }

    fn extract_hex_from(start_index: usize, hex_string: &str) -> Result<String> {
        if !hex_string.starts_with("0x") {
            return Err(Error::InvalidHexData);
        }
        if start_index >= hex_string.len() {
            return Err(Error::HexStringOutOfBounds);
        }
        // 14
        let hex_string = &hex_string[start_index..];
        Ok(hex_string.to_string())
    }

    fn extract_digest(start_index: usize, hex_string: Option<&&str>) -> Result<String> {
        if let Some(digest) = hex_string {
            // extract the digest item
            let digest = Self::extract_hex_from(start_index, digest)?;
            Ok(digest)
        } else {
            Err(Error::DigestItemMissing)
        }
    }

    fn encode_to_hex(value: &[u8]) -> String {
        hex::encode(value)
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct StateRequestMetadata {
    pub id: CommitIdRequest,
    pub timestamp: u64,
    pub height: u64,
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

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ResponseStateProofRequest {
    pub meta: StateRequestMetadata,
    pub storage_proof: StorageProofParams,
    pub consensus_proof: ConsensusProofParams,
}

impl TryFrom<ResponseStateProofRequest> for RevealResultRequest {
    type Error = Error;
    fn try_from(value: ResponseStateProofRequest) -> Result<Self> {
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

        let commit_id = value.meta.id;
        let keys = value.storage_proof.keys;

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
            justification: value.consensus_proof.justifications,
            state,
            untrusted_auth: value.consensus_proof.untrusted_authorities,
        };

        Ok(Self::new(proof_request, consensus_proof, commit_id))
    }
}
