use crate::ServiceId;
use alloc::vec::Vec;
use light_client::Hash as H256;
use scale::{Decode, Encode};
use tispark_primitives::commit_reveal::RevealProof;
use utils::types::Hash;

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct CommitIdRequest(Hash);

impl CommitIdRequest {
    pub fn new(hash: Hash) -> Self {
        CommitIdRequest(hash)
    }
}

impl From<CommitIdRequest> for H256 {
    fn from(request: CommitIdRequest) -> Self {
        H256::from_slice(request.0.as_ref())
    }
}

/// Encoded result that will be encrypted  associated to some metadata and a service id
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
