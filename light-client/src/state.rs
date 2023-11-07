use crate::{BlockNumber, GetSingleState, StateProofError, StateRootHash};
use codec::{Decode, Encode};
use primitives::{commit_reveal::SecretKey, phala_ismp::GetResponseProof};
use alloc::{borrow::ToOwned, vec::Vec};

#[derive(Debug, Clone, Encode, Decode, scale_info::TypeInfo, PartialEq, Eq)]
pub struct GetResponse(pub BlockNumber, pub GetResponseProof);

impl GetResponse {
    pub fn state_root(&self) -> StateRootHash {
        self.1.state_root().state_root
    }
}

impl GetSingleState for GetResponse {
    fn verify_key_uniquness(&self) -> bool {
        self.1.keys().len() == 1
    }

    fn verify_state(&self) -> Result<Vec<u8>, crate::StateProofError> {
        if !self.verify_key_uniquness() {
            return Err(StateProofError::InvalidKeysError);
        }

        self.1
            .verify_state_proof()
            .map_err(|_| StateProofError::StateVerifyError)
            .and_then(|proof_result| {
                // Since there is only a single key, we take the first key value pair
                let value = proof_result
                    .first_key_value()
                    .ok_or(StateProofError::FirstKeyValueError)?
                    .1;

                match value {
                    Some(data) => Ok(data.clone()),
                    None => Err(StateProofError::MissingValueError),
                }
            })
    }
}

/// commit (encrypted data) and nonce (iv)
type Commitment = (Vec<u8>, Vec<u8>);

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct ResultCommitment {
    commitment: Commitment,
    proof: SecretKey,
}

impl ResultCommitment {
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

pub type CommitId = u32;

#[derive(Debug, Clone, Encode, Decode, scale_info::TypeInfo, PartialEq, Eq)]
pub struct GetCommitmentResponseProof {
    height: BlockNumber,
    id: CommitId,
    proof: GetResponseProof,
}

#[allow(dead_code)]
impl GetCommitmentResponseProof {
    pub fn response(&self) -> GetResponse {
        GetResponse(self.height, self.proof.clone())
    }

    pub fn new(
        height: BlockNumber,
        id: CommitId,
        proof: GetResponseProof,
    ) -> Result<Self, StateProofError> {
        let commitment_response = GetCommitmentResponseProof { height, id, proof };
        if commitment_response.response().verify_key_uniquness() {
            Ok(commitment_response)
        } else {
            Err(StateProofError::InvalidKeysError)
        }
    }

    pub fn verify_commitment(&self) -> Result<ResultCommitment, StateProofError> {
        let data = self.response().verify_state()?;
        let commitments: Vec<ResultCommitment> =
            Decode::decode(&mut &data[..]).map_err(|_| StateProofError::DecodeError)?;

        if let Some(commitment) = commitments.get(self.id as usize) {
            Ok(commitment.to_owned())
        } else {
            Err(StateProofError::InvalidCommitId)
        }
    }
}
