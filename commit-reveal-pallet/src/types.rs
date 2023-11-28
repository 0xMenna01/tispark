use crate::Config;
use frame_support::{pallet_prelude::Get, storage::bounded_vec::BoundedVec};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use primitives::commit_reveal::{Commit, CommitId, RevealProof};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
use sp_std::vec::Vec;

/// Commit-Reveal to be implemented
pub trait TiSparkManager {
    type Metadata;
    type Signature;
    type Error;

    fn commit_from_request(
        request: CommitmentRequest<Self::Metadata, Self::Signature>,
    ) -> Result<(), Self::Error>;

    /// Key reveal proof
    fn reveal_from_proof(proof: RevealProof) -> Result<(), Self::Error>;

    fn commitment_storage_key_for(id: &CommitId) -> Vec<u8>;
}

#[derive(Encode, MaxEncodedLen, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct CommitmentRequest<Metadata, Signature> {
    pub commit: Commit<Metadata>,
    pub signature: Signature,
}

/// Address of the Phat Contract that is authorized for commitments
pub type PhatContractOf<T> = <T as Config>::PhatContractId;

/// Commitment
#[derive(Encode, MaxEncodedLen, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(MaxCommitmentSize))]
pub struct SecureCommitment<MaxCommitmentSize: Get<u32>>(BoundedVec<u8, MaxCommitmentSize>);

/// Initialization Vector associated to commitment
#[derive(Encode, MaxEncodedLen, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(Size))]
pub struct SecureIV<Size: Get<u32>>(BoundedVec<u8, Size>);

/// Commitment proof
#[derive(Encode, MaxEncodedLen, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(KeyLen))]
pub struct KeyProof<KeyLen: Get<u32>>(BoundedVec<u8, KeyLen>);

/// TISPARK Commitment
#[derive(Encode, MaxEncodedLen, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(MaxCommitmentLen, IVLen, KeyLen))]
pub struct TiSparkCommitment<MaxCommitmentLen, IVLen, KeyLen>
where
    MaxCommitmentLen: Get<u32>,
    IVLen: Get<u32>,
    KeyLen: Get<u32>,
{
    commit: SecureCommitment<MaxCommitmentLen>,
    iv: SecureIV<IVLen>,
    proof: KeyProof<KeyLen>,
}

impl<MaxCommitmentLen, IVLen, KeyLen> TiSparkCommitment<MaxCommitmentLen, IVLen, KeyLen>
where
    MaxCommitmentLen: Get<u32>,
    IVLen: Get<u32>,
    KeyLen: Get<u32>,
{
    pub fn new(commitment: Vec<u8>, iv: &[u8]) -> Result<Self, InvalidBytesLength> {
        Ok(Self {
            commit: SecureCommitment(
                MyBoundedVec::<u8, MaxCommitmentLen>::try_from(commitment)?.get(),
            ),
            iv: SecureIV(MyBoundedVec::<u8, IVLen>::try_from(iv.to_vec())?.get()),
            proof: KeyProof(BoundedVec::<u8, KeyLen>::new()),
        })
    }

    pub fn get_iv(&self) -> Vec<u8> {
        self.iv.0.to_vec()
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.commit.0.to_vec()
    }

    pub fn has_proof(&self) -> bool {
        !self.proof.0.is_empty()
    }

    pub fn set_proof(&mut self, proof: &mut Vec<u8>) -> Result<(), InvalidBytesLength> {
        self.proof
            .0
            .try_append(proof)
            .map_err(|_| InvalidBytesLength::ProofLengthError)
    }
}

struct MyBoundedVec<T, S>(BoundedVec<T, S>);

impl<T, S> MyBoundedVec<T, S>
where
    T: Clone,
    S: Get<u32>,
{
    pub fn get(&self) -> BoundedVec<T, S> {
        self.0.clone()
    }
}

#[derive(Debug)]
pub enum InvalidBytesLength {
    ProofLengthError,
    GenericLengthError,
}

impl<T, S: Get<u32>> TryFrom<Vec<T>> for MyBoundedVec<T, S> {
    type Error = InvalidBytesLength;
    fn try_from(mut value: Vec<T>) -> Result<Self, Self::Error> {
        let mut bounded: BoundedVec<T, S> = BoundedVec::new();
        bounded
            .try_append(&mut value)
            .map_err(|_| InvalidBytesLength::GenericLengthError)?;

        Ok(MyBoundedVec(bounded))
    }
}
