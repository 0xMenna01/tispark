use crate::{
    types::{CommitmentRequest, TiSparkCommitment, TiSparkManager},
    Config, Error, Event, Pallet, PhatContract, PhatContractCommitment,
};
use parity_scale_codec::{Decode, Encode};
use primitives::commit_reveal::{
    Commit, CommitId, CommitRevealError, Commitment, DecryptedData, EncryptedData, Reveal,
    RevealProof,
};
use sp_application_crypto::KeyTypeId;
use sp_application_crypto::RuntimeAppPublic;
use sp_core::Get;
use sp_std::vec::Vec;

impl<T: Config> TiSparkManager for Pallet<T> {
    type Metadata = T::CommitMetadata;
    type Signature = <T::PhatContractId as RuntimeAppPublic>::Signature;
    type Error = Error<T>;

    fn commit_from_request(
        request: CommitmentRequest<Self::Metadata, Self::Signature>,
    ) -> Result<(), Self::Error> {
        let plain_metadata = request.commit.get_metadata();

        // We take the commitment with the encoded metadata, since the phat contract has signed that information
        let commitment = request.commit.with_encoded_metadata();

        verify_contract_signature::<T>(&commitment, &request.signature)?;

        let commit_id = commitment.get_id();
        // We cannot commit the plain metadata because the phat contract that must decode it cannot use generics type yet (not supported in ink smart contracts yet)
        // todo! Once generic types are supported change the implementation and commit the plain metadata
        Self::commit(commitment).map_err(|_| Error::<T>::InvalidCommitment)?;

        let storage_key = Self::commitment_storage_key_for(&commit_id);
        Self::deposit_event(Event::ValueCommitted {
            id: commit_id,
            metadata: plain_metadata,
            storage_key,
        });

        Ok(())
    }

    fn reveal_from_proof(proof: RevealProof) -> Result<(), Self::Error> {
        let reveal = Self::reveal(proof.clone()).map_err(|_| Error::<T>::InvalidProof)?;
        Self::deposit_event(Event::CommitRevealed {
            proof: proof.secret,
            reveal,
            commit: proof.commit_id,
        });

        Ok(())
    }

    fn commitment_storage_key_for(id: &CommitId) -> Vec<u8> {
        PhatContractCommitment::<T>::hashed_key_for(id)
    }

    fn metadata_for_commit(commit_id: &CommitId) -> Result<Self::Metadata, Self::Error> {
        if let Some(commitment) = PhatContractCommitment::<T>::get(commit_id) {
            let metadata = commitment.get_metadata();

            let metadata: T::CommitMetadata = Decode::decode(&mut &metadata[..])
                .map_err(|_| Error::<T>::DecodingMetadataError)?;
            Ok(metadata)
        } else {
            Err(Error::<T>::InvalidCommitment.into())
        }
    }
}

fn verify_contract_signature<T: Config>(
    commit: &Commit<Vec<u8>>,
    signature: &<T::PhatContractId as RuntimeAppPublic>::Signature,
) -> Result<(), Error<T>> {
    let phat_contract_id = PhatContract::<T>::get();
    if let Some(phat_key) = phat_contract_id {
        let signature_valid =
            commit.using_encoded(|encoded_commit| phat_key.verify(&encoded_commit, signature));

        if !signature_valid {
            return Err(Error::<T>::InvalidSignature.into());
        }

        Ok(())
    } else {
        Err(Error::<T>::PhatContractNotInititialized.into())
    }
}

impl<T: Config> Commitment<EncryptedData, Vec<u8>> for Pallet<T> {
    /// Commits an encrypted SCALE encoded value using AES-GCM 256 associated to the metadata.
    /// It contains the authenticated and encrypted version of the plaintext.
    fn commit(value: Commit<Vec<u8>>) -> Result<(), CommitRevealError> {
        let commit_id = value.get_id();
        if let Some(_) = PhatContractCommitment::<T>::get(&commit_id) {
            // commitment with the given id already exists
            Err(CommitRevealError::AlreadyCommitted)
        } else {
            let (commit, iv) = value.get_commitment();
            let metadata = value.get_metadata();
            let commitment = TiSparkCommitment::new(commit, &iv, metadata)
                .map_err(|_| CommitRevealError::CommitError)?;
            // Insert new commitment into storage
            PhatContractCommitment::<T>::insert(&commit_id, commitment);

            Ok(())
        }
    }

    /// Provides the AES-GCM key as a proof for the commitment, that serves to reveal the encoded bet result.
    fn reveal(proof: RevealProof) -> Result<Reveal, CommitRevealError> {
        if proof.secret.len() as u32 != T::KeyBytes::get() {
            return Err(CommitRevealError::DecryptionRejected);
        }

        let commit_id = proof.commit_id;
        if let Some(mut commitment) = PhatContractCommitment::<T>::get(&commit_id) {
            if !commitment.has_proof() {
                let decrypted = DecryptedData::new(
                    proof.secret.clone(),
                    commitment.get_iv(),
                    commitment.get_data(),
                )
                .decrypt()?;

                let mut key = proof.secret;
                commitment.set_proof(&mut key).expect(
                    "The proof is expected to be valid 
                            (decryption: Ok, length: Ok, fresh proof: Ok)",
                );

                // insert the commitment with the updated proof
                PhatContractCommitment::<T>::insert(commit_id, commitment);

                Ok(decrypted)
            } else {
                Err(CommitRevealError::AlreadyRevealed)
            }
        } else {
            Err(CommitRevealError::InvalidCommitForReveal)
        }
    }
}

// Phat Contract key
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"pht0");

mod app {
    use sp_application_crypto::{app_crypto, sr25519};
    app_crypto!(sr25519, super::KEY_TYPE);
}

sp_application_crypto::with_pair! {
    #[warn(dead_code)]
    pub type AuthorityPair = app::Pair;
}

pub type PhatSignature = app::Signature;
pub type PhatId = app::Public;