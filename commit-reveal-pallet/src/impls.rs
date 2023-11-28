use crate::{
    types::{CommitmentRequest, TiSparkCommitment, TiSparkManager},
    Config, Error, Event, Pallet, PhatContract, PhatContractCommitment,
};
use parity_scale_codec::Encode;
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
        let phat_contract_id = PhatContract::<T>::get();
        if let Some(phat_key) = phat_contract_id {
            let signature_valid = request.commit.using_encoded(|encoded_commit| {
                phat_key.verify(&encoded_commit, &request.signature)
            });

            if !signature_valid {
                return Err(Error::<T>::InvalidSignature.into());
            }

            let metadata = request.commit.get_metadata();
            let commit_id = request.commit.get_id();

            Self::commit(request.commit).map_err(|_| Error::<T>::InvalidCommitment)?;

            let storage_key = Self::commitment_storage_key_for(&commit_id);
            Self::deposit_event(Event::ValueCommitted {
                id: commit_id,
                metadata,
                storage_key,
            });

            Ok(())
        } else {
            Err(Error::<T>::PhatContractNotInititialized.into())
        }
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
}

impl<T: Config> Commitment<EncryptedData, T::CommitMetadata> for Pallet<T> {
    /// Commits an encrypted SCALE encoded value using AES-GCM 256 associated to the metadata.
    /// It contains the authenticated and encrypted version of the plaintext.
    fn commit(value: Commit<T::CommitMetadata>) -> Result<(), CommitRevealError> {
        let commit_id = value.get_id();
        if let Some(_) = PhatContractCommitment::<T>::get(&commit_id) {
            // commitment with the given id already exists
            Err(CommitRevealError::AlreadyCommitted)
        } else {
            let (commit, iv) = value.get_commitment();
            let commitment =
                TiSparkCommitment::new(commit, &iv).map_err(|_| CommitRevealError::CommitError)?;
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
