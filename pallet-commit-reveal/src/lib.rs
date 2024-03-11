#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::pallet_prelude::*;
pub use pallet::*;
use primitives::commit_reveal::{Commit, RevealProof};
use sp_std::vec::Vec;
use types::TiSparkManager;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    pub use crate::types::{CommitmentRequest, PhatContractOf};
    use frame_system::pallet_prelude::*;
    use primitives::commit_reveal::CommitId;
    use sp_application_crypto::RuntimeAppPublic;
    use types::TiSparkCommitment;

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        // The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The identifier type for the Phat Contract.
        type PhatContractId: Parameter
            + RuntimeAppPublic
            + Ord
            + MaybeSerializeDeserialize
            + MaxEncodedLen;

        /// The maximum length for the commitment
        #[pallet::constant]
        type MaxCommitmentSize: Get<u32>;

        /// The maximum length for the encoded metadata
        #[pallet::constant]
        type MaxMetadataSize: Get<u32>;

        /// The length of the chipher key
        #[pallet::constant]
        type KeyBytes: Get<u32>;

        /// The length of the initialization vector
        #[pallet::constant]
        type IVLen: Get<u32>;

        type CommitMetadata: Parameter + MaxEncodedLen;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A bet has been commited
        ValueCommitted {
            id: CommitId,
            metadata: T::CommitMetadata,
            storage_key: Vec<u8>,
        },
        /// A commitment proof has been provided
        CommitRevealed {
            proof: Vec<u8>,
            reveal: Vec<u8>,
            commit: CommitId,
        },
        /// New Phat Contract public key,
        NewPhatContractKey { contract_id: PhatContractOf<T> },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Wrong Phat Contract signature
        InvalidSignature,
        /// Invalid Commitment
        InvalidCommitment,
        /// Invalid proof (decryption rejected)
        InvalidProof,
        /// Phat Contract key not set
        PhatContractNotInititialized,
        /// Invalid Length
        InvalidBytesLength,
        /// Decode MetadataError
        DecodingMetadataError,
    }

    #[pallet::storage]
    #[pallet::getter(fn phat_contract)]
    pub type PhatContract<T: Config> = StorageValue<_, PhatContractOf<T>, OptionQuery>;

    /// Commitment of a particular commit hash
    ///
    /// TWOX-NOTE: SAFE as `CommitId`s are crypto hashes anyway.
    #[pallet::storage]
    #[pallet::getter(fn commitment)]
    pub type PhatContractCommitment<T: Config> = StorageMap<
        _,
        Twox64Concat,
        CommitId,
        TiSparkCommitment<T::MaxCommitmentSize, T::IVLen, T::KeyBytes, T::MaxMetadataSize>,
        OptionQuery,
    >;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000, 0) + T::DbWeight::get().reads_writes(2, 1))]
        pub fn send_commitment(
            origin: OriginFor<T>,
            commit: Commit<T::CommitMetadata>,
            signature: <T::PhatContractId as RuntimeAppPublic>::Signature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // construct commitment request
            let request = CommitmentRequest { commit, signature };

            Ok(Self::commit_from_request(request)?)
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(500_00, 0) + T::DbWeight::get().reads_writes(1, 1))]
        pub fn send_proof(origin: OriginFor<T>, proof: RevealProof) -> DispatchResult {
            ensure_signed(origin)?;

            Ok(Self::reveal_from_proof(proof)?)
        }

        /// ## Complexity:
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().writes(1))]
        pub fn set_phat_contract_key(
            origin: OriginFor<T>,
            key: PhatContractOf<T>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            PhatContract::<T>::put(&key);
            Self::deposit_event(Event::NewPhatContractKey { contract_id: key });
            Ok(())
        }
    }
}

pub mod impls;
pub mod types;
