#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod mocks;
pub mod tispark_client_ref;
mod traits;
mod types;

pub use traits::*;
pub use types::*;

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod tispark_client {
    use super::pink;
    use crate::{
        consensus,
        state::{self, CommitmentStateDecoder},
        traits::CommitRevealContractManager,
        types::{
            commitment::{ContractCommitment, ContractCommitmentBuilder},
            message::{
                CommitmentRequest, ContractPubKey, ContractSecretKey, RevealResponse,
                RevealResultRequest,
            },
            ContractError, ContractResult, VersionNumber, Versioned,
        },
        ContractServiceId, ServiceId,
    };
    use alloc::vec::Vec;
    use ink::storage::{Lazy, Mapping};
    use pink::PinkEnvironment;
    use scale::Encode;
    use tispark_primitives::commit_reveal::{CommitRevealManager, DecryptedData, QueryMetadata};
    use utils::{
        types::{AccessControl, AuthorityId, ContracId, SudoAccount},
        ContractRef as ConsensusClientRef,
    };

    #[ink(storage)]
    pub struct TiSparkClient {
        /// Ed25519 secret and public key for signing and verifying
        sign_material: Lazy<SigningMaterial>,
        /// Raw secret to compute the AES-GCM secret
        commitment_key: Lazy<CommitmentKey>,
        /// Contract reference of the consensus client
        consensus_client: ConsensusClientRef,
        /// Sudo account for emergency operations
        sudo: SudoAccount,
        /// Registered services
        services: Mapping<ServiceId, ContractServiceId>,
    }

    #[derive(Encode)]
    #[ink::storage_item]
    pub enum KeyVersionInfo {
        Signature(VersionNumber),
        Commitment(VersionNumber),
    }

    #[derive(Encode)]
    #[ink::storage_item]
    pub struct KeyringVersion(pub KeyVersionInfo);

    #[ink::storage_item]
    struct CommitmentKey {
        key: ContractSecretKey,
        version: KeyringVersion,
    }

    #[ink::storage_item]
    struct SigningMaterial {
        secret_key: ContractSecretKey,
        pub_key: ContractPubKey,
        version: KeyringVersion,
    }

    #[derive(Debug)]
    #[ink::storage_item]
    pub struct ConsensusAuthorities {
        authorities: Vec<AuthorityId>,
        next_authorities: Option<Vec<AuthorityId>>,
    }

    impl TiSparkClient {
        #[ink(constructor)]
        pub fn new(consensus_client_id: ContracId) -> Self {
            // contract keyring material to sign and verify messages.
            let (version, secret_key, pub_key) =
                KeyringVersion::build_keyring_material(Versioned::Signing);

            let mut sign_material = Lazy::new();
            sign_material.set(&SigningMaterial {
                secret_key,
                pub_key,
                version,
            });

            // contract keyring material to produce commitments
            let (version, key, _) = KeyringVersion::build_keyring_material(Versioned::Commitment);

            let mut commitment_key = Lazy::new();
            commitment_key.set(&CommitmentKey { key, version });

            // Set sudo account for initializing later on the consensus client authorities
            // It can be removed at later stages for a permissionless setting
            let sudo = pink::env().caller();
            let sudo = SudoAccount::new(Some(sudo));

            let services = Mapping::new();

            Self {
                sign_material,
                commitment_key,
                consensus_client: ConsensusClientRef::new(consensus_client_id),
                sudo,
                services,
            }
        }

        fn signing_material(&self) -> SigningMaterial {
            self.sign_material
                .get()
                .expect("The key is expected to be initialized")
        }

        fn commitment_key(&self) -> CommitmentKey {
            self.commitment_key
                .get()
                .expect("The commitment key is expected to be initilized")
        }

        #[ink(message)]
        pub fn get_pub_key(&self) -> Vec<u8> {
            self.signing_material().pub_key
        }

        #[ink(message)]
        pub fn register_service(
            &mut self,
            service: ServiceId,
            contract: ContractServiceId,
        ) -> ContractResult<()> {
            self.ensure_owner()?;

            if self.ensure_service_exists(service).is_err() {
                self.services.insert(service, &contract);
                Ok(())
            } else {
                Err(ContractError::GameAlreadyExists)
            }
        }

        fn ensure_owner(&self) -> ContractResult<()> {
            AccessControl::new(self.sudo.get())
                .caller(pink::env().caller())
                .verify()
                .map_err(|_| ContractError::BadOrigin)
        }

        fn ensure_service_contract(&self, service: ServiceId) -> ContractResult<()> {
            let contract = self.ensure_service_exists(service)?;

            AccessControl::new(Some(contract))
                .caller(pink::env().caller())
                .verify()
                .map_err(|_| ContractError::BadOrigin)
        }

        fn ensure_service_exists(&self, service: ServiceId) -> ContractResult<ContractServiceId> {
            if let Some(id) = self.services.get(service) {
                Ok(id)
            } else {
                Err(ContractError::InvalidGame)
            }
        }
    }

    impl CommitRevealContractManager for TiSparkClient {
        /// Updates the key material used for key derivation
        #[ink(message)]
        fn update_keyring_material(&mut self) -> ContractResult<()> {
            self.ensure_owner()?;

            let (new_signing, secret_key, pub_key) = self.signing_material().version.increment();
            let (new_commit_key, key, _) = self.commitment_key().version.increment();

            let signing_material = SigningMaterial {
                secret_key,
                pub_key,
                version: new_signing,
            };
            self.sign_material.set(&signing_material);

            let commitment_key = CommitmentKey {
                key,
                version: new_commit_key,
            };
            self.commitment_key.set(&commitment_key);

            Ok(())
        }

        #[ink(message)]
        fn commit(&self, request: CommitmentRequest) -> ContractResult<ContractCommitment> {
            self.ensure_service_contract(request.get_service())?;

            // Get the commitment key used for deriving an AES-GCM 256 encryption key based on some nonce metadata
            let commitment_key = self.commitment_key();

            let (encoded_result, metadata) = request.get();

            let query = QueryMetadata::new(
                self.env().block_number(),
                self.env().block_timestamp(),
                metadata,
            );

            // Retrieve the commitment
            let commitment = CommitRevealManager::setup(&commitment_key.key, query)
                .map_err(|_| ContractError::CommitmentKeyDerivationError)?
                .inject(encoded_result)
                .commit()
                .map_err(|_| ContractError::CommitmentEncryptionError)?;

            // Build a commitment signed with the contract signing material
            let secret = self.signing_material().secret_key;

            let commitment = ContractCommitmentBuilder::default()
                .key(secret)
                .commitment(commitment)
                .build();

            Ok(commitment)
        }

        #[ink(message)]
        fn reveal(&self, request: RevealResultRequest) -> ContractResult<RevealResponse> {
            // Verify the consensus proof
            consensus::verify_consensus(&self.consensus_client, request.proof())
                .map_err(|_| ContractError::InvalidConsensusProof)?;

            // Verify a (key, value) pair within a state proof and a state commitment (state root hash)
            // The state commitment has been validated through the consensus state proof that includes the state root hash
            let res = state::verify_state(&self.consensus_client, request.response())
                .map_err(|_| ContractError::ConsensusClientInvalidStateProof)?;
            let res = CommitmentStateDecoder::decode(res)?;

            let commitment_key = self.commitment_key();

            let reveal_proof = CommitRevealManager::reveal(&commitment_key.key, request.commmit())
                .expect("The key derivation is expected to work in the reveal phase");

            // Reveal the value as well, it is not essential, since it is also performed on the conuterpary chain.
            // It is an additional overhead in terms of computation, but it gains performances for actors that want a quick reveal.
            let reveal_value = DecryptedData::new(
                reveal_proof.secret.clone(),
                res.nonce().to_vec(),
                res.value().to_vec(),
            )
            .decrypt()
            .expect("The decryption in the reveal phase is expected to succeed");

            Ok(RevealResponse::new(reveal_value, reveal_proof))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            mocks::env_mocks::{MockAccount, MockAuthorities, MockVecFromHex, PhatContractEnv},
            types::message::{
                ConsensusProofParams, ConsensusStateParams, StateRequestMetadata,
                StorageProofParams,
            },
        };
        use casino_types::{Bet, BetResult, CommitMetadata, GameRandom, Randomness};
        use ink::primitives::AccountId;

        fn init_contract_with_randomness() -> (AccountId, TiSparkClient) {
            (
                PhatContractEnv::setup_with_randomness(),
                TiSparkClient::new(),
            )
        }

        fn init_contract_no_randomness() -> (AccountId, TiSparkClient) {
            (PhatContractEnv::setup_no_randomness(), TiSparkClient::new())
        }

        #[ink::test]
        pub fn commit_bet_test() {
            let (_, contract) = init_contract_no_randomness();
            PhatContractEnv::setup_randomness_generation();

            let encoded_result = [0_u8; 8];
            let encoded_meta = [1_u8; 4];

            let request = CommitmentRequest::new(encoded_result.to_vec(), encoded_meta.to_vec(), 0);

            assert!(contract.commit(request).is_ok())
        }

        #[ink::test]
        fn reveal_commitment_test() {
            // Setup Mocked Environment ans Setup Contract
            let (_, mut contract) = init_contract_no_randomness();
            // Construct an authority set for the permissioned setting within the light client
            let authorities = MockAuthorities::mock_default();
            let _ = contract.initialize_permissioned_authorities(authorities.clone());
            assert_eq!(Some(authorities.clone()), contract.authorities());

            // Construct metadata
            let meta = StateRequestMetadata {
                commit_metadata: CommitMetadata::new(MockAccount::mock_default(), 100, 0),
                timestamp: 1234,
                height: 304_885,
            };

            let storage_proof = StorageProofParams {
                key: MockVecFromHex::new("a45f7230932fe9d5ebc846b873ecd53fe2b963432ae550772daa14b5f8e6e397de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d02275af68f420058e579324a409319b96400000011d2df4e979aa105cf552e9544ebd2b500000000"),
                proof: vec![
                    MockVecFromHex::new("7f1002275af68f420058e579324a409319b96400000011d2df4e979aa105cf552e9544ebd2b5000000000d01608f0df8df7bc5b572258d456db9ea587d90d3ba23395f3655a0d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d640000000000000000"),
                    MockVecFromHex::new("80edbd80bc98dd1d29f3a1bed136d6fe0cc392f2eb861d0baef352c7219536e5067bbc8380ebab11da8426498d748f63521e29364fdc00c0563f6e5b53ab4de88ac2cef4a58082710e483f27c7a6f68ed4cedac6e7c8e12869827b449638cbbbd5d61db03ff9801ec17de431d6e9271f53767e9d8cee3b3032bab824aa4e73df9a8492351e480d802964c1821f17b5041a744ddd8e595da6e78a7fd3babf8da8179a45591d81c44e80de99597d634101598b810da926b013512bb2edc1c119e03c675313d64094a6ae8075d92bb5f4fb9cb761490c74718377d834ca1b45aa2592513fa56bc0a05cd4e280ad80e7b0f6f979ad343b388fb214c9b89fc09e3d4701db3ccc0c77893baf7250804a4201f283bd957526a3e369451aa77a2cac4ed172568a1f4df0b7422c548f2b80adc34f520160f5c5601bcf56f8de318c3859d352da3803b880cce87c8381212a803fc419a4112ebb0e5127883554600ca543087ebc5dc72c56938e4a26640bec478050f85862a68a522494996024ccbc1b192bc8c05daeb4c4b56c7f718f60427d13"),
                    MockVecFromHex::new("9f045f7230932fe9d5ebc846b873ecd53f5048505f0e7b9012096b41c4eb3aaf947f6ea4290801008032fa53f483093daf1c3d5300698dfa9c81a6a2ca44656c61c49215de76e214d1805a926c67ec587d559d6a5a39c185881d60730b735597cc2935b6a986929c16f1800b697ca3a3110d2f53c9c0eb2717ad2f046b511b03f738527ea84e9f7d4abd22"),
                    MockVecFromHex::new("bf4002b963432ae550772daa14b5f8e6e397de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d070080ba74cb8c48ab8dd2b8f0096c35fd0f757413d31317aba723d7825501ca7e03d680d0cf0cc30bad0297c23ebb1b964bc7756ff2222443f4516adac0954f13df9a05807e1be42eef102a36c1166a22c2be57319be6e45a305395ec7f82313c8301b3ce"),
                ],
            };

            let consensus_proof = ConsensusProofParams {
                justification: MockVecFromHex::new("0300c600001001f35260453241a2ac703e912cc60545ee5fdafde1a79fa89cc92ace4128d6f3f0868b573d2d4c5dc94fcbfdacda8e87fd78b4e44276ff9c1c14196d2bcdc26603014c20d8dbfa488d6ac3da184d2e2888dfe147e9c6dd7d33765f6672b9f8d4f5d9f3c88c8af530c9f906dc2bc60bed8f9d994b9d9ab629fa473d15174778b71e0b000189dfe3bcc5c7547e415ea749f8ce880f87237e5377a7706d0e0e7e088c0a8365118e1c06180b525810a85718790f903c8cd980aa7cd25a1b6677de3bdbe6e90d"),
                consensus_state: ConsensusStateParams {
                    block: 307_307,
                    extrinsics_root: String::from("ada6ee42df16f0b3dc5633427ab90e85b21d1ba6109e4eef04df30862abe985f"),
                    state_root: String::from("90a1d9368fb40118cd6fb3bdb50209a657f488b2549fc3923889b87a7cb7ef5e"),
                    parent_hash: String::from("9a2e8f9f2c48a6769a0dfd82dde05fbb3f3bfb7d10a45d6b66d8ef37211cff60"),
                    aura_pre_runtime: String::from("d0642ee100000000"),
                    seal: String::from("6015fb0486e8b49581cbd45597990e76d386f7a33b5ba56d550c5828ab497e1a0883ecdb767629b065aeceb6444e7f4b3a26e00f155f7a3d0b2bfeb2d8652b84"),
                },
                untrusted_authorites: vec![
                    MockAccount::mock_authority("3249022c8a9b4ae72ed728147e29fc14c754a0fb7786f47a99eb7ec669a8c652"),
                    MockAccount::mock_authority("2934bd176f5d496b43e4723a0b31a94ea86669cbd290f5ac76aca05e48f4665e"),
                    MockAccount::mock_authority("ab0b60bddfc21290edfc61d42e77448bdcbfa6820217716ba96f4059a98c4d15"),
                    MockAccount::mock_authority("fdfad0e10a84e09963b47225bc3de363a1273c722a84bc5f7af34c9440b73dbe"),
                    ],
            };
            let reveal_request = ResponseStateProofRequest {
                meta,
                storage_proof,
                consensus_proof,
            };

            assert!(contract.reveal(reveal_request).is_ok())
        }
    }
}
