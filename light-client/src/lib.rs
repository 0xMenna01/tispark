#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use finality::types::NodeIndex;
use ink_env::hash::{Blake2x256 as InkBlakeTwo256, CryptoHash, Keccak256 as InkKeccak256};
use sp_core::Hasher;
use sp_runtime::{
    generic,
    traits::{BlakeTwo256, Header as HeaderT},
};
pub use state::GetCommitmentResponseProof;
pub use state::GetResponse;

// Remember to make all these not public and only expose what is needed
pub mod consensus;
pub mod finality;
pub mod state;

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AccountId([u8; 32]);

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type BlockHash = <Header as HeaderT>::Hash;

pub type BlockNumber = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

#[derive(Debug, PartialEq)]
pub enum StateProofError {
    StateVerifyError,
    DecodeError,
    InvalidKeysError,
    MissingValueError,
    FirstKeyValueError,
    InvalidCommitId,
}

#[derive(Debug)]
pub enum ConsensusError {
    InvalidAuthorities,
    MissingAuthorityKey,
    InvalidSignature,
    InvalidAlephLogPreRuntime,
    InvalidAlephLogSeal,
}
pub trait Proof: 'static + Send + Sync + Sized + Clone + Eq + PartialEq + core::hash::Hash {}

pub trait ConsensusClient {
    type ConsensusProof: Proof;

    /// Verifies a consensus state. It proves that the Blockchain has reached a certain height through a consensus proof.
    fn verify_consensus(
        &self,
        consensus_state: Hash,
        proof: Self::ConsensusProof,
    ) -> Result<Vec<NodeIndex>, ConsensusError>;
}

pub type FinalityVersion = u32;

pub type SessionIndex = u32;

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct VersionChange {
    pub incoming: FinalityVersion,
    pub session: SessionIndex,
}

pub trait GetSingleState {
    type Keccac: Hasher;
    type Blake2: Hasher;
    /// Verifies wheteher the state that needs to be verified is associated to a single (key, value) pair
    fn verify_key_uniquness(&self) -> bool;

    /// Verifies the actual state through the Trie
    fn verify_state(&self) -> Result<Vec<u8>, StateProofError>;
}

/// Custom hash implementations to be compatible with ink! smart contracts
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractKeccak256;

impl Hasher for ContractKeccak256 {
    type Out = sp_core::H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(s: &[u8]) -> Self::Out {
        let mut output = [0_u8; Self::LENGTH];
        InkKeccak256::hash(s, &mut output);
        output.into()
    }
}

/// Custom hash implementations to be compatible with ink! smart contracts
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ContractBlakeTwo256;

impl Hasher for ContractBlakeTwo256 {
    type Out = sp_core::H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(s: &[u8]) -> Self::Out {
        let mut output = [0_u8; Self::LENGTH];
        InkBlakeTwo256::hash(s, &mut output);
        output.into()
    }
}

#[cfg(test)]

mod test {

    use codec::Encode;
    use hex::FromHex;
    use primitives::state_proofs::{
        GetResponseProof, HashAlgorithm, Proof, StateCommitment, SubstrateStateProof,
    };

    use crate::{
        consensus::{AlephConsensusLogBuilder, PhatContractConsensusClient},
        finality::{
            crypto::{verify, AuthorityId, AuthoritySignature},
            justification,
        },
        state::GetResponse,
        BlockHash, ConsensusClient, GetSingleState, Hash,
    };
    use pink_extension::chain_extension::mock as pink_mock;

    #[test]
    fn verify_consensus() {
        pink_mock::mock_verify(|_, pubkey, msg, sign| {
            let auth_public =
                AuthorityId::try_from(pubkey).expect("Expected to be a valid public key");
            let signature = AuthoritySignature::try_from(sign).expect("Expected a valid signature");
            verify(&auth_public, msg, &signature.into())
        });

        // Data has been taken directly from the Chain
        let authorities = vec![
            "a824108d28376dea1ef85f14a8bd52e4448429c3ac09572b6e1dc324fbbdbd07",
            "ed0d45bd4a5c55e3c1855187ac903700d7f642c46561ce4466d6d4eef2c4dbbc",
            "7a46880947ce98d4379d0bedd793f4a99ee6cd3710b10196d9a094abed234378",
            "e852b5b72299153d1f61b4a4bf7f28474ae8fa3d030d98b6bcb53b8e5931e638",
        ];
        let sudo =
            Vec::from_hex("38fdbe98bb40723c9243f115b0684791f37fc92222640c478abd91e1ed48a4ee")
                .unwrap();
        let emergency_finalizer = AuthorityId::try_from(sudo.as_slice()).unwrap();

        let justifications = Vec::from_hex("0300c600001001cfa3a97cb0c48578c61884e1180975d63e70faaeeab3f9418cca164a296682c43236cb0af04dfdaa23fa72b913a5f4acdb7785c79eb5455536454f23a0602a0a000153ceebaa19d1b60622532c3d6f68737321138f88cac38af758f14ae58f29f84aabc2140261ac9150b92f9d9bc5d47621da258fd9d186b040e3c3f90e4b93830c017b159a6d634ee44a20442c875234061026ce6418f5512be9d2dbb0db707568955d536e3d7d20d79d39afcb37f4aa3ff54f31d5c5bcb2eeb39aefb652b1fa7801").unwrap();

        let justification = justification::backwards_compatible_decode(justifications).unwrap();

        let mut authority_keys = Vec::new();
        authorities.into_iter().for_each(|key| {
            let pub_key = Vec::from_hex(&key).unwrap();
            authority_keys.push(AuthorityId::try_from(pub_key.as_slice()).unwrap())
        });

        let consensus_client =
            PhatContractConsensusClient::new(authority_keys.clone(), emergency_finalizer.clone());

        match justification {
            justification::AlephJustification::CommitteeMultisignature(signatures) => {
                let block_number: u32 = 81_943;
                let extriniscs_root = Vec::from_hex(
                    "53cec44cdabc023175d84f55e4f42255419c67f87ae864d59a07b4c303560775",
                )
                .unwrap();
                let extriniscs_root = Hash::from_slice(&extriniscs_root);
                let state_root = Vec::from_hex(
                    "c312a0d65ee784da8dc7fbd7abb4ada9a3affe8e14415484d56b4f5642c123c2",
                )
                .unwrap();
                let state_root = Hash::from_slice(&state_root);
                let parent_hash = Vec::from_hex(
                    "79bfc3089355ae580d473a339935deeffab2f5a07a3d880aa253d6d4b212341a",
                )
                .unwrap();
                let parent_hash = Hash::from_slice(&parent_hash);

                let digest = AlephConsensusLogBuilder::logs("b98026e100000000", "0ada5463c19e7a08495dc58decd5a4693e40c44c2f3bcea152b189ac4382c24e3bfed0fae1e88c9a295f70f434bae198d5d6928d309625faa773aab63133ed89").unwrap().build();

                let consensus_state = consensus_client.build_consenus_state(
                    block_number,
                    extriniscs_root,
                    state_root,
                    parent_hash,
                    digest,
                );

                let nodes_verify = consensus_client.verify_consensus(consensus_state, signatures);

                if nodes_verify.is_ok() {
                    assert!(true)
                } else {
                    assert!(false)
                }
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn verify_state() {
        let state_root =
            Vec::from_hex("48ad5b198c2750f37b4067360da4636947d1ed48c65ad3a3b21e33daac957865")
                .unwrap();
        let state_root = BlockHash::from_slice(&state_root);

        let dummy_timestamp = 123456789;

        let storage_proof = vec![Vec::from_hex("5f030ebca703c85910e7164cb7d1c9e47b80025342a214a9c91f13135ccd686a047c7efee5ef4c34e1859051bf83dd9e1428").unwrap(), 
        Vec::from_hex("80809180b0fc4f8982c04cf4ff94444ded8cafa62bf35ceef1edc448d76a4f14351bb51780a6a6777fbe4ba8aed68dc6c1c71453e3c83636df239621bf967e0e35c651275580dfee03ced33eb959c00afa96f46c230bc1ea27102268f0c345937041070efb7a803eef802c531a2e5a05649bd12ae0283fe97c6e4ceb3af6dda147e42fdb48e179").unwrap(),
        Vec::from_hex("80bdb98048920e65e43b3e207c7a87879da5786a52dbcc4f12bb529bd5ad3a40427cdd998047ff6c763c2b0c08e570bafa47077407d332acda41bbbad9dcd5036712cdb456800f1dd84d371a63b592c096b9d9dcd0b795d6c168f14e36b650ef3a227d1ed7ca809496b5b0492db5ad94734ee4d269495f4901d2b8f5bf7a4b0a31d2a5e68e703f80427524c00b9fb63d6a85f6068123425c121fbc6d640c89dd2a01d326b5acbb48807cf9e9a2267f028b3b7c85033101fbe3af8abc8ccd0c19d93179a7e2b5d1a647806f4f2a8981de1c8b077af2e7962ceee5d73825e2e866d394c70650af4dd3f27280a07c157695ad8163c4434f16989b6b924cd895a3d3e551a81554b08dd80851658014ec95c09a545e281a2823d77874166da16751a5c97546a4f9936cc3bd4263c5804349a8554a46fe561c9367a3cae14092fb5535b942063755aff446d630f44d0c8044f9d43b39ef82e076cae4f255a92060ab8907bd478090b7f6ab7e36a736b574").unwrap(),
        Vec::from_hex("9e0d1176a568c1f92944340dbfed9e9c3000505f0e7b9012096b41c4eb3aaf947f6ea429080000807beb14548ee4710dc017ac798af16316362d24bb7041c725ee358f4d72743b8e").unwrap(),
        ];

        let proof = SubstrateStateProof {
            hasher: HashAlgorithm::Blake2,
            storage_proof,
        }
        .encode();

        let proof = Proof {
            height: 61_549_453,
            proof,
        };

        let root = StateCommitment {
            timestamp: dummy_timestamp,
            state_root,
        };

        let keys =
            vec![
                Vec::from_hex("5c0d1176a568c1f92944340dbfed9e9c530ebca703c85910e7164cb7d1c9e47b")
                    .unwrap(),
            ];

        let response_proof = GetResponseProof::new(&keys, &root, &proof);

        let get_response = GetResponse(response_proof);

        assert_eq!(
            get_response.verify_state(),
            Ok(
                Vec::from_hex("025342a214a9c91f13135ccd686a047c7efee5ef4c34e1859051bf83dd9e1428")
                    .unwrap()
            )
        )
    }
}
