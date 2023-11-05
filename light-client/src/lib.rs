use aleph_bft_crypto::NodeIndex;
use scale::{Decode, Encode};
#[cfg(feature = "std")]
use scale_info::{prelude::fmt::Debug, TypeInfo};
use sp_runtime::{
    generic,
    traits::{BlakeTwo256, HashOutput, Header as HeaderT},
};
pub use state::GetCommitmentResponseProof;
pub use state::GetResponse;

// Remember to make all these not public and only expose what is needed
pub mod consensus;
pub mod finality;
pub mod state;

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, TypeInfo)]
pub struct AccountId([u8; 32]);

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type BlockHash = <Header as HeaderT>::Hash;
pub type StateRootHash = <Header as HeaderT>::Hash;
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
pub trait Proof:
    'static + Send + Sync + Sized + Clone + Eq + PartialEq + Debug + core::hash::Hash
{
}

pub trait ConsensusClient {
    type ConsensusState: HashOutput;
    type ConsensusProof: Proof;

    /// Verifies a consensus state. It proves that the Blockchain has reached a certain height through a consensus proof.
    fn verify_consensus(
        &self,
        consensus_state: Self::ConsensusState,
        proof: Self::ConsensusProof,
    ) -> Result<Vec<NodeIndex>, ConsensusError>;
}

pub type FinalityVersion = u32;

pub type SessionIndex = u32;

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, TypeInfo)]
pub struct VersionChange {
    pub incoming: FinalityVersion,
    pub session: SessionIndex,
}

pub trait GetSingleState {
    /// Verifies wheteher the state that needs to be verified is associated to a single (key, value) pair
    fn verify_key_uniquness(&self) -> bool;

    /// Verifies the actual state through the Trie
    fn verify_state(&self) -> Result<Vec<u8>, StateProofError>;
}

#[cfg(test)]

mod test {

    use hex::FromHex;
    use ismp::consensus::StateCommitment;
    use primitives::phala_ismp::{GetResponseProof, HashAlgorithm, Proof, SubstrateStateProof};
    use scale::Encode;

    use crate::{
        consensus::{AlephConsensusClient, AlephConsensusLogBuilder},
        finality::{crypto::AuthorityId, justification},
        state::GetResponse,
        BlockHash, ConsensusClient, GetSingleState, Hash,
    };

    #[test]
    fn verify_consensus() {
        // Data has been taken directly from the Chain
        let authorities = vec![
            "3051fd3d9488aaeb5fdb2236841fb9332eae7a5dab2e33923ae29db71564242a",
            "bc16685f99c1ebfbaeb0bb1b1f6b81f078977cfb5418c4e125b8a989817d9fcf",
            "8f725daf2944ef12357e298058c317a409d313d5379fee88abddd2967b0c02da",
            "ce10aee99d0cfd087566ab79a09d7b9b6f2ede52b6014468d79cb52d484c1584",
            "1351b4a63b101aa06bce0c9336823dc35186b95105e629a1e8adffb79a23b3ec",
            "def643f576925be43e4e6f139c6d6787b3da8f637a3d29fef01ccaf24d82259e",
            "55f42ea5496bd242dc59f3a299ebc4f3ad6ea1b47b745abdda2b3a6129cf0afe",
            "749e7ca3ff95b3c92608500525f33071cd2ce4e592ba9535a6eb7bac1b667faa",
            "4e9800a7078b680ba72b0f077d6803c3d35ccdcba15b618542801a5cdf5c949b",
            "3e1f808aba722e8c2b605186d525330fc0602448aa1a0e4095db3e691e82aa53",
            "30b1f36452a50aefec9618c9f44ff10e9927a2f3dfafcd6851437bba6bd58d4e",
            "37371d98a2d7d88096414e55e861e06a07ba7645c49d446cc5e414bb3c00d456",
            "8e6efcceba526685383b74cc53eb09f8fe2e6bcb9988e2bc618ead55251f7e97",
            "c86669783d7c1c1516dd7bd70dcc893232c9a73b4e1095557ef3a929d324904a",
        ];
        let sudo =
            Vec::from_hex("38fdbe98bb40723c9243f115b0684791f37fc92222640c478abd91e1ed48a4ee")
                .unwrap();
        let emergency_finalizer = AuthorityId::try_from(sudo.as_slice()).unwrap();

        let justifications = Vec::from_hex("030090020038018254511e985c7bfcef723ef46ca033610ac5ddab70e96270fd412d9755ff3ac32a17f27defa04f23223a6c94830f3b00104b7d9642fccfddc59107e837d7a60001420b897a82cea8fe3115238c690a1484e809593cd02058efb03f5d9fd8a70545775e1e3767912ce630cf69031504f433beaeb0bc0318b071391c9999582be7020153a97ac8511d3170e9e4aa45b96e1a564d607ffa76b8c2bd13f895d6812c5c599d5ec53f9dc285a5bc57afd479d81e21369e993feae316b8f7050df154c4b8010000010145131dbb53b971cfcf114595878c5971741dee55641c323ef0fa2659bf2ddf215c1d7d67a1a6fcee2d0d884830b0410a9b4cfcbb7f884259953c5792cce40101f45d3983eff551ffcd234abdf6a4b1f0229876367a42625d50ac61373aaaf3ef10e13ea85664042136e6a09b6147c56f7ab6fa650c7d26f76884d7d2220b8a0a01990bed6dabb3304486583e3de4548cb39759bc05f9a6660e6b253cdc0217b26f0944d924b39e5d17f047263969b5c357f0ba4d36676136fba413cfefc5210e09000183cd0344b8b1f8d8ba8f52f98a27a6f706c87656b7eb9bb857f6ecbe2f1485fed6a1bccc593d6d31a689d17d748ccbbfbdeae15f50bc729f7b45b14fe62233060164d5822652a4970ab9b7402be0ac74e2d6bc6a3e5a55262e15629f8618882fcbec070b317614e2cfc751bd516f38cbad33733d56b67569dc3c5e1f23eaa7c40200014edffa7e3c0749edbff2955cc48cdf89bff067a8d5cf690496347a6285c1fcbe98576af1781d5daa81bd626a23cffb3bfc69920a58120dc68773eed2af38680c016cfc7cba906de4bef7d86961ebe4ff7ec20a53b6ad9f5174f9bb8bfa89adf3e4bea28946917bd4eeb76d57488279bcbd8ec5c8d3e21fffb2fc9c48efa0604005").unwrap();

        let justification = justification::backwards_compatible_decode(justifications).unwrap();

        let mut authority_keys = Vec::new();
        authorities.into_iter().for_each(|key| {
            let pub_key = Vec::from_hex(&key).unwrap();
            authority_keys.push(AuthorityId::try_from(pub_key.as_slice()).unwrap())
        });

        let consensus_client = AlephConsensusClient::<14>::consensus(
            authority_keys.clone(),
            emergency_finalizer.clone(),
        )
        .unwrap();

        match justification {
            justification::AlephJustification::CommitteeMultisignature(signatures) => {
                let block_number: u32 = 61_549_453;
                let extriniscs_root = Vec::from_hex(
                    "b1e1ea8fa70a1d562cb1889b8cb01dbe7b3ffb02b97f078de0a832ca7380febe",
                )
                .unwrap();
                let extriniscs_root = Hash::from_slice(&extriniscs_root);
                let state_root = Vec::from_hex(
                    "510495035e7246e809210fe6b77765e72fcad76ef05541514fc3f4421059bd4e",
                )
                .unwrap();
                let state_root = Hash::from_slice(&state_root);
                let parent_hash = Vec::from_hex(
                    "9466332cc9aa040141b9cb9532cae4ceeef07482c10425791372edb7e2a56fb3",
                )
                .unwrap();
                let parent_hash = Hash::from_slice(&parent_hash);

                let digest = AlephConsensusLogBuilder::logs("cbd9386500000000", "8233d4f1b48f23886f4d1c9417e4a37e386809a133b5271ac514d68cb4cdde6d33beefc18799f2f9ce7fb4e1d0c777dd8159a1b115d182d0dcac4d6069a2a78f").unwrap().build();

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
            Vec::from_hex("510495035e7246e809210fe6b77765e72fcad76ef05541514fc3f4421059bd4e")
                .unwrap();
        let state_root = BlockHash::from_slice(&state_root);

        let dummy_timestamp = 123456789;

        let storage_proof = vec![Vec::from_hex("5f030ebca703c85910e7164cb7d1c9e47b80025342a214a9c91f13135ccd686a047c7efee5ef4c34e1859051bf83dd9e1428").unwrap(), 
        Vec::from_hex("8080918086b56ff7f19023287ed809bfc62b055e68c94e622fe27bab5102b330dba4eaff801e169246fa08a0d25670d442a23c12f9f867b25b5e0a083db52d5967d4e79a4f80dfee03ced33eb959c00afa96f46c230bc1ea27102268f0c345937041070efb7a808d4eb857f49beb0b85be29fc5fbcf9b8cb1c6fc8e0b66f3d9444740ee1a8d201").unwrap(),
        Vec::from_hex("80bdb98045cc24354dcdf1f01c3bcde269735a1091c1a6b2040c395630470a381bf8c95f80abf2c3ee3aa8fff8e7d032fe259386c4306ca7c14610f3318653ca749212f22a8047081716d7e5a90ee793b9d141ad84087d253e0e3369944fa46710fc735098c6801e8b15b5a3c26159c7e27aa4f844497b0b65389304def766420d7d1ccfa0a4bd80b820eca3d091b85fee55703c49da4474d14b6e550712537a9154eab8bdc2830e80402da976a8faf4f726a0714082ccf6af4b920c01905accdd50e010327e49128380f3c7be157b3e8939c6dfe82ef4c0298a9776a69b423d4f3a5544c511151e094380624fa4330845bfcfcc9ec85697b4aea521d1fa7a823fa9cb761b21b99452cea980c1b233c17a785d19a4488f85897b7d49d97697d1690ce3bbe2e570b4ccd9cf8980e72f9794ba8822b34c5b69992c0ac2314619419990c46e8c00d483789a2fc4d080751a595bd3558907d8132e103d92bba895cc47ee3ec674f9a82de8d9876f53fa").unwrap(),
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
            overlay_root: None,
            state_root,
        };

        let keys =
            vec![
                Vec::from_hex("5c0d1176a568c1f92944340dbfed9e9c530ebca703c85910e7164cb7d1c9e47b")
                    .unwrap(),
            ];

        let response_proof = GetResponseProof::new(&keys, &root, &proof);

        let get_response = GetResponse(61_549_453, response_proof);

        assert_eq!(
            get_response.verify_state(),
            Ok(
                Vec::from_hex("025342a214a9c91f13135ccd686a047c7efee5ef4c34e1859051bf83dd9e1428")
                    .unwrap()
            )
        )
    }
}
