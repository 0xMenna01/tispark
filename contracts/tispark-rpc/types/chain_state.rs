use super::{Error, ReadProof, Result, UntrustedAuthorities, Utils};
use alloc::{format, string::String, vec, vec::Vec};
use hex::FromHex;
use scale::{Decode, Encode};
use utils::types::{AuthorityId, Twox64Concat};

/// The encoded substrate storage key for the Authorities StorageValue
const AUTH_STORAGE_KEY: &str = "0xd39f9508314957b74c787c4abb8c95bb5e0621c4869aa60c02be9adcc98a0d1d";

/// TwoxHash of Pallet name CommitReveal
const MODULE: [u8; 16] = [
    0xa4, 0x5f, 0x72, 0x30, 0x93, 0x2f, 0xe9, 0xd5, 0xeb, 0xc8, 0x46, 0xb8, 0x73, 0xec, 0xd5, 0x3f,
];
/// TwoxHash of StorageMape Name PhatContractCommitment
const METHOD: [u8; 16] = [
    0xe2, 0xb9, 0x63, 0x43, 0x2a, 0xe5, 0x50, 0x77, 0x2d, 0xaa, 0x14, 0xb5, 0xf8, 0xe6, 0xe3, 0x97,
];

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct StorageProofParams {
    pub proof: Vec<Vec<u8>>,
    pub keys: Vec<Vec<u8>>,
}

pub fn build_storage_key_for_commitment(commit: &[u8]) -> Vec<u8> {
    let twox_commit = Twox64Concat::hash(commit);
    [&MODULE[..], &METHOD[..], &twox_commit[..]].concat()
}

/// The handler of state rpc calls
pub struct ChainStateHandler<'a> {
    url: &'a String,
}

impl<'a> ChainStateHandler<'a> {
    pub fn new(url: &'a String) -> Self {
        Self { url }
    }

    pub fn get_read_proof(
        &self,
        secure_storage_key: &[u8],
        finalized_head: &String,
    ) -> Result<StorageProofParams> {
        let storage_key = Utils::encode_to_hex(secure_storage_key);
        let storage_key = format!("0x{}", storage_key);
        let data = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"state_getReadProof","params":[["{}"], "{}"]}}"#,
            storage_key, finalized_head
        )
        .into_bytes();
        let resp_body = Utils::call_rpc(&self.url, data)?;

        let (response_proof, _): (ReadProof, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

        // construct the substrate storage keys with the only necessary key
        let keys = vec![secure_storage_key.to_vec()];
        // construct the proof
        let mut proof = Vec::new();
        for hex_str in response_proof.proof.into_iter() {
            let trie_node_hash = Utils::extract_hex_from(2, hex_str)?;
            let trie_node_hash =
                Vec::from_hex(trie_node_hash).map_err(|_| Error::InvalidHexData)?;
            proof.push(trie_node_hash);
        }

        Ok(StorageProofParams { proof, keys })
    }

    pub fn get_untrusted_authorities(&self, finalized_block: &String) -> Result<Vec<AuthorityId>> {
        let data = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"state_getStorage","params":["{}", "{}"]}}"#,
            AUTH_STORAGE_KEY, finalized_block
        )
        .into_bytes();
        let resp_body = Utils::call_rpc(&self.url, data)?;

        let (authorities, _): (UntrustedAuthorities, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

        let untrusted_authorities = Utils::extract_hex_from(2, authorities.result)?;
        let encoded_authorities =
            Vec::from_hex(untrusted_authorities).map_err(|_| Error::InvalidHexData)?;

        let authorities: Vec<AuthorityId> = Decode::decode(&mut &encoded_authorities[..])
            .map_err(|_| Error::AuthoritiesDecodeError)?;

        Ok(authorities)
    }
}
