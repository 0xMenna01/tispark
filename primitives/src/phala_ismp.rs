#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::{collections::BTreeMap, format, vec::Vec};
use codec::{Decode, Encode};
use ismp::{consensus::StateCommitment, error::Error};
use sp_runtime::traits::{BlakeTwo256, Keccak256};
use sp_trie::{LayoutV0, StorageProof, Trie, TrieDBBuilder};

/// Proof holds the relevant proof data.
#[derive(Debug, Clone, Encode, Decode, scale_info::TypeInfo, PartialEq, Eq)]

pub struct Proof {
    /// State height
    pub height: u64,
    /// Scale encoded proof
    pub proof: Vec<u8>,
}

/// Hashing algorithm for the state proof
#[derive(Debug, Encode, Decode, Clone)]
pub enum HashAlgorithm {
    /// For chains that use keccak as their hashing algo
    Keccak,
    /// For chains that use blake2 as their hashing algo
    Blake2,
}

/// Holds the relevant data needed for state proof verification
#[derive(Debug, Encode, Decode, Clone)]
pub struct SubstrateStateProof {
    /// Algorithm to use for state proof verification
    pub hasher: HashAlgorithm,
    /// Storage proof for the parachain headers
    pub storage_proof: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Encode, Decode, scale_info::TypeInfo, PartialEq, Eq)]
pub struct GetResponseProof {
    keys: Vec<Vec<u8>>,
    root: StateCommitment,
    proof: Proof,
}

impl GetResponseProof {
    pub fn new(keys: &[Vec<u8>], root: &StateCommitment, proof: &Proof) -> Self {
        GetResponseProof {
            keys: keys.to_vec(),
            root: root.clone(),
            proof: proof.clone(),
        }
    }

    pub fn keys(&self) -> &[Vec<u8>] {
        &self.keys
    }

    pub fn state_root(&self) -> &StateCommitment {
        &self.root
    }

    /// Lifted directly from [`ismp_primitives::state_machine::verify_state_proof`](https://github.com/polytope-labs/ismp-substrate/blob/ed1127dd02548ee45d30ddc0e82e4adbd9834bb8/pallet-ismp/primitives/state-machine/src/lib.rs)
    pub fn verify_state_proof(&self) -> Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>, Error> {
        let state_proof: SubstrateStateProof = codec::Decode::decode(&mut &*self.proof.proof)
            .map_err(|e| Error::ImplementationSpecific(format!("failed to decode proof: {e:?}")))?;

        let data = match state_proof.hasher {
            HashAlgorithm::Keccak => {
                let db = StorageProof::new(state_proof.storage_proof).into_memory_db::<Keccak256>();
                let trie =
                    TrieDBBuilder::<LayoutV0<Keccak256>>::new(&db, &self.root.state_root).build();

                self.keys
                    .clone()
                    .into_iter()
                    .map(|key| {
                        let value = trie.get(&key).map_err(|e| {
                            Error::ImplementationSpecific(format!(
                                "Error reading state proof: {e:?}"
                            ))
                        })?;
                        Ok((key, value))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?
            }
            HashAlgorithm::Blake2 => {
                let db =
                    StorageProof::new(state_proof.storage_proof).into_memory_db::<BlakeTwo256>();

                let trie =
                    TrieDBBuilder::<LayoutV0<BlakeTwo256>>::new(&db, &self.root.state_root).build();
                self.keys
                    .clone()
                    .into_iter()
                    .map(|key| {
                        let value = trie.get(&key).map_err(|e| {
                            Error::ImplementationSpecific(format!(
                                "Error reading state proof: {e:?}"
                            ))
                        })?;
                        Ok((key, value))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?
            }
        };

        Ok(data)
    }
}
