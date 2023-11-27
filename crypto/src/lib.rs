#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod aead;
pub mod key_derive;

use ink_env::hash::{Blake2x256 as InkBlakeTwo256, CryptoHash};
use sp_core::{Blake2Hasher, Hasher};

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpandError,
    // Aead errors
    AeadInvalidKey,
    AeadEncryptError,
    AeadDecryptError,
}

/// Randomness type
#[derive(Clone, Debug)]
pub struct Random(());

impl Random {
    pub fn get_random_bytes(length: u8) -> Vec<u8> {
        #[cfg(feature = "std")]
        {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut rand = vec![0u8; length as usize];
            let rng = SystemRandom::new();
            rng.fill(&mut rand).unwrap();
            rand
        }

        #[cfg(not(feature = "std"))]
        #[cfg(feature = "phat_contract")]
        {
            pink_extension::ext().getrandom(length)
        }
    }
}

/// Hashing type
#[cfg(feature = "phat_contract")]
pub type CryptoHasher = ContractBlakeTwo256;
// If not phat_contract
#[cfg(not(feature = "phat_contract"))]
pub type CryptoHasher = Blake2Hasher;

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
