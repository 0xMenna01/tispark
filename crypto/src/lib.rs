#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

extern crate core;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod aead;
pub mod key_derive;

use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use core::hash::Hasher;
use digest::Digest;
use ink_env::hash::{Blake2x256, CryptoHash};

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
        {
            pink_extension::ext().getrandom(length)
        }
    }
}

const HASH_LENGTH: usize = 32;
pub struct CryptoHasher(());

impl CryptoHasher {
    pub fn hash(data: &[u8]) -> [u8; HASH_LENGTH] {
        let mut output = [0_u8; HASH_LENGTH];
        Blake2x256::hash(data, &mut output);
        output.into()
    }
}

pub struct Twox64Concat;
impl Twox64Concat {
    pub fn hash(x: &[u8]) -> Vec<u8> {
        let r0 = twox_hash::XxHash::with_seed(0).chain_update(x).finish();
        let mut r: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut r[0..8], r0);
        r.iter().chain(x.iter()).cloned().collect::<Vec<_>>()
    }
}
