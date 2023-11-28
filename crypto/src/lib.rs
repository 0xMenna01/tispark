#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod aead;
pub mod key_derive;

use alloc::vec::Vec;

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

pub type CryptoHasher = ink_env::hash::Blake2x256;
