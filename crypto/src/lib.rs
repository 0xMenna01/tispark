#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

extern crate core;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod aead;
pub mod key_derive;

#[cfg(any(feature = "phat_contract", feature = "std"))]
pub use crypto_hasher::Twox64Concat;

#[cfg(any(feature = "phat_contract", feature = "std"))]
pub use crypto_hasher::CryptoHasher;

#[cfg(any(feature = "phat_contract", feature = "std"))]
pub use rand_impl::Random;

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpandError,
    // Aead errors
    AeadInvalidKey,
    AeadEncryptError,
    AeadDecryptError,
}

#[cfg(feature = "std")]
mod rand_impl {
    /// Randomness type
    #[derive(Clone, Debug)]
    pub struct Random(());

    impl Random {
        pub fn get_random_bytes(length: u8) -> Vec<u8> {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut rand = vec![0u8; length as usize];
            let rng = SystemRandom::new();
            rng.fill(&mut rand).unwrap();
            rand
        }
    }
}

#[cfg(all(feature = "phat_contract", not(feature = "std")))]
mod rand_impl {
    use alloc::vec::Vec;
    /// Randomness type
    #[derive(Clone, Debug)]
    pub struct Random(());

    impl Random {
        pub fn get_random_bytes(length: u8) -> Vec<u8> {
            pink_extension::ext().getrandom(length)
        }
    }
}

#[cfg(any(feature = "phat_contract", feature = "std"))]
mod crypto_hasher {
    use alloc::vec::Vec;
    use byteorder::{ByteOrder, LittleEndian};
    use core::hash::Hasher;
    use digest::Digest;
    use ink_env::hash::{Blake2x256, CryptoHash};

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
}
