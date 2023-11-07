#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod aead;
pub mod key_derive;

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpandError,
    // Aead errors
    AeadInvalidKey,
    AeadEncryptError,
    AeadDecryptError,
}
