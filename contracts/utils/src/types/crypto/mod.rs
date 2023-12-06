use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use core::hash::Hasher;
use digest::Digest;
use ink::env::hash::{Blake2x256, CryptoHash};

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

pub struct Random(());

impl Random {
    pub fn getrandom(length: u8) -> Vec<u8> {
        pink_extension::ext().getrandom(length)
    }
}
