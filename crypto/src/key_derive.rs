use alloc::vec::Vec;
use ring::hkdf;

use crate::CryptoError;

pub struct KeyMaterial<const BYTES: usize>([u8; BYTES]);

impl<const BYTES: usize> KeyMaterial<BYTES> {
    pub fn get(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub struct KDF<const OUT_KEY_BYTES: usize> {
    secret: Vec<u8>,
}

impl<const KEY_BYTES: usize> KDF<KEY_BYTES> {
    pub fn new(secret: &[u8]) -> Self {
        KDF {
            secret: secret.to_vec(),
        }
    }

    pub fn derive_aead_key(
        &self,
        nonce: &[u8],
        info: &[&[u8]],
    ) -> Result<KeyMaterial<KEY_BYTES>, CryptoError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, nonce);
        let prk = salt.extract(self.secret.as_slice());

        let mut key_material = KeyMaterial([0_u8; KEY_BYTES]);
        let okm = prk
            .expand(info, My(KEY_BYTES))
            .map_err(|_| CryptoError::HkdfExpandError)?;

        okm.fill(key_material.0.as_mut())
            .map_err(|_| CryptoError::HkdfExpandError)?;

        Ok(key_material)
    }
}

#[derive(Debug, PartialEq)]
struct My<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for My<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ring::rand::SecureRandom;

    #[test]
    fn test_key_derivation() {
        let dummy_nonce = [0_u8; 12];
        let info = [b"test_key_derivation".as_slice()];

        let mut secret = [0_u8; 32];
        let rand = ring::rand::SystemRandom::new();
        rand.fill(&mut secret).unwrap();

        let kdf = KDF::<32>::new(secret.as_slice());
        let aead_key: Result<KeyMaterial<32>, CryptoError> =
            kdf.derive_aead_key(dummy_nonce.as_ref(), &info);

        assert!(aead_key.is_ok());
        let aead_key = aead_key.unwrap();
        assert_ne!(aead_key.0, [0_u8; 32]);
    }
}
