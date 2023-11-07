use codec::{Decode, Encode};
use crypto::{
    aead,
    key_derive::{KeyMaterial, KDF},
    CryptoError,
};
use scale_info::TypeInfo;
use alloc::vec::Vec;

const KEY_SIZE: usize = 256 / 8;
const KDF_LABEL: &[u8] = b"aesgcm256-commitkey";

pub trait Commitment<C: Encode, Metadata> {
    fn commit(value: Commit<C, Metadata>) -> Result<(), CommitRevealError>;

    fn reveal(proof: RevealProof<Metadata>) -> Result<Reveal, CommitRevealError>;
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct Commit<EncryptedData, Metadata> {
    pub metadata: Metadata,
    pub data: EncryptedData,
    pub nonce: Nonce,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct RevealProof<CommitMetadata> {
    pub commit_metadata: CommitMetadata,
    pub secret: SecretKey,
}

#[derive(Debug)]
pub enum CommitRevealError {
    CommitError,
    RevealError,
    AlreadyRevealed,
    DecryptionRejected,
    EncryptionError,
    DecodeError,
}

pub type SecretKey = Vec<u8>;
pub type Nonce = Vec<u8>;

pub struct DecryptedData {
    key: SecretKey,
    iv: Nonce,
    encrypted: EncryptedData,
}

pub type EncryptedData = Vec<u8>;
pub type Reveal = Vec<u8>;

impl DecryptedData {
    pub fn new(key: SecretKey, iv: Nonce, encrypted: EncryptedData) -> Self {
        DecryptedData { key, iv, encrypted }
    }

    pub fn decrypt(&self) -> Result<Reveal, CommitRevealError> {
        let mut decrypted = self.encrypted.clone();
        let iv = aead::generate_iv(self.iv.as_slice());
        aead::decrypt(&iv, self.key.as_slice(), decrypted.as_mut())
            .map_err(|_| CommitRevealError::DecryptionRejected)?;

        Ok(decrypted)
    }
}

// commit-reveal's implementation logic
pub struct CommitRevealManager<S> {
    state: S,
}

pub struct UnSet;

/// Setup material for initializing the aes-gcm key and iv to encrypt the data.
/// Ensure that the encoded metadata is at least 96 bit in size.
/// Every commitment is binded to a nonce, to ensure the keymaterial changes.
pub struct Setup<CommitMetadata> {
    secret: KeyMaterial<KEY_SIZE>,
    nonce: Nonce,
    metadata: CommitMetadata,
}

pub struct SchemeReady<PlainText: Encode, CommitMetadata> {
    setup_material: Setup<CommitMetadata>,
    data: PlainText,
}

pub type GameId = u32;

impl CommitRevealManager<UnSet> {
    /// Setup a new commit-reveal scheme Manager builder that derives a new one-time key
    pub fn setup<CommitMetadata: Encode>(
        secret: &[u8],
        nonce_metadata: CommitMetadata,
    ) -> Result<CommitRevealManager<Setup<CommitMetadata>>, CryptoError> {
        let kdf = KDF::<KEY_SIZE>::new(secret);
        let nonce = nonce_metadata.encode();
        let secret = kdf.derive_aead_key(&nonce, [KDF_LABEL].as_slice())?;

        let state = Setup {
            secret,
            nonce,
            metadata: nonce_metadata,
        };

        Ok(CommitRevealManager { state })
    }
}

impl<CommitMetadata> CommitRevealManager<Setup<CommitMetadata>> {
    /// inject a plaintext to be encrypted within the commit-reveal manager
    pub fn inject<PlainText: Encode>(
        self,
        data: PlainText,
    ) -> CommitRevealManager<SchemeReady<PlainText, CommitMetadata>> {
        let state = SchemeReady {
            setup_material: self.state,
            data,
        };

        CommitRevealManager { state }
    }

    /// provides the reveal proof
    pub fn reveal(self) -> RevealProof<CommitMetadata> {
        RevealProof {
            commit_metadata: self.state.metadata,
            secret: self.state.secret.get(),
        }
    }
}

impl<PlainText: Encode, CommitMetadata>
    CommitRevealManager<SchemeReady<PlainText, CommitMetadata>>
{
    pub fn commit(self) -> Result<Commit<EncryptedData, CommitMetadata>, CommitRevealError> {
        // 1. Encode data to encrypt
        let mut data = self.state.data.encode();

        // 2. Set up iv and secret
        let nonce = self.state.setup_material.nonce;
        let iv = aead::generate_iv(&nonce);
        let secret = self.state.setup_material.secret.get();

        // 3. Encrypt
        aead::encrypt(&iv, &secret, &mut data).map_err(|_| CommitRevealError::EncryptionError)?;

        Ok(Commit {
            metadata: self.state.setup_material.metadata,
            data,
            nonce,
        })
    }
}

impl<CommitMetadata> CommitRevealManager<SchemeReady<Vec<u8>, CommitMetadata>> {
    pub fn commit_already_encoded(
        self,
    ) -> Result<Commit<EncryptedData, CommitMetadata>, CommitRevealError> {
        // 1. Already encoded
        let mut data = self.state.data;

        // 2. Set up iv and secret
        let nonce = self.state.setup_material.nonce;
        let iv = aead::generate_iv(&nonce);
        let secret = self.state.setup_material.secret.get();

        // 3. Encrypt
        aead::encrypt(&iv, &secret, &mut data).map_err(|_| CommitRevealError::EncryptionError)?;

        Ok(Commit {
            metadata: self.state.setup_material.metadata,
            data,
            nonce,
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ring::rand::SecureRandom;

    #[derive(Encode, Decode, Clone, Eq, PartialEq, Debug)]
    struct PlainTextDemo {
        dummy_bet: u32,
        result: u32,
    }

    #[derive(Encode, Decode, Clone, Eq, PartialEq, Debug)]
    struct CommitMetadataDemo {
        bet_id: u32,
        game_id: u32,
        account_id: Vec<u8>,
    }

    #[test]
    fn commit_reveal() {
        let mut secret = [0_u8; 32];
        let rand = ring::rand::SystemRandom::new();
        rand.fill(&mut secret).unwrap();

        let nonce_metadata = CommitMetadataDemo {
            bet_id: 1,
            game_id: 1,
            account_id: b"12345".to_vec(),
        };

        let plain_text = PlainTextDemo {
            dummy_bet: 10,
            result: 11,
        };

        let commit = CommitRevealManager::setup(&secret, nonce_metadata.clone())
            .unwrap()
            .inject(plain_text.clone())
            .commit()
            .unwrap();

        let reveal = CommitRevealManager::setup(&secret, nonce_metadata)
            .unwrap()
            .reveal();

        let decrypted = DecryptedData::new(reveal.secret, commit.nonce, commit.data)
            .decrypt()
            .unwrap();

        let decoded: PlainTextDemo = Decode::decode(&mut &decrypted[..]).unwrap();

        assert_eq!(plain_text, decoded);
    }
}
