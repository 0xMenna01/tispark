use alloc::vec::Vec;
use codec::{Decode, Encode};
use crypto::{
    aead,
    key_derive::{KeyMaterial, KDF},
    CryptoError, CryptoHasher, Random,
};
use scale_info::TypeInfo;
use sp_core::{Hasher, H256};

const KEY_SIZE: usize = 256 / 8;
const KDF_LABEL: &[u8] = b"aesgcm256-commitkey";

pub type CommitId = H256;

pub trait Commitment<C: Encode, Metadata> {
    fn commit(value: Commit) -> Result<(), CommitRevealError>;

    fn reveal(proof: RevealProof) -> Result<Reveal, CommitRevealError>;
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct CommitData {
    data: EncryptedData,
    iv: IV,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct Commit {
    id: CommitId,
    data: CommitData,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct RevealProof {
    pub commit_id: CommitId,
    pub secret: SecretKey,
}

#[derive(Debug)]
pub enum CommitRevealError {
    CommitError,
    InvalidCommitmentId,
    AlreadyCommitted,
    RevealError,
    InvalidCommitForReveal,
    AlreadyRevealed,
    DecryptionRejected,
    EncryptionError,
    DecodeError,
}

pub type SecretKey = Vec<u8>;
pub type IV = Vec<u8>;

pub struct DecryptedData {
    key: SecretKey,
    iv: IV,
    encrypted: EncryptedData,
}

pub type EncryptedData = Vec<u8>;
pub type Reveal = Vec<u8>;

impl DecryptedData {
    pub fn new(key: SecretKey, iv: IV, encrypted: EncryptedData) -> Self {
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
pub struct Setup {
    commit_id: CommitId,
    secret: KeyMaterial<KEY_SIZE>,
    iv: IV,
}

pub struct SchemeReady<PlainText: Encode> {
    setup_material: Setup,
    data: PlainText,
}

#[derive(Encode)]
struct Height {
    block_number: u32,
    timestamp: u64,
}

#[derive(Encode)]
pub struct QueryMetadata<Metadata> {
    height: Height,
    metadata: Metadata,
}

#[derive(Encode)]
pub struct KdfNonce<Metadata> {
    addons: QueryMetadata<Metadata>,
    entropy: Vec<u8>,
}

const ENTROPY_SIZE: u8 = 16;

impl CommitRevealManager<UnSet> {
    /// Setup a new commit-reveal scheme Manager builder that derives a new one-time key
    pub fn setup<CommitMetadata: Encode>(
        secret: &[u8],
        metadata: QueryMetadata<CommitMetadata>,
    ) -> Result<CommitRevealManager<Setup>, CryptoError> {
        let kdf = KDF::<KEY_SIZE>::new(secret);
        let entropy = Random::get_random_bytes(ENTROPY_SIZE);
        let nonce = KdfNonce {
            addons: metadata,
            entropy,
        };
        let commit_id = CryptoHasher::hash(&nonce.encode());
        let secret = kdf.derive_aead_key(commit_id.as_bytes(), [KDF_LABEL].as_slice())?;
        let iv = nonce.addons.height.encode();

        let state = Setup {
            commit_id,
            secret,
            iv,
        };

        Ok(CommitRevealManager { state })
    }

    /// Setup a new commit-reveal scheme Manager builder that derives a new one-time key
    pub fn reveal(secret: &[u8], commit_id: H256) -> Result<RevealProof, CryptoError> {
        let kdf = KDF::<KEY_SIZE>::new(secret);

        let secret = kdf.derive_aead_key(commit_id.as_bytes(), [KDF_LABEL].as_slice())?;

        Ok(RevealProof {
            commit_id,
            secret: secret.get(),
        })
    }
}

impl CommitRevealManager<Setup> {
    /// inject a plaintext to be encrypted within the commit-reveal manager
    pub fn inject<PlainText: Encode>(
        self,
        data: PlainText,
    ) -> CommitRevealManager<SchemeReady<PlainText>> {
        let state = SchemeReady {
            setup_material: self.state,
            data,
        };

        CommitRevealManager { state }
    }
}

impl<PlainText: Encode> CommitRevealManager<SchemeReady<PlainText>> {
    pub fn commit(self) -> Result<Commit, CommitRevealError> {
        // 1. Encode data to encrypt
        let mut data = self.state.data.encode();

        // 2. Set up iv and secret
        let iv = self.state.setup_material.iv;
        let iv = aead::generate_iv(&iv);
        let secret = self.state.setup_material.secret.get();

        // 3. Encrypt
        aead::encrypt(&iv, &secret, &mut data).map_err(|_| CommitRevealError::EncryptionError)?;

        let data = CommitData {
            data,
            iv: iv.to_vec(),
        };

        Ok(Commit {
            id: self.state.setup_material.commit_id,
            data,
        })
    }
}

impl CommitRevealManager<SchemeReady<Vec<u8>>> {
    pub fn commit_already_encoded(self) -> Result<Commit, CommitRevealError> {
        // 1. Already encoded
        let mut data = self.state.data;

        // 2. Set up iv and secret
        let iv = self.state.setup_material.iv;
        let iv = aead::generate_iv(&iv);
        let secret = self.state.setup_material.secret.get();

        // 3. Encrypt
        aead::encrypt(&iv, &secret, &mut data).map_err(|_| CommitRevealError::EncryptionError)?;

        let data = CommitData {
            data,
            iv: iv.to_vec(),
        };

        Ok(Commit {
            id: self.state.setup_material.commit_id,
            data,
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;

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
        let secret = Random::get_random_bytes(32);

        let metadata = CommitMetadataDemo {
            bet_id: 1,
            game_id: 1,
            account_id: b"12345".to_vec(),
        };

        let plain_text = PlainTextDemo {
            dummy_bet: 10,
            result: 11,
        };

        let commit = CommitRevealManager::setup(
            &secret,
            QueryMetadata {
                height: Height {
                    block_number: 100,
                    timestamp: 1234,
                },
                metadata,
            },
        )
        .unwrap()
        .inject(plain_text.clone())
        .commit()
        .unwrap();

        let reveal = CommitRevealManager::reveal(&secret, commit.id).unwrap();

        let decrypted = DecryptedData::new(reveal.secret, commit.data.iv, commit.data.data)
            .decrypt()
            .unwrap();

        let decoded: PlainTextDemo = Decode::decode(&mut &decrypted[..]).unwrap();

        assert_eq!(plain_text, decoded);
    }
}
