use alloc::vec::Vec;
use codec::{Decode, Encode, Error};
use crypto::{
    aead,
    key_derive::{KeyMaterial, KDF},
    CryptoError,
};
use scale_info::TypeInfo;
use sp_core::H256;

const KEY_SIZE: usize = 256 / 8;
const KDF_LABEL: &[u8] = b"aesgcm256-commitkey";
const ENTROPY_SIZE: u8 = 32; // aka 256 bit

pub type CommitId = H256;
pub type EncryptedData = Vec<u8>;
pub type Reveal = Vec<u8>;
type EntropyBytes = [u8; ENTROPY_SIZE as usize];

pub type SecretKey = Vec<u8>;

pub trait Commitment<C: Encode, Metadata> {
    fn commit(value: Commit<Metadata>) -> Result<(), CommitRevealError>;

    fn reveal(proof: RevealProof) -> Result<Reveal, CommitRevealError>;
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, TypeInfo)]
pub struct Commit<Metadata> {
    id: CommitId,
    data: (EncryptedData, Metadata),
    iv: Vec<u8>,
}

impl<Metadata: Encode> Commit<Metadata> {
    pub fn with_encoded_metadata(self) -> Commit<Vec<u8>> {
        Commit {
            id: self.id,
            data: (self.data.0, self.data.1.encode()),
            iv: self.iv,
        }
    }
}

impl Commit<Vec<u8>> {
    pub fn decode<Metadata: Decode>(self) -> Result<Commit<Metadata>, Error> {
        let encoded_meta = self.data.1;
        let meta = Decode::decode(&mut &encoded_meta[..])?;
        Ok(Commit {
            id: self.id,
            data: (self.data.0, meta),
            iv: self.iv,
        })
    }
}

impl<Metadata: Clone> Commit<Metadata> {
    pub fn new(
        id: CommitId,
        commitment: (EncryptedData, Vec<u8>),
        metadata: Metadata,
    ) -> Commit<Metadata> {
        Commit {
            id,
            data: (commitment.0, metadata),
            iv: commitment.1,
        }
    }
    pub fn get_id(&self) -> CommitId {
        self.id.clone()
    }

    pub fn get_commitment(&self) -> (EncryptedData, Vec<u8>) {
        (self.data.0.clone(), self.iv.clone())
    }

    pub fn get_metadata(&self) -> Metadata {
        self.data.1.clone()
    }
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

pub struct DecryptedData {
    key: SecretKey,
    iv: Vec<u8>,
    encrypted: EncryptedData,
}

impl DecryptedData {
    pub fn new(key: SecretKey, iv: Vec<u8>, encrypted: EncryptedData) -> Self {
        DecryptedData { key, iv, encrypted }
    }

    pub fn decrypt(&self) -> Result<Reveal, CommitRevealError> {
        let mut decrypted = self.encrypted.clone();
        let iv = aead::generate_iv(self.iv.as_slice());
        aead::decrypt(&iv, &self.key, decrypted.as_mut())
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
/// The key is derived using the commit_id, which is a nonce, that identifies the commitment.
pub struct Setup<CommitMetadata> {
    commit_id: CommitId,
    meta: CommitMetadata,
    secret: KeyMaterial<KEY_SIZE>,
    iv: Vec<u8>,
}

pub struct SchemeReady<PlainText: Encode, CommitMetadata> {
    setup_material: Setup<CommitMetadata>,
    data: PlainText,
}

#[derive(Encode)]
pub struct QueryHeight {
    height: u32,
    timestamp: u64,
}

#[derive(Encode)]
pub struct QueryMetadata<Metadata> {
    height: QueryHeight,
    metadata: Metadata,
}

impl<Metadata> QueryMetadata<Metadata> {
    pub fn new(height: u32, timestamp: u64, metadata: Metadata) -> Self {
        Self {
            height: QueryHeight { height, timestamp },
            metadata,
        }
    }
}

#[derive(Encode)]
pub struct KdfNonce<Metadata> {
    addons: QueryMetadata<Metadata>,
    entropy: EntropyBytes,
}

impl CommitRevealManager<UnSet> {
    /// Setup a new commit-reveal scheme Manager builder that derives a new one-time key
    pub fn setup<CommitMetadata: Encode>(
        secret: &[u8],
        query: QueryMetadata<CommitMetadata>,
        hash: fn(&[u8]) -> [u8; 32],
        rand: fn(u8) -> Vec<u8>,
    ) -> Result<CommitRevealManager<Setup<CommitMetadata>>, CryptoError> {
        let kdf = KDF::<KEY_SIZE>::new(secret);
        // Retrieve some high entropy bytes to compute a one time key for encrypting some data, within an associated metadata
        let mut fixed_entropy = [0u8; ENTROPY_SIZE as usize];
        let entropy = rand(ENTROPY_SIZE);
        fixed_entropy.copy_from_slice(&entropy);

        // Some nonce value used to derive the commitment key
        let nonce = KdfNonce {
            addons: query,
            entropy: fixed_entropy,
        };
        let commit_id: H256 = hash(&nonce.encode()).into();
        // derive the key using the commitment id
        let secret = kdf.derive_aead_key(commit_id.as_bytes(), [KDF_LABEL].as_slice())?;
        // there is a timing window in which this iv will repeat, depends on the calling blockchain system's block time
        // it is not an issue since the key will always change during that timing window
        let iv = nonce.addons.height.encode();

        let state = Setup {
            commit_id,
            meta: nonce.addons.metadata,
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
            secret: secret.get_ownership().to_vec(),
        })
    }
}

impl<CommitMetadata> CommitRevealManager<Setup<CommitMetadata>> {
    /// inject a plaintext to be encrypted within the commit-reveal manager
    pub fn inject(
        self,
        data: Vec<u8>,
    ) -> CommitRevealManager<SchemeReady<Vec<u8>, CommitMetadata>> {
        let state = SchemeReady {
            setup_material: self.state,
            data,
        };

        CommitRevealManager { state }
    }
}

impl<CommitMetadata> CommitRevealManager<SchemeReady<Vec<u8>, CommitMetadata>> {
    pub fn commit(self) -> Result<Commit<CommitMetadata>, CommitRevealError> {
        // 1. Encoded data to encrypt
        let mut data = self.state.data;

        // 2. Set up iv and secret
        let iv = self.state.setup_material.iv;
        let iv = aead::generate_iv(&iv);
        let secret = self.state.setup_material.secret.get();

        // 3. Encrypt
        aead::encrypt(&iv, secret, &mut data).map_err(|_| CommitRevealError::EncryptionError)?;

        Ok(Commit {
            id: self.state.setup_material.commit_id,
            data: (data, self.state.setup_material.meta),
            iv: iv.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ring::{
        digest::{Context, SHA256},
        rand::{SecureRandom, SystemRandom},
    };

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

    fn mock_hash(data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        let digest = digest.as_ref();
        hash.clone_from_slice(digest);
        hash
    }

    fn mock_random(len: u8) -> Vec<u8> {
        let mut rand = vec![0u8; len as usize];
        let rng = SystemRandom::new();
        rng.fill(&mut rand).unwrap();
        rand
    }

    #[test]
    fn commit_reveal() {
        let secret = mock_random(32);

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
                height: QueryHeight {
                    height: 100,
                    timestamp: 12345,
                },
                metadata,
            },
            mock_hash,
            mock_random,
        )
        .unwrap()
        .inject(plain_text.encode())
        .commit()
        .unwrap();

        let reveal = CommitRevealManager::reveal(&secret, commit.id).unwrap();

        let decrypted = DecryptedData::new(reveal.secret, commit.iv, commit.data.0)
            .decrypt()
            .unwrap();

        let decoded: PlainTextDemo = Decode::decode(&mut &decrypted[..]).unwrap();

        assert_eq!(plain_text, decoded);
    }
}
