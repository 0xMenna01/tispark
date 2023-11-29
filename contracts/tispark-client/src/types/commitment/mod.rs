use pink_extension::chain_extension::SigType;
use scale::{Decode, Encode};
use tispark_primitives::commit_reveal::Commit;

use super::message::{ContractSecretKey, ContractSignature, SigningData};

#[derive(Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ContractCommitment {
    signature: ContractSignature,
    commit: Commit<Vec<u8>>,
}

pub struct ContractCommitmentBuilder<CommitState> {
    state: CommitState,
}

#[derive(Default)]
pub struct NotInit;
pub struct InitializedKey(ContractSecretKey);
pub struct Committed(InitializedKey, Commit<Vec<u8>>);

impl Committed {
    pub fn key(&self) -> &[u8] {
        &self.0 .0
    }

    pub fn commitment(&self) -> Commit<Vec<u8>> {
        self.1.clone()
    }
}

impl Default for ContractCommitmentBuilder<NotInit> {
    fn default() -> Self {
        Self {
            state: Default::default(),
        }
    }
}

impl ContractCommitmentBuilder<NotInit> {
    pub fn key(self, key: ContractSecretKey) -> ContractCommitmentBuilder<InitializedKey> {
        ContractCommitmentBuilder {
            state: InitializedKey(key),
        }
    }
}

impl ContractCommitmentBuilder<InitializedKey> {
    pub fn commitment(self, commit: Commit<Vec<u8>>) -> ContractCommitmentBuilder<Committed> {
        ContractCommitmentBuilder {
            state: Committed(self.state, commit),
        }
    }
}

impl ContractCommitmentBuilder<Committed> {
    pub fn build(self) -> ContractCommitment {
        // Sr25519 supported signature
        let commit = self.state.commitment();
        let signature = ContractSignature::from(SigningData::new(
            self.state.key().to_vec(),
            commit.encode(),
            SigType::Sr25519,
        ));

        ContractCommitment { signature, commit }
    }
}
