use crate::{
    message::{RevealCommitmentRequest, RevealResponse},
    types::{commitment::ContractCommitment, message::CommitmentRequest, Result as ContractResult},
};

#[ink::trait_definition]
pub trait CommitRevealContractManager {
    /// Updates the key material used for key derivation
    #[ink(message)]
    fn update_keyring_material(&mut self) -> ContractResult<()>;

    #[ink(message)]
    fn commit(&self, request: CommitmentRequest) -> ContractResult<ContractCommitment>;

    #[ink(message)]
    fn reveal(&self, request: RevealCommitmentRequest) -> ContractResult<RevealResponse>;
}
