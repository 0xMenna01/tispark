use ink::primitives::{AccountId, Hash as CryptoHash};

mod auth;

pub use auth::AccessControl;
pub type AuthorityId = AccountId;
pub type ContracId = AccountId;
pub type Hash = CryptoHash;

#[derive(Debug)]
#[ink::storage_item]
pub struct SudoAccount {
    account: Option<AuthorityId>,
}

impl SudoAccount {
    pub fn new(sudo: Option<AuthorityId>) -> Self {
        Self { account: sudo }
    }

    pub fn remove(&mut self) {
        self.account = None
    }

    pub fn set(&mut self, account: AuthorityId) {
        self.account = Some(account)
    }

    pub fn get(&self) -> Option<AuthorityId> {
        self.account
    }
}
