use ink::primitives::{AccountId, Hash as CryptoHash};

mod auth;

use alloc::vec::Vec;
pub use auth::AccessControl;
use scale::Encode;
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

    pub fn to_vec(&self) -> Vec<u8> {
        self.account.encode()
    }

    pub fn set(&mut self, account: AuthorityId) {
        self.account = Some(account)
    }

    pub fn get(&self) -> Option<AuthorityId> {
        self.account
    }
}
