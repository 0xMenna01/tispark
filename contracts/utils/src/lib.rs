#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

pub mod types;

use ink::env::{
    call::{build_call, ExecutionInput},
    DefaultEnvironment,
};
use types::ContractId;

#[derive(Debug)]
#[ink::storage_item]
pub struct ContractRef(ContractId);

impl ContractRef {
    pub fn new(id: ContractId) -> Self {
        Self(id)
    }

    pub fn get(&self) -> ContractId {
        self.0.clone()
    }

    pub fn query<Args, Res>(&self, exec: ExecutionInput<Args>) -> Res
    where
        Args: scale::Encode,
        Res: scale::Decode,
    {
        build_call::<DefaultEnvironment>()
            .call(self.0)
            .gas_limit(Default::default())
            .exec_input(exec)
            .returns::<Res>()
            .invoke()
    }
}
