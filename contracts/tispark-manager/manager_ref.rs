use ink::env::call::{ExecutionInput, Selector};
use tispark_client::{ServiceId, tispark_client_ref::{TisparkContractRef, TiSparkBuilder}};
use utils::{types::ContractId, ContractRef};

#[derive(Debug)]
#[ink::storage_item]
pub struct TiSparkManagerRef {
    contract_ref: ContractRef,
    service: ServiceId,
}

impl TiSparkManagerRef {
    pub fn new(contract_id: ContractId, service: ServiceId) -> Self {
        let contract_ref = ContractRef::new(contract_id);
        Self {
            contract_ref,
            service,
        }
    }

    pub fn contract(&self) -> TisparkContractRef {
        // Prepare to for the call to know the current tispark client
        let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!("get_client")));
        // execure cross contract call
        let client_id: ContractId = self.contract_ref.query(exec);

        // build tispark client
        TiSparkBuilder::default()
            .address(client_id)
            .service(self.service)
            .build()
    }
}
