use self::input::SensitiveData;
use crate::{
    commitment::ContractCommitment, message::CommitmentRequest, ContractError, ContractResult,
    ServiceId,
};
use alloc::vec::Vec;
use ink::{
    env::call::{ExecutionInput, Selector},
    primitives::AccountId,
};
use scale::{Decode, Encode};
use utils::ContractRef;

pub mod input {
    use super::*;
    pub struct SensitiveData<Value, Metadata> {
        commit_to_value: Value,
        metadata: Metadata,
    }

    impl<Value: Encode, Metadata: Encode> SensitiveData<Value, Metadata> {
        pub fn new(data: Value, metadata: Metadata) -> Self {
            Self {
                commit_to_value: data,
                metadata,
            }
        }

        pub fn encode(&self) -> (Vec<u8>, Vec<u8>) {
            (self.commit_to_value.encode(), self.metadata.encode())
        }
    }
}

pub type TisparkClientId = AccountId;
pub type Error = ContractError;

#[derive(Default, Debug)]
struct VoidContract;
struct ClientLoaded(TisparkClientId);
struct ClientForService {
    client: TisparkClientId,
    service_request: ServiceId,
}

#[derive(Default, Debug)]
pub struct TiSparkBuilder<S> {
    state: S,
}

impl TiSparkBuilder<VoidContract> {
    pub fn new() -> Self {
        Default::default()
    }
}

impl TiSparkBuilder<VoidContract> {
    pub fn address(self, address: TisparkClientId) -> TiSparkBuilder<ClientLoaded> {
        TiSparkBuilder {
            state: ClientLoaded(address),
        }
    }
}

impl TiSparkBuilder<ClientLoaded> {
    pub fn service(self, service: ServiceId) -> TiSparkBuilder<ClientForService> {
        TiSparkBuilder {
            state: ClientForService {
                client: self.state.0,
                service_request: service,
            },
        }
    }
}

impl TiSparkBuilder<ClientForService> {
    pub fn build(self) -> TisparkContractRef {
        TisparkContractRef {
            id: self.state.client,
            service: self.state.service_request,
        }
    }
}

#[derive(Debug)]
#[ink::storage_item]
pub struct TisparkContractRef {
    id: TisparkClientId,
    service: ServiceId,
}

impl TisparkContractRef {
    pub fn commit<Value: Encode, Metadata: Encode>(
        &self,
        data: SensitiveData<Value, Metadata>,
    ) -> ContractResult<ContractCommitment> {
        let (data, metadata) = data.encode();
        // construct contract request
        let request = CommitmentRequest::new(data, metadata, self.service);

        let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!(
            "CommitRevealContractManager::commit"
        )))
        .push_arg(request);

        // make cross contract call
        ContractRef::new(self.id).query(exec)
    }

    pub fn reveal<Value: Decode>() {
        todo!()
    }
}
