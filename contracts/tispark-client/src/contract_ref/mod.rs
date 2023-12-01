use crate::{
    commitment::ContractCommitment, message::CommitmentRequest, ContractResult, ServiceId,
};
use ink::{
    env::{
        call::{build_call, ExecutionInput, Selector},
        DefaultEnvironment,
    },
    primitives::AccountId,
};
use scale::{Decode, Encode};

pub type TisparkClientId = AccountId;
pub type Error = crate::ContractError;

pub struct SensitiveData<Value, Metadata> {
    commit_to_value: Value,
    metadata: Metadata,
}

impl<Value: Encode + Decode, Metadata: Encode + Decode> SensitiveData<Value, Metadata> {
    pub fn new(data: Value, metadata: Metadata) -> Self {
        Self {
            commit_to_value: data,
            metadata,
        }
    }
}

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

#[derive(Debug, Clone, Copy)]
pub struct TisparkContractRef {
    id: TisparkClientId,
    service: ServiceId,
}

impl TisparkContractRef {
    pub fn commit<Value: Encode, Metadata: Encode>(
        &self,
        data: SensitiveData<Value, Metadata>,
    ) -> ContractResult<ContractCommitment> {
        // construct contract request
        let request = CommitmentRequest::new(
            data.commit_to_value.encode(),
            data.metadata.encode(),
            self.service,
        );

        // make cross contract call
        build_call::<DefaultEnvironment>()
            .call(self.id)
            .gas_limit(0)
            .exec_input(
                ExecutionInput::new(Selector::new(ink::selector_bytes!(
                    "CommitRevealBetManager::commit"
                )))
                .push_arg(request),
            )
            .returns::<ContractResult<ContractCommitment>>()
            .invoke()
    }

    pub fn reveal<Value: Decode>() {
        let method = b"POST";
        let url = "https://devnet-rpc-1.icebergnodes.io";
        let data = r#"{"id":1, "jsonrpc":"2.0", "method": "state_getStorage", "params": ["0x5c0d1176a568c1f92944340dbfed9e9c530ebca703c85910e7164cb7d1c9e47b"]}"#;
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        
        let response = pink_extension::http_req!(method.to_vec(), url, data, headers);
    }
}
