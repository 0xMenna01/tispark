use self::input::SensitiveData;
use crate::{
    commitment::ContractCommitment,
    message::{CommitmentRequest, ContractSignature, RevealCommitmentRequest, RevealResponse},
    ContractResult, ServiceId,
};
use alloc::vec::Vec;
use ink::{
    env::call::{ExecutionInput, Selector},
    primitives::AccountId,
};
use scale::{Decode, Encode};
use tispark_primitives::commit_reveal::{Commit, RevealProof};
use utils::{types::Hash, ContractRef};

pub enum Error {
    CommitmentError,
    RevealError,
    DecodingMetadataError,
}

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

#[derive(Default, Debug)]
pub struct VoidContract;
pub struct ClientLoaded(TisparkClientId);
pub struct ClientForService {
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
            contract: ContractRef::new(self.state.client),
            service: self.state.service_request,
        }
    }
}

#[derive(Debug)]
#[ink::storage_item]
pub struct TisparkContractRef {
    contract: ContractRef,
    service: ServiceId,
}

#[derive(Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct CommitmentPlainResponse<Metadata> {
    pub signature: ContractSignature,
    pub commit: Commit<Metadata>,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct RevealPlainResponse<Value> {
    pub result: Value,
    pub proof: RevealProof,
}

impl TisparkContractRef {
    pub fn commit<Value: Encode, Metadata: Encode + Decode>(
        &self,
        data: SensitiveData<Value, Metadata>,
    ) -> Result<CommitmentPlainResponse<Metadata>, Error> {
        let (data, metadata) = data.encode();
        // construct contract request
        let request = CommitmentRequest::new(data, metadata, self.service);

        let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!(
            "CommitRevealContractManager::commit"
        )))
        .push_arg(request);

        // make cross contract call
        let res: ContractResult<ContractCommitment> = self.contract.query(exec);

        res.map_or(Err(Error::CommitmentError), |contract_commitment| {
            Ok(CommitmentPlainResponse {
                signature: contract_commitment.signature,
                commit: contract_commitment
                    .commit
                    .decode()
                    .map_err(|_| Error::DecodingMetadataError)?,
            })
        })
    }

    pub fn reveal<Value: Decode>(
        &self,
        commit_id: Hash,
    ) -> Result<RevealPlainResponse<Value>, Error> {
        let request = RevealCommitmentRequest::new(commit_id, self.service);

        let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!(
            "CommitRevealContractManager::reveal"
        )))
        .push_arg(request);

        let res: ContractResult<RevealResponse> = self.contract.query(exec);

        res.map_or(Err(Error::RevealError), |reveal_response| {
            let encoded_res = reveal_response.result();
            let result: Value =
                Decode::decode(&mut &encoded_res[..]).map_err(|_| Error::DecodingMetadataError)?;

            Ok(RevealPlainResponse {
                result,
                proof: reveal_response.proof(),
            })
        })
    }
}
