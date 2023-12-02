#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod types;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod tispark_rpc {
    use crate::types::{Block, FinalizedBlockHash};

    use super::pink;
    use alloc::{string::String, vec::Vec};
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};
    use tispark_client::message::ConsensusProofParams;
    use utils::{
        types::{AccessControl, ContracId, SudoAccount},
        ContractRef,
    };

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        RequestFailed,
        InvalidBody,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    /// Simple rpc call implementation
    // todo - before production: implement a dedicated web server with an apikey that in one call returs all info
    #[ink(storage)]
    pub struct TisparkRpc {
        admin: SudoAccount,
        rpc_node: String,
    }

    impl TisparkRpc {
        /// Constructor to initializes your contract
        #[ink(constructor)]
        pub fn new(id: ContracId) -> Self {
            let admin = pink::env().caller();
            let admin = SudoAccount::new(Some(admin));

            let http_endpoint = String::from("https://devnet-rpc-1.icebergnodes.io/");
            Self {
                admin,
                rpc_node: http_endpoint,
            }
        }

        fn ensure_owner(&self) -> Result<()> {
            AccessControl::new(self.admin.get())
                .caller(self.env().caller())
                .verify()
                .map_err(|_| Error::BadOrigin)
        }

        #[ink(message)]
        pub fn update_client(&mut self, id: ContracId) -> Result<()> {
            self.ensure_owner()?;
            // update tispark client
            self.client = ContractRef::new(id);
            Ok(())
        }

        fn get_finalized_head(&self) -> Result<String> {
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getFinalizedHead","params":[]}"#
                    .to_string()
                    .into_bytes();
            let resp_body = self.call_rpc(&self.rpc_node, data)?;
            let (finalized_block, _): (FinalizedBlockHash, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            Ok(finalized_block.result.to_string())
        }

        fn get_consensus_proof(&self, hash: &String) -> Result<ConsensusProofParams> {
            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"chain_getBlock","params":["{}"]}}"#,
                hash
            )
            .into_bytes();
            let resp_body = self.call_rpc(&self.rpc_node, data)?;

            let (block, _): (Block, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;
        }

        fn call_rpc(&self, rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];

            let response = pink::http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }

            let body = response.body;
            Ok(body)
        }
    }
}
