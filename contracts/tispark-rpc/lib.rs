#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod types;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod tispark_rpc {
    use crate::types::{FinalizedBlockHash, SignedBlock};

    use super::pink;
    use alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};
    use tispark_client::message::ConsensusStateParams;
    use utils::types::{AccessControl, ContracId, SudoAccount};

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        RequestFailed,
        InvalidBody,
        InvalidHexData,
        HexStringOutOfBounds,
        DigestItemMissing,
        U32ConversionError,
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
        pub fn new() -> Self {
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
            Ok(())
        }

        fn get_finalized_head(&self) -> Result<String> {
            let data =
                r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getFinalizedHead","params":[]}"#
                    .to_string()
                    .into_bytes();
            let resp_body = call_rpc(&self.rpc_node, data)?;
            let (finalized_block, _): (FinalizedBlockHash, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            Ok(finalized_block.result.to_string())
        }

        #[ink(message)]
        pub fn get_consensus_proof(
            &self,
            hash: String,
        ) -> Result<(ConsensusStateParams, Vec<u8>)> {
            let data = format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"chain_getBlock","params":["{}"]}}"#,
                hash
            )
            .into_bytes();
            let resp_body = call_rpc(&self.rpc_node, data)?;

            let (block, _): (SignedBlock, usize) =
                serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

            // Block Header
            let block_number = extract_hex_from(2, block.result.block.header.number)?;
            let block_number =
                u32::from_str_radix(&block_number, 16).map_err(|_| Error::U32ConversionError)?;
            let extrinsics_root = extract_hex_from(2, block.result.block.header.extrinsicsRoot)?;
            let state_root = extract_hex_from(2, block.result.block.header.stateRoot)?;
            let parent_hash = extract_hex_from(2, block.result.block.header.parentHash)?;
            // Digest Items
            let aura_pre_runtime = block.result.block.header.digest.logs.get(0);
            let aura_pre_runtime = extract_digest(14, aura_pre_runtime)?;
            let seal = block.result.block.header.digest.logs.get(1);
            let seal = extract_digest(16, seal)?;
            let justifications = block.result.justifications;

            let consensus_params = ConsensusStateParams {
                block: block_number.clone(),
                extrinsics_root,
                state_root,
                parent_hash,
                aura_pre_runtime,
                seal,
            };
            Ok((consensus_params, justifications.get(0).unwrap().get(1).unwrap().to_owned()))
        }
    }

    fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<Vec<u8>> {
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

    fn extract_hex_from(start_index: usize, hex_string: &str) -> Result<String> {
        if !hex_string.starts_with("0x") {
            return Err(Error::InvalidHexData);
        }
        if start_index >= hex_string.len() {
            return Err(Error::HexStringOutOfBounds);
        }
        // 14
        let hex_string = &hex_string[start_index..];
        Ok(hex_string.to_string())
    }

    fn extract_digest(start_index: usize, hex_string: Option<&&str>) -> Result<String> {
        if let Some(digest) = hex_string {
            // extract the digest item
            let digest = extract_hex_from(start_index, digest)?;
            Ok(digest)
        } else {
            Err(Error::DigestItemMissing)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tispark_rpc::TisparkRpc;

    use super::*;
    use hex_literal::hex;
    use ink::env::Environment;
    use pink::chain_extension::{mock, HttpResponse};
    use pink_extension::PinkEnvironment;

    fn default_accounts() -> ink::env::test::DefaultAccounts<PinkEnvironment> {
        ink::env::test::default_accounts::<PinkEnvironment>()
    }

    #[ink::test]
    fn end_to_end() {
        let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
        ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);

        //get nonce
        mock::mock_http_request(|_| {
            HttpResponse::ok(br#"{"jsonrpc":"2.0","result":{"block":{"header":{"parentHash":"0x58f695d121e59758daabc104e11562b150be9a55dad690e0888b2183e983f750","number":"0x9e6b8","stateRoot":"0x55560f01595557360b71710ff25f2598c24eccfd36414c56479afdd63f4cb76f","extrinsicsRoot":"0xddbd663c7365766e04684c547614019c98463ca153ff9de26161a4d44418f2fe","digest":{"logs":["0x066175726120f88e5ee100000000","0x056175726101018ae5c8c9449bb4dcce12dcb52ae0ac10b4718a5c5a67a99244e77e5598899d1efc6b40e8c0b2bf9d6527ebd260dfff7e1f7d9fda2209a9623c238774126b198e"]}},"extrinsics":["0x280404000bf04f37288c01"]},"justifications":[[[70,82,78,75],[3,0,198,0,0,16,1,63,72,42,119,130,206,24,79,226,195,146,78,90,246,101,174,167,239,53,86,54,81,189,115,194,163,121,15,29,12,66,37,100,102,100,219,112,185,75,115,212,166,27,40,173,238,176,163,164,191,73,68,244,161,66,65,90,93,29,234,131,215,84,9,1,225,8,38,252,13,21,134,127,159,91,36,149,41,235,143,101,146,162,3,3,154,148,172,75,149,21,65,186,156,68,211,184,141,150,41,218,211,200,186,151,219,203,88,92,218,39,225,133,114,117,209,123,173,135,251,229,81,255,236,138,222,106,150,5,0,1,186,252,177,252,109,83,63,187,238,10,141,243,160,60,24,255,156,100,55,59,37,15,174,18,16,149,179,84,246,236,205,125,229,222,174,128,197,230,206,239,189,130,199,41,194,154,139,204,21,201,165,136,211,98,116,53,78,224,237,25,165,89,58,15]]]},"id":1}"#.to_vec())
        });

        let contract = TisparkRpc::new();
        let hash =
            String::from("0x67b5ddfeb077a2f6e0bbfa5d9e134940aaaacec8ea12ff3b8b007efb046bc011");
        assert!(contract.get_consensus_proof(hash).is_ok())
    }
}
