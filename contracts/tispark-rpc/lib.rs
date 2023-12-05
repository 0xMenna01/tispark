#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

mod types;

// pink_extension is short for Phala ink! extension
pub use self::tispark_rpc::TiSparkRpcRef;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod tispark_rpc {
    use super::pink;
    use crate::types::{
        chain_state::{self, ChainStateHandler},
        consensus::{ConsensusHandler, ConsensusProofParams},
        CommitIdRequest, Error, ResponseStateProofRequest, Result, RevealResultRequest,
        StateRequestMetadata,
    };
    use alloc::string::String;
    use pink::PinkEnvironment;
    use utils::types::{AccessControl, SudoAccount};

    /// Simple rpc call implementation
    // todo - before production: implement a dedicated web server with an apikey that in one call returs all info
    #[ink(storage)]
    pub struct TiSparkRpc {
        admin: SudoAccount,
        rpc_node: String,
    }

    impl TiSparkRpc {
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
        pub fn reveal_request(&self, id: CommitIdRequest) -> Result<RevealResultRequest> {
            self.ensure_owner()?;

            let endpoint = &self.rpc_node;
            // Some state request metadata
            let meta = StateRequestMetadata {
                id: id.clone(),
                timestamp: self.env().block_timestamp(),
                height: self.env().block_number() as u64,
            };
            // Storage key associated to the commitment id that is the key of the substrate StorageMap
            let storage_key = chain_state::build_storage_key_for_commitment(id.as_ref());

            // Handler for consensus related rpc calls
            let consensus_handler = ConsensusHandler::new(endpoint);
            // Last finalized block
            let finalized_block = consensus_handler.get_finalized_head()?;
            // Consensus state and justifications
            let (consensus_state, justifications) =
                consensus_handler.get_consensus_proof(&finalized_block)?;

            // Handler for state rpc calls
            let state_handler = ChainStateHandler::new(endpoint);
            // Storage read proof
            let storage_proof = state_handler.get_read_proof(&storage_key, &finalized_block)?;
            // Untrasted authorities that eventually finalized the block
            let untrusted_authorities =
                state_handler.get_untrusted_authorities(&finalized_block)?;

            let consensus_proof = ConsensusProofParams {
                untrusted_authorities,
                justifications,
                consensus_state,
            };

            let request = ResponseStateProofRequest {
                meta,
                storage_proof,
                consensus_proof,
            };

            Ok(RevealResultRequest::try_from(request)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::ConsensusHandler;
    use pink::chain_extension::{mock, HttpResponse};

    #[ink::test]
    fn end_to_end_for_consensus_proof() {
        let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
        ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);

        let mock_endpoint = String::from("http://localhost:9933");

        mock::mock_http_request(|_| {
            HttpResponse::ok(br#"{"jsonrpc":"2.0","result":{"block":{"header":{"parentHash":"0x58f695d121e59758daabc104e11562b150be9a55dad690e0888b2183e983f750","number":"0x9e6b8","stateRoot":"0x55560f01595557360b71710ff25f2598c24eccfd36414c56479afdd63f4cb76f","extrinsicsRoot":"0xddbd663c7365766e04684c547614019c98463ca153ff9de26161a4d44418f2fe","digest":{"logs":["0x066175726120f88e5ee100000000","0x056175726101018ae5c8c9449bb4dcce12dcb52ae0ac10b4718a5c5a67a99244e77e5598899d1efc6b40e8c0b2bf9d6527ebd260dfff7e1f7d9fda2209a9623c238774126b198e"]}},"extrinsics":["0x280404000bf04f37288c01"]},"justifications":[[[70,82,78,75],[3,0,198,0,0,16,1,63,72,42,119,130,206,24,79,226,195,146,78,90,246,101,174,167,239,53,86,54,81,189,115,194,163,121,15,29,12,66,37,100,102,100,219,112,185,75,115,212,166,27,40,173,238,176,163,164,191,73,68,244,161,66,65,90,93,29,234,131,215,84,9,1,225,8,38,252,13,21,134,127,159,91,36,149,41,235,143,101,146,162,3,3,154,148,172,75,149,21,65,186,156,68,211,184,141,150,41,218,211,200,186,151,219,203,88,92,218,39,225,133,114,117,209,123,173,135,251,229,81,255,236,138,222,106,150,5,0,1,186,252,177,252,109,83,63,187,238,10,141,243,160,60,24,255,156,100,55,59,37,15,174,18,16,149,179,84,246,236,205,125,229,222,174,128,197,230,206,239,189,130,199,41,194,154,139,204,21,201,165,136,211,98,116,53,78,224,237,25,165,89,58,15]]]},"id":1}"#.to_vec())
        });

        let hash =
            String::from("0x67b5ddfeb077a2f6e0bbfa5d9e134940aaaacec8ea12ff3b8b007efb046bc011");

        assert!(ConsensusHandler::new(&mock_endpoint)
            .get_consensus_proof(&hash)
            .is_ok())
    }
}
