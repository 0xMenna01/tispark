use super::{Error, FinalizedBlockHash, Result, SignedBlock, Utils};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};
use hex::FromHex;
use light_client::{consensus::AlephLogs, Hash};
use scale::{Decode, Encode};
use utils::types::AuthorityId;

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusStateParams {
    pub block: u32,
    pub extrinsics_root: String,
    pub state_root: String,
    pub parent_hash: String,
    pub aura_pre_runtime: String,
    pub seal: String,
}

impl<'a> TryFrom<SignedBlock<'a>> for ConsensusStateParams {
    type Error = Error;
    fn try_from(block: SignedBlock) -> Result<Self> {
        // Block Header
        let block_number = Utils::extract_hex_from(2, block.result.block.header.number)?;
        let block_number =
            u32::from_str_radix(&block_number, 16).map_err(|_| Error::U32ConversionError)?;
        let extrinsics_root = Utils::extract_hex_from(2, block.result.block.header.extrinsicsRoot)?;
        let state_root = Utils::extract_hex_from(2, block.result.block.header.stateRoot)?;
        let parent_hash = Utils::extract_hex_from(2, block.result.block.header.parentHash)?;
        // Digest Items
        let aura_pre_runtime = block.result.block.header.digest.logs.get(0);
        let aura_pre_runtime = Utils::extract_digest(14, aura_pre_runtime)?;
        let seal = block.result.block.header.digest.logs.get(1);
        let seal = Utils::extract_digest(16, seal)?;

        Ok(Self {
            block: block_number.clone(),
            extrinsics_root,
            state_root,
            parent_hash,
            aura_pre_runtime,
            seal,
        })
    }
}

pub struct ConsensusHandler<'a> {
    url: &'a String,
}

impl<'a> ConsensusHandler<'a> {
    pub fn new(url: &'a String) -> Self {
        Self { url }
    }

    pub fn get_consensus_proof(&self, hash: &String) -> Result<(ConsensusStateParams, Vec<u8>)> {
        let data = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"chain_getBlock","params":["{}"]}}"#,
            hash
        )
        .into_bytes();
        let resp_body = Utils::call_rpc(&self.url, data)?;

        let (block, _): (SignedBlock, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

        let justifications = get_justifications(&block.result.justifications)?;
        let consensus_state = ConsensusStateParams::try_from(block)?;
        Ok((consensus_state, justifications))
    }

    pub fn get_finalized_head(&self) -> Result<String> {
        let data = r#"{"id":1, "jsonrpc":"2.0", "method": "chain_getFinalizedHead","params":[]}"#
            .to_string()
            .into_bytes();
        let resp_body = Utils::call_rpc(&self.url, data)?;
        let (finalized_block, _): (FinalizedBlockHash, usize) =
            serde_json_core::from_slice(&resp_body).or(Err(Error::InvalidBody))?;

        Ok(finalized_block.result.to_string())
    }
}

fn get_justifications(justifications_response: &Vec<Vec<Vec<u8>>>) -> Result<Vec<u8>> {
    if let Some(value) = justifications_response.get(0) {
        let justifications = value.get(1).ok_or(Error::InvalidJustificationsFormat)?;
        Ok(justifications.to_owned())
    } else {
        Err(Error::InvalidJustificationsFormat)
    }
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ConsensusProofParams {
    pub untrusted_authorities: Vec<AuthorityId>,
    pub justifications: Vec<u8>,
    pub consensus_state: ConsensusStateParams,
}

impl ConsensusProofParams {
    pub fn state_root(&self) -> Result<Hash> {
        let state_root =
            Vec::from_hex(&self.consensus_state.state_root).map_err(|_| Error::InvalidHexData)?;

        Ok(Hash::from_slice(&state_root))
    }

    pub fn block(&self) -> u32 {
        self.consensus_state.block.clone()
    }

    pub fn extrinsics_root(&self) -> Result<Hash> {
        let extrinsics_hash = Vec::from_hex(&self.consensus_state.extrinsics_root)
            .map_err(|_| Error::InvalidHexData)?;

        Ok(Hash::from_slice(&extrinsics_hash))
    }

    pub fn parent_hash(&self) -> Result<Hash> {
        let parent_hash =
            Vec::from_hex(&self.consensus_state.parent_hash).map_err(|_| Error::InvalidHexData)?;

        Ok(Hash::from_slice(&parent_hash))
    }

    pub fn logs(&self) -> AlephLogs {
        AlephLogs {
            aura_pre_runtime: self.consensus_state.aura_pre_runtime.clone(),
            seal: self.consensus_state.seal.clone(),
        }
    }
}
