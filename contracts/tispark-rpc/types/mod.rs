use scale::Encode;
use serde::Deserialize;

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct FinalizedBlockHash<'a> {
    pub jsonrpc: &'a str,
    pub result: &'a str,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct Block<'a> {
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub result: BlockData<'a>,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct BlockData<'a> {
    #[serde(borrow)]
    pub header: BlockHeader<'a>,
    #[serde(borrow)]
    pub extrinsics: Vec<&'a str>,
    pub justifications: Vec<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct BlockHeader<'a> {
    pub parent_hash: &'a str,
    pub number: u32,
    pub state_root: &'a str,
    pub extrinsics_root: &'a str,
    #[serde(borrow)]
    pub digest: Logs<'a>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct Logs<'a> {
    #[serde(borrow)]
    pub logs: Vec<&'a str>,
}
