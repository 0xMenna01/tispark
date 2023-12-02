use alloc::vec::Vec;
use scale::Encode;
use serde::Deserialize;

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct FinalizedBlockHash<'a> {
    pub jsonrpc: &'a str,
    pub result: &'a str,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct SignedBlock<'a> {
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub result: BlockData<'a>,
    pub id: u32,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct BlockData<'a> {
    #[serde(borrow)]
    pub block: Block<'a>,
    pub justifications: Vec<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct Block<'a> {
    #[serde(borrow)]
    pub header: Header<'a>,
    #[serde(borrow)]
    pub extrinsics: Vec<&'a str>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
pub struct Header<'a> {
    pub parentHash: &'a str,
    pub number: &'a str,
    pub stateRoot: &'a str,
    pub extrinsicsRoot: &'a str,
    #[serde(borrow)]
    pub digest: Digest<'a>,
}

#[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
#[serde(bound(deserialize = "Vec<&'a str>: Deserialize<'de>"))]
pub struct Digest<'a> {
    #[serde(borrow)]
    pub logs: Vec<&'a str>,
}
