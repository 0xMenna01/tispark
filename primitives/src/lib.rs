#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// Commit reveal primitives
pub mod commit_reveal;

/// Phala ISMP
pub mod state_proofs;

pub const MAX_COMMITMENT_SIZE: u32 = 2048 / 8;
pub const ALGO_SIZE: u32 = 256 / 8;
pub const IV_SIZE: u32 = 96 / 8;
pub const METADATA_SIZE: u32 = 1024 / 8;
