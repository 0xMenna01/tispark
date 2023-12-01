#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

mod types;

#[pink::contract(env=PinkEnvironment)]
mod tispark_manager {
    use super::{pink, types::*};
    use alloc::{string::String, vec::Vec};
    use ink::env::{
        call::{build_call, ExecutionInput, Selector},
        DefaultEnvironment,
    };
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BetRequestError,
        DiceOutcomeDecodeError,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    type Contract

    #[ink(storage)]
    pub struct TisparkManager {
        game: DiceGame,
    }

    #[ink::storage_item]
    #[derive(Debug)]
    pub struct TisparkManager {
        client: String,
        admin: GameId,
    }

    impl DemoGame {
        /// Constructor to initializes your contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                game: DiceGame {
                    name: String::from("Dice Game"),
                    id: 0,
                },
            }
        }

        #[ink(message)]
        // make the construction of BetCommitRequest more trnsparent, implement a method in primitives that takes generic Bet type and Outcome and constructs a BetCommitment Request
        pub fn demo(&self) -> Result<()> {
            Ok(())
        }
    }
}
