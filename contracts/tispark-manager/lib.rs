#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

// pink_extension is short for Phala ink! extension
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod tispark_manager {
    use super::pink;
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};
    use utils::{
        types::{AccessControl, ContracId, SudoAccount},
        ContractRef,
    };

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    #[ink(storage)]
    pub struct TisparkManager {
        /// Tispark contract reference
        client: ContractRef,
        admin: SudoAccount,
    }

    impl TisparkManager {
        /// Constructor to initializes your contract
        #[ink(constructor)]
        pub fn new(id: ContracId) -> Self {
            let admin = pink::env().caller();
            let admin = SudoAccount::new(Some(admin));

            Self {
                client: ContractRef::new(id),
                admin,
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

        #[ink(message)]
        pub fn get_client(&self) -> ContracId {
            self.client.get()
        }
    }
}
