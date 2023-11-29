use ink::primitives::AccountId;

use super::{consensus::AuthorityId, ContractError, Result as ContractResult};

pub struct NoControl;
pub struct Control(AccountId);
pub struct ControlVerify {
    control: AccountId,
    verify: AccountId,
}

pub struct AccessControl<T> {
    phase: T,
}

impl AccessControl<NoControl> {
    pub fn new(account: Option<AuthorityId>) -> AccessControl<Control> {
        AccessControl {
            phase: Control(account.expect("Expected a sudo account")),
        }
    }
}

impl AccessControl<Control> {
    pub fn caller(self, caller: AccountId) -> AccessControl<ControlVerify> {
        AccessControl {
            phase: ControlVerify {
                control: self.phase.0,
                verify: caller,
            },
        }
    }
}

impl AccessControl<ControlVerify> {
    pub fn verify(&self) -> ContractResult<()> {
        if self.phase.control == self.phase.verify {
            Ok(())
        } else {
            Err(ContractError::BadOrigin)
        }
    }
}
