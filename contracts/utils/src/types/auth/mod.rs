use ink::primitives::AccountId;

use super::AuthorityId;

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

pub struct PermissionDeined;

impl AccessControl<ControlVerify> {
    pub fn verify(&self) -> Result<(), PermissionDeined> {
        if self.phase.control == self.phase.verify {
            Ok(())
        } else {
            Err(PermissionDeined)
        }
    }
}
