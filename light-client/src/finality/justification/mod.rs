/// Lifted directly from [`finality_aleph::justification`](https://github.com/Cardinal-Cryptography/aleph-node/blob/main/finality-aleph/src/justification/mod.rs)
use crate::consensus::ALEPH_ENGINE_ID;
use codec::{Decode, Encode};
pub use compatibility::{backwards_compatible_decode, versioned_encode, Error as DecodeError};
use sp_runtime::Justification;

use super::crypto::{AlephSignature, AuthoritySignature, SignatureSet};
mod compatibility;

#[derive(Encode, Eq, Decode, PartialEq, Debug, Copy, Clone)]
pub struct Version(pub u16);

const LOG_TARGET: &str = "aleph-justification";

/// A proof of block finality, currently in the form of a sufficiently long list of signatures or a
/// sudo signature of a block for emergency finalization.
#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub enum AlephJustification {
    CommitteeMultisignature(SignatureSet<AlephSignature>),
    EmergencySignature(AuthoritySignature),
}

impl From<AlephJustification> for Justification {
    fn from(val: AlephJustification) -> Self {
        (ALEPH_ENGINE_ID, versioned_encode(val))
    }
}
