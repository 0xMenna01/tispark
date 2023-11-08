use super::types::{AlephNodeIndex, NodeCount, PartialMultisignature, Signature, SignatureSet};
use alloc::boxed::Box;
use codec::{Decode, Encode};
use pink_extension::{chain_extension::SigType, ext as contract_ext};
use scale_info::TypeInfo;
use sp_core::crypto::KeyTypeId;
use sp_runtime::RuntimeAppPublic;

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"alp0");

mod app {
    use sp_application_crypto::{app_crypto, ed25519};
    app_crypto!(ed25519, super::KEY_TYPE);
}

sp_application_crypto::with_pair! {
    pub type AuthorityPair = app::Pair;
}
pub type AuthoritySignature = app::Signature;
pub type AuthorityId = app::Public;

/// Verify the signature given an authority id.
pub fn verify(authority: &AuthorityId, message: &[u8], signature: &AlephSignature) -> bool {
    authority.verify(&message, &signature.get())
}

/// Verify the signature given an authority id from a phat contract
pub fn verify_from_contract(
    authority: &AuthorityId,
    message: &[u8],
    signature: &AlephSignature,
) -> bool {
    let key = authority.to_raw_vec();
    let signature = signature.get().to_vec();
    contract_ext().verify(SigType::Ed25519, &key, message, &signature)
}

/// Wrapper for `SignatureSet` to be able to implement both legacy and current `PartialMultisignature` trait.
/// Inner `SignatureSet` is imported from `aleph_bft_crypto` with fixed version for compatibility reasons:
/// this is also used in the justification which already exist in our chain history and we
/// need to be careful with changing this. (lifted from aleph repository)
#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode, TypeInfo)]
pub struct AlephSignatureSet<Signature>(pub SignatureSet<Signature>);

impl<S: Clone> AlephSignatureSet<S> {
    pub fn size(&self) -> NodeCount {
        self.0.size().into()
    }

    pub fn with_size(len: NodeCount) -> Self {
        AlephSignatureSet(SignatureSet::with_size(len))
    }

    pub fn iter(&self) -> impl Iterator<Item = (AlephNodeIndex, &S)> {
        self.0.iter().map(|(idx, s)| (idx.into(), s))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (AlephNodeIndex, &mut S)> {
        self.0.iter_mut().map(|(idx, s)| (idx.into(), s))
    }

    pub fn add_signature(self, signature: &S, index: AlephNodeIndex) -> Self
    where
        S: Signature,
    {
        AlephSignatureSet(self.0.add_signature(signature, index.into()))
    }
}

impl<S: 'static> IntoIterator for AlephSignatureSet<S> {
    type Item = (AlephNodeIndex, S);
    type IntoIter = Box<dyn Iterator<Item = (AlephNodeIndex, S)>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.0.into_iter().map(|(idx, s)| (idx.into(), s)))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Hash, Decode, Encode, TypeInfo)]
pub struct AlephSignature(AuthoritySignature);

impl AlephSignature {
    pub fn get(&self) -> AuthoritySignature {
        self.0.clone()
    }
}

impl From<AuthoritySignature> for AlephSignature {
    fn from(authority_signature: AuthoritySignature) -> AlephSignature {
        AlephSignature(authority_signature)
    }
}

/// Old format of signatures, needed for backwards compatibility. (lifted from aleph repository)
#[derive(PartialEq, Eq, Clone, Debug, Decode, Encode)]
pub struct SignatureV1 {
    pub _id: AlephNodeIndex,
    pub sgn: AuthoritySignature,
}

impl From<SignatureV1> for AlephSignature {
    fn from(sig_v1: SignatureV1) -> AlephSignature {
        AlephSignature(sig_v1.sgn)
    }
}
