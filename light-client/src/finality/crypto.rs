use super::types::{NodeCount, NodeIndex};
use aleph_bft_crypto::{PartialMultisignature, Signature};
use codec::{Decode, Encode};
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

/// Wrapper for `SignatureSet` to be able to implement both legacy and current `PartialMultisignature` trait.
/// Inner `SignatureSet` is imported from `aleph_bft_crypto` with fixed version for compatibility reasons:
/// this is also used in the justification which already exist in our chain history and we
/// need to be careful with changing this. (lifted from aleph repository)
#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode, TypeInfo)]
pub struct SignatureSet<Signature>(pub aleph_bft_crypto::SignatureSet<Signature>);

impl<S: Clone> SignatureSet<S> {
    pub fn size(&self) -> NodeCount {
        self.0.size().into()
    }

    pub fn with_size(len: NodeCount) -> Self {
        SignatureSet(legacy_aleph_bft::SignatureSet::with_size(len.into()))
    }

    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, &S)> {
        self.0.iter().map(|(idx, s)| (idx.into(), s))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (NodeIndex, &mut S)> {
        self.0.iter_mut().map(|(idx, s)| (idx.into(), s))
    }

    pub fn add_signature(self, signature: &S, index: NodeIndex) -> Self
    where
        S: Signature,
    {
        SignatureSet(self.0.add_signature(signature, index.into()))
    }
}

impl<S: 'static> IntoIterator for SignatureSet<S> {
    type Item = (NodeIndex, S);
    type IntoIter = Box<dyn Iterator<Item = (NodeIndex, S)>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.0.into_iter().map(|(idx, s)| (idx.into(), s)))
    }
}

impl<S: legacy_aleph_bft::Signature> legacy_aleph_bft::PartialMultisignature for SignatureSet<S> {
    type Signature = S;

    fn add_signature(
        self,
        signature: &Self::Signature,
        index: legacy_aleph_bft::NodeIndex,
    ) -> Self {
        SignatureSet::add_signature(self, signature, index.into())
    }
}

impl<S: legacy_aleph_bft::Signature> current_aleph_bft::PartialMultisignature for SignatureSet<S> {
    type Signature = S;

    fn add_signature(
        self,
        signature: &Self::Signature,
        index: current_aleph_bft::NodeIndex,
    ) -> Self {
        SignatureSet::add_signature(self, signature, index.into())
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
    pub _id: NodeIndex,
    pub sgn: AuthoritySignature,
}

impl From<SignatureV1> for AlephSignature {
    fn from(sig_v1: SignatureV1) -> AlephSignature {
        AlephSignature(sig_v1.sgn)
    }
}
