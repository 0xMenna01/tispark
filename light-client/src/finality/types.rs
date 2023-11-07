use alloc::{boxed::Box, vec, vec::Vec};
use codec::{Codec, Decode, Encode, Error, Input, Output};
use derive_more::{From, Into};
use scale_info::prelude::ops::{Div, Mul};

/// The index of a node
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From, Into)]
pub struct AlephNodeIndex(pub usize);

impl Encode for AlephNodeIndex {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        (self.0 as u64).encode_to(dest);
    }
}

impl Decode for AlephNodeIndex {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        Ok(AlephNodeIndex(u64::decode(value)? as usize))
    }
}

impl From<AlephNodeIndex> for NodeIndex {
    fn from(idx: AlephNodeIndex) -> Self {
        NodeIndex(idx.0)
    }
}

impl From<NodeIndex> for AlephNodeIndex {
    fn from(idx: NodeIndex) -> Self {
        Self(idx.0)
    }
}

/// The index of a node
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From, Into)]
pub struct NodeIndex(pub usize);

impl Encode for NodeIndex {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        let val = self.0 as u64;
        let bytes = val.to_le_bytes();
        dest.write(&bytes);
    }
}

impl Decode for NodeIndex {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        let mut arr = [0u8; 8];
        value.read(&mut arr)?;
        let val: u64 = u64::from_le_bytes(arr);
        Ok(NodeIndex(val as usize))
    }
}

/// Indicates that an implementor has been assigned some index.
pub trait Index {
    fn index(&self) -> NodeIndex;
}

/// Node count. Right now it doubles as node weight in many places in the code, in the future we
/// might need a new type for that.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From, Into)]
pub struct NodeCount(pub usize);

// deriving Mul and Div is somehow cumbersome
impl Mul<usize> for NodeCount {
    type Output = Self;
    fn mul(self, rhs: usize) -> Self::Output {
        NodeCount(self.0 * rhs)
    }
}

impl Div<usize> for NodeCount {
    type Output = Self;
    fn div(self, rhs: usize) -> Self::Output {
        NodeCount(self.0 / rhs)
    }
}

impl NodeCount {
    pub fn into_range(self) -> core::ops::Range<NodeIndex> {
        core::ops::Range {
            start: 0.into(),
            end: self.0.into(),
        }
    }

    pub fn into_iterator(self) -> impl Iterator<Item = NodeIndex> {
        (0..self.0).map(NodeIndex)
    }
}

/// A container keeping items indexed by NodeIndex.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Decode, Encode, From)]
pub struct NodeMap<T>(Vec<Option<T>>);

impl<T> NodeMap<T> {
    /// Constructs a new node map with a given length.
    pub fn with_size(len: NodeCount) -> Self
    where
        T: Clone,
    {
        let v = vec![None; len.into()];
        NodeMap(v)
    }

    pub fn size(&self) -> NodeCount {
        self.0.len().into()
    }

    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, &T)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(idx, maybe_value)| Some((NodeIndex(idx), maybe_value.as_ref()?)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (NodeIndex, &mut T)> {
        self.0
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, maybe_value)| Some((NodeIndex(idx), maybe_value.as_mut()?)))
    }

    fn into_iter(self) -> impl Iterator<Item = (NodeIndex, T)>
    where
        T: 'static,
    {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(idx, maybe_value)| Some((NodeIndex(idx), maybe_value?)))
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.iter().map(|(_, value)| value)
    }

    pub fn into_values(self) -> impl Iterator<Item = T>
    where
        T: 'static,
    {
        self.into_iter().map(|(_, value)| value)
    }

    pub fn get(&self, node_id: NodeIndex) -> Option<&T> {
        self.0[node_id.0].as_ref()
    }

    pub fn insert(&mut self, node_id: NodeIndex, value: T) {
        self.0[node_id.0] = Some(value)
    }

    pub fn to_subset(&self) -> NodeSubset {
        NodeSubset(self.0.iter().map(Option::is_some).collect())
    }

    pub fn item_count(&self) -> usize {
        self.iter().count()
    }
}

impl<T: 'static> IntoIterator for NodeMap<T> {
    type Item = (NodeIndex, T);
    type IntoIter = Box<dyn Iterator<Item = (NodeIndex, T)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.into_iter())
    }
}

impl<'a, T> IntoIterator for &'a NodeMap<T> {
    type Item = (NodeIndex, &'a T);
    type IntoIter = Box<dyn Iterator<Item = (NodeIndex, &'a T)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

impl<'a, T> IntoIterator for &'a mut NodeMap<T> {
    type Item = (NodeIndex, &'a mut T);
    type IntoIter = Box<dyn Iterator<Item = (NodeIndex, &'a mut T)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter_mut())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct NodeSubset(bit_vec::BitVec<u32>);

impl NodeSubset {
    pub fn with_size(capacity: NodeCount) -> Self {
        NodeSubset(bit_vec::BitVec::from_elem(capacity.0, false))
    }

    pub fn insert(&mut self, i: NodeIndex) {
        self.0.set(i.0, true);
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn elements(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, b)| if b { Some(i.into()) } else { None })
    }

    pub fn len(&self) -> usize {
        self.elements().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Encode for NodeSubset {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        (self.0.len() as u32).encode_to(dest);
        self.0.to_bytes().encode_to(dest);
    }
}

impl Decode for NodeSubset {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let capacity = u32::decode(input)? as usize;
        let bytes = Vec::decode(input)?;
        let mut bv = bit_vec::BitVec::from_bytes(&bytes);
        // Length should be capacity rounded up to the closest multiple of 8
        if bv.len() != 8 * ((capacity + 7) / 8) {
            return Err(Error::from(
                "Length of bitvector inconsistent with encoded capacity.",
            ));
        }
        while bv.len() > capacity {
            if bv.pop() != Some(false) {
                return Err(Error::from(
                    "Non-canonical encoding. Trailing bits should be all 0.",
                ));
            }
        }
        bv.truncate(capacity);
        Ok(NodeSubset(bv))
    }
}

/// The type used as a signature.
///
/// The Signature typically does not contain the index of the node who signed the data.
pub trait Signature: Clone + Codec + Send + Sync + Eq + 'static {}

impl<T: Clone + Codec + Send + Sync + Eq + 'static> Signature for T {}

/// A type to which signatures can be aggregated.
///
/// Any signature can be added to multisignature.
/// After adding sufficiently many signatures, the partial multisignature becomes a "complete"
/// multisignature.
/// Whether a multisignature is complete, can be verified with [`MultiKeychain::is_complete`] method.
/// The signature and the index passed to the `add_signature` method are required to be valid.
pub trait PartialMultisignature: Signature {
    type Signature: Signature;
    /// Adds the signature.
    #[must_use = "consumes the original and returns the aggregated signature which should be used"]
    fn add_signature(self, signature: &Self::Signature, index: NodeIndex) -> Self;
}

/// A set of signatures of a subset of nodes serving as a (partial) multisignature
pub type SignatureSet<S> = NodeMap<S>;

impl<S: Signature> PartialMultisignature for SignatureSet<S> {
    type Signature = S;

    #[must_use = "consumes the original and returns the aggregated signature which should be used"]
    fn add_signature(mut self, signature: &Self::Signature, index: NodeIndex) -> Self {
        self.insert(index, signature.clone());
        self
    }
}
