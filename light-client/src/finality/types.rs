//! Types common for current & legacy abft used across finality-aleph

use derive_more::{From, Into};
use scale::{Decode, Encode, Error, Input, Output};

/// The index of a node
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From, Into)]
pub struct NodeIndex(pub usize);

impl Encode for NodeIndex {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        (self.0 as u64).encode_to(dest);
    }
}

impl Decode for NodeIndex {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        Ok(NodeIndex(u64::decode(value)? as usize))
    }
}

/// Node count. Right now it doubles as node weight in many places in the code, in the future we
/// might need a new type for that.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, From, Into)]
pub struct NodeCount(pub usize);

impl From<NodeCount> for current_aleph_bft::NodeCount {
    fn from(count: NodeCount) -> Self {
        current_aleph_bft::NodeCount(count.0)
    }
}
impl From<NodeCount> for legacy_aleph_bft::NodeCount {
    fn from(count: NodeCount) -> Self {
        legacy_aleph_bft::NodeCount(count.0)
    }
}

impl From<legacy_aleph_bft::NodeCount> for NodeCount {
    fn from(count: legacy_aleph_bft::NodeCount) -> Self {
        Self(count.0)
    }
}

impl From<current_aleph_bft::NodeCount> for NodeCount {
    fn from(count: current_aleph_bft::NodeCount) -> Self {
        Self(count.0)
    }
}

impl From<NodeIndex> for current_aleph_bft::NodeIndex {
    fn from(idx: NodeIndex) -> Self {
        current_aleph_bft::NodeIndex(idx.0)
    }
}

impl From<NodeIndex> for legacy_aleph_bft::NodeIndex {
    fn from(idx: NodeIndex) -> Self {
        legacy_aleph_bft::NodeIndex(idx.0)
    }
}

impl From<legacy_aleph_bft::NodeIndex> for NodeIndex {
    fn from(idx: legacy_aleph_bft::NodeIndex) -> Self {
        Self(idx.0)
    }
}

impl From<current_aleph_bft::NodeIndex> for NodeIndex {
    fn from(idx: current_aleph_bft::NodeIndex) -> Self {
        Self(idx.0)
    }
}
