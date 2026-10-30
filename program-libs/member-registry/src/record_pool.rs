//! The record pool a policy proof opens, mirror `prover/circuits/policy/record_pool.go`
//! and `prover/circuits/registry/shared_path.go`.

use custom_ring_interface::{MEMBER_REGISTRY_CAPACITY, QUAD_ARITY, QUAD_HEIGHT};

use crate::{
    path::{check_index, children, quad_node, NodePosition},
    MemberRecord, RecordTreeError,
};

/// The tree level `levels` below the root, `4^levels` nodes wide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Canopy {
    levels: usize,
}

impl Canopy {
    /// The narrowest canopy over `openings` paths, mirror `registry.NewSharedQuadProof`.
    pub fn covering(openings: usize) -> Result<Self, RecordTreeError> {
        if openings == 0 || openings as u64 > MEMBER_REGISTRY_CAPACITY {
            return Err(RecordTreeError::PoolCapacity);
        }
        let levels = (0..=QUAD_HEIGHT)
            .find(|levels| QUAD_ARITY.pow(*levels as u32) >= openings)
            .ok_or(RecordTreeError::PoolCapacity)?;
        Ok(Self { levels })
    }

    pub const fn width(self) -> usize {
        1 << (2 * self.levels)
    }

    /// The sibling levels each path keeps below the canopy.
    pub const fn path_levels(self) -> usize {
        QUAD_HEIGHT - self.levels
    }

    pub fn positions(self) -> impl Iterator<Item = NodePosition> {
        let level = self.path_levels();
        (0..self.width() as u64).map(move |position| NodePosition { level, position })
    }

    fn of_width(width: usize) -> Result<Self, RecordTreeError> {
        let canopy = Self::covering(width).map_err(|_| RecordTreeError::PoolShape)?;
        match canopy.width() == width {
            true => Ok(canopy),
            false => Err(RecordTreeError::PoolShape),
        }
    }
}

/// A leaf index and the siblings of its lowest [`Canopy::path_levels`] levels, leaf level first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPath {
    pub index: u64,
    pub siblings: Vec<[[u8; 32]; QUAD_ARITY - 1]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedProof {
    pub canopy: Vec<[u8; 32]>,
    pub paths: Vec<SharedPath>,
}

/// `record_index` names the subject's record in [`RecordPool::records`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSubject {
    pub member: [u8; 32],
    pub record_index: u32,
}

/// Path `i` of `proof` opens `records[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordPool {
    pub records: Vec<MemberRecord>,
    pub proof: SharedProof,
    pub subjects: Vec<PoolSubject>,
}

impl RecordPool {
    /// Refuses unless every record opens under `root` and each subject's record is its own or brackets it.
    pub fn verify(&self, root: &[u8; 32]) -> Result<(), RecordTreeError> {
        let leaves = self
            .records
            .iter()
            .map(MemberRecord::hash)
            .collect::<Result<Vec<_>, _>>()?;
        self.proof.verify(root, &leaves)?;
        self.subjects.iter().try_for_each(|subject| {
            let record = self
                .records
                .get(subject.record_index as usize)
                .ok_or(RecordTreeError::PoolShape)?;
            match record.member == subject.member || record.brackets(&subject.member) {
                true => Ok(()),
                false => Err(RecordTreeError::NotBracketed),
            }
        })
    }

    /// Repeats the records and the subjects cyclically to the `openings` a key's pool takes.
    pub fn padded(self, openings: usize) -> Result<Self, RecordTreeError> {
        if self.records.is_empty()
            || self.subjects.is_empty()
            || self.records.len() > openings
            || self.subjects.len() > openings
        {
            return Err(RecordTreeError::PoolCapacity);
        }
        if Canopy::covering(openings)?.width() != self.proof.canopy.len() {
            return Err(RecordTreeError::PoolShape);
        }
        Ok(Self {
            records: cycled(&self.records, openings),
            proof: SharedProof {
                paths: cycled(&self.proof.paths, openings),
                canopy: self.proof.canopy,
            },
            subjects: cycled(&self.subjects, openings),
        })
    }
}

impl SharedProof {
    /// Refuses unless the canopy roots `root` and path `i` folds `leaves[i]` into it.
    pub fn verify(&self, root: &[u8; 32], leaves: &[[u8; 32]]) -> Result<(), RecordTreeError> {
        let canopy = Canopy::of_width(self.canopy.len())?;
        if self.paths.len() != leaves.len() {
            return Err(RecordTreeError::PoolShape);
        }
        if canopy_root(&self.canopy)? != *root {
            return Err(RecordTreeError::RootMismatch);
        }
        self.paths.iter().zip(leaves).try_for_each(|(path, leaf)| {
            if path.siblings.len() != canopy.path_levels() {
                return Err(RecordTreeError::PoolShape);
            }
            let node = path.fold(*leaf)?;
            match self.canopy.get(node.position) == Some(&node.value) {
                true => Ok(()),
                false => Err(RecordTreeError::RootMismatch),
            }
        })
    }
}

struct CanopyNode {
    position: usize,
    value: [u8; 32],
}

impl SharedPath {
    fn fold(&self, leaf: [u8; 32]) -> Result<CanopyNode, RecordTreeError> {
        check_index(self.index)?;
        let mut node = leaf;
        for (level, siblings) in self.siblings.iter().enumerate() {
            let digit = NodePosition::on_path(self.index, level).digit();
            node = quad_node(&children(node, digit, siblings))?;
        }
        Ok(CanopyNode {
            position: NodePosition::on_path(self.index, self.siblings.len()).position as usize,
            value: node,
        })
    }
}

fn cycled<T: Clone>(values: &[T], length: usize) -> Vec<T> {
    values.iter().cycle().take(length).cloned().collect()
}

fn canopy_root(nodes: &[[u8; 32]]) -> Result<[u8; 32], RecordTreeError> {
    let mut level = nodes.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(QUAD_ARITY)
            .map(|chunk| {
                let children = chunk.try_into().map_err(|_| RecordTreeError::PoolShape)?;
                Ok(quad_node(children)?)
            })
            .collect::<Result<_, RecordTreeError>>()?;
    }
    level.first().copied().ok_or(RecordTreeError::PoolShape)
}
