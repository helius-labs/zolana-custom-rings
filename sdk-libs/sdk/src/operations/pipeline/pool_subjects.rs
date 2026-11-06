//! Mirror `resolveSubjects` in `prover/circuits/policy/subjects.go`.

use custom_ring_interface::{domain, key_catalog::RecordPools};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use zolana_ring_client::{records::RecordPoolRead, rpc::SubjectListSalt};
use zolana_ring_member_registry::{RecordPool, TrackingRecord};
use zolana_ring_policy::{Member, RecordLists, SourceMap};

use crate::{
    request::{OwnerEntry, PoolEntry},
    RingError,
};

/// The key's width, an unopened pool where the key binds no root.
pub(crate) fn pool_at_width(
    read: Option<&RecordPoolRead>,
    width: usize,
) -> Result<RecordPool, RingError> {
    Ok(match read {
        Some(read) => read.pool().clone().padded(width)?,
        None => RecordPool::unopened(width)?,
    })
}

/// Distinct pool members in first use order, an absent subject takes index 0.
#[derive(Default)]
pub(crate) struct PoolSubjects {
    members: Vec<[u8; 32]>,
}

/// A read with no subject still opens one path, the proof folds every pool slot under the root.
const NO_SUBJECT: [[u8; 32]; 1] = [right_align_one()];

const fn right_align_one() -> [u8; 32] {
    let mut member = [0; 32];
    member[31] = 1;
    member
}

impl PoolSubjects {
    pub fn opened(&self) -> &[[u8; 32]] {
        match self.members.is_empty() {
            true => &NO_SUBJECT,
            false => &self.members,
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Index 0 outside the pool, read only for an opened member.
    pub fn position(&self, member: &[u8; 32]) -> u32 {
        self.members
            .iter()
            .position(|known| known == member)
            .unwrap_or(0) as u32
    }

    pub fn index(&mut self, member: Option<[u8; 32]>) -> u32 {
        let Some(member) = member else {
            return 0;
        };
        let index = match self.members.iter().position(|known| *known == member) {
            Some(index) => index,
            None => {
                self.members.push(member);
                self.members.len() - 1
            }
        };
        // At most `MAX_RING_MEMBER_PAGE_LIMIT` members, the pool read refuses more.
        index as u32
    }
}

/// Mirror `readSources` in `prover/circuits/policy/table.go`.
#[derive(Clone, Copy, Default)]
pub(crate) struct SourceGates {
    foreign: u16,
    salted: u16,
}

impl SourceGates {
    pub fn of(sources: &SourceMap) -> Self {
        let foreign = sources
            .slots()
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.registry != [0; 32])
            .fold(0, |bits, (slot, _)| bits | 1 << slot);
        Self {
            foreign,
            salted: sources.salted().bits(),
        }
    }

    pub const fn any_salted(self) -> bool {
        self.salted != 0
    }

    const fn any_foreign(self) -> bool {
        self.foreign != 0
    }

    const fn public_foreign(self) -> bool {
        self.foreign & !self.salted != 0
    }

    const fn salted_own(self) -> bool {
        self.salted & !self.foreign != 0
    }

    const fn salted_curated(self) -> bool {
        self.salted & self.foreign != 0
    }

    /// List `i + 1` reads the registry serving it.
    const fn served(self, own: u64, curator: u64) -> u64 {
        let foreign = self.foreign as u64;
        (own & !foreign) | (curator & foreign)
    }
}

#[derive(Default)]
pub(crate) struct KnownSalts(Vec<SubjectListSalt>);

#[derive(Clone, Copy)]
pub(crate) struct SaltedKey {
    pub list_salt: [u8; 32],
    pub key: [u8; 32],
}

impl KnownSalts {
    pub fn new(salts: Vec<SubjectListSalt>) -> Self {
        Self(salts)
    }

    /// `None` only with no tracking row.
    pub fn salted_key(
        &self,
        member: &[u8; 32],
        row: Option<&TrackingRecord>,
    ) -> Result<Option<SaltedKey>, RingError> {
        let Some(row) = row.filter(|row| row.nullifier_pk != ZERO_NULLIFIER_PUBKEY) else {
            return Ok(None);
        };
        let mut known = self
            .0
            .iter()
            .filter(|salt| salt.member == *member && salt.list_salt != [0; 32])
            .peekable();
        if known.peek().is_none() {
            return Err(RingError::ListSaltUnknown { member: *member });
        }
        let list_salt = known
            .map(|salt| salt.list_salt)
            .find(|salt| domain::list_tag(salt).is_ok_and(|tag| tag == row.list_tag))
            .ok_or(RingError::ListSaltMismatch { member: *member })?;
        let key = Member::salted(&Member::from_bytes(*member)?, &list_salt)?;
        Ok(Some(SaltedKey {
            list_salt,
            key: *key.as_bytes(),
        }))
    }
}

pub(crate) struct OwnerQuery {
    pub member: [u8; 32],
    /// Read only on a table with a salted list.
    pub tracking: u32,
    /// `None` with no tracking row.
    pub salted: Option<SaltedKey>,
}

#[derive(Default)]
pub(crate) struct RecordPlan {
    gates: SourceGates,
    pub own: PoolSubjects,
    pub curator: PoolSubjects,
    salted_keys: Vec<([u8; 32], [u8; 32])>,
}

impl RecordPlan {
    pub fn new(gates: SourceGates) -> Self {
        Self {
            gates,
            ..Self::default()
        }
    }

    pub fn owner(&mut self, query: OwnerQuery) -> OwnerEntry {
        let OwnerQuery {
            member,
            tracking,
            salted,
        } = query;
        let gates = self.gates;
        let entry = PoolEntry {
            own: self.own.index(Some(member)),
            curator: [self.curator.index(gates.public_foreign().then_some(member))],
        };
        let salted_key = salted.map(|salted| salted.key);
        if let Some(key) = salted_key {
            self.salted_keys.push((member, key));
        }
        OwnerEntry {
            entry,
            tracking,
            list_salt: salted.map_or([0; 32], |salted| salted.list_salt),
            own_salted: self.own.index(salted_key.filter(|_| gates.salted_own())),
            curator_salted: [self
                .curator
                .index(salted_key.filter(|_| gates.salted_curated()))],
        }
    }

    pub fn asset(&mut self, asset: [u8; 32]) -> PoolEntry {
        PoolEntry {
            own: self.own.index(Some(asset)),
            curator: [self
                .curator
                .index(self.gates.any_foreign().then_some(asset))],
        }
    }

    /// Public assets resolve in the own pool alone.
    pub fn public_asset(&mut self, asset: [u8; 32]) -> u32 {
        self.own.index(Some(asset))
    }

    pub fn pools(&self, tracking: &PoolSubjects) -> RecordPools {
        RecordPools {
            own: self.own.len(),
            curator: self.curator.len(),
            tracking: tracking.len(),
        }
    }

    /// Mirror `sourceView.lists` over the salted record.
    pub fn lists(
        &self,
        member: &[u8; 32],
        own: impl Fn(&[u8; 32]) -> u64,
        curator: impl Fn(&[u8; 32]) -> u64,
    ) -> RecordLists {
        let salted = self
            .salted_keys
            .iter()
            .find(|(owner, _)| owner == member)
            .map_or(0, |(_, key)| self.gates.served(own(key), curator(key)));
        RecordLists {
            own: own(member),
            curator: curator(member),
            salted,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/operations/pool_subjects.rs"]
mod tests;
