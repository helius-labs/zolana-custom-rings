//! Member record views as record tree types, every opening checked against its root.

use custom_ring_interface::{
    EscrowKey, QueueEntry, AUDIT_CIPHERTEXT_LEN, QUAD_ARITY, QUAD_HEIGHT, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use spr_hasher::{primitives::hash_bytes, HasherError};
use spr_keypair::X25519Pubkey;
use zolana_ring_indexer::rpc::{
    GetRingApplyProofInputsResponse, GetRingMemberRecordsResponse, GetRingRecordPoolResponse,
    GetStorageApplyProofInputsResponse, RingMemberOpening, RingMemberRecordView,
    RingRecordPathView, RingRecordWriteView, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_member_registry::{
    ApplyProofInputs, Canopy, MemberRecord, OpeningCheck, PoolSubject, QuadPath, RecordOpening,
    RecordPool, RecordWriteProofInput, SharedPath, SharedProof,
};
use zolana_ring_policy::ListId;

use crate::{AuditError, SealedNullifierKey};

/// A member's record, or the low record bracketing its absence, read under one root.
#[derive(Clone, PartialEq, Eq)]
pub struct MemberOpeningRead {
    pub opening: RecordOpening,
    /// The nullifier secret a registered member sealed to the auditor.
    pub sealed: Option<SealedNullifierKey>,
    /// The `RegisterKey` signer whose owner identity is the member.
    pub owner_pubkey: Option<Address>,
    /// The key the escrow key binds beside the sealed secret.
    pub nullifier_pk: Option<[u8; 32]>,
}

/// The chain-pinned newest registry root every record page is read under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryTip {
    pub root: [u8; 32],
    pub root_index: u8,
    pub next_index: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EscrowedRecord<'a> {
    pub record: &'a MemberRecord,
    pub path: &'a QuadPath,
    pub sealed: &'a SealedNullifierKey,
}

impl EscrowedRecord<'_> {
    /// What the escrow key binds beside the nullifier key.
    pub fn ct_hash(&self) -> Result<[u8; 32], HasherError> {
        ct_hash(self.sealed)
    }
}

/// Every record of a pool read under one root, each subject's own or the low record bracketing it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordPoolRead {
    pool: RecordPool,
    /// `sealed[i]` is the key `pool.records[i]` sealed to the auditor.
    sealed: Vec<Option<SealedNullifierKey>>,
}

/// One pool read of distinct `members` under `root`, its canopy sized for `openings` paths.
#[must_use]
pub struct RecordPoolCheck<'a> {
    pub response: &'a GetRingRecordPoolResponse,
    pub root: &'a [u8; 32],
    pub members: &'a [[u8; 32]],
    pub openings: usize,
}

impl RecordPoolCheck<'_> {
    pub fn verify(self) -> Result<RecordPoolRead, AuditError> {
        let response = self.response;
        let invalid = |_| AuditError::InvalidMemberRegistry;
        let canopy = Canopy::covering(self.openings).map_err(invalid)?;
        if response.root.root.0 != *self.root
            || response.canopy.len() != canopy.width()
            || response.subjects.len() != self.members.len()
        {
            return Err(AuditError::InvalidMemberRegistry);
        }
        let pool = RecordPool {
            records: response
                .records
                .iter()
                .map(|row| member_record(&row.record))
                .collect(),
            proof: SharedProof {
                canopy: response.canopy.iter().map(|node| node.0).collect(),
                paths: response
                    .records
                    .iter()
                    .map(|row| SharedPath {
                        index: row.path.index,
                        siblings: row
                            .path
                            .siblings
                            .iter()
                            .map(|level| level.clone().map(|sibling| sibling.0))
                            .collect(),
                    })
                    .collect(),
            },
            subjects: self
                .members
                .iter()
                .zip(&response.subjects)
                .map(|(member, record_index)| PoolSubject {
                    member: *member,
                    record_index: *record_index,
                })
                .collect(),
        };
        pool.verify(self.root).map_err(invalid)?;
        let sealed = response
            .records
            .iter()
            .map(|row| sealed_key(&row.record))
            .collect::<Result<_, _>>()?;
        Ok(RecordPoolRead { pool, sealed })
    }
}

impl RecordPoolRead {
    pub fn pool(&self) -> &RecordPool {
        &self.pool
    }

    /// The member's record, `None` for an absent member or one outside the pool.
    pub fn record(&self, member: &[u8; 32]) -> Option<&MemberRecord> {
        self.position(member)
            .and_then(|index| self.pool.records.get(index))
            .filter(|record| record.member == *member)
    }

    /// The ciphertext hash the member's escrow key binds beside `nullifier_pk`, `None` when it binds none.
    pub fn escrowed_ct_hash(
        &self,
        member: &[u8; 32],
        nullifier_pk: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let Some(index) = self.position(member) else {
            return Ok(None);
        };
        let (Some(record), Some(Some(sealed))) =
            (self.pool.records.get(index), self.sealed.get(index))
        else {
            return Ok(None);
        };
        match record.member == *member && escrow_binds(record, sealed, nullifier_pk)? {
            true => Ok(Some(ct_hash(sealed)?)),
            false => Ok(None),
        }
    }

    fn position(&self, member: &[u8; 32]) -> Option<usize> {
        self.pool
            .subjects
            .iter()
            .find(|subject| subject.member == *member)
            .map(|subject| subject.record_index as usize)
    }
}

impl RegistryTip {
    /// True only for every record from `start_index` to the page end, read under the tip.
    #[must_use]
    pub fn covers(&self, page: &GetRingMemberRecordsResponse, start_index: u64) -> bool {
        if start_index >= self.next_index {
            return false;
        }
        let end_index =
            start_index + (self.next_index - start_index).min(MAX_RING_MEMBER_PAGE_LIMIT);
        page.root.root.0 == self.root
            && page.root.root_index == self.root_index
            && page.root.next_index == self.next_index
            && page.records.len() == (end_index - start_index) as usize
            && page
                .records
                .iter()
                .enumerate()
                .all(|(offset, row)| row.path.index == start_index + offset as u64)
            && page.next_leaf_index == (end_index < self.next_index).then_some(end_index)
    }
}

impl MemberOpeningRead {
    /// `member`'s opening under `root`, refused unless the path reaches the root.
    pub fn verify(
        view: &RingMemberOpening,
        root: &[u8; 32],
        member: &[u8; 32],
    ) -> Result<Self, AuditError> {
        let record = member_record(&view.record);
        let path = quad_path(&view.path)?;
        let opening = match view.present {
            true => RecordOpening::Present { record, path },
            false => RecordOpening::Absent { low: record, path },
        };
        OpeningCheck {
            opening: &opening,
            root,
            member,
        }
        .verify()
        .map_err(|_| AuditError::InvalidMemberRegistry)?;
        // An absent member's opening carries the low record, its keys belong to another member.
        let registered = view.present.then_some(&view.record);
        Ok(Self {
            opening,
            sealed: registered.map(sealed_key).transpose()?.flatten(),
            owner_pubkey: registered
                .and_then(|record| record.owner_pubkey.as_ref())
                .map(|owner| owner.0),
            nullifier_pk: registered
                .and_then(|record| record.nullifier_pk.as_ref())
                .map(|key| key.0),
        })
    }

    /// The member's record, `None` for an absent member.
    pub fn record(&self) -> Option<&MemberRecord> {
        match &self.opening {
            RecordOpening::Present { record, .. } => Some(record),
            RecordOpening::Absent { .. } => None,
        }
    }

    pub fn listed(&self, list: ListId) -> bool {
        self.record()
            .is_some_and(|record| record.lists & list.record_bit() != 0)
    }

    /// `None` unless the record's escrow key binds `nullifier_pk` to the sealed secret.
    pub fn escrowed(
        &self,
        nullifier_pk: &[u8; 32],
    ) -> Result<Option<EscrowedRecord<'_>>, AuditError> {
        let (RecordOpening::Present { record, path }, Some(sealed)) = (&self.opening, &self.sealed)
        else {
            return Ok(None);
        };
        let binds = escrow_binds(record, sealed, nullifier_pk)?;
        Ok(binds.then_some(EscrowedRecord {
            record,
            path,
            sealed,
        }))
    }
}

fn escrow_binds(
    record: &MemberRecord,
    sealed: &SealedNullifierKey,
    nullifier_pk: &[u8; 32],
) -> Result<bool, AuditError> {
    let escrow_key = EscrowKey {
        nullifier_pk,
        ciphertext: &sealed.ciphertext,
    }
    .hash()?;
    Ok(escrow_key == record.escrow_key)
}

fn ct_hash(sealed: &SealedNullifierKey) -> Result<[u8; 32], HasherError> {
    hash_bytes(&sealed.ciphertext)
}

/// Ten levels of three siblings, leaf level first.
pub fn quad_path(view: &RingRecordPathView) -> Result<QuadPath, AuditError> {
    let levels: [[_; QUAD_ARITY - 1]; QUAD_HEIGHT] = view
        .siblings
        .iter()
        .map(|level| level.clone().map(|sibling| sibling.0))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| AuditError::InvalidMemberRegistry)?;
    Ok(QuadPath {
        index: view.index,
        siblings: levels,
    })
}

pub fn member_record(view: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        member: view.member.0,
        next: view.next.0,
        lists: view.lists,
        escrow_key: view.escrow_key.0,
        mint_policy: view.mint_policy,
    }
}

/// Both apply responses carry the same proof input fields.
macro_rules! proof_inputs {
    ($response:expr) => {
        Ok(ApplyProofInputs {
            old_root: $response.old_root.0,
            new_root: $response.new_root.0,
            old_next_index: $response.old_next_index,
            new_next_index: $response.new_next_index,
            chain_start: $response.chain_start.0,
            chain_end: $response.chain_end.0,
            writes: record_writes(&$response.writes)?,
        })
    };
}

/// The proof inputs of one application, in queue order.
pub fn apply_proof_inputs(
    response: &GetRingApplyProofInputsResponse,
) -> Result<ApplyProofInputs, AuditError> {
    proof_inputs!(response)
}

/// The proof inputs of one storage `Update`, in request order.
pub fn storage_apply_proof_inputs(
    response: &GetStorageApplyProofInputsResponse,
) -> Result<ApplyProofInputs, AuditError> {
    proof_inputs!(response)
}

fn record_writes(views: &[RingRecordWriteView]) -> Result<Vec<RecordWriteProofInput>, AuditError> {
    views.iter().map(record_write).collect()
}

/// The sealed nullifier secret a record view carries, refused when only half of it is present.
pub(crate) fn sealed_key(
    view: &RingMemberRecordView,
) -> Result<Option<SealedNullifierKey>, AuditError> {
    let (eph_pk, ciphertext) = match (&view.eph_pk, &view.ciphertext) {
        (Some(eph_pk), Some(ciphertext)) => (eph_pk, ciphertext),
        (None, None) => return Ok(None),
        _ => return Err(AuditError::InvalidMemberRegistry),
    };
    Ok(Some(SealedNullifierKey {
        eph_pk: X25519Pubkey::from_bytes(
            <[u8; TAGGED_X25519_KEY_LEN]>::try_from(eph_pk.0.as_slice())
                .map_err(|_| AuditError::InvalidMemberRegistry)?,
        )?,
        ciphertext: <[u8; AUDIT_CIPHERTEXT_LEN]>::try_from(ciphertext.0.as_slice())
            .map_err(|_| AuditError::InvalidMemberRegistry)?,
    }))
}

fn record_write(view: &RingRecordWriteView) -> Result<RecordWriteProofInput, AuditError> {
    Ok(RecordWriteProofInput {
        entry: QueueEntry {
            member: view.member.0,
            mask: view.mask,
            value: view.value,
            escrow_key: view.escrow_key.0,
            mint_policy: view.mint_policy,
        },
        exists: view.exists,
        old_next: view.old_next.0,
        old_lists: view.old_lists,
        old_escrow: view.old_escrow.0,
        old_mint_policy: view.old_mint_policy,
        slot: quad_path(&view.slot)?,
        low: member_record(&view.low),
        low_path: quad_path(&view.low_path)?,
    })
}
