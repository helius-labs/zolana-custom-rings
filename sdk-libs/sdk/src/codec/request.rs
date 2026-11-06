//! The ring prover's request bodies, field for field the Go `prover/ring` params.

use custom_ring_interface::{RecordWrite, QUAD_ARITY};
use serde::{Serialize, Serializer};
use spr_hasher::primitives::right_align;
use spr_keypair::{PublicKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::SppProofOutputUtxo,
    utxo::{ProofInputUtxo, SppProofInputUtxo},
};
use zeroize::Zeroizing;
use zolana_ring_member_registry::{
    MemberRecord, QuadPath, RecordPool, RecordWriteProofInput, SharedProof, TrackingOpening,
    TrackingPool, TrackingRecord, TrackingWriteProofInput,
};
use zolana_ring_policy::{AssetLimits, EncodedRuleTable, SourceMap, MAX_SOURCES};
use zolana_ring_transaction::ClassifiedInput;

use crate::{prover::fe, RingError, REDACTED};

#[cfg(test)]
#[path = "../tests/rpc/request.rs"]
mod tests;

/// One transaction slot as SPP hashes it, its owner split into the identity and the nullifier key.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Opening {
    #[serde(with = "fe")]
    pub domain: [u8; 32],
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub owner_pk_hash: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
}

impl core::fmt::Debug for Opening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            domain,
            tree_id,
            owner_pk_hash,
            nullifier_pk,
            asset,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
            ring_program_id,
        } = self;
        f.debug_struct("Opening")
            .field("domain", domain)
            .field("tree_id", tree_id)
            .field("owner_pk_hash", owner_pk_hash)
            .field("nullifier_pk", nullifier_pk)
            .field("asset", asset)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .field("ring_program_id", ring_program_id)
            .finish()
    }
}

impl Opening {
    pub fn output(output: &SppProofOutputUtxo, tree_id: u16) -> Result<Self, RingError> {
        let owner = output.owner_address;
        Ok(Self::with_owner(
            ProofInputUtxo::try_from((output, tree_id))?,
            owner
                .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                .transpose()?
                .unwrap_or_default(),
            owner
                .map(|owner| owner.nullifier_pubkey)
                .unwrap_or_default(),
        ))
    }

    pub fn input(input: &SppProofInputUtxo) -> Result<Self, RingError> {
        let real = input.is_note();
        Ok(Self::with_owner(
            ProofInputUtxo::try_from(input)?,
            match real {
                true => input.utxo.owner.owner_proof_input_hash()?,
                false => [0; 32],
            },
            match real {
                true => input.nullifier_pubkey,
                false => [0; 32],
            },
        ))
    }

    /// A slot past the spent notes, a zero domain opens neither a note nor a dummy.
    pub fn input_padding() -> Self {
        let mut domain = [0; 32];
        domain[30..].copy_from_slice(&spr_interface::DUMMY_DOMAIN.to_be_bytes());
        Self {
            domain,
            ..Self::default()
        }
    }

    fn with_owner(fields: ProofInputUtxo, owner_pk_hash: [u8; 32], nullifier_pk: [u8; 32]) -> Self {
        Self {
            domain: fields.domain,
            tree_id: fields.tree_id,
            owner_pk_hash,
            nullifier_pk,
            asset: fields.asset,
            amount: fields.amount,
            blinding: fields.blinding,
            data_hash: fields.data_hash,
            ring_data_hash: fields.ring_data_hash,
            ring_program_id: fields.ring_program_id,
        }
    }
}

/// The ring id sits in `PolicyParams`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditParams {
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub tx_viewing_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    #[serde(with = "fe")]
    pub salt: [u8; 16],
    /// The statement's layout flags.
    pub layout: u8,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OutputOpening {
    pub output: Opening,
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub mint_chunks: [[u8; 32]; 2],
}

/// Zero off a default-ring input.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryOpening {
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub mint_chunks: [[u8; 32]; 2],
}

/// One subject's index in each pool, the curator index 0 without a curator registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct PoolEntry {
    pub own: u32,
    pub curator: [u32; 1],
}

#[derive(Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OwnerEntry {
    #[serde(flatten)]
    pub entry: PoolEntry,
    pub tracking: u32,
    /// Zero with no tracking row.
    #[serde(with = "fe")]
    pub list_salt: [u8; 32],
    pub own_salted: u32,
    pub curator_salted: [u32; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubjectRequest {
    #[serde(with = "fe")]
    member: [u8; 32],
    record_index: u32,
}

#[derive(Serialize)]
struct PathRequest<'a> {
    index: u64,
    #[serde(serialize_with = "levels")]
    siblings: &'a [[[u8; 32]; QUAD_ARITY - 1]],
}

#[derive(Serialize)]
struct ProofRequest<'a> {
    #[serde(serialize_with = "fe::seq")]
    canopy: &'a [[u8; 32]],
    paths: Vec<PathRequest<'a>>,
}

impl<'a> From<&'a SharedProof> for ProofRequest<'a> {
    fn from(proof: &'a SharedProof) -> Self {
        Self {
            canopy: &proof.canopy,
            paths: proof
                .paths
                .iter()
                .map(|path| PathRequest {
                    index: path.index,
                    siblings: &path.siblings,
                })
                .collect(),
        }
    }
}

fn subject_requests(subjects: &[zolana_ring_member_registry::PoolSubject]) -> Vec<SubjectRequest> {
    subjects
        .iter()
        .map(|subject| SubjectRequest {
            member: subject.member,
            record_index: subject.record_index,
        })
        .collect()
}

/// Both pools at the key's widths, an unopened pool where the key binds no root.
pub(crate) struct RecordPools {
    pub own: RecordPool,
    pub curator: RecordPool,
}

impl Serialize for RecordPools {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record {
            #[serde(with = "fe")]
            member: [u8; 32],
            #[serde(with = "fe")]
            next: [u8; 32],
            lists: u64,
            #[serde(with = "fe")]
            mint_policy: [u8; 32],
            #[serde(with = "fe")]
            withdrawal_threshold: [u8; 32],
            #[serde(serialize_with = "fe::seq")]
            asset_limits: [[u8; 32]; AssetLimits::FIELDS],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Pools<'a> {
            own_records: Vec<Record>,
            curator_records: Vec<Record>,
            own_proof: ProofRequest<'a>,
            curator_proof: ProofRequest<'a>,
            own_subjects: Vec<SubjectRequest>,
            curator_subjects: Vec<SubjectRequest>,
        }
        let records = |pool: &RecordPool| {
            pool.records
                .iter()
                .map(|record| Record {
                    member: record.member,
                    next: record.next,
                    lists: record.lists,
                    mint_policy: record.mint_policy.field(),
                    withdrawal_threshold: right_align(
                        &record.mint_policy.withdrawal_threshold.to_be_bytes(),
                    ),
                    asset_limits: record.mint_policy.limits.fields(),
                })
                .collect()
        };
        Pools {
            own_records: records(&self.own),
            curator_records: records(&self.curator),
            own_proof: (&self.own.proof).into(),
            curator_proof: (&self.curator.proof).into(),
            own_subjects: subject_requests(&self.own.subjects),
            curator_subjects: subject_requests(&self.curator.subjects),
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrackingLeafRequest {
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(with = "fe")]
    pub next: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub ct_hash: [u8; 32],
    #[serde(with = "fe")]
    pub list_tag: [u8; 32],
}

impl From<&TrackingRecord> for TrackingLeafRequest {
    fn from(record: &TrackingRecord) -> Self {
        Self {
            member: record.member,
            next: record.next,
            nullifier_pk: record.nullifier_pk,
            ct_hash: record.ct_hash,
            list_tag: record.list_tag,
        }
    }
}

pub(crate) struct TrackingParams {
    pub tracking_root: [u8; 32],
    pub pool: TrackingPool,
    pub row_entries: Vec<u32>,
    pub output_entries: Vec<u32>,
}

impl Serialize for TrackingParams {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Tracking<'a> {
            #[serde(with = "fe")]
            tracking_root: [u8; 32],
            tracking_records: Vec<TrackingLeafRequest>,
            tracking_proof: ProofRequest<'a>,
            tracking_subjects: Vec<SubjectRequest>,
            row_entries: &'a [u32],
            output_entries: &'a [u32],
        }
        Tracking {
            tracking_root: self.tracking_root,
            tracking_records: self.pool.records.iter().map(Into::into).collect(),
            tracking_proof: (&self.pool.proof).into(),
            tracking_subjects: subject_requests(&self.pool.subjects),
            row_entries: &self.row_entries,
            output_entries: &self.output_entries,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrackingOpeningRequest {
    pub present: bool,
    pub record: TrackingLeafRequest,
    pub path: TrackingPathRequest,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrackingPathRequest {
    pub index: u64,
    pub siblings: Vec<[[u8; 32]; QUAD_ARITY - 1]>,
}

impl Serialize for TrackingPathRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PathRequest {
            index: self.index,
            siblings: &self.siblings,
        }
        .serialize(serializer)
    }
}

impl From<&TrackingOpening> for TrackingOpeningRequest {
    fn from(opening: &TrackingOpening) -> Self {
        let (present, record, path) = match opening {
            TrackingOpening::Present { record, path } => (true, record, path),
            TrackingOpening::Absent { low, path } => (false, low, path),
        };
        Self {
            present,
            record: record.into(),
            path: TrackingPathRequest {
                index: path.index,
                siblings: path.siblings.to_vec(),
            },
        }
    }
}

pub(crate) struct PolicyTable<'a> {
    pub rules: &'a EncodedRuleTable,
    pub sources: &'a SourceMap,
}

impl Serialize for PolicyTable<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Source {
            list_id: u8,
            #[serde(with = "fe")]
            registry: [u8; 32],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Table<'a> {
            sources: [Source; MAX_SOURCES],
            salted: u16,
            policy_len: u8,
            #[serde(serialize_with = "fe::seq")]
            rules: &'a [[u8; 32]],
        }
        let rules = self.rules;
        let slots = self.sources.slots();
        Table {
            sources: core::array::from_fn(|i| Source {
                list_id: slots[i].list_id,
                registry: slots[i].registry,
            }),
            salted: self.sources.salted().bits(),
            policy_len: rules.rule_count,
            rules: &rules.rules,
        }
        .serialize(serializer)
    }
}

/// The policy section as Go `PolicyParams` reads it, every list at the key's capacity.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyParams<'a> {
    pub withdrawal_count: u8,
    #[serde(with = "fe")]
    pub withdrawal_hash: [u8; 32],
    pub withdrawals: Vec<PolicyWithdrawalRequest>,
    #[serde(with = "fe")]
    pub policy_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub own_root: [u8; 32],
    #[serde(with = "fe")]
    pub curator_root: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub public_assets: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub public_amounts: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub public_gross: Vec<[u8; 32]>,
    #[serde(flatten)]
    pub table: PolicyTable<'a>,
    #[serde(flatten)]
    pub pools: RecordPools,
    /// `S` entries in row order.
    pub sender_entries: Vec<OwnerEntry>,
    pub owner_entries: Vec<OwnerEntry>,
    pub asset_entries: Vec<PoolEntry>,
    pub public_asset_entries: Vec<u32>,
}

/// Mirror Go `TransferParams`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferParams<'a> {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditParams,
    pub approval_mask: u8,
    /// Both unset on a frame that discloses nothing.
    #[serde(skip_serializing_if = "Option::is_none", with = "fe::option")]
    pub approval_totals: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none", with = "fe::option")]
    pub approval_blinder: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_data_counts: Option<u64>,
    /// `m`, the published slots.
    pub output_count: u8,
    pub outputs: Vec<OutputOpening>,
    /// `n`, the frame's nullifier count.
    pub input_count: u8,
    /// The input class, the slots past the spent notes carry no UTXO.
    pub inputs: Vec<Opening>,
    /// The published nullifiers in SPP order, zero to the input class.
    #[serde(serialize_with = "fe::seq")]
    pub input_nullifiers: Vec<[u8; 32]>,
    /// The program's chain over `n` and `input_nullifiers`.
    #[serde(with = "fe")]
    pub input_nullifier_chain: [u8; 32],
    /// An entry key's default-ring preimages, none off one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<EntryOpening>,
    /// The deduplicated owner run.
    pub signer_count: u8,
    /// The input class, the owner run in its order and zero past `signer_count`.
    #[serde(serialize_with = "fe::seq")]
    pub signers: Vec<[u8; 32]>,
    /// The key's `S` rows, ascending with zero rows last.
    #[serde(serialize_with = "fe::seq")]
    pub rows: Vec<[u8; 32]>,
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    pub in_proof: bool,
    pub hidden: bool,
    pub delegate: bool,
    /// The in-proof owner, zero on every other rail.
    #[serde(with = "fe")]
    pub sender: [u8; 32],
    /// Payer, co-signer and exit destination of an anonymous frame, zero when absent.
    #[serde(serialize_with = "fe::seq")]
    pub party_identities: Vec<[u8; 32]>,
    #[serde(flatten)]
    pub tracking: TrackingParams,
    #[serde(flatten)]
    pub policy: PolicyParams<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordWriteProofInputRequest {
    pub entry: RecordWriteRequest,
    pub exists: bool,
    #[serde(with = "fe")]
    pub old_next: [u8; 32],
    pub old_lists: u64,
    #[serde(with = "fe")]
    pub old_mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub old_withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub old_asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    pub low_lists: u64,
    #[serde(with = "fe")]
    pub low_mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub low_withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub low_asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    pub low_index: u64,
    #[serde(serialize_with = "path")]
    pub low_path: QuadPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordWriteRequest {
    #[serde(with = "fe")]
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    #[serde(with = "fe")]
    pub mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub asset_limits: [[u8; 32]; AssetLimits::FIELDS],
}

impl From<&RecordWrite> for RecordWriteRequest {
    fn from(entry: &RecordWrite) -> Self {
        let policy = entry.mint_policy.unwrap_or_default();
        Self {
            member: entry.member,
            mask: entry.mask,
            value: entry.value,
            mint_policy: entry.mint_policy_field(),
            withdrawal_threshold: right_align(&policy.withdrawal_threshold.to_be_bytes()),
            asset_limits: policy.limits.fields(),
        }
    }
}

impl From<&RecordWriteProofInput> for RecordWriteProofInputRequest {
    fn from(write: &RecordWriteProofInput) -> Self {
        let MemberRecord {
            member: low_member,
            next: low_next,
            lists: low_lists,
            mint_policy: low_mint_policy,
        } = write.low;
        Self {
            entry: (&write.entry).into(),
            exists: write.exists,
            old_next: write.old_next,
            old_lists: write.old_lists,
            old_mint_policy: write.old_mint_policy.field(),
            old_withdrawal_threshold: right_align(
                &write.old_mint_policy.withdrawal_threshold.to_be_bytes(),
            ),
            old_asset_limits: write.old_mint_policy.limits.fields(),
            index: write.slot.index,
            path: write.slot,
            low_member,
            low_next,
            low_lists,
            low_mint_policy: low_mint_policy.field(),
            low_withdrawal_threshold: right_align(
                &low_mint_policy.withdrawal_threshold.to_be_bytes(),
            ),
            low_asset_limits: low_mint_policy.limits.fields(),
            low_index: write.low_path.index,
            low_path: write.low_path,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplyRecords {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub old_root: [u8; 32],
    #[serde(with = "fe")]
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    #[serde(with = "fe")]
    pub chain_start: [u8; 32],
    #[serde(with = "fe")]
    pub chain_end: [u8; 32],
    pub count: u8,
    /// The key's batch, writes past `count` assign zeros.
    pub writes: Vec<Option<RecordWriteProofInputRequest>>,
    /// Absent on a public key, the prover refuses private fields there.
    #[serde(flatten)]
    pub private: Option<PrivateApplyRecords>,
}

/// Go `PrivateApplyRecordsParams` beside the shared apply fields.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrivateApplyRecords {
    pub private_writes: u64,
    #[serde(with = "fe")]
    pub tracking_root: [u8; 32],
    /// One per batch write, null where the write names no private owner.
    pub owners: Vec<Option<PrivateOwnerRequest>>,
}

/// Go `PrivateOwnerParams`, the enrolled row whose salted key a private write names.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrivateOwnerRequest {
    #[serde(with = "fe")]
    pub list_salt: [u8; 32],
    pub record: TrackingLeafRequest,
    pub index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub path: Vec<[u8; 32]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRegister {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(with = "fe")]
    pub list_salt: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
}

/// Mirror Go `TrackingWrite`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrackingWrite {
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub ct_hash: [u8; 32],
    #[serde(with = "fe")]
    pub list_tag: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub path: Vec<[u8; 32]>,
    pub low_record: TrackingLeafRequest,
    pub low_index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub low_path: Vec<[u8; 32]>,
}

impl From<&TrackingWriteProofInput> for TrackingWrite {
    fn from(write: &TrackingWriteProofInput) -> Self {
        let entry = &write.entry;
        Self {
            member: entry.member,
            nullifier_pk: entry.nullifier_pk,
            ct_hash: entry.ct_hash,
            list_tag: entry.list_tag,
            index: write.slot.index,
            path: write.slot.siblings.as_flattened().to_vec(),
            low_record: (&write.low).into(),
            low_index: write.low_path.index,
            low_path: write.low_path.siblings.as_flattened().to_vec(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplyEnrollments {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub old_root: [u8; 32],
    #[serde(with = "fe")]
    pub new_root: [u8; 32],
    pub old_next_index: u64,
    pub new_next_index: u64,
    #[serde(with = "fe")]
    pub chain_start: [u8; 32],
    #[serde(with = "fe")]
    pub chain_end: [u8; 32],
    pub count: u8,
    /// The key's batch, writes past `count` assign zeros.
    pub writes: Vec<Option<TrackingWrite>>,
}

/// `tracking` is `None` under a zero key.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeRequest {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub output_utxo_hash: [u8; 32],
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    #[serde(with = "fe")]
    pub payer: [u8; 32],
    #[serde(with = "fe")]
    pub tracking_root: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(with = "fe")]
    pub owner_pk_hash: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub mint_chunks: [[u8; 32]; 2],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub seed: Zeroizing<[u8; 32]>,
    #[serde(with = "fe")]
    pub output_tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub output_ring_data_hash: [u8; 32],
    pub tracking: Option<TrackingOpeningRequest>,
}

/// The Solana key an owner identity hashes, the disclosure names it.
pub(crate) fn owner_key(owner: &PublicKey) -> Result<[u8; 32], RingError> {
    Ok(owner.confidential_view_tag()?)
}

/// The circuits witness the untagged 32-byte coordinate.
fn coordinate<S: Serializer>(key: &X25519Pubkey, serializer: S) -> Result<S::Ok, S::Error> {
    fe::bytes(&key.u(), serializer)
}

fn levels<S: Serializer>(
    levels: &&[[[u8; 32]; QUAD_ARITY - 1]],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct Level<'a>(&'a [[u8; 32]; QUAD_ARITY - 1]);
    impl Serialize for Level<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            fe::seq(self.0, serializer)
        }
    }
    serializer.collect_seq(levels.iter().map(Level))
}

/// Every level's siblings from the leaf up, in child order.
fn path<S: Serializer>(path: &QuadPath, serializer: S) -> Result<S::Ok, S::Error> {
    let flat: Vec<[u8; 32]> = path
        .siblings
        .iter()
        .flat_map(|level: &[[u8; 32]; QUAD_ARITY - 1]| level.iter().copied())
        .collect();
    fe::seq(&flat, serializer)
}

#[derive(Serialize)]
pub(crate) struct PolicyWithdrawalRequest {
    #[serde(with = "fe")]
    pub owner: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
}
