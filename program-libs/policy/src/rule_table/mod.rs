//! The rule table a ring pins and every policy proof reads, and the checks the circuit leaves to the program.
//!
//! SPP has no policy. A ring's rules are 32 byte rows, each read as one field, and `policy_hash` folds
//! them with the source map. The circuit decodes any row through one equation and holds its table to
//! the hash, and it never judges whether a row makes sense. `EncodedRuleTable::validate` runs at every
//! policy write and is the one place a table's meaning is checked. A table it refuses has no hash on
//! the account, so no proof reads it.
//!
//! Read after `program-libs/policy/src/list.rs`, `docs/design/records-and-roots.md`. Read before
//! `program-libs/policy/src/rules.rs`, `prover/circuits/policy/table.go`, `prover/circuits/policy/rules.go`.
//!
//! Named list semantics a stored table holds.
//! 1. `Allow`, `Approval` and `PrivateAllow` are grant lists, read by presence. A rule over several passes on any one, within the rule the lists join with OR.
//! 2. `Block`, `Frozen`, `PrivateBlock` and `PrivateFrozen` are deny lists, read by absence, one per rule. Rules join with AND, so a public and a private block are two rules.
//! 3. No rule reads `Reader` or the member written `RingViewing`, so an owner admits itself to nothing and a reader grant moves no funds.
//! 4. `PrivateAllow`, `PrivateBlock` and `PrivateFrozen` are always salted. An owner reads them at its salted key once its tracking row is present, and an asset reads its public record. An owner with no row reads no salted list, so a deny rule on one passes and an allow rule on one fails.
//!
//! Invariants of a stored table.
//! 1. Every row is one `Rule::encoded` emits and no two rows share a signature, the circuit's equation alone admits more.
//! 2. Every list a rule reads has a source, the circuit reads a slot with a zero registry as the ring's own.
//! 3. Rows past `rule_count` stay zero, each enters the hash as stored.
//! 4. Every curator slot names one registry, the circuit opens one curator pool beside the own one.

use bytemuck::{Pod, Zeroable};
use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};
use thiserror::Error;
use wincode::{SchemaRead, SchemaWrite};

use crate::{field_u8, ListId, ListSet, Member};

/// Rule slots compiled into the circuit, a new value rotates the proving key.
pub const MAX_RULES: usize = 16;
/// Source slots, one per list the enum can name.
pub const MAX_SOURCES: usize = 9;
/// `"CRTB"`, the first field of the table hash, `domain::POLICY_TABLE` of the interface.
pub const POLICY_TABLE_DOMAIN: u32 = 0x4352_5442;
pub const POLICY_TABLE_FIELDS: usize =
    (3 + 2 * MAX_SOURCES + MAX_RULES).div_ceil(POLICY_TABLE_RATE) * POLICY_TABLE_RATE;
/// Fields absorbed per Poseidon call beside the accumulator, the 12-input syscall maximum.
pub(crate) const POLICY_TABLE_RATE: usize = 11;

const _: () =
    assert!(POLICY_TABLE_FIELDS == 44 && POLICY_TABLE_FIELDS.is_multiple_of(POLICY_TABLE_RATE));

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicySource {
    /// Zero marks an empty slot.
    pub list_id: u8,
    /// A curator's `registry_field`, zero for the ring's own.
    pub registry: [u8; 32],
}

/// Positional source map, slot `i` is empty or serves list `i + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceMap {
    slots: [PolicySource; MAX_SOURCES],
}

impl SourceMap {
    pub fn new(entries: &[(ListId, [u8; 32])]) -> Result<Self, SourceMapError> {
        let mut sources = Self::default();
        for (list_id, registry) in entries {
            let slot = &mut sources.slots[list_id.slot()];
            if slot.list_id != 0 {
                return Err(SourceMapError::Duplicate);
            }
            *slot = PolicySource {
                list_id: *list_id as u8,
                registry: *registry,
            };
        }
        sources.check_curators()?;
        Ok(sources)
    }

    /// Validates stored slots instead of re-canonicalizing them.
    pub fn from_slots(slots: [PolicySource; MAX_SOURCES]) -> Result<Self, SourceMapError> {
        for (index, slot) in slots.iter().enumerate() {
            let empty = slot.list_id == 0 && slot.registry == [0u8; 32];
            let positional = slot.list_id as usize == index + 1;
            if !empty && !positional {
                return Err(SourceMapError::NotPositional);
            }
        }
        let map = Self { slots };
        map.check_curators()?;
        Ok(map)
    }

    /// Every curator slot names the one registry the circuit opens beside the ring's own.
    fn check_curators(&self) -> Result<(), SourceMapError> {
        let mut curators = self
            .slots
            .iter()
            .map(|slot| slot.registry)
            .filter(|registry| *registry != [0u8; 32]);
        let first = curators.next();
        if curators.any(|registry| Some(registry) != first) {
            return Err(SourceMapError::SeveralCurators);
        }
        Ok(())
    }

    /// Owners read these lists at their salted keys, an asset keeps its public record. An
    /// unmapped bit would ask a prover for a salt no rule reads.
    pub fn salted(&self) -> ListSet {
        ListSet::salted_among(|list_id| self.slots[list_id.slot()].list_id != 0)
    }

    /// The registry serving a list, zero for the ring's own, `None` when unmapped.
    pub fn registry(&self, list_id: ListId) -> Option<&[u8; 32]> {
        let slot = &self.slots[list_id.slot()];
        (slot.list_id != 0).then_some(&slot.registry)
    }

    /// The curator registry a slot names, `None` when every mapped list is the ring's own.
    pub fn curator(&self) -> Option<[u8; 32]> {
        self.slots
            .iter()
            .map(|slot| slot.registry)
            .find(|registry| *registry != [0u8; 32])
    }

    pub const fn slots(&self) -> &[PolicySource; MAX_SOURCES] {
        &self.slots
    }
}

/// Whom a rule screens in the transfer openings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Subject {
    OutputOwner = 1,
    Sender = 2,
    Asset = 4,
}

/// Present demands the list's bit, Absent forbids it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Present = 1,
    Absent = 2,
}

/// Amount guards compare `owner_guard` or `asset_guard` in asset base units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Always,
    AboveAmount(u64),
    AboveAmountByAsset,
}

/// A disjunction over registry lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Lists { present: ListSet, absent: ListSet },
}

/// One obligation, packed into a single field element for the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    pub source: RuleSource,
    pub guard: Guard,
}

/// Byte positions are the circuit packed-field weights (Go `ruleParts`), reordering breaks proof verification.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Row {
    /// Zero, `decodeRule` recomposes the row from the 15 bytes below and a set bit here fails it.
    reserved: [u8; 17],
    alternative: [u8; 2],
    threshold: [u8; 8],
    guard_tag: u8,
    mask: [u8; 2],
    mode: u8,
    subject: u8,
}

const _: () = assert!(core::mem::size_of::<Row>() == 32);

impl Row {
    /// `None` past the named lists, the circuit splits a mask into `MAX_SOURCES` bits and fails there.
    const fn mask_lists(&self) -> Option<ListSet> {
        ListSet::from_record_bits(u16::from_be_bytes(self.mask) as u64)
    }

    const fn alternative_lists(&self) -> Option<ListSet> {
        ListSet::from_record_bits(u16::from_be_bytes(self.alternative) as u64)
    }
}

impl Rule {
    /// Every live instance of the subject needs the list's bit.
    pub const fn require(subject: Subject, list_id: ListId) -> Self {
        Self::any_of(subject, ListSet::single(list_id), ListSet::EMPTY)
    }

    /// Every live instance of the subject needs a provable absence.
    pub const fn forbid(subject: Subject, list_id: ListId) -> Self {
        Self::any_of(subject, ListSet::EMPTY, ListSet::single(list_id))
    }

    /// Every live instance must be present in at least one of the lists.
    pub const fn require_any(subject: Subject, lists: ListSet) -> Self {
        Self::any_of(subject, lists, ListSet::EMPTY)
    }

    /// An instance on only some lists passes, `RuleTable::validate` refuses the row on a policy
    /// write and `RuleTableBuilder::forbid_each` is the form a table stores.
    pub const fn forbid_only_on_all(subject: Subject, lists: ListSet) -> Self {
        Self::any_of(subject, ListSet::EMPTY, lists)
    }

    /// A presence in any of `present` or an absence from any one of `absent` passes, the circuit
    /// equation for a row, `RuleTable::validate` bounds the forms a table stores.
    pub const fn any_of(subject: Subject, present: ListSet, absent: ListSet) -> Self {
        Self {
            subject,
            source: RuleSource::Lists { present, absent },
            guard: Guard::Always,
        }
    }

    /// The rule passes at or below the threshold without a membership check.
    #[must_use]
    pub const fn above(self, amount: u64) -> Self {
        Self {
            guard: Guard::AboveAmount(amount),
            ..self
        }
    }

    #[must_use]
    pub const fn above_by_asset(self) -> Self {
        Self {
            guard: Guard::AboveAmountByAsset,
            ..self
        }
    }

    pub const fn primary_mode(&self) -> Mode {
        match self.source {
            RuleSource::Lists { present, .. } if present.is_empty() => Mode::Absent,
            RuleSource::Lists { .. } => Mode::Present,
        }
    }

    pub const fn referenced(&self) -> ListSet {
        match self.source {
            RuleSource::Lists { present, absent } => present.union(absent),
        }
    }

    /// Presences first, each in `ListId::ALL` order.
    pub fn alternatives(&self) -> impl Iterator<Item = (ListId, Mode)> {
        let (present, absent) = match self.source {
            RuleSource::Lists { present, absent } => (present, absent),
        };
        present
            .iter()
            .map(|list_id| (list_id, Mode::Present))
            .chain(absent.iter().map(|list_id| (list_id, Mode::Absent)))
    }

    pub fn encoded(&self) -> [u8; 32] {
        let (mask, alternative) = match self.source {
            RuleSource::Lists { present, absent } => match self.primary_mode() {
                Mode::Present => (present, absent),
                Mode::Absent => (absent, ListSet::EMPTY),
            },
        };
        let (guard_tag, threshold) = match self.guard {
            Guard::Always => (0, 0),
            Guard::AboveAmount(amount) => (1, amount),
            Guard::AboveAmountByAsset => (2, 0),
        };
        bytemuck::cast(Row {
            reserved: [0; 17],
            alternative: alternative.bits().to_be_bytes(),
            threshold: threshold.to_be_bytes(),
            guard_tag,
            mask: mask.bits().to_be_bytes(),
            mode: self.primary_mode() as u8,
            subject: self.subject as u8,
        })
    }

    /// Refuses every row `encoded` never emits, the circuit equation alone admits them.
    pub fn decode(bytes: &[u8; 32]) -> Result<Self, RuleTableError> {
        let row: &Row = bytemuck::cast_ref(bytes);
        if row.reserved != [0; 17] {
            return Err(RuleTableError::ReservedBytes);
        }
        let subject = match row.subject {
            1 => Subject::OutputOwner,
            2 => Subject::Sender,
            4 => Subject::Asset,
            _ => return Err(RuleTableError::UnknownSubject),
        };
        let mode = match row.mode {
            1 => Mode::Present,
            2 => Mode::Absent,
            _ => return Err(RuleTableError::UnknownMode),
        };
        let (Some(mask), Some(alternative)) = (row.mask_lists(), row.alternative_lists()) else {
            return Err(RuleTableError::UnknownList);
        };
        if mask.is_empty() {
            return Err(RuleTableError::EmptyLists);
        }
        let source = match mode {
            Mode::Present => RuleSource::Lists {
                present: mask,
                absent: alternative,
            },
            Mode::Absent if !alternative.is_empty() => {
                return Err(RuleTableError::NonCanonicalAlternative)
            }
            Mode::Absent => RuleSource::Lists {
                present: ListSet::EMPTY,
                absent: mask,
            },
        };
        let threshold = u64::from_be_bytes(row.threshold);
        let guard = match row.guard_tag {
            0 if threshold != 0 => return Err(RuleTableError::ThresholdWithoutGuard),
            0 => Guard::Always,
            1 => Guard::AboveAmount(threshold),
            2 if threshold == 0 => Guard::AboveAmountByAsset,
            2 => return Err(RuleTableError::ThresholdWithoutGuard),
            _ => return Err(RuleTableError::UnknownGuardTag),
        };
        let rule = Self {
            subject,
            source,
            guard,
        };
        rule.check().map(|()| rule)
    }

    const fn check(&self) -> Result<(), RuleTableError> {
        match self.source {
            RuleSource::Lists { present, absent } if present.union(absent).is_empty() => {
                return Err(RuleTableError::EmptyLists)
            }
            RuleSource::Lists { present, absent } if present.intersects(absent) => {
                return Err(RuleTableError::ListInBothSets)
            }
            RuleSource::Lists { .. } => {}
        }
        match self.guard {
            Guard::AboveAmount(_) if matches!(self.subject, Subject::Sender) => {
                Err(RuleTableError::SenderGuard)
            }
            Guard::AboveAmount(0) => Err(RuleTableError::ZeroThreshold),
            Guard::AboveAmountByAsset if !matches!(self.subject, Subject::OutputOwner) => {
                Err(RuleTableError::PerAssetGuardNotOwner)
            }
            Guard::Always | Guard::AboveAmount(_) | Guard::AboveAmountByAsset => Ok(()),
        }
    }

    /// One polarity per row, a grant over grant lists or a denial of one deny list.
    const fn check_polarity(&self) -> Result<(), RuleTableError> {
        let RuleSource::Lists { present, absent } = self.source;
        if !present.is_empty() && !absent.is_empty() {
            return Err(RuleTableError::MixedPolarity);
        }
        if absent.len() > 1 {
            return Err(RuleTableError::MultiListAbsence);
        }
        if !present.is_subset(ListSet::GRANT_LISTS) || !absent.is_subset(ListSet::DENY_LISTS) {
            return Err(RuleTableError::InvertedPolarity);
        }
        Ok(())
    }

    const fn signature(&self) -> u64 {
        let (present, absent) = match self.source {
            RuleSource::Lists { present, absent } => (present.bits(), absent.bits()),
        };
        ((self.subject as u64) << 32) | ((present as u64) << 16) | absent as u64
    }

    const fn disabled() -> Self {
        Self::require(Subject::OutputOwner, ListId::Allow)
    }
}

/// Bounds one transfer's outflow of `asset`, zero leaves a bound off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct OutflowLimit {
    asset: [u8; 32],
    /// The transfer fails above it.
    pub cap: u64,
    /// The transfer needs the co-signer above it.
    pub cosign_above: u64,
}

impl OutflowLimit {
    pub const EMPTY: Self = Self {
        asset: [0u8; 32],
        cap: 0,
        cosign_above: 0,
    };

    /// Both bounds off.
    pub const fn of(asset: &Member) -> Self {
        Self {
            asset: *asset.as_bytes(),
            cap: 0,
            cosign_above: 0,
        }
    }

    #[must_use]
    pub const fn with_cap(self, cap: u64) -> Self {
        Self { cap, ..self }
    }

    #[must_use]
    pub const fn with_cosign_above(self, cosign_above: u64) -> Self {
        Self {
            cosign_above,
            ..self
        }
    }

    /// The field public slots carry for the asset.
    pub const fn asset(&self) -> &[u8; 32] {
        &self.asset
    }
}

/// The circuit can enforce every instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleTable {
    rules: [Rule; MAX_RULES],
    len: u8,
}

impl RuleTable {
    pub const fn empty() -> Self {
        Self {
            rules: [Rule::disabled(); MAX_RULES],
            len: 0,
        }
    }

    pub const fn builder() -> RuleTableBuilder {
        RuleTableBuilder {
            table: Self::empty(),
            rule_count: 0,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules[..usize::from(self.len)]
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn referenced(&self) -> ListSet {
        let mut set = ListSet::EMPTY;
        let mut i = 0;
        while i < self.len as usize {
            set = set.union(self.rules[i].referenced());
            i += 1;
        }
        set
    }

    /// What a stored table may read and how, every policy write runs it through
    /// `EncodedRuleTable::validate`.
    ///
    /// The guarantee is that configured list operations have consistent semantics, never that
    /// every accepted policy is restrictive. An empty table passes, and a grant over a list the
    /// authority opens to everyone passes. A rule is a grant requirement, met by presence in any
    /// of its grant lists, or a denial, met by absence from its one deny list. Every rule holds
    /// at once, so grants and denials combine with AND and each denied list takes its own rule.
    ///
    /// The row layout and the circuit evaluate any OR of presences and absences, `holds` in
    /// `rules.rs` mirrors them, and three forms read against those semantics. Multi-list absence
    /// passes a subject off any one list, a publicly blocked owner with no private entry passes
    /// a row over `{Block, PrivateBlock}`. A mixed row passes on either branch, a grant lifts the
    /// denial for a blocked owner and the absence lifts the grant for everyone unblocked. Inverted
    /// polarity makes a set bit on a deny list grant and a set bit on a grant list deny.
    pub fn validate(&self) -> Result<(), RuleTableError> {
        let referenced = self.referenced();
        if referenced.intersects(ListSet::MEMBER_LISTS) {
            return Err(RuleTableError::MemberWrittenList);
        }
        if !referenced.is_subset(ListSet::POLICY_LISTS) {
            return Err(RuleTableError::ListNotPolicyReadable);
        }
        self.rules().iter().try_for_each(Rule::check_polarity)
    }

    pub fn encode(&self) -> EncodedRuleTable {
        let mut encoded = EncodedRuleTable {
            rule_count: self.len,
            ..EncodedRuleTable::default()
        };
        for (row, rule) in encoded.rules.iter_mut().zip(self.rules()) {
            *row = rule.encoded();
        }
        encoded
    }

    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], HasherError> {
        self.encode().hash(sources)
    }
}

/// Const-evaluable, an illegal table fails the consuming build, never a transaction.
#[derive(Clone, Copy, Debug)]
pub struct RuleTableBuilder {
    table: RuleTable,
    rule_count: usize,
}

impl RuleTableBuilder {
    #[must_use]
    pub const fn rule(mut self, rule: Rule) -> Self {
        push(&mut self.table.rules, &mut self.rule_count, &[rule]);
        self
    }

    /// The form a public and a private block need.
    #[must_use]
    pub const fn forbid_each(mut self, subject: Subject, lists: ListSet) -> Self {
        let mut i = 0;
        while i < MAX_SOURCES {
            if lists.contains(ListId::ALL[i]) {
                self = self.rule(Rule::forbid(subject, ListId::ALL[i]));
            }
            i += 1;
        }
        self
    }

    pub const fn try_build(mut self) -> Result<RuleTable, RuleTableError> {
        if self.rule_count > MAX_RULES {
            return Err(RuleTableError::TooManyRules);
        }
        self.table.len = self.rule_count as u8;
        let mut i = 0;
        while i < self.rule_count {
            let rule = self.table.rules[i];
            if let Err(error) = rule.check() {
                return Err(error);
            }
            let mut j = 0;
            while j < i {
                if self.table.rules[j].signature() == rule.signature() {
                    return Err(RuleTableError::DuplicateRule);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(self.table)
    }

    pub const fn build(self) -> RuleTable {
        match self.try_build() {
            Ok(table) => table,
            Err(error) => panic!("{}", error.message()),
        }
    }
}

/// Counts every item and stores those that fit, `try_build` refuses an overflowing count.
const fn push<T: Copy, const N: usize>(slots: &mut [T; N], len: &mut usize, items: &[T]) {
    let mut i = 0;
    while i < items.len() {
        if *len < N {
            slots[*len] = items[i];
        }
        *len += 1;
        i += 1;
    }
}

/// Rows past `rule_count` stay zero. Mint settings live in asset records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EncodedRuleTable {
    pub rule_count: u8,
    pub rules: [[u8; 32]; MAX_RULES],
}

/// Wire parts of a table, `encode` checks the counts and `decode` the rest.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct TableParts<'a> {
    pub rows: &'a [[u8; 32]],
}

impl TableParts<'_> {
    pub fn encode(self) -> Result<EncodedRuleTable, RuleTableError> {
        if self.rows.len() > MAX_RULES {
            return Err(RuleTableError::TooManyRules);
        }
        let mut encoded = EncodedRuleTable {
            rule_count: self.rows.len() as u8,
            ..EncodedRuleTable::default()
        };
        encoded.rules[..self.rows.len()].copy_from_slice(self.rows);
        Ok(encoded)
    }
}

impl EncodedRuleTable {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn decode(&self) -> Result<RuleTable, RuleTableError> {
        let rows = self
            .rules
            .get(..usize::from(self.rule_count))
            .ok_or(RuleTableError::TooManyRules)?;
        if !zero_past(&self.rules, rows.len()) {
            return Err(RuleTableError::NonZeroPadding);
        }
        let mut builder = RuleTable::builder();
        for row in rows {
            builder = builder.rule(Rule::decode(row)?);
        }
        builder.try_build()
    }

    pub fn referenced(&self) -> ListSet {
        self.rules
            .iter()
            .take(usize::from(self.rule_count))
            .map(|bytes| {
                let row: &Row = bytemuck::cast_ref(bytes);
                let bits = u16::from_be_bytes(row.mask) | u16::from_be_bytes(row.alternative);
                ListSet::named_in(u64::from(bits))
            })
            .fold(ListSet::EMPTY, ListSet::union)
    }

    /// The table a policy write stores, every check the circuit leaves to the program.
    pub fn validate(&self, sources: &SourceMap) -> Result<RuleTable, PolicyTableError> {
        // 1. Every row is a form `Rule::encoded` emits, unique, with zeros past the count.
        let table = self.decode()?;
        // 2. The named list semantics hold.
        table.validate()?;
        // 3. Every list a rule reads has a source, an empty slot would read as the ring's own registry in the circuit.
        let missing = table.rules().iter().find_map(|rule| {
            rule.referenced()
                .iter()
                .find(|list_id| sources.registry(*list_id).is_none())
        });
        match missing {
            Some(list_id) => Err(PolicyTableError::MissingSource(list_id)),
            None => Ok(table),
        }
    }

    /// Every slot past a count enters as stored, `validate` keeps it zero.
    ///
    /// `salted` follows from the slots and still enters, the circuit reads it as a wire and only the
    /// hash pins it. A wire off the slots would let an owner read a private list at its public key.
    pub fn fields(&self, sources: &SourceMap) -> [[u8; 32]; POLICY_TABLE_FIELDS] {
        let values = [right_align(&POLICY_TABLE_DOMAIN.to_be_bytes())]
            .into_iter()
            .chain(
                sources
                    .slots()
                    .iter()
                    .flat_map(|slot| [field_u8(slot.list_id), slot.registry]),
            )
            .chain([
                right_align(&sources.salted().bits().to_be_bytes()),
                field_u8(self.rule_count),
            ])
            .chain(self.rules.iter().copied());
        let mut fields = [[0u8; 32]; POLICY_TABLE_FIELDS];
        for (field, value) in fields.iter_mut().zip(values) {
            *field = value;
        }
        fields
    }

    /// `acc = Poseidon(acc, fields[11c..11c + 11])` from `acc = 0`, mirror
    /// `prover/circuits/policy/table.go`.
    pub fn hash(&self, sources: &SourceMap) -> Result<[u8; 32], HasherError> {
        let fields = self.fields(sources);
        let mut acc = [0u8; 32];
        for chunk in fields.as_chunks::<POLICY_TABLE_RATE>().0 {
            let mut inputs: [&[u8]; POLICY_TABLE_RATE + 1] = [&[]; POLICY_TABLE_RATE + 1];
            inputs[0] = &acc;
            for (input, field) in inputs[1..].iter_mut().zip(chunk) {
                *input = field;
            }
            acc = Poseidon::hashv(&inputs)?;
        }
        Ok(acc)
    }
}

fn zero_past<const N: usize>(slots: &[[u8; N]], len: usize) -> bool {
    slots[len..].iter().all(|slot| *slot == [0u8; N])
}

/// A slot violates the positional layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapError {
    #[error("slot breaks the positional layout")]
    NotPositional,
    #[error("list is already mapped")]
    Duplicate,
    #[error("the curator slots name more than one registry")]
    SeveralCurators,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyTableError {
    #[error("no source serves a list a rule reads")]
    MissingSource(ListId),
    #[error(transparent)]
    Table(#[from] RuleTableError),
}

macro_rules! rule_errors {
    ($($variant:ident => $message:literal,)*) => {
        /// A table or a row the program refuses.
        #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
        pub enum RuleTableError {
            $(#[error($message)] $variant,)*
        }

        impl RuleTableError {
            /// Const, a refused `RuleTableBuilder::build` panics with it at compile time.
            pub const fn message(&self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)*
                }
            }
        }
    };
}

rule_errors! {
    TooManyRules => "policy table is full",
    EmptyLists => "a group names no list",
    ListInBothSets => "a list is both required and forbidden",
    SenderGuard => "sender rules take no amount guard",
    ZeroThreshold => "a zero threshold is Guard::Always",
    DuplicateRule => "duplicate rule",
    PerAssetGuardNotOwner => "per-asset limits apply to output owners only",
    UnknownSubject => "unknown subject",
    UnknownMode => "unknown mode",
    UnknownGuardTag => "unknown guard tag",
    ThresholdWithoutGuard => "a threshold without a guard",
    ReservedBytes => "reserved row bytes are not zero",
    NonCanonicalAlternative => "an alternative beside an absent primary",
    NonZeroPadding => "padding past the counts is not zero",
    TooManyOutflowLimits => "outflow limits exceed the circuit width",
    ZeroLimitAsset => "an outflow limit names no mint",
    DuplicateLimitAsset => "outflow limit mints must be unique",
    LimitWithoutBound => "an outflow limit needs a cap or a cosign threshold",
    MemberWrittenList => "a rule reads a list its members write",
    ListNotPolicyReadable => "a rule reads a list outside the policy lists",
    MultiListAbsence => "a rule reads more than one list by absence",
    InvertedPolarity => "a rule reads a grant list by absence or a deny list by presence",
    MixedPolarity => "a rule mixes presences and absences",
    UnknownList => "a row names a list past the named lists",
}

const _: () = assert!(EncodedRuleTable::SIZE == 513);
const _: () = assert!(core::mem::align_of::<EncodedRuleTable>() == 1);

#[cfg(test)]
mod tests;
