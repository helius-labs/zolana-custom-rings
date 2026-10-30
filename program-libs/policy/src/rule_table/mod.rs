use bytemuck::{Pod, Zeroable};
use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};
use thiserror::Error;
use wincode::{SchemaRead, SchemaWrite};

use crate::{field_u8, ListId, ListSet, Member};

/// Rule slots compiled into the circuit, a new value rotates the proving key.
pub const MAX_RULES: usize = 16;
/// Source slots, one per list the enum can name.
pub const MAX_SOURCES: usize = 8;
/// Curator registries one policy may read lists from, a circuit width.
pub const N_FOREIGN: usize = 1;
/// Enters `policy_hash`, bump it with any change of the encoding below.
pub const POLICY_TABLE_VERSION: u8 = 12;
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

/// A slot violates the positional layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceMapError {
    #[error("slot breaks the positional layout")]
    NotPositional,
    #[error("list is already mapped")]
    Duplicate,
    #[error("the curator slots name more than {N_FOREIGN} registry")]
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
    TooManyInlineAssets => "asset thresholds exceed the circuit width",
    ZeroInlineAsset => "zero is the padding value, never a member",
    PoolWithoutInlineRule => "asset thresholds without a per-asset guard",
    EmptyLists => "a group names no list",
    ListInBothSets => "a list is both required and forbidden",
    SenderGuard => "sender rules take no amount guard",
    ExitDestination => "exit destinations are enforced by no plane",
    ZeroThreshold => "a zero threshold is Guard::Always",
    DuplicateRule => "duplicate rule",
    PerAssetGuardNotOwner => "per-asset limits apply to output owners only",
    MissingAssetLimit => "every mint threshold needs a nonzero limit",
    AssetLimitWithoutGuard => "asset limits need a per-asset guard",
    DuplicateInlineAsset => "mint thresholds must name distinct assets",
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

    /// Every curator slot names the one foreign registry the circuit opens.
    fn check_curators(&self) -> Result<(), SourceMapError> {
        const _: () = assert!(N_FOREIGN == 1);
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
    ExitDestination = 3,
    Asset = 4,
}

/// Present demands a live Active entry, Absent forbids one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Present = 1,
    Absent = 2,
}

/// Amount guards compare output sums in asset base units.
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

/// Byte positions are the circuit packed-field weights (Go `ruleShift`), reordering breaks proof verification.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Row {
    reserved: [u8; 19],
    alternative: u8,
    threshold: [u8; 8],
    guard_tag: u8,
    mask: u8,
    mode: u8,
    subject: u8,
}

const _: () = assert!(core::mem::size_of::<Row>() == 32);

impl Rule {
    /// Every live instance of the subject needs a live Active entry.
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

    /// A live instance is refused only when present in every one of the lists.
    pub const fn forbid_all(subject: Subject, lists: ListSet) -> Self {
        Self::any_of(subject, ListSet::EMPTY, lists)
    }

    /// A presence in any of `present` or an absence from any of `absent` passes.
    pub const fn any_of(subject: Subject, present: ListSet, absent: ListSet) -> Self {
        Self {
            subject,
            source: RuleSource::Lists { present, absent },
            guard: Guard::Always,
        }
    }

    /// The rule passes below the threshold without a membership check.
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
            reserved: [0; 19],
            alternative: alternative.bits(),
            threshold: threshold.to_be_bytes(),
            guard_tag,
            mask: mask.bits(),
            mode: self.primary_mode() as u8,
            subject: self.subject as u8,
        })
    }

    /// Refuses every row `encoded` never emits, the circuit equation alone admits them.
    pub fn decode(bytes: &[u8; 32]) -> Result<Self, RuleTableError> {
        let row: &Row = bytemuck::cast_ref(bytes);
        if row.reserved != [0; 19] {
            return Err(RuleTableError::ReservedBytes);
        }
        let subject = match row.subject {
            1 => Subject::OutputOwner,
            2 => Subject::Sender,
            3 => Subject::ExitDestination,
            4 => Subject::Asset,
            _ => return Err(RuleTableError::UnknownSubject),
        };
        let mode = match row.mode {
            1 => Mode::Present,
            2 => Mode::Absent,
            _ => return Err(RuleTableError::UnknownMode),
        };
        let mask = ListSet::from_bits(row.mask);
        let alternative = ListSet::from_bits(row.alternative);
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
        if matches!(self.subject, Subject::ExitDestination) {
            return Err(RuleTableError::ExitDestination);
        }
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

    const fn signature(&self) -> u32 {
        let (present, absent) = match self.source {
            RuleSource::Lists { present, absent } => (present.bits(), absent.bits()),
        };
        ((self.subject as u32) << 16) | ((present as u32) << 8) | absent as u32
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
                ListSet::from_bits(row.mask | row.alternative)
            })
            .fold(ListSet::EMPTY, ListSet::union)
    }

    /// The table a policy write stores, every check the circuit leaves to the program.
    pub fn validate(&self, sources: &SourceMap) -> Result<RuleTable, PolicyTableError> {
        let table = self.decode()?;
        let referenced = self.referenced();
        if !referenced.is_subset(ListSet::AUTHORITY_WRITES) {
            return Err(RuleTableError::MemberWrittenList.into());
        }
        match referenced
            .iter()
            .find(|list_id| sources.registry(*list_id).is_none())
        {
            Some(list_id) => Err(PolicyTableError::MissingSource(list_id)),
            None => Ok(table),
        }
    }

    /// Every slot past a count enters as stored, `validate` keeps it zero.
    pub fn fields(&self, sources: &SourceMap) -> [[u8; 32]; POLICY_TABLE_FIELDS] {
        let header = [
            right_align(&POLICY_TABLE_DOMAIN.to_be_bytes()),
            field_u8(POLICY_TABLE_VERSION),
        ];
        let values = header
            .into_iter()
            .chain(
                sources
                    .slots()
                    .iter()
                    .flat_map(|slot| [field_u8(slot.list_id), slot.registry]),
            )
            .chain([field_u8(self.rule_count)])
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

const _: () = assert!(EncodedRuleTable::SIZE == 513);
const _: () = assert!(core::mem::align_of::<EncodedRuleTable>() == 1);

#[cfg(test)]
mod tests;
