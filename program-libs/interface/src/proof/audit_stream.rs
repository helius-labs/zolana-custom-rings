//! Mirror of `prover/circuits/audit`.
//!
//! SPP publishes these bytes and opens none of them. The proof holds the auditor's stream to each
//! slot's note, so every length and counter here must match the circuit, a record read at another
//! counter decrypts to noise. A key fixes the counters by its capacity, and a frame transmits its
//! published slots alone.
//!
//! The encrypted head holds the viewing secret in bytes 0 through 31 and note count `R` at byte 32.
//! The big endian address bitmap `A` occupies bytes 33 through 40. Bit `i` names absolute input slot `i`.
//! An entry head adds the big endian default bitmap in bytes 41 through 48, entry records start at byte 49.
//! The key capacity fixes the reserved envelope blocks, the published count fixes the transmitted record count.
//!
//! Read after `program-libs/interface/src/proof/domain.rs`. Read before `program-libs/interface/src/proof/disclosure.rs`,
//! `prover/circuits/audit/audit.go`.

use crate::{bytes::Bytes, error::CustomRingError, TAGGED_X25519_KEY_LEN};

pub const STREAM_BLOCK_LEN: usize = 16;
pub const STREAM_FIRST_COUNTER: u32 = 2;
/// The sealed `tx_viewing_sk`, the envelope's first bytes.
pub const ENVELOPE_KEY_LEN: usize = 32;
/// `R`, spent notes among the published inputs, dummies last.
pub const REAL_INPUT_COUNT_LEN: usize = 1;
pub const ADDRESS_INPUT_BITS_LEN: usize = 8;
pub const ENVELOPE_HEAD_LEN: usize =
    ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN + ADDRESS_INPUT_BITS_LEN;
/// Keys with entry capacity alone, bit `i` set when input `i` is a default-ring note.
pub const DEFAULT_INPUT_BITS_LEN: usize = 8;
pub const AUDIT_RECORD_LEN: usize = 105;
pub const DATA_TAIL_LEN: usize = 64;
pub const ENTRY_RECORD_LEN: usize = 136;
/// The secret is the merge's seed.
pub const OPENING_RECORD_LEN: usize = RECORD_STRIDE + FIELD_LEN;
pub const RECIPIENT_BODY_LEN: usize = 72;
pub const COMPACT_RECIPIENT_BODY_LEN: usize = 48;
pub const COMPACT_AUDIT_RECORD_LEN: usize = 73;
pub const RECIPIENT_BODY_LENGTH_LEN: usize = 2;
pub const SINGLE_ASSET_PAYOUT_INPUTS: usize = 1;
pub const SINGLE_ASSET_PAYOUT_OUTPUTS: usize = 16;
/// `mint || u64be(amount)`, one per bodiless slot of the bundle.
pub const CHANGE_CELL_LEN: usize = FIELD_LEN + AMOUNT_LEN;
/// `viewing_u || owner_key || nullifier_pk`, one byte for the wincode of no data.
pub const MIN_REPLY_LEN: usize = 97;
pub const RECORD_BLOCKS: usize = AUDIT_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN);
/// The padding past a record keeps slot `i` at its counter, a transfer frame omits it.
pub const RECORD_STRIDE: usize = RECORD_BLOCKS * STREAM_BLOCK_LEN;
pub const TAIL_BLOCKS: usize = DATA_TAIL_LEN / STREAM_BLOCK_LEN;
const FIELD_LEN: usize = 32;
const AMOUNT_LEN: usize = 8;

const _: () = assert!(1 + AMOUNT_LEN + 3 * FIELD_LEN == AUDIT_RECORD_LEN);
const _: () = assert!(OPENING_RECORD_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(DATA_TAIL_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(AMOUNT_LEN + 4 * FIELD_LEN == ENTRY_RECORD_LEN);
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == RECIPIENT_BODY_LEN);
const _: () = assert!(3 * FIELD_LEN + 1 == MIN_REPLY_LEN);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum DisclosureFormat {
    #[default]
    Standard = 0,
    SingleAssetPayout = 1,
}

impl DisclosureFormat {
    pub const fn record_len(self) -> usize {
        match self {
            Self::Standard => AUDIT_RECORD_LEN,
            Self::SingleAssetPayout => COMPACT_AUDIT_RECORD_LEN,
        }
    }

    pub const fn record_blocks(self) -> usize {
        self.record_len().div_ceil(STREAM_BLOCK_LEN)
    }

    pub const fn recipient_body_len(self) -> usize {
        match self {
            Self::Standard => RECIPIENT_BODY_LEN,
            Self::SingleAssetPayout => COMPACT_RECIPIENT_BODY_LEN,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditKey {
    pub format: DisclosureFormat,
    /// The widest published input count.
    pub class: usize,
    pub entry: bool,
}

impl AuditKey {
    pub const fn class(self) -> usize {
        self.class
    }

    /// `S`, the owner signers the key's statement chains.
    pub const fn signer_slots(self) -> usize {
        self.class
    }

    const fn head_len(self) -> usize {
        ENVELOPE_HEAD_LEN
            + match self.format {
                DisclosureFormat::Standard => 0,
                DisclosureFormat::SingleAssetPayout => FIELD_LEN,
            }
            + if self.entry {
                DEFAULT_INPUT_BITS_LEN
            } else {
                0
            }
    }

    const fn entry_len(self) -> usize {
        match self.entry {
            true => ENTRY_RECORD_LEN,
            false => 0,
        }
    }

    /// `E`, the same at every published input count so no record's counter moves.
    pub const fn envelope_blocks(self) -> usize {
        (self.head_len() + self.entry_len() * self.class).div_ceil(STREAM_BLOCK_LEN)
    }

    /// `R0`.
    pub const fn first_record_counter(self) -> u32 {
        STREAM_FIRST_COUNTER + self.envelope_blocks() as u32
    }
}

/// One stretch of the auditor keystream, no counter serves two regions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamRegion {
    pub start_counter: u32,
    pub max_blocks: usize,
    /// Transmitted bytes, padding and unused blocks never leave the prover.
    pub len: usize,
}

impl StreamRegion {
    /// Where the region starts in a keystream read from the first counter.
    pub const fn keystream_offset(self) -> usize {
        (self.start_counter - STREAM_FIRST_COUNTER) as usize * STREAM_BLOCK_LEN
    }
}

/// Every length of one transfer's auditor stream, a frame of any other length is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditStreamLayout {
    pub key: AuditKey,
    /// `n`, the frame's nullifier count, never the key capacity or a private live count.
    pub inputs: usize,
    /// `m`, the published slots.
    pub outputs: usize,
    /// `N`, the key's output capacity, records and tails span every slot of it.
    pub capacity: usize,
    pub has_data: bool,
}

impl AuditStreamLayout {
    pub fn checked(self) -> Result<Self, CustomRingError> {
        let outputs_fit = self.outputs >= 1 && self.outputs <= self.capacity;
        let profile_fits = match self.key.format {
            DisclosureFormat::Standard => true,
            DisclosureFormat::SingleAssetPayout => {
                self.inputs == SINGLE_ASSET_PAYOUT_INPUTS
                    && self.key.class == SINGLE_ASSET_PAYOUT_INPUTS
                    && self.outputs == SINGLE_ASSET_PAYOUT_OUTPUTS
                    && self.capacity == SINGLE_ASSET_PAYOUT_OUTPUTS
                    && !self.key.entry
                    && !self.has_data
            }
        };
        match profile_fits
            && self.inputs >= 1
            && self.inputs <= self.key.class()
            && self.key.class() <= u64::BITS as usize
            && outputs_fit
        {
            true => Ok(self),
            false => Err(CustomRingError::RingTransactLength),
        }
    }

    pub const fn first_record_counter(self) -> u32 {
        self.key.first_record_counter()
    }

    /// `T0`, past every record of `N` slots.
    pub const fn first_tail_counter(self) -> u32 {
        self.first_record_counter() + (self.capacity * self.key.format.record_blocks()) as u32
    }

    /// Slots at or past `n` stay absent from the evidence.
    pub const fn envelope(self) -> StreamRegion {
        StreamRegion {
            start_counter: STREAM_FIRST_COUNTER,
            max_blocks: self.key.envelope_blocks(),
            len: self.key.head_len() + self.key.entry_len() * self.inputs,
        }
    }

    pub const fn record(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_record_counter()
                + (slot * self.key.format.record_blocks()) as u32,
            max_blocks: self.key.format.record_blocks(),
            len: self.record_len(slot),
        }
    }

    pub const fn tail(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_tail_counter() + (slot * TAIL_BLOCKS) as u32,
            max_blocks: TAIL_BLOCKS,
            len: self.tail_len(slot),
        }
    }

    pub const fn record_len(self, slot: usize) -> usize {
        match slot < self.outputs {
            true => self.key.format.record_len(),
            false => 0,
        }
    }

    pub const fn tail_len(self, slot: usize) -> usize {
        match self.has_data && slot < self.outputs {
            true => DATA_TAIL_LEN,
            false => 0,
        }
    }

    pub const fn records_len(self) -> usize {
        self.key.format.record_len() * self.outputs
    }

    pub const fn tails_len(self) -> usize {
        match self.has_data {
            true => DATA_TAIL_LEN * self.outputs,
            false => 0,
        }
    }

    pub const fn message_len(self) -> usize {
        TAGGED_X25519_KEY_LEN + self.envelope().len + self.records_len() + self.tails_len()
    }

    /// The blocks a reader decrypts, a clear `has_data` reaches no tail.
    pub const fn capacity_blocks(self) -> usize {
        let tails = match self.has_data {
            true => self.capacity * TAIL_BLOCKS,
            false => 0,
        };
        self.key.envelope_blocks() + self.capacity * self.key.format.record_blocks() + tails
    }
}

/// The frame publishes both counts, the bundle spends no byte on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleLayout {
    /// The frame's `m`.
    pub outputs: usize,
    /// The frame's bodiless slots, at most `outputs`.
    pub change: usize,
}

impl BundleLayout {
    pub const fn byte_len(self) -> usize {
        FIELD_LEN + CHANGE_CELL_LEN * self.change + FIELD_LEN * self.recipient_keys()
    }

    const fn recipient_keys(self) -> usize {
        self.outputs.saturating_sub(self.change)
    }
}

/// A record's first byte, the circuit derives it from the slot's domain and ring id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    #[default]
    Dummy = 0,
    Ring = 1,
    Exit = 2,
}

/// One published slot, the proof holds a dummy's plaintext to zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditRecord {
    pub kind: RecordKind,
    pub amount: u64,
    pub owner_key: [u8; 32],
    pub mint: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

impl AuditRecord {
    pub fn encode(&self) -> [u8; AUDIT_RECORD_LEN] {
        let mut out = [0; AUDIT_RECORD_LEN];
        out[0] = self.kind as u8;
        out[1..9].copy_from_slice(&self.amount.to_be_bytes());
        out[9..41].copy_from_slice(&self.owner_key);
        out[41..73].copy_from_slice(&self.mint);
        out[73..].copy_from_slice(&self.nullifier_pk);
        out
    }

    pub fn encode_compact(&self) -> [u8; COMPACT_AUDIT_RECORD_LEN] {
        let mut out = [0; COMPACT_AUDIT_RECORD_LEN];
        out[0] = self.kind as u8;
        out[1..9].copy_from_slice(&self.amount.to_be_bytes());
        out[9..41].copy_from_slice(&self.owner_key);
        out[41..].copy_from_slice(&self.nullifier_pk);
        out
    }

    pub fn decode_compact(
        plaintext: &[u8],
        mint: &[u8; FIELD_LEN],
    ) -> Result<Self, CustomRingError> {
        if plaintext.len() != COMPACT_AUDIT_RECORD_LEN {
            return Err(CustomRingError::RingTransactLength);
        }
        let mut standard = [0; AUDIT_RECORD_LEN];
        standard[..41].copy_from_slice(&plaintext[..41]);
        standard[41..73].copy_from_slice(mint);
        standard[73..].copy_from_slice(&plaintext[41..]);
        let record = Self::decode(&standard)?;
        if record.kind != RecordKind::Ring {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(record)
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let kind = match bytes.byte()? {
                0 => RecordKind::Dummy,
                1 => RecordKind::Ring,
                2 => RecordKind::Exit,
                _ => return Err(CustomRingError::RingTransactLength),
            };
            let record = Self {
                kind,
                amount: read_amount(bytes)?,
                owner_key: *bytes.array()?,
                mint: *bytes.array()?,
                nullifier_pk: *bytes.array()?,
            };
            match kind == RecordKind::Dummy && record != Self::default() {
                true => Err(CustomRingError::RingTransactLength),
                false => Ok(record),
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningRecord {
    pub record: AuditRecord,
    pub secret: [u8; 32],
}

impl OpeningRecord {
    pub fn encode(&self) -> [u8; OPENING_RECORD_LEN] {
        let mut out = [0; OPENING_RECORD_LEN];
        out[..AUDIT_RECORD_LEN].copy_from_slice(&self.record.encode());
        out[RECORD_STRIDE..].copy_from_slice(&self.secret);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let record = AuditRecord::decode(bytes.take(AUDIT_RECORD_LEN)?)?;
            let padding = bytes.take(RECORD_STRIDE - AUDIT_RECORD_LEN)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(CustomRingError::RingTransactLength);
            }
            Ok(Self {
                record,
                secret: *bytes.array()?,
            })
        })
    }
}

/// Zero fields while `has_data` is clear and on a dummy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataTail {
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

impl DataTail {
    pub fn encode(&self) -> [u8; DATA_TAIL_LEN] {
        let mut out = [0; DATA_TAIL_LEN];
        out[..FIELD_LEN].copy_from_slice(&self.data_hash);
        out[FIELD_LEN..].copy_from_slice(&self.ring_data_hash);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                data_hash: *bytes.array()?,
                ring_data_hash: *bytes.array()?,
            })
        })
    }
}

/// One default-ring input's record, zero on any other slot, never its blinding or nullifier secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryRecord {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub amount: u64,
    pub mint: [u8; 32],
    /// SPP's spent UTXO hash, the value `private_tx_hash` chains.
    pub input_commitment: [u8; 32],
}

impl EntryRecord {
    fn extend(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.owner_key);
        out.extend_from_slice(&self.nullifier_pk);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.mint);
        out.extend_from_slice(&self.input_commitment);
    }

    fn read(bytes: &mut Bytes<'_>) -> Result<Self, CustomRingError> {
        Ok(Self {
            owner_key: *bytes.array()?,
            nullifier_pk: *bytes.array()?,
            amount: read_amount(bytes)?,
            mint: *bytes.array()?,
            input_commitment: *bytes.array()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputClass {
    Note,
    Address,
    Dummy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputClassification {
    pub published_inputs: usize,
    pub capacity: usize,
    pub note_count: u8,
    pub address_input_bits: u64,
}

/// Checks classification bounds and order, not nullifiers or proof validity.
/// The hidden owner rail separately requires slot zero to be a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputMap {
    classification: InputClassification,
    non_dummy_count: usize,
}

impl InputClassification {
    pub fn check(self) -> Result<InputMap, CustomRingError> {
        // 1. Each live slot is a note or address, their counts fix the prefix length L = R + popcount(A).
        let non_dummy_count =
            usize::from(self.note_count) + self.address_input_bits.count_ones() as usize;
        // 2. Require 1 <= n <= C <= 64 for published count n and key capacity C.
        // L <= n and every address bit must fall below L.
        // Clear bits below L then name exactly R notes, slots L..C are dummies.
        if self.published_inputs == 0
            || self.published_inputs > self.capacity
            || self.capacity > u64::BITS as usize
            || non_dummy_count > self.published_inputs
            || self
                .address_input_bits
                .checked_shr(non_dummy_count as u32)
                .unwrap_or(0)
                != 0
        {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(InputMap {
            classification: self,
            non_dummy_count,
        })
    }
}

impl InputMap {
    pub fn from_classes(
        classes: &[InputClass],
        published_inputs: usize,
    ) -> Result<Self, CustomRingError> {
        // 1. Capacity bounds every absolute bit position before any shift.
        if classes.len() > u64::BITS as usize {
            return Err(CustomRingError::RingTransactLength);
        }
        let mut note_count = 0;
        let mut address_input_bits = 0;
        let mut padding = false;
        // 2. Notes and addresses can interleave, a dummy or the published boundary starts the dummy suffix.
        for (slot, class) in classes.iter().enumerate() {
            if (padding || slot >= published_inputs) && *class != InputClass::Dummy {
                return Err(CustomRingError::RingTransactLength);
            }
            match class {
                InputClass::Note => note_count += 1,
                InputClass::Address => address_input_bits |= 1 << slot,
                InputClass::Dummy => padding = true,
            }
        }
        // 3. The bitmap and note count must reproduce the same bounded live prefix.
        InputClassification {
            published_inputs,
            capacity: classes.len(),
            note_count,
            address_input_bits,
        }
        .check()
    }

    pub const fn note_count(self) -> u8 {
        self.classification.note_count
    }

    pub const fn address_input_bits(self) -> u64 {
        self.classification.address_input_bits
    }

    pub const fn published_inputs(self) -> usize {
        self.classification.published_inputs
    }

    pub const fn capacity(self) -> usize {
        self.classification.capacity
    }

    pub const fn non_dummy_count(self) -> usize {
        self.non_dummy_count
    }

    pub const fn slot(self, slot: usize) -> Option<InputClass> {
        if slot >= self.capacity() {
            None
        } else {
            Some(self.class_at(slot))
        }
    }

    pub fn classes(self) -> impl ExactSizeIterator<Item = InputClass> {
        (0..self.capacity()).map(move |slot| self.class_at(slot))
    }

    /// Default bits select absolute note positions, never an address or a dummy.
    pub fn validate_default_input_bits(self, bits: u64) -> Result<(), CustomRingError> {
        if bits & self.address_input_bits() != 0
            || bits.checked_shr(self.non_dummy_count as u32).unwrap_or(0) != 0
        {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(())
    }

    const fn class_at(self, slot: usize) -> InputClass {
        if slot >= self.non_dummy_count {
            InputClass::Dummy
        } else if self.address_input_bits() & (1 << slot) != 0 {
            InputClass::Address
        } else {
            InputClass::Note
        }
    }
}

/// Entry evidence follows the sealed viewing key, note count and address bitmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvidence {
    None,
    SingleAssetPayout {
        mint: [u8; FIELD_LEN],
    },
    Entry {
        default_input_bits: u64,
        /// One per published input.
        inputs: Vec<EntryRecord>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub tx_viewing_secret: [u8; ENVELOPE_KEY_LEN],
    pub real_inputs: u8,
    pub address_input_bits: u64,
    pub evidence: AuditEvidence,
}

impl AuditEnvelope {
    pub fn input_map(&self, layout: AuditStreamLayout) -> Result<InputMap, CustomRingError> {
        if layout.key.format == DisclosureFormat::SingleAssetPayout
            && (usize::from(self.real_inputs) != SINGLE_ASSET_PAYOUT_INPUTS
                || self.address_input_bits != 0)
        {
            return Err(CustomRingError::RingTransactLength);
        }
        InputClassification {
            published_inputs: layout.inputs,
            capacity: layout.key.class(),
            note_count: self.real_inputs,
            address_input_bits: self.address_input_bits,
        }
        .check()
    }

    /// Writes the raw fields, use `input_map` or `decode` to check classification bounds.
    pub fn encode(&self) -> Vec<u8> {
        let evidence_len = match &self.evidence {
            AuditEvidence::None => 0,
            AuditEvidence::SingleAssetPayout { .. } => FIELD_LEN,
            AuditEvidence::Entry { inputs, .. } => {
                DEFAULT_INPUT_BITS_LEN + ENTRY_RECORD_LEN * inputs.len()
            }
        };
        let mut out = Vec::with_capacity(ENVELOPE_HEAD_LEN + evidence_len);
        out.extend_from_slice(&self.tx_viewing_secret);
        out.push(self.real_inputs);
        out.extend_from_slice(&self.address_input_bits.to_be_bytes());
        if let AuditEvidence::SingleAssetPayout { mint } = &self.evidence {
            out.extend_from_slice(mint);
        }
        if let AuditEvidence::Entry {
            default_input_bits,
            inputs,
        } = &self.evidence
        {
            out.extend_from_slice(&default_input_bits.to_be_bytes());
            inputs.iter().for_each(|input| input.extend(&mut out));
        }
        out
    }

    /// Refuses lengths and classification outside `layout`, ciphertext authentication remains with the caller.
    pub fn decode(plaintext: &[u8], layout: AuditStreamLayout) -> Result<Self, CustomRingError> {
        // 1. The selected layout bounds both counts, read_all refuses bytes after its final record.
        layout.checked()?;
        read_all(plaintext, |bytes| {
            let tx_viewing_secret = *bytes.array()?;
            let real_inputs = bytes.byte()?;
            let address_input_bits = u64::from_be_bytes(*bytes.array()?);
            // 2. Entry records retain absolute published positions, absent capacity slots carry no bytes.
            let evidence = match (layout.key.format, layout.key.entry) {
                (DisclosureFormat::SingleAssetPayout, false) => AuditEvidence::SingleAssetPayout {
                    mint: *bytes.array()?,
                },
                (DisclosureFormat::SingleAssetPayout, true) => {
                    return Err(CustomRingError::RingTransactLength)
                }
                (DisclosureFormat::Standard, false) => AuditEvidence::None,
                (DisclosureFormat::Standard, true) => AuditEvidence::Entry {
                    default_input_bits: u64::from_be_bytes(*bytes.array()?),
                    inputs: (0..layout.inputs)
                        .map(|_| EntryRecord::read(bytes))
                        .collect::<Result<_, CustomRingError>>()?,
                },
            };
            let envelope = Self {
                tx_viewing_secret,
                real_inputs,
                address_input_bits,
                evidence,
            };
            // 3. R and A define one live prefix, entry bits select only its notes.
            let inputs = envelope.input_map(layout)?;
            if let AuditEvidence::Entry {
                default_input_bits,
                inputs: records,
            } = &envelope.evidence
            {
                inputs.validate_default_input_bits(*default_input_bits)?;
                // 4. Unselected records must be zero, matching the circuit's multiplication by the default note selector.
                // Selected values remain unverified here, the ring proof binds them to the input commitments.
                for (slot, record) in records.iter().enumerate() {
                    if default_input_bits & (1 << slot) == 0 && *record != EntryRecord::default() {
                        return Err(CustomRingError::RingTransactLength);
                    }
                }
            }
            Ok(envelope)
        })
    }
}

/// The recipient's plaintext, outside the proof, one form on every rail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecipientBody {
    pub blinding: [u8; 32],
    pub amount: u64,
    pub mint: [u8; 32],
    /// The commitment covers it, a nonzero value travels with the note.
    pub ring_data_hash: Option<[u8; 32]>,
    pub data: Vec<u8>,
}

impl RecipientBody {
    pub fn encoded_len(&self) -> usize {
        let extended = self.ring_data_hash.is_some() || !self.data.is_empty();
        RECIPIENT_BODY_LEN
            + if extended {
                RECIPIENT_BODY_LENGTH_LEN
                    + 1
                    + self.ring_data_hash.map_or(0, |_| FIELD_LEN)
                    + self.data.len()
            } else {
                0
            }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let mut out = self.base();
        if self.encoded_len() > RECIPIENT_BODY_LEN {
            self.extend_payload(&mut out)?;
        }
        Ok(out)
    }

    pub fn encode_padded(&self, width: usize) -> Result<Vec<u8>, CustomRingError> {
        if width < self.encoded_len()
            || width > usize::from(u16::MAX)
            || (width != RECIPIENT_BODY_LEN
                && width < RECIPIENT_BODY_LEN + RECIPIENT_BODY_LENGTH_LEN)
        {
            return Err(CustomRingError::OutputBodyLength);
        }
        let mut out = self.encode()?;
        if width > RECIPIENT_BODY_LEN && out.len() == RECIPIENT_BODY_LEN {
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        out.resize(width, 0);
        Ok(out)
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(plaintext, CustomRingError::RingTransactLength);
        let mut body = Self {
            blinding: *bytes.array()?,
            amount: read_amount(&mut bytes)?,
            mint: *bytes.array()?,
            ..Self::default()
        };
        if plaintext.len() == RECIPIENT_BODY_LEN {
            return Ok(body);
        }
        let length = usize::from(u16::from_be_bytes(*bytes.array()?));
        let payload = bytes.take(length)?;
        if bytes.rest().iter().any(|byte| *byte != 0) {
            return Err(CustomRingError::RingTransactLength);
        }
        if payload.is_empty() {
            return Ok(body);
        }
        let mut payload = Bytes::new(payload, CustomRingError::RingTransactLength);
        body.ring_data_hash = match payload.byte()? {
            0 => None,
            1 => Some(*payload.array()?),
            _ => return Err(CustomRingError::RingTransactLength),
        };
        body.data = payload.rest().to_vec();
        Ok(body)
    }

    fn base(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&self.blinding);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.mint);
        out
    }

    fn extend_payload(&self, out: &mut Vec<u8>) -> Result<(), CustomRingError> {
        let length = 1 + self.ring_data_hash.map_or(0, |_| FIELD_LEN) + self.data.len();
        let length = u16::try_from(length).map_err(|_| CustomRingError::OutputBodyLength)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.push(u8::from(self.ring_data_hash.is_some()));
        if let Some(ring_data_hash) = self.ring_data_hash {
            out.extend_from_slice(&ring_data_hash);
        }
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactRecipientBody {
    pub blinding: [u8; FIELD_LEN],
    pub amount: u64,
    pub asset_id: u64,
}

impl CompactRecipientBody {
    pub fn encode(self) -> [u8; COMPACT_RECIPIENT_BODY_LEN] {
        let mut out = [0; COMPACT_RECIPIENT_BODY_LEN];
        out[..FIELD_LEN].copy_from_slice(&self.blinding);
        out[FIELD_LEN..FIELD_LEN + AMOUNT_LEN].copy_from_slice(&self.amount.to_be_bytes());
        out[FIELD_LEN + AMOUNT_LEN..].copy_from_slice(&self.asset_id.to_be_bytes());
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                blinding: *bytes.array()?,
                amount: read_amount(bytes)?,
                asset_id: read_amount(bytes)?,
            })
        })
    }
}

/// The cells the sender rebuilds change and recipients from, outside the proof.
///
/// `output_seed || change cells || recipient keys`, cell k rebuilds bodiless slot k, key k names body-bearing slot k.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SenderBundle {
    pub output_seed: [u8; 32],
    pub change: Vec<ChangeCell>,
    /// Zero on exit and dummy.
    pub recipient_keys: Vec<[u8; 32]>,
}

/// A bodiless slot's mint and amount, its blinding derives from the bundle's seed at the slot index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChangeCell {
    pub mint: [u8; 32],
    pub amount: u64,
}

impl SenderBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.layout().byte_len());
        out.extend_from_slice(&self.output_seed);
        for cell in &self.change {
            out.extend_from_slice(&cell.mint);
            out.extend_from_slice(&cell.amount.to_be_bytes());
        }
        self.recipient_keys
            .iter()
            .for_each(|key| out.extend_from_slice(key));
        out
    }

    pub fn decode(plaintext: &[u8], layout: BundleLayout) -> Result<Self, CustomRingError> {
        if layout.change > layout.outputs {
            return Err(CustomRingError::RingTransactLength);
        }
        read_all(plaintext, |bytes| {
            Ok(Self {
                output_seed: *bytes.array()?,
                change: (0..layout.change)
                    .map(|_| {
                        Ok(ChangeCell {
                            mint: *bytes.array()?,
                            amount: read_amount(bytes)?,
                        })
                    })
                    .collect::<Result<_, CustomRingError>>()?,
                recipient_keys: bytes.fields(layout.recipient_keys())?.to_vec(),
            })
        })
    }

    pub fn layout(&self) -> BundleLayout {
        BundleLayout {
            outputs: self.change.len() + self.recipient_keys.len(),
            change: self.change.len(),
        }
    }
}

fn read_amount(bytes: &mut Bytes<'_>) -> Result<u64, CustomRingError> {
    Ok(u64::from_be_bytes(*bytes.array()?))
}

fn read_all<'a, T>(
    plaintext: &'a [u8],
    read: impl FnOnce(&mut Bytes<'a>) -> Result<T, CustomRingError>,
) -> Result<T, CustomRingError> {
    let mut bytes = Bytes::new(plaintext, CustomRingError::RingTransactLength);
    let value = read(&mut bytes)?;
    match bytes.rest().is_empty() {
        true => Ok(value),
        false => Err(CustomRingError::RingTransactLength),
    }
}
