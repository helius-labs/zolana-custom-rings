//! One planned key per transfer, fixed before its seal and read by every later stage.
//!
//! The key fixes every counter of the auditor stream. Sealing, the proof request, the relay terms
//! and the size check read one `PlannedTransfer` and never select a key again. Only a record read
//! can change the key, and it keeps the seal only where both streams open alike. Otherwise the
//! owner seals again and signs the new message, the stream never moves under a signature.
//!
//! Read after `program-libs/interface/src/proof/key_catalog.rs` and `Prepared` in `mod.rs`. Read
//! before `policy.rs`, `audit.rs`, `relay.rs`.

use custom_ring_interface::{
    key_catalog::{RecordPools, RingCircuit, TransferSpend},
    AuditStreamLayout, CustomRingError,
};
use spr_keypair::ShieldedAddress;
use spr_transaction::instructions::transact::SppProofInputs;
use zolana_ring_transaction::RingOutputRail;

use super::{Preview, TransferKey};
use crate::RingError;

/// One of the two rows a transfer's counts select between, the frame header's wide flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealRow {
    Narrow,
    Wide,
}

impl SealRow {
    pub const fn of(wide: bool) -> Self {
        match wide {
            true => Self::Wide,
            false => Self::Narrow,
        }
    }

    pub const fn wide(self) -> bool {
        matches!(self, Self::Wide)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlannedTransfer {
    pub key: TransferKey,
    pub stream: AuditStreamLayout,
    /// A data tail or a disclosed approval opening spans every slot of the key's `N`.
    pub spans_capacity: bool,
}

impl PlannedTransfer {
    /// The key `read` selects, carrying the seal made under `self` or refusing until resealed.
    /// Mirrors `TransferShape::seals_like`, an approval opening binds `N` like a tail.
    pub fn rekeyed(self, read: Self) -> Result<Self, RingError> {
        let opens_alike = self.stream.key.format == read.stream.key.format
            && self.stream.first_record_counter() == read.stream.first_record_counter()
            && (!self.spans_capacity || self.stream.capacity == read.stream.capacity);
        match opens_alike {
            true => Ok(read),
            false => Err(RingError::ResealRequired {
                row: SealRow::of(read.key.wide),
            }),
        }
    }
}

/// Every count a key is chosen from, all public before any record read.
pub(super) struct TransferPlanner<'a> {
    /// `pools` empty and `wide` clear, a plan fills them.
    pub subjects: TransferSpend,
    pub preview: &'a Preview,
    pub inputs: &'a SppProofInputs,
    pub rail: &'a RingOutputRail,
    pub sender: &'a ShieldedAddress,
    pub spans_capacity: bool,
}

impl TransferPlanner<'_> {
    /// The narrowest key holding the counts and `pools`, empty pools ahead of every record read.
    pub fn plan(&self, pools: RecordPools) -> Result<PlannedTransfer, RingError> {
        self.keyed(
            TransferSpend {
                pools,
                ..self.subjects
            }
            .fitted(),
        )
    }

    /// The key of `row` whatever the reads.
    pub fn plan_at(&self, row: SealRow) -> Result<PlannedTransfer, RingError> {
        self.keyed(TransferSpend {
            wide: row.wide(),
            ..self.subjects
        })
    }

    fn keyed(&self, spend: TransferSpend) -> Result<PlannedTransfer, RingError> {
        let unkeyed = || RingError::ShapeUnkeyed { rail: spend.rail };
        let key = TransferKey {
            circuit: RingCircuit::transfer(spend).ok_or_else(unkeyed)?,
            wide: spend.wide,
        };
        // The program derives the stream from the frame header, so the plan reads it the same way.
        let stream = self
            .preview
            .parts(self.inputs, self.rail, self.sender, key)?
            .data()?
            .audit_stream()
            .map_err(|error| match error {
                CustomRingError::RingShapeUnkeyed => unkeyed(),
                error => error.into(),
            })?;
        Ok(PlannedTransfer {
            key,
            stream,
            spans_capacity: self.spans_capacity,
        })
    }
}

#[cfg(test)]
#[path = "../../tests/operations/plan.rs"]
mod tests;
