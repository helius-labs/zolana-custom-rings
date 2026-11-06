//! The repair schedule of a ring's unread frames, mirrored in `spend_unread_frames`.
//!
//! A frame never tried comes first, then failed frames in the order their backoff ends. A failure
//! moves its frame behind every due frame, so a fixed set of failing frames never holds back another.

use std::collections::BTreeMap;

use crate::utxos::CreatedIn;

pub(crate) const MAX_REPAIRED_FRAMES: usize = 16;
/// Seconds before the first retry, doubled per failure up to `BACKOFF_CAP`.
const BACKOFF_BASE: u64 = 30;
const BACKOFF_CAP: u64 = 3_600;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RepairAttempt {
    pub attempts: u32,
    /// Unix seconds.
    pub retry_after: u64,
}

/// Mutated only under the backfill lock.
#[derive(Debug, Default)]
pub(crate) struct RepairBook {
    attempts: BTreeMap<CreatedIn, RepairAttempt>,
}

impl RepairBook {
    /// At most `MAX_REPAIRED_FRAMES` unread frames whose backoff ended by `now`.
    pub(crate) fn due(
        &self,
        unread: impl IntoIterator<Item = CreatedIn>,
        now: u64,
    ) -> Vec<CreatedIn> {
        let mut due: Vec<(u64, CreatedIn)> = unread
            .into_iter()
            .map(|frame| {
                let after = self
                    .attempts
                    .get(&frame)
                    .map_or(0, |attempt| attempt.retry_after);
                (after, frame)
            })
            .filter(|(after, _)| *after <= now)
            .collect();
        due.sort_unstable();
        due.into_iter()
            .take(MAX_REPAIRED_FRAMES)
            .map(|(_, frame)| frame)
            .collect()
    }

    pub(crate) fn failed(&mut self, frame: CreatedIn, now: u64) -> RepairAttempt {
        let attempt = self.attempts.entry(frame).or_default();
        attempt.attempts = attempt.attempts.saturating_add(1);
        let doublings = attempt.attempts.saturating_sub(1).min(7);
        attempt.retry_after = now.saturating_add((BACKOFF_BASE << doublings).min(BACKOFF_CAP));
        *attempt
    }

    pub(crate) fn forget(&mut self, frame: &CreatedIn) {
        self.attempts.remove(frame);
    }
}

impl FromIterator<(CreatedIn, RepairAttempt)> for RepairBook {
    fn from_iter<I: IntoIterator<Item = (CreatedIn, RepairAttempt)>>(iter: I) -> Self {
        Self {
            attempts: iter.into_iter().collect(),
        }
    }
}
