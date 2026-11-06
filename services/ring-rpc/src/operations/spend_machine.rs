//! One state per published nullifier, driven only by finalized frames and note openings.
//!
//! A transfer's proof names `R` and no note position, so a nullifier reads as a spend until the
//! index resolves it. `R` checks a frame's flows, never a row.

use zolana_ring_client::rpc::WalletNoteStatus;

use crate::utxos::CreatedIn;

/// `Padding` and `Resolved` are terminal, an unclassified row never reads as padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpendState {
    /// The frame's stream is unreadable, the frame retries.
    Observed,
    /// A merge's padding slot, its record names every real nullifier.
    Padding,
    Resolved {
        note: [u8; 32],
    },
    /// No opened note owns it yet, an unopened note, address, default-ring note or transfer
    /// padding.
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendRow {
    pub nullifier: [u8; 32],
    pub frame: CreatedIn,
    pub position: u16,
    pub state: SpendState,
}

/// What the frame's proven stream says of one input position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputRead {
    Unreadable,
    Padding,
    /// Any slot the index may resolve to a note.
    Spend,
}

/// One nullifier as a frame publishes it, `hit` is the note index's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub nullifier: [u8; 32],
    pub frame: CreatedIn,
    pub position: u16,
    pub read: InputRead,
    pub hit: Option<[u8; 32]>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    Unchanged,
    Write(SpendRow),
    /// A second event on one nullifier, the first state stays.
    Integrity(SpendRow),
}

impl Observation {
    pub(crate) fn state(self) -> SpendState {
        match (self.read, self.hit) {
            (InputRead::Unreadable, _) => SpendState::Observed,
            (InputRead::Padding, _) => SpendState::Padding,
            (InputRead::Spend, Some(note)) => SpendState::Resolved { note },
            (InputRead::Spend, None) => SpendState::Unclassified,
        }
    }

    /// A replay of one frame is idempotent, a read moves only `Observed` or `Unclassified`.
    pub(crate) fn apply(self, existing: Option<&SpendRow>) -> Transition {
        let row = SpendRow {
            nullifier: self.nullifier,
            frame: self.frame,
            position: self.position,
            state: self.state(),
        };
        let Some(existing) = existing else {
            return Transition::Write(row);
        };
        if existing.frame != self.frame || existing.position != self.position {
            return Transition::Integrity(row);
        }
        let moves = match existing.state {
            SpendState::Observed => row.state != SpendState::Observed,
            SpendState::Unclassified => matches!(row.state, SpendState::Resolved { .. }),
            SpendState::Padding | SpendState::Resolved { .. } => false,
        };
        match moves {
            true => Transition::Write(row),
            false => Transition::Unchanged,
        }
    }
}

impl SpendRow {
    /// A newly opened note or a late secret moves an unclassified row only.
    pub(crate) fn opened(self, note: [u8; 32]) -> Transition {
        match self.state {
            SpendState::Unclassified => Transition::Write(Self {
                state: SpendState::Resolved { note },
                ..self
            }),
            SpendState::Resolved { note: held } if held != note => Transition::Integrity(self),
            SpendState::Resolved { .. } | SpendState::Observed | SpendState::Padding => {
                Transition::Unchanged
            }
        }
    }
}
/// The inputs of one note's status, each read from its own nullifier and no other row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoteRead {
    pub nullifier_known: bool,
    /// The published row of the note's nullifier.
    pub spent_at: Option<u64>,
    pub zero_key_wallet: bool,
    pub history_through: u64,
}

impl NoteRead {
    /// `Spent` comes first, a spent zero key note leaves the exposed list.
    pub(crate) fn status(self) -> WalletNoteStatus {
        let spent = self
            .spent_at
            .is_some_and(|slot| slot <= self.history_through);
        match (spent, self.nullifier_known, self.zero_key_wallet) {
            (true, _, _) => WalletNoteStatus::Spent,
            (false, _, true) => WalletNoteStatus::ExposedIfSpent,
            (false, false, false) => WalletNoteStatus::Unknown,
            (false, true, false) => WalletNoteStatus::Unspent,
        }
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;

    use super::*;

    fn frame(byte: u8) -> CreatedIn {
        CreatedIn {
            slot: u64::from(byte),
            tx_signature: Signature::from([byte; 64]),
            event_index: 0,
        }
    }

    fn observed(read: InputRead, hit: Option<[u8; 32]>) -> Observation {
        Observation {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            read,
            hit,
        }
    }

    fn written(transition: Transition) -> SpendState {
        match transition {
            Transition::Write(row) => row.state,
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn each_read_enters_its_state() {
        let spend = InputRead::Spend;
        for (read, hit, state) in [
            (InputRead::Padding, None, SpendState::Padding),
            (spend, None, SpendState::Unclassified),
            (spend, Some([2; 32]), SpendState::Resolved { note: [2; 32] }),
            (InputRead::Unreadable, None, SpendState::Observed),
            (InputRead::Unreadable, Some([2; 32]), SpendState::Observed),
        ] {
            assert_eq!(written(observed(read, hit).apply(None)), state);
        }
    }

    #[test]
    fn merge_padding_ignores_a_hit() {
        assert!(!matches!(
            observed(InputRead::Padding, Some([2; 32])).state(),
            SpendState::Resolved { .. }
        ));
    }

    #[test]
    fn an_unreadable_row_moves_only_once_read() {
        let row = SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state: SpendState::Observed,
        };
        assert_eq!(
            observed(InputRead::Unreadable, None).apply(Some(&row)),
            Transition::Unchanged
        );
        assert_eq!(
            written(observed(InputRead::Padding, None).apply(Some(&row))),
            SpendState::Padding
        );
    }

    #[test]
    fn a_replay_changes_no_terminal_row() {
        for state in [SpendState::Padding, SpendState::Resolved { note: [2; 32] }] {
            let row = SpendRow {
                nullifier: [1; 32],
                frame: frame(1),
                position: 0,
                state,
            };
            for read in [InputRead::Padding, InputRead::Unreadable, InputRead::Spend] {
                assert_eq!(
                    observed(read, Some([3; 32])).apply(Some(&row)),
                    Transition::Unchanged
                );
            }
        }
    }

    #[test]
    fn a_second_event_on_one_nullifier_is_an_integrity_fault_and_overwrites_nothing() {
        let row = SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state: SpendState::Resolved { note: [2; 32] },
        };
        let second = Observation {
            frame: frame(2),
            ..observed(InputRead::Spend, Some([3; 32]))
        };
        assert!(matches!(
            second.apply(Some(&row)),
            Transition::Integrity(fault) if fault.frame == frame(2)
        ));
    }

    #[test]
    fn an_opened_note_resolves_an_unclassified_row_and_no_other() {
        let row = |state| SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state,
        };
        assert_eq!(
            written(row(SpendState::Unclassified).opened([2; 32])),
            SpendState::Resolved { note: [2; 32] }
        );
        for state in [
            SpendState::Observed,
            SpendState::Padding,
            SpendState::Resolved { note: [2; 32] },
        ] {
            assert_eq!(row(state).opened([2; 32]), Transition::Unchanged);
        }
        assert!(matches!(
            row(SpendState::Resolved { note: [3; 32] }).opened([2; 32]),
            Transition::Integrity(_)
        ));
    }

    #[test]
    fn spent_comes_before_every_other_status() {
        let read = NoteRead {
            nullifier_known: true,
            spent_at: None,
            zero_key_wallet: false,
            history_through: 10,
        };
        assert_eq!(read.status(), WalletNoteStatus::Unspent);
        assert_eq!(
            NoteRead {
                nullifier_known: false,
                ..read
            }
            .status(),
            WalletNoteStatus::Unknown
        );
        let exposed = NoteRead {
            zero_key_wallet: true,
            ..read
        };
        assert_eq!(exposed.status(), WalletNoteStatus::ExposedIfSpent);
        assert_eq!(
            NoteRead {
                spent_at: Some(10),
                ..exposed
            }
            .status(),
            WalletNoteStatus::Spent
        );
    }

    #[test]
    fn a_spend_past_the_history_slot_stays_unspent_so_a_note_and_its_change_never_both_count() {
        let read = NoteRead {
            nullifier_known: true,
            spent_at: Some(11),
            zero_key_wallet: false,
            history_through: 10,
        };
        assert_eq!(read.status(), WalletNoteStatus::Unspent);
    }
}
