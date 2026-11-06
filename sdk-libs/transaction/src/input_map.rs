//! The one SDK reading of SPP's input order, the interface `InputMap` validates the order.

use custom_ring_interface::{CustomRingError, InputClass, InputMap};
use spr_transaction::utxo::SppProofInputUtxo;

/// SPP interleaves notes and addresses ahead of its dummy suffix.
pub trait ClassifiedInput {
    fn input_class(&self) -> InputClass;

    /// A spent note, the only input whose owner and amount the ring screens.
    fn is_note(&self) -> bool {
        self.input_class() == InputClass::Note
    }
}

impl ClassifiedInput for SppProofInputUtxo {
    /// The address flag decides first, a dummy is the zero owner.
    fn input_class(&self) -> InputClass {
        if self.is_address() {
            InputClass::Address
        } else if self.is_dummy() {
            InputClass::Dummy
        } else {
            InputClass::Note
        }
    }
}

/// The published inputs of `inputs` under a key of input class `capacity`, compact padding publishes no nullifier.
pub fn published_input_map(
    inputs: &[SppProofInputUtxo],
    capacity: usize,
) -> Result<InputMap, CustomRingError> {
    let published: Vec<InputClass> = inputs
        .iter()
        .filter(|input| !input.is_compact())
        .map(ClassifiedInput::input_class)
        .collect();
    let padding = capacity
        .checked_sub(published.len())
        .ok_or(CustomRingError::RingTransactLength)?;
    let classes: Vec<InputClass> = published
        .iter()
        .copied()
        .chain(core::iter::repeat_n(InputClass::Dummy, padding))
        .collect();
    InputMap::from_classes(&classes, published.len())
}

#[cfg(test)]
mod tests {
    use spr_keypair::PublicKey;

    use super::*;

    fn note() -> SppProofInputUtxo {
        let mut note = SppProofInputUtxo::dummy(0).unwrap();
        note.utxo.owner = PublicKey::from_ed25519(&[3; 32]);
        note
    }

    fn address() -> SppProofInputUtxo {
        SppProofInputUtxo::new_address(PublicKey::from_ed25519(&[4; 32]), [5; 32], 0).unwrap()
    }

    fn dummy() -> SppProofInputUtxo {
        SppProofInputUtxo::dummy(0).unwrap()
    }

    fn compact() -> SppProofInputUtxo {
        SppProofInputUtxo::compact(0).unwrap()
    }

    #[test]
    fn an_address_between_notes_keeps_its_absolute_position() {
        use InputClass::{Address, Dummy, Note};
        let inputs = [note(), address(), note(), dummy(), compact()];
        let map = published_input_map(&inputs, 8).unwrap();
        assert_eq!(map.published_inputs(), 4);
        assert_eq!(map.note_count(), 2);
        assert_eq!(map.address_input_bits(), 0b010);
        assert_eq!(
            map.classes().take(5).collect::<Vec<_>>(),
            [Note, Address, Note, Dummy, Dummy]
        );
        assert!(address().input_class() == Address && !address().is_note());
    }

    /// An address alone spends no note, `R` is zero while SPP still authorizes it.
    #[test]
    fn an_address_only_spend_counts_no_note() {
        let map = published_input_map(&[address(), compact()], 2).unwrap();
        assert_eq!(map.note_count(), 0);
        assert_eq!(map.address_input_bits(), 0b1);
        assert_eq!(map.published_inputs(), 1);
    }

    #[test]
    fn a_dummy_ahead_of_a_note_or_inputs_past_the_class_are_refused() {
        for (inputs, capacity) in [
            (vec![dummy(), note()], 2),
            (vec![note(), dummy(), address()], 4),
            (vec![note(), note(), note()], 2),
        ] {
            assert_eq!(
                published_input_map(&inputs, capacity),
                Err(CustomRingError::RingTransactLength)
            );
        }
    }
}
