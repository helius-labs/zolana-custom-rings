//! The one SDK reading of SPP's input order. The ring's input wires hold SPP's notes in order, then
//! dummies, and an address reaches the ring proof only through `private_tx_hash`.

use spr_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use spr_transaction::utxo::SppProofInputUtxo;

use crate::RingRailError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputClass {
    Note,
    Address,
    Dummy,
}

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

/// `R`, the envelope's count of spent notes.
pub fn note_count(inputs: &[SppProofInputUtxo]) -> Result<u8, RingRailError> {
    let notes = inputs.iter().filter(|input| input.is_note()).count();
    u8::try_from(notes).map_err(|_| {
        spr_transaction::TransactionError::TooManyInputs {
            got: notes,
            max: usize::from(u8::MAX),
        }
        .into()
    })
}

/// SPP's address chain over the address nullifiers in slot order, the ring proof reopens it inside
/// `private_tx_hash` alone.
pub fn address_chain(inputs: &[SppProofInputUtxo]) -> Result<[u8; 32], RingRailError> {
    let addresses: Vec<[u8; 32]> = inputs
        .iter()
        .filter(|input| input.is_address())
        .map(SppProofInputUtxo::nullifier)
        .collect();
    Ok(create_nonzero_hash_chain_from_slice(&addresses)?)
}
