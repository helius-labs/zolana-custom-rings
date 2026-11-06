//! The one lookup from a ring circuit to its compiled verifying key.
//!
//! A frame selects a circuit by shape, a shape off the catalog fails here with no key to verify under.
//!
//! Read after `instructions/transfer/verify.rs`. Read before `program-libs/interface/src/proof/key_catalog.rs`.

use custom_ring_interface::{key_catalog::RingCircuit, verifying_key, CustomRingError};
use groth16_solana::groth16::Groth16Verifyingkey;

pub(crate) use custom_ring_interface::RingProof;

pub(crate) fn ring_key(
    circuit: RingCircuit,
) -> Result<&'static Groth16Verifyingkey<'static>, CustomRingError> {
    verifying_key(circuit).ok_or(CustomRingError::UnsupportedCircuit)
}
