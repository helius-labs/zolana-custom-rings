use custom_ring_interface::{key_catalog::RingCircuit, verifying_key, CustomRingError};
use groth16_solana::groth16::Groth16Verifyingkey;

pub(crate) use custom_ring_interface::RingProof;

pub(crate) fn ring_key(
    circuit: RingCircuit,
) -> Result<&'static Groth16Verifyingkey<'static>, CustomRingError> {
    verifying_key(circuit).ok_or(CustomRingError::UnsupportedCircuit)
}
