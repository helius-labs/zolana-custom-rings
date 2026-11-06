//! The audit layout element and the packing of a ciphertext into statement fields, mirror of `prover/circuits/audit/layout.go`.
//!
//! Read after `program-libs/interface/src/proof/audit_stream.rs`. Read before `program-libs/interface/src/codec/output.rs`.

use spr_hasher::primitives::{pack_be_chunks, PACK_BE_CHUNK_BYTES};

pub const TRANSFER_OUTPUT_CAPACITIES: [usize; 4] = [2, 4, 8, 16];

/// The transfer statement's layout element, mirror `prover/circuits/audit/layout.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditLayout {
    pub format: crate::DisclosureFormat,
    /// One tail per published slot, the proof holds every data hash to zero while clear.
    pub has_data: bool,
    /// The key carries default bits and one evidence entry per published input.
    pub entry: bool,
}

impl AuditLayout {
    pub const fn value(self) -> u8 {
        self.has_data as u8 | (self.entry as u8) << 1 | (self.format as u8) << 2
    }
}

/// Zero pads the plaintext at its end to whole 31-byte chunks, one chunk per field.
pub fn pack_disclosure(plaintext: &[u8]) -> Vec<[u8; 32]> {
    plaintext
        .chunks(PACK_BE_CHUNK_BYTES)
        .map(|chunk| {
            let mut field = [0u8; 32];
            field[1..1 + chunk.len()].copy_from_slice(chunk);
            field
        })
        .collect()
}

/// Inverts [`pack_disclosure`], `None` when a field holds bytes outside its chunk.
pub fn unpack_disclosure(fields: &[[u8; 32]], len: usize) -> Option<Vec<u8>> {
    if fields.len() != pack_be_chunks(len) {
        return None;
    }
    let mut plaintext = Vec::with_capacity(len);
    for (index, field) in fields.iter().enumerate() {
        let chunk = (len - index * PACK_BE_CHUNK_BYTES).min(PACK_BE_CHUNK_BYTES);
        let (bytes, padding) = field[1..].split_at(chunk);
        if field[0] != 0 || padding.iter().any(|byte| *byte != 0) {
            return None;
        }
        plaintext.extend_from_slice(bytes);
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_value_is_the_circuit_flags() {
        let value = |has_data, entry| {
            AuditLayout {
                has_data,
                entry,
                format: crate::DisclosureFormat::Standard,
            }
            .value()
        };
        assert_eq!(value(false, false), 0);
        assert_eq!(value(true, false), 1);
        assert_eq!(value(false, true), 2);
        assert_eq!(value(true, true), 3);
    }

    #[test]
    fn a_short_tail_chunk_is_left_aligned_and_zero_padded() {
        let plaintext: Vec<u8> = (1..=40).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0][0], 0);
        assert_eq!(fields[0][1..], plaintext[..31]);
        assert_eq!(fields[1][..10], [0, 32, 33, 34, 35, 36, 37, 38, 39, 40]);
        assert_eq!(fields[1][10..], [0u8; 22]);
        assert_eq!(
            unpack_disclosure(&fields, 40).as_deref(),
            Some(&plaintext[..])
        );
    }

    #[test]
    fn unpacking_rejects_bytes_outside_a_chunk() {
        let plaintext: Vec<u8> = (1..=70).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 3);
        assert_eq!(unpack_disclosure(&fields, 94), None);
        let mut padded = fields.clone();
        padded[2][9] = 1;
        assert_eq!(unpack_disclosure(&padded, 70), None);
        let mut widened = fields;
        widened[0][0] = 1;
        assert_eq!(unpack_disclosure(&widened, 70), None);
    }
}
