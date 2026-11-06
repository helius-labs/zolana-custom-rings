use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr32BE;
use custom_ring_interface::STREAM_FIRST_COUNTER;
use spr_hasher::primitives::right_align;
use spr_keypair::hash::poseidon;
use zeroize::Zeroizing;

use crate::RingKeyError;

const CTR_NONCE_LEN: usize = 12;

/// One AES key and nonce of the ring schedule, mirrored by `AuditStreamKeySchedule` in `prover/circuits/shared/envelope.go`.
pub struct RingStream {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; CTR_NONCE_LEN],
}

impl RingStream {
    pub fn new(shared_secret: &[u8; 32], label: &[u8; 9]) -> Result<Self, RingKeyError> {
        let mut tag = [0u8; 10];
        tag[..9].copy_from_slice(label);
        let head = Zeroizing::new(poseidon(&[&right_align(&tag), shared_secret])?);
        tag[9] = 1;
        let tail = Zeroizing::new(poseidon(&[&right_align(&tag), shared_secret])?);
        let mut key = Zeroizing::new([0u8; 32]);
        key[..31].copy_from_slice(&head[1..]);
        key[31] = tail[19];
        let mut nonce = [0u8; CTR_NONCE_LEN];
        nonce.copy_from_slice(&tail[20..]);
        Ok(Self { key, nonce })
    }

    /// A counter that serves two plaintexts reveals their XOR.
    pub fn apply_at(&self, counter: u32, buf: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..CTR_NONCE_LEN].copy_from_slice(&self.nonce);
        iv[CTR_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
        Ctr32BE::<Aes256>::new((&*self.key).into(), (&iv).into()).apply_keystream(buf);
    }
}

/// The whole stream of `label` from its first counter.
pub fn symmetric_apply_audit(
    shared_secret: &[u8; 32],
    label: &[u8; 9],
    buf: &mut [u8],
) -> Result<(), RingKeyError> {
    RingStream::new(shared_secret, label)?.apply_at(STREAM_FIRST_COUNTER, buf);
    Ok(())
}

#[cfg(test)]
mod audit_stream_tests {
    use custom_ring_interface::{
        domain::{AUDIT_STREAM_LABEL, REGISTER_KEY_LABEL},
        STREAM_FIRST_COUNTER,
    };

    use super::{symmetric_apply_audit, RingStream};

    fn shared() -> [u8; 32] {
        let mut shared = [0u8; 32];
        shared[29..].copy_from_slice(&[1, 0x23, 0x45]);
        shared
    }

    #[test]
    fn matches_the_go_auditor_stream_vector() {
        let shared = shared();
        let mut ciphertext = [0u8; 32];
        symmetric_apply_audit(&shared, AUDIT_STREAM_LABEL, &mut ciphertext).unwrap();
        assert_eq!(
            hex::encode(ciphertext),
            "1bdac2890094c5e4113d9e5b60b17aca409d3f9baba3912c65c8fc76bef1ae3c"
        );
        symmetric_apply_audit(&shared, AUDIT_STREAM_LABEL, &mut ciphertext).unwrap();
        assert_eq!(ciphertext, [0; 32]);
    }

    #[test]
    fn a_range_reads_the_same_keystream_as_the_whole_stream() {
        let shared = shared();
        let mut whole = [0u8; 160];
        symmetric_apply_audit(&shared, AUDIT_STREAM_LABEL, &mut whole).unwrap();
        let stream = RingStream::new(&shared, AUDIT_STREAM_LABEL).unwrap();
        for block in 0..9 {
            let mut range = [0u8; 16];
            stream.apply_at(STREAM_FIRST_COUNTER + block as u32, &mut range);
            assert_eq!(range, whole[16 * block..16 * block + 16], "block {block}");
        }
    }

    #[test]
    fn a_label_separates_the_keystreams_of_one_secret() {
        let shared = shared();
        let keystream = |label| {
            let mut buf = [0u8; 16];
            symmetric_apply_audit(&shared, label, &mut buf).unwrap();
            buf
        };
        let labels = [AUDIT_STREAM_LABEL, REGISTER_KEY_LABEL];
        for (index, label) in labels.iter().enumerate() {
            for other in &labels[index + 1..] {
                assert_ne!(keystream(label), keystream(other));
            }
        }
    }
}
