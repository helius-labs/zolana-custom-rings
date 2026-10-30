use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr32BE;
use spr_hasher::primitives::right_align;
use spr_keypair::hash::poseidon;
use zeroize::Zeroizing;

use crate::RingKeyError;

const CTR_NONCE_LEN: usize = 12;

/// The stream schedule the audit circuits prove, for the envelope and every delivered body.
pub fn symmetric_apply_audit(
    shared_secret: &[u8; 32],
    info: &[u8; 10],
    buf: &mut [u8],
) -> Result<(), RingKeyError> {
    let mut tag = [0u8; 11];
    tag[..10].copy_from_slice(info);
    let mut key = Zeroizing::new([0u8; 32]);
    tag[10] = 0;
    let head = Zeroizing::new(poseidon(&[&right_align(&tag), shared_secret])?);
    key[..31].copy_from_slice(&head[1..]);
    tag[10] = 1;
    let tail = Zeroizing::new(poseidon(&[&right_align(&tag), shared_secret])?);
    key[31] = tail[19];
    let mut nonce = [0u8; CTR_NONCE_LEN];
    nonce.copy_from_slice(&tail[20..]);
    ctr_apply(&key, &nonce, buf);
    Ok(())
}

/// AES-256-CTR from `nonce || 2`, the counter zolana's transfer ciphertexts start at.
fn ctr_apply(key: &[u8; 32], nonce: &[u8; CTR_NONCE_LEN], buf: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..CTR_NONCE_LEN].copy_from_slice(nonce);
    iv[15] = 2;
    let mut cipher = Ctr32BE::<Aes256>::new(key.into(), (&iv).into());
    cipher.apply_keystream(buf);
}

#[cfg(test)]
mod audit_stream_tests {
    use super::symmetric_apply_audit;

    #[test]
    fn matches_the_go_auditor_stream_vector() {
        let mut shared = [0u8; 32];
        shared[29..].copy_from_slice(&[1, 0x23, 0x45]);
        let mut ciphertext = [0u8; 32];
        symmetric_apply_audit(&shared, b"CRING/adt1", &mut ciphertext).unwrap();
        assert_eq!(
            hex::encode(ciphertext),
            "001d45a89ea12a64c7e6886ce543a66f77971b2c1052688ff668fe8c0c5d7c7b"
        );
        symmetric_apply_audit(&shared, b"CRING/adt1", &mut ciphertext).unwrap();
        assert_eq!(ciphertext, [0; 32]);
    }
}
