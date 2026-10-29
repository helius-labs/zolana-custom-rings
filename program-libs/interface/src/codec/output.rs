//! Ring output bodies in SPP's encrypted output framing, schemes SPP stores without parsing.

use spr_event::{
    OutputDataEncoding, ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
    ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};

use crate::CustomRingError;

pub const RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG: u8 = 10;
/// Scheme 10 led by its recipient key, under the owner's own key on the in-proof owner rail.
pub const RING_OWNER_DELIVERED_SCHEME_TAG: u8 = 11;

/// AES-CTR of the 32-byte blinding then the big-endian u64 amount.
pub const RING_DELIVERED_BODY_LEN: usize = 40;

/// `0x04 || u`, the recipient key a scheme 3 body leads with.
pub const RECIPIENT_KEY_LEN: usize = 33;

/// Asset id, amount and blinding open every confidential plaintext.
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN: usize = 8 + 8 + 32;

/// Scheme 3 body of an output with no data and no ring id, each one zero byte.
pub const CONFIDENTIAL_DATA_FREE_BODY_LEN: usize =
    RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

/// The encoding tag and the u32 body length before the scheme byte.
const BODY_OFFSET: usize = 1 + 4;

pub fn ring_confidential_delivered_output_body(
    data: &[u8],
) -> Option<&[u8; RING_DELIVERED_BODY_LEN]> {
    encrypted_output_body(data, RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG)?
        .try_into()
        .ok()
}

pub fn ring_owner_delivered_output(
    data: &[u8],
) -> Option<(&[u8; 32], &[u8; RING_DELIVERED_BODY_LEN])> {
    let (u, body) =
        encrypted_output_body(data, RING_OWNER_DELIVERED_SCHEME_TAG)?.split_first_chunk::<32>()?;
    Some((u, body.try_into().ok()?))
}

pub fn encode_confidential_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, body)
}

pub fn encode_ring_confidential_delivered_output(
    body: &[u8; RING_DELIVERED_BODY_LEN],
) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG, body)
}

pub fn encode_ring_owner_delivered_output(
    u: &[u8; 32],
    body: &[u8; RING_DELIVERED_BODY_LEN],
) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(RING_OWNER_DELIVERED_SCHEME_TAG, &[&u[..], body].concat())
}

pub fn encode_anonymous_recipient_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG, body)
}

pub fn encode_anonymous_sender_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG, body)
}

pub fn anonymous_recipient_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG)
}

pub fn anonymous_sender_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG)
}

/// `Encrypted(len || scheme || payload)`, the length counting the scheme byte.
fn encode_encrypted_output(scheme: u8, payload: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    let body_len = payload.len() + 1;
    let prefix = u32::try_from(body_len).map_err(|_| CustomRingError::OutputBodyLength)?;
    let mut out = Vec::with_capacity(BODY_OFFSET + body_len);
    out.push(OutputDataEncoding::ENCRYPTED_TAG);
    out.extend_from_slice(&prefix.to_le_bytes());
    out.push(scheme);
    out.extend_from_slice(payload);
    Ok(out)
}

fn encrypted_output_body(data: &[u8], scheme: u8) -> Option<&[u8]> {
    encrypted_output(data)
        .filter(|(scheme_byte, _)| *scheme_byte == scheme)
        .map(|(_, payload)| payload)
}

/// The scheme byte and payload of `Encrypted(len || scheme || payload)`.
fn encrypted_output(data: &[u8]) -> Option<(u8, &[u8])> {
    let (&encoding_tag, rest) = data.split_first()?;
    if encoding_tag != OutputDataEncoding::ENCRYPTED_TAG {
        return None;
    }
    let (len_bytes, body) = rest.split_first_chunk::<4>()?;
    let body_len = usize::try_from(u32::from_le_bytes(*len_bytes)).ok()?;
    let (&scheme_byte, payload) = body.split_first()?;
    (body_len == body.len()).then_some((scheme_byte, payload))
}
