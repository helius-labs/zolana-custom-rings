//! Ring output bodies in SPP's encrypted output framing, schemes SPP stores without parsing.
//! Owned output buffers and borrowed SPP payloads share the same header and segment order.
//! A ring body is the slot's proven record followed by its unproven payload, one stream.
//!
//! Read after `program-libs/interface/src/proof/disclosure.rs`. Read before `program-libs/interface/src/codec/stream.rs`.

use spr_event::{OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG};

use crate::{audit_stream::OUTPUT_RECORD_LEN, CustomRingError};

pub const RING_SENDER_BUNDLE_SCHEME_TAG: u8 = 9;
/// `u16le(body_len) || record || payload || reply`, one form on every rail, the reply absent without reply metadata.
pub const RING_BODY_SCHEME_TAG: u8 = 10;

/// `0x04 || u`, the recipient key a scheme 3 body leads with.
pub const RECIPIENT_KEY_LEN: usize = 33;

/// Asset id, amount and blinding open every confidential plaintext.
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN: usize = 8 + 8 + 32;

/// Scheme 3 body of an output with no data and no ring id, each one zero byte.
pub const CONFIDENTIAL_DATA_FREE_BODY_LEN: usize =
    RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

/// The encoding tag and the u32 body length before the scheme byte.
const BODY_OFFSET: usize = 1 + 4;

#[derive(Clone, Copy)]
pub(crate) enum OutputPayload<'a> {
    Confidential(&'a [u8]),
    Recipient { body: &'a [u8], reply: &'a [u8] },
    SenderBundle(&'a [u8]),
}

pub(crate) struct OutputHeader {
    bytes: [u8; BODY_OFFSET + 1 + core::mem::size_of::<u16>()],
    len: usize,
}

impl<'a> OutputPayload<'a> {
    pub(crate) fn header(self) -> Result<OutputHeader, CustomRingError> {
        // 1. The recipient length covers its body alone, leaving reply bytes outside the inner `u16` boundary.
        let (scheme, body, reply, body_prefix) = match self {
            Self::Confidential(body) => (CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, body, &[][..], None),
            Self::Recipient { body, reply } => {
                let len =
                    u16::try_from(body.len()).map_err(|_| CustomRingError::OutputBodyLength)?;
                if body.len() < OUTPUT_RECORD_LEN {
                    return Err(CustomRingError::OutputBodyLength);
                }
                (RING_BODY_SCHEME_TAG, body, reply, Some(len.to_le_bytes()))
            }
            Self::SenderBundle(body) => (RING_SENDER_BUNDLE_SCHEME_TAG, body, &[][..], None),
        };
        // 2. The outer `u32` length covers the scheme byte, optional recipient length, body and reply.
        let len = BODY_OFFSET + 1 + body_prefix.map_or(0, |prefix| prefix.len());
        let body_len = body
            .len()
            .checked_add(reply.len())
            .and_then(|body_len| body_len.checked_add(len - BODY_OFFSET))
            .and_then(|body_len| u32::try_from(body_len).ok())
            .ok_or(CustomRingError::OutputBodyLength)?;
        // 3. The shared header fixes the encrypted tag, little endian lengths and scheme position for both expansion paths.
        let mut bytes = [0; BODY_OFFSET + 1 + core::mem::size_of::<u16>()];
        bytes[0] = OutputDataEncoding::ENCRYPTED_TAG;
        bytes[1..BODY_OFFSET].copy_from_slice(&body_len.to_le_bytes());
        bytes[BODY_OFFSET] = scheme;
        if let Some(prefix) = body_prefix {
            bytes[BODY_OFFSET + 1..].copy_from_slice(&prefix);
        }
        Ok(OutputHeader { bytes, len })
    }

    pub(crate) fn segments<'header>(self, header: &'header OutputHeader) -> [&'header [u8]; 3]
    where
        'a: 'header,
    {
        match self {
            Self::Confidential(body) | Self::SenderBundle(body) => {
                [&header.bytes[..header.len], body, &[]]
            }
            Self::Recipient { body, reply } => [&header.bytes[..header.len], body, reply],
        }
    }

    pub(crate) fn encode(self) -> Result<Vec<u8>, CustomRingError> {
        let header = self.header()?;
        Ok(self.segments(&header).concat())
    }
}

pub fn encode_confidential_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    OutputPayload::Confidential(body).encode()
}

pub fn encode_ring_body_output(body: &[u8], reply: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    OutputPayload::Recipient { body, reply }.encode()
}

pub fn encode_ring_sender_bundle_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    OutputPayload::SenderBundle(body).encode()
}

/// `body || reply` of a well-formed ring body output, `None` otherwise.
pub fn ring_body_output(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let payload = encrypted_output_body(data, RING_BODY_SCHEME_TAG)?;
    let (body_len, rest) = payload.split_first_chunk()?;
    rest.split_at_checked(usize::from(u16::from_le_bytes(*body_len)))
        .filter(|(body, _)| body.len() >= OUTPUT_RECORD_LEN)
}

/// The record ciphertext a ring body opens with, the bytes the statement's record chain binds.
pub fn ring_body_record(body: &[u8]) -> Option<&[u8; OUTPUT_RECORD_LEN]> {
    body.first_chunk()
}

pub fn ring_sender_bundle_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, RING_SENDER_BUNDLE_SCHEME_TAG)
}

fn encrypted_output_body(data: &[u8], scheme: u8) -> Option<&[u8]> {
    encrypted_output(data)
        .filter(|(scheme_byte, _)| *scheme_byte == scheme)
        .map(|(_, payload)| payload)
}

/// The scheme byte and payload of `Encrypted(len || scheme || payload)`.
pub fn encrypted_output(data: &[u8]) -> Option<(u8, &[u8])> {
    let (&encoding_tag, rest) = data.split_first()?;
    if encoding_tag != OutputDataEncoding::ENCRYPTED_TAG {
        return None;
    }
    let (len_bytes, body) = rest.split_first_chunk::<4>()?;
    let body_len = usize::try_from(u32::from_le_bytes(*len_bytes)).ok()?;
    let (&scheme_byte, payload) = body.split_first()?;
    (body_len == body.len()).then_some((scheme_byte, payload))
}
