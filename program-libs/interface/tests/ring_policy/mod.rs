//! The ring account a frame expands under, apart from `frames` for the test targets that only encode.

use custom_ring_interface::{RingPolicy, RING_POLICY};

pub fn config() -> Box<RingPolicy> {
    let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
    config.discriminator = RING_POLICY;
    config.auditor_pubkey[0] = 4;
    config.auditor_pubkey[1..].copy_from_slice(&[0xa1; 32]);
    config
}
