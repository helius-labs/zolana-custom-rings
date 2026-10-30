use custom_ring_interface::stream::StreamError;
use spr_keypair::KeypairError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum RingKeyError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error("the keypair holds no viewing key for the requested public key")]
    UnknownViewingKey,
    #[error("ring payment request does not start with zolana:")]
    InvalidRingAddressScheme,
    #[error("ring address is not base58")]
    InvalidRingAddressBase58,
    #[error("ring address has the wrong length")]
    InvalidRingAddressLength,
    #[error("unknown ring address version {0}")]
    UnknownRingAddressVersion(u8),
    #[error("ring address checksum mismatch")]
    InvalidRingAddressChecksum,
    #[error("unknown ring payment query key")]
    UnknownRingPaymentKey,
    #[error("duplicated ring payment query key")]
    DuplicateRingPaymentKey,
    #[error("ring payment request names no request tag")]
    MissingRingPaymentTag,
    #[error("ring payment tag is not 32 lowercase hex bytes led by a zero byte")]
    InvalidRingPaymentTag,
    #[error("ring payment amount is not a u64")]
    InvalidRingPaymentAmount,
    #[error("ring payment mint is not an address")]
    InvalidRingPaymentMint,
    #[error("ring payment label is not percent-encoded UTF-8")]
    InvalidRingPaymentLabel,
}
