use custom_ring_interface::stream::StreamError;
use spr_hasher::HasherError;
use spr_keypair::KeypairError;
use spr_transaction::TransactionError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum RingKeyError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("the keypair holds no viewing key for the requested public key")]
    UnknownViewingKey,
    #[error("merge seed is not a nonzero field element")]
    InvalidMergeSeed,
    #[error("list salt derivation failed")]
    InvalidListSalt,
    #[error("ring payment request does not start with zolana:")]
    InvalidRingAddressScheme,
    #[error("ring address is not base58")]
    InvalidRingAddressBase58,
    #[error("ring address has the wrong length")]
    InvalidRingAddressLength,
    #[error("ring address checksum mismatch")]
    InvalidRingAddressChecksum,
    #[error("ring address list salt does not fit its nullifier key")]
    InvalidRingAddressListSalt,
    #[error("unknown ring payment query key")]
    UnknownRingPaymentKey,
    #[error("duplicated ring payment query key")]
    DuplicateRingPaymentKey,
    #[error("ring payment amount is not a u64")]
    InvalidRingPaymentAmount,
    #[error("ring payment mint is not an address")]
    InvalidRingPaymentMint,
    #[error("ring payment label is not percent-encoded UTF-8")]
    InvalidRingPaymentLabel,
}
