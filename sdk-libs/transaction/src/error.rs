use custom_ring_interface::{stream::StreamError, CustomRingError};
use spr_hasher::HasherError;
use spr_keypair::KeypairError;
use spr_transaction::TransactionError;
use thiserror::Error;
use zolana_ring_keys::RingKeyError;

#[derive(Debug, Error)]
pub enum RingRailError {
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Interface(#[from] CustomRingError),
    #[error("output {slot_index} carries data, a ring rail slot has a fixed body")]
    DeliveredOutputData { slot_index: usize },
    #[error("output {slot_index} is compact padding, a ring rail publishes every slot")]
    DeliveredCompactPadding { slot_index: usize },
    #[error("output {slot_index} does not frame as its ring rail publishes it")]
    RingOutputFraming { slot_index: usize },
    #[error("anonymous ring output {slot_index} is not the planned payment's recipient, or a payment found no ring output")]
    RingPaymentSlot { slot_index: usize },
    #[error("anonymous ring output {slot_index} pays another owner without a planned payment")]
    UnplannedRingOutput { slot_index: usize },
    #[error("output {slot_index} pays the sender after another output, the change leads")]
    AnonymousChange { slot_index: usize },
    #[error("the anonymous transfer has no sender change at output 0")]
    MissingSenderChange,
    #[error("exit {slot_index} pays the hidden sender, its owner tag would publish the sender")]
    RingSenderExit { slot_index: usize },
    #[error(
        "the anonymous change holds one SPL and one SOL output at most, a zero one only alone"
    )]
    AnonymousChangeCount,
    #[error("the anonymous sender bundle is not the transfer's first message")]
    SenderBundleFraming,
}
