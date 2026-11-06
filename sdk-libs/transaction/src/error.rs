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
    #[error("ring output {slot_index} holds data its recipient body cannot carry")]
    OutputDataNotCarried { slot_index: usize },
    #[error("output {slot_index} does not frame as its ring rail publishes it")]
    RingOutputFraming { slot_index: usize },
    #[error("anonymous ring output {slot_index} is not the planned payment's recipient, or a payment found no ring output")]
    RingPaymentSlot { slot_index: usize },
    #[error("anonymous ring output {slot_index} pays another owner without a planned payment")]
    UnplannedRingOutput { slot_index: usize },
    #[error("output {slot_index} pays the sender after another output, the change leads")]
    AnonymousChange { slot_index: usize },
    #[error("exit {slot_index} pays the hidden sender, its owner tag would publish the sender")]
    RingSenderExit { slot_index: usize },
    #[error("the anonymous sender bundle is not the transfer's first message")]
    SenderBundleFraming,
    #[error("a sender bundle of {len} bytes does not match the frame's output count")]
    SenderBundleLength { len: usize },
    #[error("reply length {reply_len} is below the reply's encoding or the minimum")]
    ReplyMetadataLength { reply_len: usize },
}
