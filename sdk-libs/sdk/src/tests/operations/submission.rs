use custom_ring_interface::RingMode;

use super::*;
use crate::tests::support::{ring, Chain, Registry, RingSettings, SLOT};

#[tokio::test]
async fn a_policy_write_moves_the_proof() {
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(Registry::new(&[]), &crate::tests::pipeline_rules());
    let pinned = ring().require_policy(&chain).await.unwrap().policy_hash;
    let policy = |hash| BoundState {
        policy: Some(BoundPolicy { ring: ring(), hash }),
        ..BoundState::default()
    };
    assert!(!policy(pinned).moved(&chain).await.unwrap());
    assert!(policy([1; 32]).moved(&chain).await.unwrap());
}

#[tokio::test]
async fn a_fresh_proof_fixes_a_stale_root_and_an_expired_blockhash_alone() {
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let ring_failure = |error: CustomRingError| {
        TransactionError::InstructionError(0, InstructionError::Custom(error as u32))
    };
    let unmoved = BoundState::default();
    for (error, fixed) in [
        (TransactionError::BlockhashNotFound, true),
        (ring_failure(CustomRingError::MirrorRootExpired), true),
        (ring_failure(CustomRingError::MirrorNotSynced), true),
        (
            ring_failure(CustomRingError::ProofVerificationFailed),
            false,
        ),
        (ring_failure(CustomRingError::UnauthorizedAuthority), false),
        (TransactionError::AccountNotFound, false),
    ] {
        assert_eq!(
            unmoved.reproof_fixes(&error, &chain).await.unwrap(),
            fixed,
            "{error:?}"
        );
    }
}

/// Answers the block height alone, every status lookup fails.
struct StatusRefused {
    block_height: u64,
}

#[async_trait::async_trait]
impl AsyncRpc for StatusRefused {
    async fn get_block_height(&self) -> Result<u64, spr_client::ClientError> {
        Ok(self.block_height)
    }
}

#[tokio::test]
async fn a_refused_status_lookup_keeps_polling_until_the_blockhash_expires() {
    let rpc = StatusRefused { block_height: 10 };
    assert_eq!(
        outcome(&rpc, Signature::default(), 10).await.unwrap(),
        Outcome::Unknown
    );
    assert!(matches!(
        outcome(&rpc, Signature::default(), 9).await,
        Err(RingError::Client(_))
    ));
}

#[test]
fn only_a_confirmed_status_settles_an_attempt() {
    let status = |confirmation, err| TransactionStatus {
        slot: SLOT,
        confirmations: None,
        status: Ok(()),
        err,
        confirmation_status: Some(confirmation),
    };
    assert_eq!(decode_status(vec![None]), None);
    assert_eq!(decode_status(Vec::new()), Some(Outcome::Unknown));
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Processed,
            None
        ))]),
        Some(Outcome::Unknown)
    );
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Confirmed,
            None
        ))]),
        Some(Outcome::Confirmed { slot: SLOT })
    );
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Finalized,
            Some(TransactionError::AccountNotFound)
        ))]),
        Some(Outcome::Failed(TransactionError::AccountNotFound))
    );
}
