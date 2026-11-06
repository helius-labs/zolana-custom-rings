//! One signed request, one row, every message of it charged until settlement or proven expiry.

use zolana_ring_rpc::ChainOutcome;

use super::*;

fn fresh(quote: &RelayQuote) -> RelayQuote {
    RelayQuote {
        valid_until_slot: quote.valid_until_slot - 1,
        ..quote.clone()
    }
}

fn paid_failure() -> Option<Option<ChainOutcome>> {
    Some(Some(ChainOutcome::Failed {
        reason: "the transaction failed".to_owned(),
    }))
}

fn past_window(fixture: &Fixture) {
    fixture
        .chain
        .slot
        .fetch_add(ABANDONED_AFTER_SLOTS + 1, Ordering::Relaxed);
}

fn past_blockhash(fixture: &Fixture) {
    fixture
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
}

fn pending_answer(fixture: &Fixture, answer: Option<Option<ChainOutcome>>) {
    *fixture.chain.outcome.lock().expect("outcome") = answer;
}

#[tokio::test]
async fn a_fresh_quote_while_the_old_message_can_land_refuses_and_the_old_stays_charged() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the first relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };

    let retried = fixture
        .prepare(&enrollment(&owner, vec![6, 1], fresh(&quote)))
        .await;

    assert!(
        refused_with(&retried, RelayError::LiveAttempt),
        "{retried:?}"
    );
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);

    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );

    // The landed rent and fees stay in the total, no second message exists to expire and refund them.
    past_blockhash(&fixture);
    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn a_fresh_quote_while_a_sent_message_can_land_refuses_and_sends_nothing() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let inputs = proof_inputs(RING, anonymous_rail());
    pending_answer(&fixture, Some(None));
    let step = fixture
        .prepare(&signed_request(quote.clone(), &inputs))
        .await
        .expect("the first relay");
    assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");

    let retried = fixture
        .prepare(&signed_request(fresh(&quote), &inputs))
        .await;

    assert!(
        refused_with(&retried, RelayError::LiveAttempt),
        "{retried:?}"
    );
    assert_eq!(fixture.sent().len(), 1);
    assert_eq!(fixture.prover.requests.lock().expect("requests").len(), 1);
}

#[tokio::test]
async fn a_fresh_quote_past_proven_expiry_replaces_the_attempt_and_charges_once() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let first = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the first relay");
    past_blockhash(&fixture);

    let second = fixture
        .prepare(&enrollment(&owner, vec![6, 1], fresh(&quote)))
        .await
        .expect("the old message can no longer land");

    let (
        RelayStep::SignMessage { relay_id: old, .. },
        RelayStep::SignMessage { relay_id: new, .. },
    ) = (first, second)
    else {
        panic!("the owner signs each message");
    };
    assert_ne!(old, new);
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn concurrent_duplicates_send_once() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = signed_request(quote, &proof_inputs(RING, anonymous_rail()));

    let (first, second) = tokio::join!(fixture.prepare(&request), fixture.prepare(&request));

    assert!(first.is_ok() || second.is_ok(), "{first:?} {second:?}");
    assert_eq!(fixture.sent().len(), 1);
}

/// The failure and its fee commit once, a repeated status read charges nothing more.
#[tokio::test]
async fn a_failed_settlement_charges_its_fee_once_and_frees_the_key() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote))
        .await
        .expect("the relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    pending_answer(&fixture, paid_failure());
    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;
    for _ in 0..2 {
        let status: RelayStatus = fixture
            .call(
                GET_RELAY_STATUS,
                GetRelayStatusRequest {
                    relay_id: relay_id.clone(),
                },
            )
            .await;
        assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    }
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, 2 * 5_000);
}

/// A signed enrollment the chain never answers keeps its charge under its persisted signature until expiry.
#[tokio::test]
async fn a_sent_enrollment_that_never_lands_is_reconciled_at_expiry_and_charges_nothing() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    pending_answer(&fixture, Some(None));
    let sent: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;
    assert!(matches!(sent, RelayStatus::Sent { .. }), "{sent:?}");

    let retried = fixture
        .prepare(&enrollment(&owner, vec![6, 1], fresh(&quote)))
        .await;
    assert!(
        refused_with(&retried, RelayError::LiveAttempt),
        "{retried:?}"
    );
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);

    past_blockhash(&fixture);
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;

    assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    assert_eq!(fixture.row_count().await, 0);
    assert_eq!(fixture.committed().await, 0);
    assert_eq!(fixture.sent().len(), 1);
}
