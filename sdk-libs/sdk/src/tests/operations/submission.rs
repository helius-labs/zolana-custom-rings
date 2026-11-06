use std::sync::{Arc, Mutex};

use custom_ring_interface::{tag, RingMode};
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_message::Hash;
use spr_client::{AsyncProverClient, AsyncSprClient};
use spr_keypair::ShieldedKeypair;

use super::*;
use crate::tests::support::{keypair, program, ring, Chain, Registry, RingSettings, SLOT};

#[tokio::test]
async fn a_policy_write_moves_the_proof() {
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
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
        (ring_failure(CustomRingError::RootNotServed), true),
        (ring_failure(CustomRingError::TrackingRootBelowFloor), true),
        (ring_failure(CustomRingError::UnboundRegistry), true),
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

#[async_trait::async_trait]
impl SignatureHistory for StatusRefused {
    async fn signature_statuses_with_history(
        &self,
        _: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, spr_client::ClientError> {
        Err(spr_client::ClientError::UnsupportedRpcMethod(
            "get_signature_statuses_with_history",
        ))
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

/// The status cache dropped the signature, the ledger still holds it.
struct LandedPastTheCache;

#[async_trait::async_trait]
impl AsyncRpc for LandedPastTheCache {
    async fn get_block_height(&self) -> Result<u64, spr_client::ClientError> {
        Ok(11)
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, spr_client::ClientError> {
        Ok(vec![None; signatures.len()])
    }
}

#[async_trait::async_trait]
impl SignatureHistory for LandedPastTheCache {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, spr_client::ClientError> {
        let landed = TransactionStatus {
            slot: SLOT,
            confirmations: None,
            status: Ok(()),
            err: None,
            confirmation_status: Some(TransactionConfirmationStatus::Finalized),
        };
        Ok(vec![Some(landed); signatures.len()])
    }
}

/// A fresh attempt here would debit a deposit's funder twice.
#[tokio::test]
async fn a_landed_signature_past_the_status_cache_never_reads_as_expired() {
    assert_eq!(
        outcome(&LandedPastTheCache, Signature::default(), 10)
            .await
            .unwrap(),
        Outcome::Confirmed { slot: SLOT }
    );
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

const VALID_UNTIL: u64 = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Status {
    #[default]
    Landed,
    Absent,
    LookupFails,
}

#[derive(Default)]
struct ClusterState {
    sent: Vec<VersionedTransaction>,
    transfer: Status,
    expired: bool,
}

/// Answers by the tag of each sent transaction.
#[derive(Clone, Default)]
struct Cluster(Arc<Mutex<ClusterState>>);

fn first_tag(transaction: &VersionedTransaction) -> u8 {
    transaction.message.instructions()[0].data[0]
}

const REFUSED: ClientError = ClientError::UnsupportedRpcMethod("refused");

impl Cluster {
    fn set(&self, change: impl FnOnce(&mut ClusterState)) {
        change(&mut self.0.lock().unwrap());
    }

    fn sent_tags(&self) -> Vec<u8> {
        self.0.lock().unwrap().sent.iter().map(first_tag).collect()
    }

    fn last_signature(&self) -> Signature {
        self.0.lock().unwrap().sent.last().unwrap().signatures[0]
    }
}

#[async_trait::async_trait]
impl AsyncRpc for Cluster {
    async fn get_account(&self, _: Address) -> Result<Option<Account>, ClientError> {
        Ok(None)
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::default(), VALID_UNTIL))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        let state = self.0.lock().unwrap();
        let transferring = state
            .sent
            .last()
            .is_some_and(|sent| first_tag(sent) == tag::TRANSFER);
        if transferring && state.transfer == Status::LookupFails {
            return Err(REFUSED);
        }
        Ok(VALID_UNTIL + u64::from(state.expired))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let state = self.0.lock().unwrap();
        signatures
            .iter()
            .map(|signature| {
                let tag_of = state
                    .sent
                    .iter()
                    .find(|sent| sent.signatures[0] == *signature)
                    .map(first_tag);
                let status = match tag_of {
                    Some(tag::TRANSFER) => state.transfer,
                    Some(_) => Status::Landed,
                    None => Status::Absent,
                };
                let landed = Some(TransactionStatus {
                    slot: SLOT,
                    confirmations: None,
                    status: Ok(()),
                    err: None,
                    confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
                });
                match status {
                    Status::Landed => Ok(landed),
                    Status::Absent => Ok(None),
                    Status::LookupFails => Err(REFUSED),
                }
            })
            .collect()
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.0.lock().unwrap().sent.push(transaction.clone());
        Ok(transaction.signatures[0])
    }
}

#[async_trait::async_trait]
impl SignatureHistory for Cluster {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.get_signature_statuses(signatures).await
    }
}

fn client(cluster: &Cluster) -> RingClient<Cluster, Chain> {
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    RingClient::new(
        AsyncSprClient::new(cluster.clone(), chain, AsyncProverClient::local()),
        AsyncProverClient::local(),
    )
}

/// Holds a proven transfer, a new proof shows as `tag::SET_DELEGATE`.
fn held_transfer(payer: &ShieldedKeypair) -> RingSubmission<'static> {
    let proved = Proved {
        instruction: Instruction {
            program_id: program(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true)],
            data: vec![tag::TRANSFER; 6],
        },
        budget: send_budget(InstructionTag::Transfer, None),
        bound: BoundState::default(),
        charged_outflows: Vec::new(),
    };
    let mut submission = RingSubmission::new(RingOperation::Instruction(Instruction {
        program_id: program(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![tag::SET_DELEGATE],
    }));
    submission.pending = Some(Attempt { proved, sent: None });
    submission.attempts = 1;
    submission
}

#[tokio::test]
async fn a_submission_signs_only_an_attempt_its_charges_were_read_from() {
    let cluster = Cluster::default();
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = RingSubmission::new(RingOperation::Instruction(Instruction {
        program_id: program(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![tag::SET_DELEGATE],
    }));
    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::SubmissionUnproved)
    ));
    assert!(cluster.sent_tags().is_empty());
    assert!(submission
        .prove(&client, &payer, &[])
        .await
        .unwrap()
        .is_empty());
    let _sent = submission.send(&client, &payer, &[]).await.unwrap();
    assert_eq!(cluster.sent_tags(), [tag::SET_DELEGATE]);
}

#[tokio::test]
async fn an_unknown_transfer_holds_its_attempt_and_blocks_a_new_proof() {
    let cluster = Cluster::default();
    cluster.set(|state| state.transfer = Status::LookupFails);
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = held_transfer(&payer);

    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::Client(_))
    ));
    assert_eq!(cluster.sent_tags(), [tag::TRANSFER]);
    let transfer = cluster.last_signature();
    assert_eq!(
        submission.pending_transaction().unwrap().signatures[0],
        transfer
    );

    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::Client(_))
    ));
    cluster.set(|state| state.transfer = Status::Absent);
    assert_eq!(
        submission.send(&client, &payer, &[]).await.unwrap(),
        SubmissionStatus::Pending {
            signature: transfer
        }
    );
    assert_eq!(cluster.sent_tags(), [tag::TRANSFER]);
    assert_eq!(submission.attempts(), 1);

    cluster.set(|state| state.transfer = Status::Landed);
    assert_eq!(
        submission.send(&client, &payer, &[]).await.unwrap(),
        SubmissionStatus::Settled(SettledSubmission::Confirmed {
            signature: transfer,
            slot: SLOT,
        })
    );
    assert_eq!(cluster.sent_tags(), [tag::TRANSFER]);
    assert!(submission.pending_transaction().is_none());
}

#[tokio::test]
async fn an_expired_transfer_proves_again() {
    let cluster = Cluster::default();
    cluster.set(|state| state.transfer = Status::Absent);
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = held_transfer(&payer);
    let held = submission.send(&client, &payer, &[]).await.unwrap();
    assert!(matches!(held, SubmissionStatus::Pending { .. }));

    cluster.set(|state| state.expired = true);
    let settled = submission.send(&client, &payer, &[]).await.unwrap();
    assert!(matches!(
        settled,
        SubmissionStatus::Settled(SettledSubmission::Confirmed { .. })
    ));
    assert_eq!(cluster.sent_tags(), [tag::TRANSFER, tag::SET_DELEGATE]);
    assert_eq!(submission.attempts(), 2);
}
