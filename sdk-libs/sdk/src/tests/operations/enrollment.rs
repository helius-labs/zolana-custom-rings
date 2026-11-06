use std::sync::{Arc, Mutex};

use bytemuck::Zeroable;
use custom_ring_interface::{
    tracking::FirstEnrollment, CustomRingProof, RingMode, REGISTER_KEY_CIPHERTEXT_LEN,
    STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_message::Hash;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use spr_client::{AsyncProverClient, AsyncSprClient, ClientError};
use spr_keypair::ShieldedKeypair;

use super::*;
use crate::tests::support::{
    keypair, owner_record, ring, Chain, Registry, RingSettings, SLOT, TRACKING,
};
use crate::MemberRecords;

const VALID_UNTIL: u64 = 500;

fn sealed() -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: [1; 32],
        list_tag: [2; 32],
        viewing_u: [3; 32],
        eph_u: [4; 32],
        ciphertext: [5; REGISTER_KEY_CIPHERTEXT_LEN],
    }
}

fn enroll_instruction(
    owner: Address,
    payer: Address,
    proof: Option<&CustomRingProof>,
) -> EnrollInstruction {
    EnrollInstruction {
        payer,
        owner,
        tracking_registry: TRACKING,
        request: EnrollRequest {
            ix: &sealed(),
            proof,
        }
        .encode(),
    }
}

fn instruction(owner: Address, payer: Address) -> EnrollInstruction {
    enroll_instruction(owner, payer, Some(&CustomRingProof::zeroed()))
}

#[tokio::test]
async fn member_records_come_back_in_member_order() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(
        Registry::new(&[(&registered, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let reads = MemberRecords {
        ring: ring(),
        members: &[owner_record(&stranger), owner_record(&registered)],
    }
    .read(client.zolana())
    .await
    .unwrap();
    assert!(reads[0].record().is_none());
    assert_eq!(reads[1].record().unwrap().lists, 1);
}

#[test]
fn an_enrollment_writes_the_owner_authorization_on_the_pinned_registry() {
    let owner = Address::new_from_array([3; 32]);
    let payer = Address::new_from_array([7; 32]);
    let rotation = enroll_instruction(owner, payer, None).instruction();
    let first = instruction(owner, payer).instruction();
    assert_eq!(rotation.program_id, STORAGE_PROGRAM_ID);
    assert_eq!(rotation.data[0], tag::ENROLL);
    assert_eq!(rotation.data.len(), 1 + EnrollIxData::SIZE);
    assert!(first.data.len() > rotation.data.len());
    let (authorization, _) = TrackingAuthorization::find_address(&TRACKING, &owner);
    assert_eq!(rotation.accounts[0].pubkey, payer);
    assert_eq!(rotation.accounts[1].pubkey, owner);
    assert!(rotation.accounts[1].is_signer);
    assert_eq!(rotation.accounts[2].pubkey, TRACKING);
    assert_eq!(rotation.accounts[3].pubkey, authorization);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Landing {
    Landed,
    Failed,
    Absent,
}

struct LedgerState {
    sent: Vec<VersionedTransaction>,
    landing: Landing,
    reserved: bool,
    expired: bool,
    preflight_refuses: bool,
}

#[derive(Clone)]
struct Ledger(Arc<Mutex<LedgerState>>);

impl Ledger {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(LedgerState {
            sent: Vec::new(),
            landing: Landing::Absent,
            reserved: false,
            expired: false,
            preflight_refuses: false,
        })))
    }

    fn set(&self, change: impl FnOnce(&mut LedgerState)) {
        change(&mut self.0.lock().unwrap());
    }

    fn sent(&self) -> Vec<VersionedTransaction> {
        self.0.lock().unwrap().sent.clone()
    }

    fn client(&self) -> RingClient<Ledger, Chain> {
        let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
        RingClient::new(
            AsyncSprClient::new(self.clone(), chain, AsyncProverClient::local()),
            AsyncProverClient::local(),
        )
    }
}

#[async_trait]
impl AsyncRpc for Ledger {
    /// A reserved owner's authorization holds the fixture key and viewing key.
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let reserved = self.0.lock().unwrap().reserved;
        let enrolled = FirstEnrollment {
            registry: TRACKING,
            owner: keypair(1).pubkey(),
            ix: &sealed(),
        }
        .account();
        Ok((reserved
            && address == instruction(keypair(1).pubkey(), keypair(2).pubkey()).authorization())
        .then(|| Account {
            data: bytemuck::bytes_of(&enrolled).to_vec(),
            owner: STORAGE_PROGRAM_ID,
            ..Account::default()
        }))
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::new_unique(), VALID_UNTIL))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        Ok(VALID_UNTIL + u64::from(self.0.lock().unwrap().expired))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let state = self.0.lock().unwrap();
        let status = |err| TransactionStatus {
            slot: SLOT,
            confirmations: None,
            status: Ok(()),
            err,
            confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
        };
        Ok(signatures
            .iter()
            .map(|_| match state.landing {
                Landing::Landed => Some(status(None)),
                Landing::Failed => Some(status(Some(TransactionError::AccountNotFound))),
                Landing::Absent => None,
            })
            .collect())
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        let mut state = self.0.lock().unwrap();
        state.sent.push(transaction.clone());
        match state.preflight_refuses {
            true => Err(ClientError::UnsupportedRpcMethod("transport")),
            false => Ok(transaction.signatures[0]),
        }
    }
}

#[async_trait::async_trait]
impl SignatureHistory for Ledger {
    async fn signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.get_signature_statuses(signatures).await
    }
}

/// Each record keeps the ledger's sent count at that moment.
struct Journal {
    ledger: Ledger,
    recorded: Mutex<Vec<(Vec<u8>, usize)>>,
    fails: bool,
}

impl Journal {
    fn new(ledger: &Ledger) -> Self {
        Self {
            ledger: ledger.clone(),
            recorded: Mutex::new(Vec::new()),
            fails: false,
        }
    }

    fn last(&self) -> EnrollmentAttempt {
        let recorded = self.recorded.lock().unwrap();
        EnrollmentAttempt::decode(&recorded.last().unwrap().0).unwrap()
    }
}

#[async_trait]
impl EnrollmentJournal for Journal {
    async fn record(
        &self,
        attempt: &EnrollmentAttempt,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        if self.fails {
            return Err("disk full".into());
        }
        let encoded = attempt.encode()?;
        self.recorded
            .lock()
            .unwrap()
            .push((encoded, self.ledger.sent().len()));
        Ok(())
    }
}

fn wallets() -> (ShieldedKeypair, ShieldedKeypair) {
    (keypair(1), keypair(2))
}

#[tokio::test]
async fn an_attempt_is_recorded_before_its_broadcast_and_signed_by_owner_and_payer() {
    let ledger = Ledger::new();
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();

    let attempt = instruction(owner.pubkey(), payer.pubkey())
        .submit(&ledger.client(), &[&payer, &owner], &journal)
        .await
        .unwrap();

    let recorded = journal.recorded.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1, 0, "nothing left before the record");
    assert_eq!(ledger.sent(), std::slice::from_ref(&attempt.transaction));
    assert_eq!(attempt.transaction.signatures.len(), 2);
    assert_eq!(
        attempt.transaction.message.static_account_keys()[0],
        payer.pubkey()
    );
}

#[tokio::test]
async fn an_unrecorded_attempt_sends_nothing() {
    let ledger = Ledger::new();
    let journal = Journal {
        fails: true,
        ..Journal::new(&ledger)
    };
    let (owner, payer) = wallets();

    let refused = instruction(owner.pubkey(), payer.pubkey())
        .submit(&ledger.client(), &[&payer, &owner], &journal)
        .await;

    assert!(matches!(refused, Err(RingError::AttemptNotRecorded(_))));
    assert!(ledger.sent().is_empty());
}

/// A transport error after the record leaves the outcome to reconciliation, never to a new send.
#[tokio::test]
async fn an_in_doubt_attempt_reconciles_from_its_record_after_a_restart() {
    let ledger = Ledger::new();
    ledger.set(|state| state.preflight_refuses = true);
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();
    let client = ledger.client();
    let sent = instruction(owner.pubkey(), payer.pubkey())
        .submit(&client, &[&payer, &owner], &journal)
        .await;
    assert!(sent.is_ok(), "a lost answer is in doubt, not refused");
    let restored = journal.last();

    let outcome = || async { restored.reconcile(&client).await.unwrap() };
    assert_eq!(outcome().await, EnrollmentOutcome::Pending);
    assert!(matches!(
        restored
            .clone()
            .resubmit(&client, &[&payer, &owner], &journal)
            .await,
        Err(RingError::AttemptNotExpired(EnrollmentOutcome::Pending))
    ));
    ledger.set(|state| state.reserved = true);
    assert_eq!(outcome().await, EnrollmentOutcome::Reserved);
    ledger.set(|state| state.landing = Landing::Failed);
    assert_eq!(outcome().await, EnrollmentOutcome::Reserved);
    ledger.set(|state| state.reserved = false);
    assert_eq!(
        outcome().await,
        EnrollmentOutcome::Failed(TransactionError::AccountNotFound)
    );
    ledger.set(|state| state.landing = Landing::Landed);
    assert_eq!(outcome().await, EnrollmentOutcome::Landed { slot: SLOT });
    assert_eq!(ledger.sent().len(), 1);
}

#[tokio::test]
async fn only_an_expired_attempt_with_no_reservation_goes_again_with_the_same_request() {
    let ledger = Ledger::new();
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();
    let client = ledger.client();
    let first = instruction(owner.pubkey(), payer.pubkey())
        .submit(&client, &[&payer, &owner], &journal)
        .await
        .unwrap();
    ledger.set(|state| {
        state.expired = true;
        state.reserved = true;
    });
    assert!(matches!(
        first
            .clone()
            .resubmit(&client, &[&payer, &owner], &journal)
            .await,
        Err(RingError::AttemptNotExpired(EnrollmentOutcome::Reserved))
    ));
    ledger.set(|state| state.reserved = false);
    assert_eq!(
        first.reconcile(&client).await.unwrap(),
        EnrollmentOutcome::Expired
    );

    let second = first
        .clone()
        .resubmit(&client, &[&payer, &owner], &journal)
        .await
        .unwrap();

    assert_eq!(second.instruction, first.instruction);
    assert_ne!(second.signature(), first.signature());
    assert_eq!(journal.recorded.lock().unwrap().len(), 2);
}
