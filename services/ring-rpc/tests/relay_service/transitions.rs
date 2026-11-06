//! Workers sharing one store race on a relay, only the writer of the newest revision settles it.

use std::{sync::Mutex, time::Duration};

use tokio::sync::Notify;
use zolana_ring_client::rpc::RelayId;
use zolana_ring_rpc::{
    ChainOutcome, ChainSubmit, CoSignDecision, CoSignPolicy, CoSignRequest, CoSignSettlement,
    LatestBlockhash,
};

use super::*;

const PROGRESS: Duration = Duration::from_secs(5);

/// Parks the first call after `arm` until `release`.
#[derive(Default)]
struct Gate {
    armed: std::sync::atomic::AtomicBool,
    parked: Notify,
    released: Notify,
}

impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn pass(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.parked.notify_one();
            self.released.notified().await;
        }
    }

    async fn parked(&self) {
        self.parked.notified().await;
    }

    fn release(&self) {
        self.released.notify_one();
    }
}

struct WorkerChain {
    chain: Arc<RecordingChain>,
    /// Read in place of the shared height, a view the shared chain has moved past.
    height: Option<u64>,
    /// Every send reports success and forwards nothing.
    lost_sends: bool,
    send_gate: Gate,
    height_gate: Gate,
    outcome_gate: Gate,
}

impl WorkerChain {
    fn of(fixture: &Fixture) -> Self {
        Self {
            chain: fixture.chain.clone(),
            height: None,
            lost_sends: false,
            send_gate: Gate::default(),
            height_gate: Gate::default(),
            outcome_gate: Gate::default(),
        }
    }
}

#[async_trait]
impl ChainSubmit for WorkerChain {
    async fn simulate(
        &self,
        message: &solana_message::VersionedMessage,
    ) -> Result<zolana_ring_rpc::Simulation, RingRpcError> {
        self.chain.simulate(message).await
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        self.chain.slot().await
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        self.chain.latest_blockhash().await
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        self.height_gate.pass().await;
        match self.height {
            Some(height) => Ok(height),
            None => self.chain.block_height().await,
        }
    }

    async fn account_data(&self, address: Address) -> Result<Option<Vec<u8>>, RingRpcError> {
        self.chain.account_data(address).await
    }

    async fn rent_exempt_lamports(&self, data_len: usize) -> Result<u64, RingRpcError> {
        self.chain.rent_exempt_lamports(data_len).await
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.send_gate.pass().await;
        match self.lost_sends {
            true => Ok(()),
            false => self.chain.send(transaction).await,
        }
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        self.outcome_gate.pass().await;
        self.chain.outcome(signature).await
    }
}

/// Signs every message it is asked to and records each settlement.
struct RecordingCoSigner {
    keypair: Keypair,
    gate: Gate,
    settled: Mutex<Vec<CoSignSettlement>>,
}

impl RecordingCoSigner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            keypair: Keypair::new_from_array([0x63; 32]),
            gate: Gate::default(),
            settled: Mutex::default(),
        })
    }

    fn settled(&self) -> Vec<CoSignSettlement> {
        self.settled.lock().expect("settled").clone()
    }
}

#[async_trait]
impl CoSignPolicy for RecordingCoSigner {
    fn signer(&self) -> Option<Address> {
        Some(self.keypair.pubkey())
    }

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        self.gate.pass().await;
        Ok(CoSignDecision::Signed(
            self.keypair.sign_message(&request.message.serialize()),
        ))
    }

    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        self.settled.lock().expect("settled").push(settlement);
        Ok(())
    }
}

#[must_use]
struct Worker {
    chain: Arc<WorkerChain>,
    co_signer: Option<Arc<RecordingCoSigner>>,
    budget: u64,
}

impl Worker {
    fn start(self, fixture: &Fixture) -> Arc<Relay> {
        let relay = Relay::new(RelayParts {
            store: fixture.store.clone(),
            prover: fixture.prover.clone(),
            fee_payer: Keypair::new_from_array([31; 32]),
            chain: self.chain,
        })
        .with_rings(Arc::new(OneRing(RING)))
        .with_budget(RelayBudget {
            total_lamports: self.budget,
            signer_lamports: self.budget,
        });
        Arc::new(match self.co_signer {
            Some(co_signer) => relay.with_co_signer(co_signer),
            None => relay,
        })
    }
}

async fn signed_deposit(fixture: &Fixture, relay: &Relay) -> SubmitRelayRequest {
    let depositor = Keypair::new_from_array([41; 32]);
    let quote = fixture.quote(RelayOperation::Deposit).await;
    let step = relay
        .prepare(&deposit_request(quote, RING, &depositor, 700))
        .await
        .expect("prepared deposit");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the depositor signs its funding, got {step:?}");
    };
    SubmitRelayRequest {
        relay_id,
        signer: depositor.pubkey().into(),
        signature: depositor.sign_message(&message.0).into(),
    }
}

async fn status(relay: &Relay, relay_id: &RelayId) -> RelayStatus {
    relay
        .status(&GetRelayStatusRequest {
            relay_id: relay_id.clone(),
        })
        .await
        .expect("status")
}

async fn stored_status(fixture: &Fixture, relay_id: &RelayId) -> String {
    let connection = fixture.store.connection();
    connection
        .query_one(Statement::from_sql_and_values(
            connection.get_database_backend(),
            "SELECT status FROM relay_relays WHERE relay_id=$1",
            vec![relay_id.0 .0.to_vec().into()],
        ))
        .await
        .expect("relay query")
        .expect("stored relay")
        .try_get("", "status")
        .expect("status")
}

fn confirmed(sent: &VersionedTransaction) -> RelayStatus {
    RelayStatus::Confirmed {
        signature: sent.signatures[0].into(),
        slot: SLOT + 1,
    }
}

/// The overtaken submission reads the relay the other one sent, it sends nothing and frees no allowance.
#[tokio::test]
async fn duplicate_submissions_send_once_and_keep_the_co_sign_allowance() {
    let fixture = Fixture::new().await;
    let co_signer = RecordingCoSigner::new();
    let worker = || Worker {
        chain: Arc::new(WorkerChain::of(&fixture)),
        co_signer: Some(co_signer.clone()),
        budget: 0,
    };
    let (first, second) = (worker().start(&fixture), worker().start(&fixture));
    let submit = signed_deposit(&fixture, &first).await;
    co_signer.gate.arm();
    let parked = tokio::spawn({
        let submit = submit.clone();
        async move { first.submit(&submit).await }
    });
    co_signer.gate.parked().await;

    let landed = tokio::time::timeout(PROGRESS, second.submit(&submit))
        .await
        .expect("no lock holds the second submission")
        .expect("the second submission");
    co_signer.gate.release();
    let overtaken = parked.await.expect("joined").expect("the first submission");

    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(landed, confirmed(&sent));
    assert_eq!(overtaken, landed);
    let co_signature = co_signer.keypair.sign_message(&sent.message.serialize());
    assert_eq!(
        co_signer.settled(),
        [CoSignSettlement::Confirmed(co_signature)]
    );
}

/// A worker that read the unsigned relay and saw its blockhash expire loses its write to the settlement.
#[tokio::test]
async fn a_stale_worker_does_not_overwrite_a_settled_relay() {
    let fixture = Fixture::new().await;
    let co_signer = RecordingCoSigner::new();
    let stale_chain = Arc::new(WorkerChain {
        height: Some(LAST_VALID_BLOCK_HEIGHT + 1),
        ..WorkerChain::of(&fixture)
    });
    let live = Worker {
        chain: Arc::new(WorkerChain::of(&fixture)),
        co_signer: Some(co_signer.clone()),
        budget: 0,
    }
    .start(&fixture);
    let stale = Worker {
        chain: stale_chain.clone(),
        co_signer: Some(co_signer.clone()),
        budget: 0,
    }
    .start(&fixture);
    let submit = signed_deposit(&fixture, &live).await;
    let relay_id = submit.relay_id.clone();
    stale_chain.height_gate.arm();
    let parked = tokio::spawn({
        let relay_id = relay_id.clone();
        async move { status(&stale, &relay_id).await }
    });
    stale_chain.height_gate.parked().await;

    let landed = tokio::time::timeout(PROGRESS, live.submit(&submit))
        .await
        .expect("no lock holds the submission")
        .expect("the submission");
    stale_chain.height_gate.release();
    let overtaken = parked.await.expect("joined");

    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(landed, confirmed(&sent));
    assert_eq!(overtaken, landed);
    assert_eq!(stored_status(&fixture, &relay_id).await, "confirmed");
    let co_signature = co_signer.keypair.sign_message(&sent.message.serialize());
    assert_eq!(
        co_signer.settled(),
        [CoSignSettlement::Confirmed(co_signature)]
    );
}

/// The attempt is stored before its send, a new process resends the same transaction.
#[tokio::test]
async fn a_restarted_service_resends_the_stored_attempt() {
    let fixture = Fixture::new().await;
    let before = Worker {
        chain: Arc::new(WorkerChain {
            lost_sends: true,
            ..WorkerChain::of(&fixture)
        }),
        co_signer: None,
        budget: 0,
    }
    .start(&fixture);
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = signed_request(quote, &proof_inputs(RING, anonymous_rail()));
    let step = before.prepare(&request).await.expect("prepared");
    let RelayStep::Submitted { relay_id } = step else {
        panic!("an anonymous relay asks the wallet for nothing more, got {step:?}");
    };
    let stored = status(&before, &relay_id).await;
    let RelayStatus::Sent { signature } = stored else {
        panic!("the lost send stays pending, got {stored:?}");
    };
    assert!(fixture.sent().is_empty());
    drop(before);

    let after = Worker {
        chain: Arc::new(WorkerChain::of(&fixture)),
        co_signer: None,
        budget: 0,
    }
    .start(&fixture);
    after.track().await.expect("a tracking pass");

    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(signature, sent.signatures[0].into());
    assert_eq!(status(&after, &relay_id).await, confirmed(&sent));
}

#[tokio::test]
async fn a_refused_first_send_keeps_a_pending_tracker_copy_open() {
    let fixture = Fixture::new().await;
    *fixture.chain.outcome.lock().expect("outcome") = Some(None);
    let co_signer = RecordingCoSigner::new();
    let first_chain = Arc::new(WorkerChain::of(&fixture));
    let first = Worker {
        chain: first_chain.clone(),
        co_signer: Some(co_signer.clone()),
        budget: 0,
    }
    .start(&fixture);
    let tracker = Worker {
        chain: Arc::new(WorkerChain::of(&fixture)),
        co_signer: Some(co_signer.clone()),
        budget: 0,
    }
    .start(&fixture);
    let submit = signed_deposit(&fixture, &first).await;
    let relay_id = submit.relay_id.clone();
    first_chain.send_gate.arm();
    let parked = tokio::spawn(async move { first.submit(&submit).await });
    first_chain.send_gate.parked().await;

    tokio::time::timeout(PROGRESS, tracker.track())
        .await
        .expect("the tracker can send the stored transaction")
        .expect("tracking pass");
    let [sent] = fixture.sent().try_into().expect("one tracker copy");
    fixture.chain.refuse_next.store(true, Ordering::Relaxed);
    first_chain.send_gate.release();
    let pending = parked.await.expect("joined").expect("submission");
    assert_eq!(
        pending,
        RelayStatus::Sent {
            signature: sent.signatures[0].into(),
        }
    );
    assert_eq!(stored_status(&fixture, &relay_id).await, "sent");
    assert!(co_signer.settled().is_empty());

    *fixture.chain.outcome.lock().expect("outcome") = None;
    assert_eq!(status(&tracker, &relay_id).await, confirmed(&sent));
    assert_eq!(status(&tracker, &relay_id).await, confirmed(&sent));
    let co_signature = co_signer.keypair.sign_message(&sent.message.serialize());
    assert_eq!(
        co_signer.settled(),
        [CoSignSettlement::Confirmed(co_signature)]
    );
}

/// A relay whose chain read stalls holds nothing another relay needs.
#[tokio::test]
async fn a_delayed_relay_leaves_another_relay_progressing() {
    let fixture = Fixture::new().await;
    let chain = Arc::new(WorkerChain::of(&fixture));
    let relay = Worker {
        chain: chain.clone(),
        co_signer: None,
        budget: 0,
    }
    .start(&fixture);
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let slow_inputs = proof_inputs(RING, anonymous_rail());
    let mut fast_inputs = proof_inputs(RING, anonymous_rail());
    fast_inputs.blinding_seed = [29; 32];
    let slow = relay
        .prepare(&signed_request(quote.clone(), &slow_inputs))
        .await
        .expect("the slow relay");
    let RelayStep::Submitted { relay_id: slow } = slow else {
        panic!("submitted at once, got {slow:?}");
    };
    chain.outcome_gate.arm();
    let parked = tokio::spawn({
        let relay = relay.clone();
        let slow = slow.clone();
        async move { status(&relay, &slow).await }
    });
    chain.outcome_gate.parked().await;

    let fast = tokio::time::timeout(PROGRESS, async {
        let step = relay
            .prepare(&signed_request(quote, &fast_inputs))
            .await
            .expect("the fast relay");
        let RelayStep::Submitted { relay_id } = step else {
            panic!("submitted at once, got {step:?}");
        };
        status(&relay, &relay_id).await
    })
    .await
    .expect("the stalled relay holds no lock the other one needs");
    chain.outcome_gate.release();
    let delayed = parked.await.expect("joined");

    let [slow_sent, fast_sent] = fixture.sent().try_into().expect("two sent transactions");
    assert_eq!(fast, confirmed(&fast_sent));
    assert_eq!(delayed, confirmed(&slow_sent));
}
