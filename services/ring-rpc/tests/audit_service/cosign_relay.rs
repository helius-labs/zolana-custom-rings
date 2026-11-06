//! The relay co-signs within its asset's window caps, sends once a second approver signed, and refuses an outflow beyond them, a proof naming a co-signer the run left out, or a ring whose auditor key it does not hold, and keeps a reservation while a stored relay holds it.

use custom_ring_sdk::CustomRing;
use jsonrpsee::RpcModule;
use sea_orm::{ConnectionTrait, Statement};
use solana_instruction::AccountMeta;
use spr_keypair::{ShieldedKeypair, SigningKey};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayEnrollInputs, RelayId,
    RelayProofInputs, RelayQuote, RelayRail, RelayStatus, RelayStep, SubmitRelayRequest,
    GET_RELAY_QUOTE, GET_RELAY_STATUS, PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_policy::{AssetLimits, MintPolicy};
use zolana_ring_rpc::{
    ChainOutcome, DelegateSeal, ProvenRelay, RelayError, RelayParties, RelayParts, RelayPayload,
    RelayProofRequest, RelayProver,
};

use super::transfer::{Frame as TransferFrame, Publish, Rail};

use super::relay_fixture::{
    anonymous_rail, deposit_request, owner, proof_inputs, signed_request, signers_verify,
    RecordingChain, RecordingProver, LAST_VALID_BLOCK_HEIGHT, SLOT,
};
use super::*;

const SENDER_CAP: u64 = 1_000;
const DEPOSIT_CAP: u64 = 1_000;

/// The frame a limited co-signer opens, one published note spent into the transfer's first output.
struct FramedProver {
    inner: RecordingProver,
    auditor: X25519Pubkey,
    /// The published nullifier of the note the frames spend.
    nullifier: [u8; 32],
}

/// The sender's note the ring opened, a limit reads it through the auditor store.
fn sender_fields(amount: u64) -> UtxoFields {
    let sender = owner().shielded_address().expect("sender");
    UtxoFields {
        owner_key: sender.signing_pubkey.as_ed25519().expect("ed25519"),
        nullifier_pk: sender.nullifier_pubkey,
        asset_address: SOL_MINT,
        amount,
        ..UtxoFields::default()
    }
}

impl FramedProver {
    /// `[record, signer]` per co-signer, then SPP's transact list, `spp[1]` the output tree and the ring auth at 4.
    fn accounts(ring: Address, fee_payer: Address, named: &[Address]) -> Vec<AccountMeta> {
        named
            .iter()
            .flat_map(|signer| CustomRing::new(ring).co_signer_metas(*signer))
            .chain([
                AccountMeta::new(fee_payer, true),
                AccountMeta::new(spr_interface::pda::tree(TREE_ID), false),
                AccountMeta::new_readonly(spr_interface::PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(spr_interface::pda::ring_auth(&ring).0, false),
                AccountMeta::new(spr_interface::pda::tree(TREE_ID), false),
                AccountMeta::new(Address::new_from_array([0x61; 32]), false),
            ])
            .collect()
    }

    /// The first output's owner and amount, the rest of the note returns to the sender.
    fn frame(&self, inputs: &RelayProofInputs) -> Vec<u8> {
        let paid_out = &inputs.outputs[0];
        let fields = UtxoFields {
            owner_key: paid_out
                .owner_address
                .expect("output owner")
                .signing_pubkey
                .as_ed25519()
                .expect("ed25519"),
            nullifier_pk: paid_out
                .owner_address
                .expect("output owner")
                .nullifier_pubkey,
            asset_address: SOL_MINT,
            amount: paid_out.amount,
            ..UtxoFields::default()
        };
        let payment = match paid_out.ring_program_id {
            Some(_) => paid(fields, x25519_u(0x50)),
            None => Output::Exit(fields),
        };
        let change = match SENDER_CAP.saturating_sub(paid_out.amount) {
            0 => Output::Dummy,
            amount => paid(sender_fields(amount), x25519_u(0x52)),
        };
        let outputs = [payment, change];
        let transfer = spending(inputs.blinding_seed[0], &[self.nullifier]);
        let mut disclosure = transfer.disclosure(Rail::Delivered, &outputs);
        disclosure.real_inputs = 1;
        let tx = transfer.publish(Publish {
            slots: transfer
                .slots(&outputs)
                .into_iter()
                .map(|slot| slot.output)
                .collect(),
            disclosure: &disclosure,
            auditor: &self.auditor,
            rail: Rail::Delivered,
        });
        transfer.frame(TransferFrame {
            tx: &tx,
            disclosure: &disclosure,
            rail: Rail::Delivered,
        })
    }
}

#[async_trait::async_trait]
impl RelayProver for FramedProver {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        let (ring, fee_payer) = (request.ring, request.parties.fee_payer);
        let framed = match &request.payload {
            RelayPayload::Transfer(inputs) => Some(self.frame(inputs)),
            RelayPayload::Deposit(_) | RelayPayload::Merge(_) | RelayPayload::Enroll(_) => None,
        };
        let mut proven = self.inner.prove(request).await?;
        if let Some(data) = framed {
            proven.instruction.data = data;
            proven.instruction.accounts = Self::accounts(ring, fee_payer, &proven.co_signers);
        }
        Ok(proven)
    }

    async fn seal_delegate(
        &self,
        seal: DelegateSeal<'_>,
        parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError> {
        self.inner.seal_delegate(seal, parties).await
    }

    async fn check_enrollment(&self, enrollment: &RelayEnrollInputs) -> Result<(), RingRpcError> {
        self.inner.check_enrollment(enrollment).await
    }
}

struct CappedRelay {
    hub: Arc<Hub<StaticSource>>,
    module: RpcModule<Arc<Hub<StaticSource>>>,
    store: Store,
    chain: Arc<RecordingChain>,
    co_signer: Address,
    quote: RelayQuote,
    rail: fn() -> RelayRail,
}

impl CappedRelay {
    async fn new(rail: fn() -> RelayRail) -> Self {
        Self::naming(rail, None, sender_capped()).await
    }

    /// `named` replaces the hub's co-signer in the proof.
    async fn naming(rail: fn() -> RelayRail, named: Option<Address>, limits: AssetLimits) -> Self {
        let fixture = Fixture::new();
        // The note a capped transfer spends, the co-signer reads its owner from the store.
        let sender = owner();
        let (note_row, nullifier) = KeyedNote {
            fixture: &fixture,
            seed: 0x40,
            note: sender_fields(SENDER_CAP),
            key: &sender.nullifier_key,
        }
        .delivered();
        let mut source = fixture.source().with_transactions(vec![note_row]);
        source.tracking.enroll(
            &sender_fields(SENDER_CAP).owner_key,
            &sender.nullifier_key,
            &fixture.auditor.pubkey(),
        );
        // The history ends at the note, the default cursor names its own page.
        source.next_cursor = None;
        source.records.write_mint_policy(
            Member::asset(&SOL_MINT).expect("asset member"),
            MintPolicy {
                limits,
                ..MintPolicy::EMPTY
            },
        );
        let co_signer = co_signer_key().pubkey();
        source.co_signers.extend([
            (
                co_signer,
                CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS | CoSignScope::DEPOSITS,
            ),
            (second_approver().pubkey(), CoSignScope::APPROVE_OUTFLOW),
        ]);
        let chain = Arc::new(RecordingChain::default());
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let hub = Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .with_store(store.clone())
            .with_co_signer(co_signer_key())
            .with_co_signer_approval(CoSignerApproval::new([
                ApproveClass::Transfers,
                ApproveClass::Withdrawals,
                ApproveClass::Deposits,
            ]))
            .with_relay(RelayParts {
                store: store.clone(),
                prover: Arc::new(FramedProver {
                    inner: RecordingProver {
                        co_signers: named.map(|named| vec![named]),
                        ..RecordingProver::default()
                    },
                    auditor: fixture.auditor.pubkey(),
                    nullifier,
                }),
                fee_payer: Keypair::new_from_array([31; 32]),
                chain: chain.clone(),
            })
            .local(RING, fixture.auditor.clone())
            .expect("hub");
        hub.service(None)
            .expect("service")
            .backfill_utxos()
            .await
            .expect("the note opens");
        let hub = Arc::new(hub);
        let module = rpc_module(hub.clone()).expect("module");
        let quote = module
            .call(
                GET_RELAY_QUOTE,
                as_object(GetRelayQuoteRequest {
                    ring: RING.into(),
                    operation: rail().operation(),
                }),
            )
            .await
            .expect("quote");
        Self {
            hub,
            module,
            store,
            chain,
            co_signer,
            quote,
            rail,
        }
    }

    async fn fault(&self, fault: StoreFault) {
        self.store
            .connection()
            .execute_unprepared(&fault.trigger())
            .await
            .expect("store fault");
    }

    async fn heal(&self) {
        self.store
            .connection()
            .execute_unprepared(&format!("DROP TRIGGER {FAULT_TRIGGER}"))
            .await
            .expect("store healed");
    }

    /// The transfer of `seed` spends the whole SENDER_CAP.
    fn spending_cap(&self, seed: u8) -> PrepareRelayRequest {
        let mut inputs = proof_inputs(RING, (self.rail)());
        inputs.outputs[0].ring_program_id = None;
        inputs.outputs[0].amount = SENDER_CAP;
        inputs.blinding_seed = [seed; 32];
        signed_request(self.quote.clone(), &inputs)
    }

    /// `outflow` fits SENDER_CAP once and passes it twice.
    async fn assert_second_refused(&self, outflow: impl Fn(&mut RelayProofInputs)) {
        let prepare = |seed| {
            let mut inputs = proof_inputs(RING, (self.rail)());
            outflow(&mut inputs);
            inputs.blinding_seed = [seed; 32];
            self.module.call::<_, RelayStep>(
                PREPARE_RELAY,
                as_object(signed_request(self.quote.clone(), &inputs)),
            )
        };

        let within = prepare(1).await.expect("within the cap");
        let beyond = prepare(2).await;

        assert!(matches!(within, RelayStep::Submitted { .. }));
        let [sent] = self.chain.sent().try_into().expect("one sent transaction");
        assert_eq!(sent.message.static_account_keys()[1], self.co_signer);
        assert!(signers_verify(&sent));
        assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
    }

    async fn status(&self, relay_id: RelayId) -> RelayStatus {
        self.module
            .call(
                GET_RELAY_STATUS,
                as_object(GetRelayStatusRequest { relay_id }),
            )
            .await
            .expect("status")
    }

    /// A full cap fits only while no reservation holds the window.
    async fn second_cap_fits(&self) {
        let step = self
            .module
            .call::<_, RelayStep>(PREPARE_RELAY, as_object(self.spending_cap(2)))
            .await
            .expect("the freed window holds a full cap");
        assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");
    }

    /// Prepares and signs, the caller submits.
    async fn deposit(&self, depositor: &Keypair, amount: u64) -> SubmitRelayRequest {
        let step: RelayStep = self
            .module
            .call(
                PREPARE_RELAY,
                as_object(deposit_request(self.quote.clone(), RING, depositor, amount)),
            )
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
}

const FAULT_TRIGGER: &str = "relay_store_fault";

enum StoreFault {
    /// A NOT NULL refusal proves the update never committed.
    UpdateRefused,
    /// The attempt's transaction rolls the insert back.
    InsertFailed,
    /// `RAISE(FAIL)` keeps the updated row and still returns an error.
    UpdateReplyLost,
    ReservationReleaseRefused,
}

impl StoreFault {
    fn trigger(self) -> String {
        let (event, raise) = match self {
            Self::UpdateRefused => (
                "BEFORE UPDATE ON relay_relays",
                "INSERT INTO relay_relays(status) VALUES(NULL)",
            ),
            Self::InsertFailed => (
                "AFTER INSERT ON relay_relays",
                "SELECT RAISE(FAIL, 'the insert failed')",
            ),
            Self::UpdateReplyLost => (
                "AFTER UPDATE ON relay_relays",
                "SELECT RAISE(FAIL, 'the update reply was lost')",
            ),
            Self::ReservationReleaseRefused => (
                "BEFORE UPDATE OF state ON cosign_usage WHEN NEW.state='released'",
                "SELECT RAISE(ABORT, 'reservation release refused')",
            ),
        };
        format!("CREATE TRIGGER {FAULT_TRIGGER} {event} BEGIN {raise}; END")
    }
}

fn sender_capped() -> AssetLimits {
    AssetLimits {
        sender_cap: SENDER_CAP,
        sender_window_slots: 100,
        ..AssetLimits::EMPTY
    }
}

fn deposit_capped() -> AssetLimits {
    AssetLimits {
        deposit_cap: DEPOSIT_CAP,
        deposit_window_slots: 100,
        ..AssetLimits::EMPTY
    }
}

#[tokio::test]
async fn a_relayed_transfer_over_the_sender_window_cap_is_refused() {
    let recipient = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[47; 32]))
        .expect("recipient")
        .shielded_address()
        .expect("recipient address");
    assert_ne!(recipient, owner().shielded_address().expect("sender"));
    CappedRelay::new(anonymous_rail)
        .await
        .assert_second_refused(|inputs| inputs.outputs[0].owner_address = Some(recipient))
        .await;
}

#[tokio::test]
async fn a_relayed_exit_to_the_sender_over_the_sender_window_cap_is_refused() {
    CappedRelay::new(|| RelayRail::Confidential)
        .await
        // An exit leaves the ring even to the sender, the sender cap counts it.
        .assert_second_refused(|inputs| inputs.outputs[0].ring_program_id = None)
        .await;
}

fn second_approver() -> Keypair {
    Keypair::new_from_array([0x62; 32])
}

#[tokio::test]
async fn two_approvers_carry_their_pairs_and_the_relay_sends_once_both_signed() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let second = second_approver();
    let mut inputs = proof_inputs(RING, RelayRail::Confidential);
    inputs.outputs[0].ring_program_id = None;
    let mut request = signed_request(relay.quote.clone(), &inputs);
    request.co_signers = vec![second.pubkey().into(), relay.co_signer.into()];
    let step: RelayStep = relay
        .module
        .call(PREPARE_RELAY, as_object(request))
        .await
        .expect("prepared");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the second approver signs, got {step:?}");
    };
    assert!(relay.chain.sent().is_empty());

    let _: RelayStatus = relay
        .module
        .call(
            SUBMIT_RELAY,
            as_object(SubmitRelayRequest {
                relay_id,
                signer: second.pubkey().into(),
                signature: second.sign_message(&message.0).into(),
            }),
        )
        .await
        .expect("both signed");

    let [sent] = relay.chain.sent().try_into().expect("one sent transaction");
    assert!(signers_verify(&sent));
    let keys = sent.message.static_account_keys();
    let ring = CustomRing::new(RING);
    for signer in [second.pubkey(), relay.co_signer] {
        assert!(keys.contains(&signer));
        assert!(keys.contains(&ring.co_signer_pda(&signer)));
    }
    assert_eq!(
        usize::from(sent.message.header().num_required_signatures),
        3
    );
}

#[tokio::test]
async fn a_proof_naming_another_co_signer_is_refused_unsent() {
    let relay = CappedRelay::naming(
        anonymous_rail,
        Some(Address::new_from_array([0x99; 32])),
        sender_capped(),
    )
    .await;

    let refused = relay
        .module
        .call::<_, RelayStep>(
            PREPARE_RELAY,
            as_object(signed_request(
                relay.quote.clone(),
                &proof_inputs(RING, anonymous_rail()),
            )),
        )
        .await;

    assert_eq!(refusal(refused), RelayError::CoSignRefused.code());
    assert!(relay.chain.sent().is_empty());
}

#[tokio::test]
async fn a_transfer_that_landed_before_a_lost_send_reply_keeps_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let landed = relay.spending_cap(1);
    let relay_id = landed.relay_id().expect("relay id");
    relay.chain.reply_lost.store(true, Ordering::Relaxed);
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&landed))
        .await;
    assert!(interrupted.is_err());

    relay
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    let status: RelayStatus = relay
        .module
        .call(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await
        .expect("status");

    let [sent] = relay.chain.sent().try_into().expect("one sent transaction");
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
    // A freed reservation would let a second full cap through.
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_failed_insert_stores_nothing_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let failed = relay.spending_cap(1);
    let relay_id = failed.relay_id().expect("relay id");
    relay.fault(StoreFault::InsertFailed).await;
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&failed))
        .await;
    assert!(interrupted.is_err());
    relay.heal().await;

    assert!(relay.chain.sent().is_empty());
    let unknown = relay
        .module
        .call::<_, RelayStatus>(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await;
    assert_eq!(refusal(unknown), RelayError::UnknownRelay.code());
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn a_stored_relay_whose_update_reply_was_lost_keeps_its_reservation() {
    let relay = CappedRelay::naming(anonymous_rail, None, deposit_capped()).await;
    let (first, second) = (
        Keypair::new_from_array([51; 32]),
        Keypair::new_from_array([52; 32]),
    );
    let first_signed = relay.deposit(&first, 700).await;
    let second_signed = relay.deposit(&second, 700).await;
    let relay_id = first_signed.relay_id.clone();
    relay.fault(StoreFault::UpdateReplyLost).await;
    let interrupted = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(first_signed))
        .await;
    assert!(interrupted.is_err());
    relay.heal().await;

    // A whole pass, a tracker cut inside a store write would close the in-memory store.
    relay
        .hub
        .relay()
        .expect("relay")
        .track()
        .await
        .expect("a tracking pass");
    assert!(
        !relay.chain.sent().is_empty(),
        "the tracker resends the stored relay"
    );

    let status = relay.status(relay_id).await;
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    // A freed reservation would let the second deposit past the cap.
    let beyond = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(second_signed))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_refused_send_keeps_its_reservation_through_a_resend() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let refused = relay.spending_cap(1);
    let relay_id = refused.relay_id().expect("relay id");
    relay.chain.refuse_next.store(true, Ordering::Relaxed);
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&refused))
        .await
        .expect("pending relay");
    let pending = relay.status(relay_id.clone()).await;
    assert!(matches!(pending, RelayStatus::Sent { .. }), "{pending:?}");
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());

    // The record still reads `Sent`, the tracker resends it and the resend lands.
    relay
        .hub
        .relay()
        .expect("relay")
        .track()
        .await
        .expect("a tracking pass");
    assert!(
        !relay.chain.sent().is_empty(),
        "the tracker resends the stored relay"
    );
    let status: RelayStatus = relay
        .module
        .call(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await
        .expect("status");
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    // The landed debit still counts, a freed reservation would let a second full cap through.
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_refused_send_frees_its_reservation_only_after_finalized_expiry() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    relay.chain.refuse_next.store(true, Ordering::Relaxed);
    let refused = relay.spending_cap(1);
    let relay_id = refused.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&refused))
        .await
        .expect("pending relay");
    let pending = relay.status(relay_id.clone()).await;
    assert!(matches!(pending, RelayStatus::Sent { .. }), "{pending:?}");
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
    relay
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    let status = relay.status(relay_id).await;
    assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    relay.chain.height.store(400, Ordering::Relaxed);
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn an_on_chain_failure_reads_failed_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    *relay.chain.outcome.lock().expect("outcome") = Some(Some(ChainOutcome::Failed {
        reason: "custom program error".to_owned(),
    }));
    let failed = relay.spending_cap(1);
    let relay_id = failed.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&failed))
        .await
        .expect("sent");
    let status = relay.status(relay_id).await;
    assert_eq!(
        status,
        RelayStatus::Failed {
            reason: "custom program error".to_owned(),
        }
    );
    *relay.chain.outcome.lock().expect("outcome") = None;
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn blockhash_expiry_reads_failed_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    *relay.chain.outcome.lock().expect("outcome") = Some(None);
    let unlanded = relay.spending_cap(1);
    let relay_id = unlanded.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&unlanded))
        .await
        .expect("sent");
    // A pending transaction under a live blockhash keeps its reservation.
    let pending = relay.status(relay_id.clone()).await;
    assert!(matches!(pending, RelayStatus::Sent { .. }), "{pending:?}");
    relay
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    let expired = relay.status(relay_id).await;
    assert!(matches!(expired, RelayStatus::Failed { .. }), "{expired:?}");

    relay.chain.height.store(400, Ordering::Relaxed);
    *relay.chain.outcome.lock().expect("outcome") = None;
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn a_submit_whose_store_update_failed_frees_its_reservation() {
    let relay = CappedRelay::naming(anonymous_rail, None, deposit_capped()).await;
    let (first, second) = (
        Keypair::new_from_array([51; 32]),
        Keypair::new_from_array([52; 32]),
    );
    let first_signed = relay.deposit(&first, 700).await;
    let second_signed = relay.deposit(&second, 700).await;
    relay.fault(StoreFault::UpdateRefused).await;
    let refused = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(first_signed))
        .await;
    assert!(refused.is_err());
    relay.heal().await;

    let landed: RelayStatus = relay
        .module
        .call(SUBMIT_RELAY, as_object(second_signed))
        .await
        .expect("the unstored relay holds no allowance");

    assert!(
        matches!(landed, RelayStatus::Confirmed { .. }),
        "{landed:?}"
    );
}

#[tokio::test]
async fn an_unsigned_relay_holds_no_allowance_and_the_signed_one_past_the_cap_is_refused() {
    let relay = CappedRelay::naming(anonymous_rail, None, deposit_capped()).await;
    let (first, second) = (
        Keypair::new_from_array([51; 32]),
        Keypair::new_from_array([52; 32]),
    );

    let first_signed = relay.deposit(&first, 700).await;
    let second_signed = relay.deposit(&second, 700).await;

    assert!(relay.chain.sent().is_empty());
    let landed: RelayStatus = relay
        .module
        .call(SUBMIT_RELAY, as_object(first_signed))
        .await
        .expect("the first signed deposit fits the cap");
    assert!(
        matches!(landed, RelayStatus::Confirmed { .. }),
        "{landed:?}"
    );
    let beyond = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(second_signed))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
    let [sent] = relay.chain.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.message.static_account_keys()[1], first.pubkey());
    assert!(signers_verify(&sent));
}

#[tokio::test]
async fn a_derived_relay_refuses_a_ring_whose_auditor_key_it_does_not_hold() {
    let fixture = Fixture::new();
    let prover = Arc::new(RecordingProver::default());
    let chain = Arc::new(RecordingChain::default());
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let hub = Hub::builder(fixture.source(), identity(GENESIS))
        .with_origins(origins())
        .with_store(store.clone())
        .with_relay(RelayParts {
            store,
            prover: prover.clone(),
            fee_payer: Keypair::new_from_array([31; 32]),
            chain: chain.clone(),
        })
        .derived(RootSecret::from_bytes([7; 32]).expect("root"))
        .expect("hub");
    let module = rpc_module(Arc::new(hub)).expect("module");
    let quote_request = as_object(GetRelayQuoteRequest {
        ring: RING.into(),
        operation: anonymous_rail().operation(),
    });
    let quote = RelayQuote {
        fee_payer: Keypair::new_from_array([31; 32]).pubkey().into(),
        valid_until_slot: super::relay_fixture::SLOT,
    };

    let quoted = module
        .call::<_, RelayQuote>(GET_RELAY_QUOTE, quote_request)
        .await;
    let prepared = module
        .call::<_, RelayStep>(
            PREPARE_RELAY,
            as_object(signed_request(quote, &proof_inputs(RING, anonymous_rail()))),
        )
        .await;

    assert_eq!(refusal(quoted), RelayError::RingNotServed.code());
    assert_eq!(refusal(prepared), RelayError::RingNotServed.code());
    assert!(prover.requests.lock().expect("requests").is_empty());
    assert!(chain.sent().is_empty());
}

#[tokio::test]
async fn a_failed_reservation_release_is_retried_by_status() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let failed = relay.spending_cap(1);
    let relay_id = failed.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&failed))
        .await
        .expect("sent relay");
    *relay.chain.outcome.lock().expect("outcome") = Some(Some(ChainOutcome::Failed {
        reason: "custom program error".to_owned(),
    }));
    relay.fault(StoreFault::ReservationReleaseRefused).await;
    let interrupted = relay
        .module
        .call::<_, RelayStatus>(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest {
                relay_id: relay_id.clone(),
            }),
        )
        .await;
    assert!(interrupted.is_err());

    let connection = relay.store.connection();
    let stored = connection
        .query_one(Statement::from_string(
            connection.get_database_backend(),
            "SELECT status FROM relay_relays",
        ))
        .await
        .expect("relay query")
        .expect("stored relay");
    assert_eq!(
        stored.try_get::<String>("", "status").expect("status"),
        "failed"
    );
    assert_eq!(relay.chain.sent().len(), 1);
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());

    relay.heal().await;
    let status = relay.status(relay_id.clone()).await;
    assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    assert_eq!(relay.status(relay_id).await, status);
    *relay.chain.outcome.lock().expect("outcome") = None;
    relay.second_cap_fits().await;
}
