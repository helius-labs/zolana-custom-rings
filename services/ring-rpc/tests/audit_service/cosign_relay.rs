//! The relay co-signs within its asset's window caps and refuses an outflow beyond them, a proof naming another co-signer, or a ring whose auditor key it does not hold, and keeps the reservation of a transfer that landed before a lost send reply.

use jsonrpsee::RpcModule;
use spr_keypair::{ShieldedKeypair, SigningKey};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayProofInputs, RelayQuote,
    RelayRail, RelayStatus, RelayStep, SubmitRelayRequest, GET_RELAY_QUOTE, GET_RELAY_STATUS,
    PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_policy::{AssetLimits, MintPolicy};
use zolana_ring_rpc::{RelayError, RelayParts};

use super::relay_fixture::{
    anonymous_rail, deposit_request, owner, proof_inputs, signed_request, signers_verify,
    RecordingChain, RecordingProver, LAST_VALID_BLOCK_HEIGHT, SLOT,
};
use super::*;

const SENDER_CAP: u64 = 1_000;
const DEPOSIT_CAP: u64 = 1_000;

struct CappedRelay {
    module: RpcModule<Arc<Hub<StaticSource>>>,
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
        let source = fixture.source();
        source.records.write_mint_policy(
            Member::asset(&SOL_MINT).expect("asset member"),
            MintPolicy {
                limits,
                ..MintPolicy::EMPTY
            },
        );
        let co_signer = co_signer_key().pubkey();
        let chain = Arc::new(RecordingChain::default());
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let hub = Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .with_store(store.clone())
            .with_co_signer(co_signer_key())
            .with_relay(RelayParts {
                store,
                prover: Arc::new(RecordingProver {
                    co_signer: Some(named.unwrap_or(co_signer)),
                    ..RecordingProver::default()
                }),
                fee_payer: Keypair::new_from_array([31; 32]),
                chain: chain.clone(),
            })
            .local(RING, fixture.auditor.clone())
            .expect("hub");
        let module = rpc_module(Arc::new(hub)).expect("module");
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
            module,
            chain,
            co_signer,
            quote,
            rail,
        }
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

    /// Prepares and signs, the caller submits.
    async fn deposit(&self, depositor: &Keypair, amount: u64) -> SubmitRelayRequest {
        let step: RelayStep = self
            .module
            .call(
                PREPARE_RELAY,
                as_object(deposit_request(
                    self.quote.clone(),
                    RING,
                    depositor.pubkey(),
                    amount,
                )),
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

fn sender_capped() -> AssetLimits {
    AssetLimits {
        sender_cap: SENDER_CAP,
        sender_window_slots: 100,
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
async fn an_unsigned_relay_holds_no_allowance_and_the_signed_one_past_the_cap_is_refused() {
    let relay = CappedRelay::naming(
        anonymous_rail,
        None,
        AssetLimits {
            deposit_cap: DEPOSIT_CAP,
            deposit_window_slots: 100,
            ..AssetLimits::EMPTY
        },
    )
    .await;
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
    assert!(matches!(landed, RelayStatus::Sent { .. }), "{landed:?}");
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
