//! The relay co-signs within its asset's sender window cap and refuses an outflow beyond it or a proof naming another co-signer.

use jsonrpsee::RpcModule;
use spr_keypair::{ShieldedKeypair, SigningKey};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, RelayProofInputs, RelayQuote, RelayRail, RelayStep, GET_RELAY_QUOTE,
    PREPARE_RELAY,
};
use zolana_ring_policy::{AssetLimits, MintPolicy};
use zolana_ring_rpc::{FeePayerSubmit, RelayError, RelayParts, ServedRings};

use super::relay_fixture::{
    anonymous_rail, owner, proof_inputs, signed_request, signers_verify, RecordingChain,
    RecordingProver,
};
use super::*;

const SENDER_CAP: u64 = 1_000;

struct CappedRelay {
    module: RpcModule<Arc<Hub<StaticSource>>>,
    chain: Arc<RecordingChain>,
    co_signer: Address,
    quote: RelayQuote,
    rail: fn() -> RelayRail,
}

impl CappedRelay {
    async fn new(rail: fn() -> RelayRail) -> Self {
        Self::naming(rail, None).await
    }

    /// `named` replaces the hub's co-signer in the proof.
    async fn naming(rail: fn() -> RelayRail, named: Option<Address>) -> Self {
        let fixture = Fixture::new();
        let source = fixture.source();
        source.records.write_mint_policy(
            Member::asset(&SOL_MINT).expect("asset member"),
            MintPolicy {
                limits: AssetLimits {
                    sender_cap: SENDER_CAP,
                    sender_window_slots: 100,
                    ..AssetLimits::EMPTY
                },
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
                submit: Arc::new(FeePayerSubmit::new(
                    Keypair::new_from_array([31; 32]),
                    chain.clone(),
                )),
                chain: chain.clone(),
                rings: ServedRings::One(RING),
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
    let relay =
        CappedRelay::naming(anonymous_rail, Some(Address::new_from_array([0x99; 32]))).await;

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
