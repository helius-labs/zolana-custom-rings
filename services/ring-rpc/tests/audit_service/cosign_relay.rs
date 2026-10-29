//! The relay co-signs a transfer within its asset's sender window cap and refuses one beyond it.

use jsonrpsee::MethodsError;
use spr_keypair::{ShieldedKeypair, SigningKey};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, RelayOperation, RelayQuote, RelayStep, GET_RELAY_QUOTE, PREPARE_RELAY,
};
use zolana_ring_policy::{AssetLimits, MintPolicy};
use zolana_ring_rpc::{FeePayerSubmit, RelayError, RelayParts, ServedRings};

use super::relay_fixture::{
    anonymous_rail, owner, proof_inputs, signed_request, signers_verify, RecordingChain,
    RecordingProver,
};
use super::*;

const SENDER_CAP: u64 = 1_000;

#[tokio::test]
async fn a_relayed_transfer_over_the_sender_window_cap_is_refused() {
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
    let co_signer = fixture
        .hub(fixture.source())
        .co_signer_keypair()
        .expect("co-signer")
        .pubkey();
    let chain = Arc::new(RecordingChain::default());
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let hub = Hub::builder(source, GENESIS)
        .with_origins(origins())
        .with_store(store.clone())
        .with_relay(RelayParts {
            store,
            prover: Arc::new(RecordingProver {
                co_signer: Some(co_signer),
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
    let quote: RelayQuote = module
        .call(
            GET_RELAY_QUOTE,
            as_object(GetRelayQuoteRequest {
                ring: RING.into(),
                operation: RelayOperation::Anonymous,
            }),
        )
        .await
        .expect("quote");
    let recipient = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[47; 32]))
        .expect("recipient")
        .shielded_address()
        .expect("recipient address");
    let transfer = |seed| {
        let mut inputs = proof_inputs(RING, anonymous_rail());
        inputs.outputs[0].owner_address = Some(recipient);
        inputs.blinding_seed = [seed; 32];
        as_object(signed_request(quote.clone(), &inputs))
    };
    assert_ne!(recipient, owner().shielded_address().expect("sender"));

    let within: RelayStep = module
        .call(PREPARE_RELAY, transfer(1))
        .await
        .expect("within the cap");
    let beyond = module
        .call::<_, RelayStep>(PREPARE_RELAY, transfer(2))
        .await;

    assert!(matches!(within, RelayStep::Submitted { .. }));
    let [sent] = chain.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.message.static_account_keys()[1], co_signer);
    assert!(signers_verify(&sent));
    match beyond {
        Err(MethodsError::JsonRpc(error)) => {
            assert_eq!(error.code(), RelayError::CoSignRefused.code())
        }
        other => panic!("the second transfer passes the sender cap, got {other:?}"),
    }
}
