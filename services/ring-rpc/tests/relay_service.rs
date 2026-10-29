//! A wallet relays a sealed transfer, Ring RPC proves, pays and sends it.

#[path = "common/relay.rs"]
mod relay_fixture;

use std::sync::Arc;

use jsonrpsee::RpcModule;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, RelayIntent, RelayOperation, RelayQuote,
    RelayRail, RelayStatus, RelayStep, SubmitRelayRequest, GET_RELAY_QUOTE, GET_RELAY_STATUS,
    PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_rpc::{relay_module, FeePayerSubmit, Relay, RelayParts, ServedRings, Store};

use relay_fixture::{
    anonymous_rail, owner_wallet, proof_inputs, signed_request, signers_verify, RecordingChain,
    RecordingProver, SLOT,
};

const RING: Address = Address::new_from_array([6; 32]);

struct Fixture {
    module: RpcModule<Arc<Relay>>,
    prover: Arc<RecordingProver>,
    chain: Arc<RecordingChain>,
    fee_payer: Address,
}

impl Fixture {
    async fn new() -> Self {
        let prover = Arc::new(RecordingProver::default());
        let chain = Arc::new(RecordingChain::default());
        let fee_payer = Keypair::new_from_array([31; 32]);
        let fee_payer_address = fee_payer.pubkey();
        let relay = Relay::new(RelayParts {
            store: Store::open("sqlite::memory:", 1).await.expect("store"),
            prover: prover.clone(),
            submit: Arc::new(FeePayerSubmit::new(fee_payer, chain.clone())),
            chain: chain.clone(),
            rings: ServedRings::One(RING),
        });
        Self {
            module: relay_module(Arc::new(relay)).expect("module"),
            prover,
            chain,
            fee_payer: fee_payer_address,
        }
    }

    async fn call<T: serde::de::DeserializeOwned + Clone>(
        &self,
        method: &str,
        request: impl serde::Serialize,
    ) -> T {
        let serde_json::Value::Object(params) = serde_json::to_value(request).expect("json") else {
            panic!("request is no object");
        };
        self.module.call(method, params).await.expect(method)
    }

    async fn quote(&self, operation: RelayOperation) -> RelayQuote {
        self.call(
            GET_RELAY_QUOTE,
            GetRelayQuoteRequest {
                ring: RING.into(),
                operation,
            },
        )
        .await
    }

    fn sent(&self) -> Vec<VersionedTransaction> {
        self.chain.sent()
    }
}

#[tokio::test]
async fn an_anonymous_transfer_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let proof_inputs = proof_inputs(RING, anonymous_rail());
    let request = signed_request(quote, &proof_inputs);
    let RelayIntent::Anonymous {
        owner_signature, ..
    } = &request.intent
    else {
        unreachable!("anonymous intent");
    };
    let owner_signature = <[u8; 64]>::from(owner_signature.0);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("an anonymous relay asks the wallet for nothing more, got {step:?}");
    };
    assert_eq!(
        *fixture.prover.requests.lock().expect("requests"),
        [(fixture.fee_payer, Some(owner_signature))]
    );
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.message.static_account_keys()[0], fixture.fee_payer);
    assert_eq!(sent.signatures.len(), 1);
    assert!(signers_verify(&sent));
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
}

#[tokio::test]
async fn a_confidential_transfer_relays_through_a_signed_message() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Confidential).await;
    let request = signed_request(quote, &proof_inputs(RING, RelayRail::Confidential));

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs the confidential transaction, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let wallet = owner_wallet();
    let status: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id,
                signer: wallet.pubkey().into(),
                signature: wallet.sign_message(&message.0).into(),
            },
        )
        .await;

    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(
        sent.message.static_account_keys()[..2],
        [fixture.fee_payer, wallet.pubkey()]
    );
    assert_eq!(sent.message.serialize(), message.0);
    assert!(signers_verify(&sent));
    assert_eq!(
        status,
        RelayStatus::Sent {
            signature: sent.signatures[0].into(),
        }
    );
}
