//! A wallet relays a sealed transfer, deposit or merge, Ring RPC proves, pays and sends it.

#[path = "common/relay.rs"]
mod relay_fixture;

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::RpcModule;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_keypair::NullifierKey;
use spr_transaction::{utxo::SppProofInputUtxo, WalletUtxo};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, ProofInputBytes, RelayIntent,
    RelayMergeInputs, RelayOperation, RelayQuote, RelayRail, RelayStatus, RelayStep,
    SubmitRelayRequest, GET_RELAY_QUOTE, GET_RELAY_STATUS, PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_rpc::{
    relay_module, Relay, RelayError, RelayParts, RingRpcError, ServedRings, Store,
};

use relay_fixture::{
    anonymous_rail, deposit_request, proof_inputs, signed_request, signers_verify, RecordingChain,
    RecordingProver, SLOT,
};

const RING: Address = Address::new_from_array([6; 32]);

struct OneRing(Address);

#[async_trait]
impl ServedRings for OneRing {
    async fn check(&self, ring: Address) -> Result<(), RingRpcError> {
        match ring == self.0 {
            true => Ok(()),
            false => Err(RelayError::RingNotServed.into()),
        }
    }
}

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
            fee_payer,
            chain: chain.clone(),
        })
        .with_rings(Arc::new(OneRing(RING)));
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
async fn a_confidential_transfer_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Confidential).await;
    let request = signed_request(quote, &proof_inputs(RING, RelayRail::Confidential));
    let RelayIntent::Confidential {
        owner_signature, ..
    } = &request.intent
    else {
        unreachable!("confidential intent");
    };
    let owner_signature = <[u8; 64]>::from(owner_signature.0);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("the owner signs inside the proof, got {step:?}");
    };
    assert_eq!(
        *fixture.prover.requests.lock().expect("requests"),
        [(fixture.fee_payer, Some(owner_signature))]
    );
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.signatures.len(), 1);
    assert_eq!(sent.message.static_account_keys()[0], fixture.fee_payer);
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
async fn a_deposit_relays_through_the_depositors_signature() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Deposit).await;
    let depositor = Keypair::new_from_array([41; 32]);
    let request = deposit_request(quote, RING, depositor.pubkey(), 700);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the depositor signs its funding, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: depositor.pubkey().into(),
                signature: depositor.sign_message(&message.0).into(),
            },
        )
        .await;
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(
        sent.message.static_account_keys()[..2],
        [fixture.fee_payer, depositor.pubkey()]
    );
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
async fn a_merge_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Merge).await;
    let spends = proof_inputs(RING, RelayRail::Confidential);
    let note = |spend: &SppProofInputUtxo| WalletUtxo {
        utxo: spend.utxo.clone(),
        nullifier_pubkey: spend.nullifier_pubkey,
        utxo_hash: spend.utxo_hash,
        nullifier: spend.nullifier,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: spend.tree_id,
        leaf_index: spend.leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    };
    let merge = RelayMergeInputs {
        ring_program_id: RING,
        sender: spends.sender,
        nullifier_key: NullifierKey::from_secret(*spends.nullifier_key.secret()),
        inputs: spends.inputs.iter().map(note).collect(),
    };
    let request = PrepareRelayRequest {
        ring: RING.into(),
        quote,
        intent: RelayIntent::Merge {
            proof_inputs: ProofInputBytes::new(merge.encode().expect("encode")),
        },
    };

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("a merge needs no wallet signature, got {step:?}");
    };
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
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
