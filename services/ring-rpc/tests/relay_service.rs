//! A wallet relays a sealed transfer, Ring RPC proves, pays and sends it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use custom_ring_interface::cosign::CoSignDemand;
use jsonrpsee::RpcModule;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::ComputeBudgetConfig;
use spr_event::MessageData;
use spr_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    MAX_OUTPUTS,
};
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, ViewingKey, X25519Keypair};
use spr_transaction::{
    instructions::transact::ExternalData, utxo::SppProofInputUtxo, Data, Mint, SppProofOutputUtxo,
    Utxo,
};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, ProofInputBytes, RelayIntent,
    RelayOperation, RelayProofInputs, RelayQuote, RelayRail, RelayStatus, RelayStep,
    SubmitRelayRequest, GET_RELAY_QUOTE, GET_RELAY_STATUS, PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_rpc::{
    relay_module, ChainOutcome, FeePayerSubmit, ProvenRelay, Relay, RelayChain, RelayParts,
    RelayProofRequest, RelayProver, RingRpcError, ServedRings, Store,
};
use zolana_ring_transaction::{AnonymousPlan, TaggedPayment};

const RING: Address = Address::new_from_array([6; 32]);
const SLOT: u64 = 1_000;
const OWNER_SEED: [u8; 32] = [5; 32];

#[derive(Default)]
struct RecordingProver {
    requests: Mutex<Vec<(Address, Option<[u8; 64]>)>>,
}

#[async_trait]
impl RelayProver for RecordingProver {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        self.requests
            .lock()
            .expect("requests")
            .push((request.fee_payer, request.owner_signature));
        let signers = match request.proof_inputs.rail {
            RelayRail::Confidential => vec![request.proof_inputs.sender.solana_address()?],
            _ => Vec::new(),
        };
        let accounts = core::iter::once(AccountMeta::new(request.fee_payer, true))
            .chain(
                signers
                    .iter()
                    .map(|owner| AccountMeta::new_readonly(*owner, true)),
            )
            .collect();
        Ok(ProvenRelay {
            instruction: Instruction {
                program_id: request.ring,
                accounts,
                data: vec![1, 2, 3],
            },
            budget: ComputeBudgetConfig::new(400_000),
            co_signer: None,
            co_sign_demand: CoSignDemand::transact(false, &[]),
            signers,
        })
    }
}

#[derive(Default)]
struct RecordingChain {
    sent: Mutex<Vec<VersionedTransaction>>,
}

#[async_trait]
impl RelayChain for RecordingChain {
    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(SLOT)
    }

    async fn latest_blockhash(&self) -> Result<(Hash, u64), RingRpcError> {
        Ok((Hash::new_from_array([8; 32]), 500))
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(400)
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.sent.lock().expect("sent").push(transaction.clone());
        Ok(())
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        let sent = self.sent.lock().expect("sent");
        Ok(sent
            .iter()
            .any(|transaction| transaction.signatures[0] == signature)
            .then_some(ChainOutcome::Confirmed { slot: SLOT + 1 }))
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
        self.chain.sent.lock().expect("sent").clone()
    }
}

fn owner() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&OWNER_SEED)).expect("owner")
}

/// One ring UTXO spent back to the sender, the outputs sealed as a wallet would leave them.
fn proof_inputs(rail: RelayRail) -> RelayProofInputs {
    let owner = owner();
    let sender = owner.shielded_address().expect("address");
    let utxo = Utxo {
        owner: sender.signing_pubkey,
        asset: Mint::SOL,
        amount: 900,
        blinding: [11; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], 4)
        .expect("hash");
    let spend = SppProofInputUtxo {
        address: false,
        nullifier: owner
            .nullifier_key
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: sender.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 4,
        leaf_index: 17,
        cache_slot: None,
        compact: false,
    };
    let tx_viewing_key = ViewingKey::from_secret_key(X25519Keypair::from_bytes(&[13; 32]));
    RelayProofInputs {
        rail,
        ring_program_id: RING,
        nullifier_key: NullifierKey::from_secret(*owner.nullifier_key.secret()),
        sender,
        external_data: ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            [15; 16],
            vec![TransactOutput {
                utxo_hash: [16; 32],
                owner_tag: OwnerTag::Inline([17; 32]),
                data: Some(vec![18, 19]),
            }],
            vec![[20; 32]],
            vec![MessageData {
                view_tag: [21; 32],
                data: vec![22],
            }],
        ),
        tx_viewing_key,
        audit_ephemeral_key: zeroize::Zeroizing::new([26; 32]),
        inputs: vec![spend],
        outputs: vec![SppProofOutputUtxo {
            asset: Mint::SOL,
            amount: 900,
            blinding: [12; 32],
            ring_program_id: Some(RING),
            owner_address: Some(sender),
            ..SppProofOutputUtxo::default()
        }],
        interface_transfer_accounts: Vec::new(),
        blinding_seed: [28; 32],
        output_tree_id: 4,
    }
}

/// The owner signs `SppProofInputs::message_hash` before the relay proves.
fn signed_request(quote: RelayQuote, proof_inputs: &RelayProofInputs) -> PrepareRelayRequest {
    let digest = proof_inputs
        .spp_proof_inputs(quote.fee_payer.0)
        .message_hash()
        .expect("message hash");
    let owner_signature = Signature::from(
        SigningKey::from_ed25519_bytes(&OWNER_SEED)
            .sign_message(&digest)
            .expect("signature"),
    )
    .into();
    let encoded = ProofInputBytes::new(proof_inputs.encode().expect("encode"));
    PrepareRelayRequest {
        ring: RING.into(),
        quote,
        intent: match proof_inputs.rail {
            RelayRail::Anonymous { .. } => RelayIntent::Anonymous {
                proof_inputs: encoded,
                owner_signature,
            },
            _ => RelayIntent::Confidential {
                proof_inputs: encoded,
                owner_signature,
            },
        },
    }
}

fn signers_verify(transaction: &VersionedTransaction) -> bool {
    let message = transaction.message.serialize();
    transaction
        .signatures
        .iter()
        .zip(transaction.message.static_account_keys())
        .all(|(signature, signer)| signature.verify(signer.as_ref(), &message))
}

#[tokio::test]
async fn an_anonymous_transfer_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let proof_inputs = proof_inputs(RelayRail::Anonymous {
        plan: Box::new(AnonymousPlan::from_tags(
            [23; 32],
            vec![TaggedPayment {
                recipient: owner().viewing_pubkey(),
                tag: [24; 32],
            }],
            [[25; 32]; MAX_OUTPUTS],
        )),
        exit_token_owner: None,
    });
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
    let request = signed_request(quote, &proof_inputs(RelayRail::Confidential));

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs the confidential transaction, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let wallet = Keypair::new_from_array(OWNER_SEED);
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
