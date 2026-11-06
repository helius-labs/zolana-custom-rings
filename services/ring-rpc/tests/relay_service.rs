//! A wallet relays a sealed transfer, deposit or merge, Ring RPC proves, pays and sends it.

#[path = "relay_service/attempts.rs"]
mod attempts;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/store.rs"]
mod store_fixture;
#[path = "relay_service/transitions.rs"]
mod transitions;
#[path = "common/wide_frame.rs"]
mod wide_frame;

use std::sync::{atomic::Ordering, Arc};

use async_trait::async_trait;
use jsonrpsee::RpcModule;
use sea_orm::{ConnectionTrait, Statement};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_instruction::instruction::{
    CreateAssociatedTokenAccount, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplWithdrawalAccounts,
};
use spr_interface::SPL_TOKEN_PROGRAM_ID;
use spr_keypair::NullifierKey;
use spr_transaction::{
    instructions::transact::SettlementTransfer, utxo::SppProofInputUtxo, WalletUtxo,
};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, ProofInputBytes,
    RelayEnrollInputs, RelayIntent, RelayMergeInputs, RelayOperation, RelayProofInputs, RelayQuote,
    RelayRail, RelayStatus, RelayStep, SubmitRelayRequest, TokenAccountSetup, GET_RELAY_QUOTE,
    GET_RELAY_STATUS, PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_rpc::{
    relay_module, Migrator, Relay, RelayBudget, RelayError, RelayParts, RingRpcError, ServedRings,
    Store, ABANDONED_AFTER_SLOTS, STORE_CONNECTIONS,
};

use wide_frame::wide_frame;

use relay_fixture::{
    anonymous_rail, deposit_request, owner_wallet, proof_inputs, signed_request, signers_verify,
    RecordingChain, RecordingProver, LAST_VALID_BLOCK_HEIGHT, RENT_LAMPORTS, SLOT, TREE_FEES,
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

    async fn tracking_registry(&self, _ring: Address) -> Result<Address, RingRpcError> {
        Ok(TRACKING_REGISTRY)
    }

    async fn delegate(&self, _ring: Address) -> Result<Option<Address>, RingRpcError> {
        Ok(Some(ring_delegate().pubkey()))
    }
}

fn ring_delegate() -> Keypair {
    Keypair::new_from_array([51; 32])
}

struct Fixture {
    relay: Arc<Relay>,
    module: RpcModule<Arc<Relay>>,
    prover: Arc<RecordingProver>,
    chain: Arc<RecordingChain>,
    fee_payer: Address,
    store: Store,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_budget(0).await
    }

    async fn with_budget(budget: u64) -> Self {
        Self::with_budgets(RelayBudget {
            total_lamports: budget,
            signer_lamports: budget,
        })
        .await
    }

    async fn with_budgets(budget: RelayBudget) -> Self {
        let prover = Arc::new(RecordingProver::default());
        let chain = Arc::new(RecordingChain::default());
        let fee_payer = Keypair::new_from_array([31; 32]);
        let fee_payer_address = fee_payer.pubkey();
        let store = store_fixture::test_store().await;
        let relay = Relay::new(RelayParts {
            store: store.clone(),
            prover: prover.clone(),
            fee_payer,
            chain: chain.clone(),
        })
        .with_rings(Arc::new(OneRing(RING)))
        .with_budget(budget);
        let relay = Arc::new(relay);
        Self {
            relay: relay.clone(),
            module: relay_module(relay).expect("module"),
            prover,
            chain,
            fee_payer: fee_payer_address,
            store,
        }
    }

    /// Lamports the total scope holds outstanding.
    async fn outstanding(&self) -> i64 {
        let connection = self.store.connection();
        connection
            .query_one(Statement::from_string(
                connection.get_database_backend(),
                "SELECT CAST(COALESCE(SUM(lamports), 0) AS BIGINT) AS total FROM relay_reservations"
                    .to_owned(),
            ))
            .await
            .expect("sum")
            .expect("row")
            .try_get("", "total")
            .expect("total")
    }

    async fn row_count(&self) -> i64 {
        let connection = self.store.connection();
        connection
            .query_one(Statement::from_string(
                connection.get_database_backend(),
                "SELECT COUNT(*) AS total FROM relay_reservations".to_owned(),
            ))
            .await
            .expect("count")
            .expect("row")
            .try_get("", "total")
            .expect("total")
    }

    /// Lamports the total counts, reserved and spent for good.
    async fn committed(&self) -> i64 {
        let connection = self.store.connection();
        connection
            .query_one(Statement::from_sql_and_values(
                connection.get_database_backend(),
                "SELECT CAST(COALESCE(SUM(committed), 0) AS BIGINT) AS total FROM relay_reserved \
                 WHERE scope=$1",
                vec![vec![0u8; 32].into()],
            ))
            .await
            .expect("sum")
            .expect("row")
            .try_get("", "total")
            .expect("total")
    }

    async fn prepare(
        &self,
        request: &PrepareRelayRequest,
    ) -> Result<RelayStep, jsonrpsee::MethodsError> {
        let serde_json::Value::Object(params) = serde_json::to_value(request).expect("json") else {
            panic!("request is no object");
        };
        self.module.call(PREPARE_RELAY, params).await
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
    let request = deposit_request(quote, RING, &depositor, 700);

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
async fn an_unsigned_deposit_reaches_no_prover_and_stores_nothing() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Deposit).await;
    let depositor = Keypair::new_from_array([41; 32]);
    let mut request = deposit_request(quote, RING, &depositor, 700);
    let RelayIntent::Deposit {
        proof_inputs,
        depositor_signature,
    } = &mut request.intent
    else {
        panic!("a deposit request");
    };
    *depositor_signature = Keypair::new_from_array([43; 32])
        .sign_message(&proof_inputs.deposit_request_digest())
        .into();

    let refused = fixture.prepare(&request).await;

    assert!(
        refused_with(&refused, RelayError::DepositorSignature),
        "{refused:?}"
    );
    assert!(fixture.prover.requests.lock().expect("requests").is_empty());
    assert_eq!(fixture.row_count().await, 0);
}

/// A deposit frame names one funder that is not the fee payer and rides the deposit rail.
#[tokio::test]
async fn a_deposit_frame_off_the_deposit_rail_or_its_one_funder_is_refused() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Deposit).await;
    let depositor = Keypair::new_from_array([41; 32]);
    let resigned = |inputs: &RelayProofInputs, signer: &Keypair| {
        let proof_inputs = ProofInputBytes::new(inputs.encode().expect("encode"));
        let depositor_signature = signer
            .sign_message(&proof_inputs.deposit_request_digest())
            .into();
        PrepareRelayRequest {
            intent: RelayIntent::Deposit {
                proof_inputs,
                depositor_signature,
            },
            ..deposit_request(quote.clone(), RING, &depositor, 700)
        }
    };
    let honest = deposit_request(quote.clone(), RING, &depositor, 700);
    let inputs = RelayProofInputs::decode(honest.intent.proof_inputs().as_bytes()).expect("decode");

    let mut confidential =
        RelayProofInputs::decode(honest.intent.proof_inputs().as_bytes()).expect("decode");
    confidential.rail = RelayRail::Confidential;
    let mut two_funders =
        RelayProofInputs::decode(honest.intent.proof_inputs().as_bytes()).expect("decode");
    let second = Keypair::new_from_array([42; 32]);
    two_funders
        .external_data
        .interface_transfers
        .push(SettlementTransfer::Sol {
            is_deposit: true,
            amount: 1,
            user_sol_account: second.pubkey(),
        });
    two_funders
        .interface_transfer_accounts
        .push(TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: second.pubkey(),
            },
        ));
    let fee_payer_funds =
        deposit_request(quote.clone(), RING, &Keypair::new_from_array([31; 32]), 700);

    for (request, error) in [
        (
            resigned(&confidential, &depositor),
            RelayError::RailMismatch,
        ),
        (
            resigned(&two_funders, &depositor),
            RelayError::DepositorSignature,
        ),
        (fee_payer_funds, RelayError::DepositorIsFeePayer),
        (resigned(&inputs, &second), RelayError::DepositorSignature),
    ] {
        let refused = fixture.prepare(&request).await;
        assert!(refused_with(&refused, error), "{refused:?}");
    }
    assert!(fixture.prover.requests.lock().expect("requests").is_empty());
}

const TRACKING_REGISTRY: Address = Address::new_from_array([0x71; 32]);

fn enrollment(owner: &Keypair, data: Vec<u8>, quote: RelayQuote) -> PrepareRelayRequest {
    enrollment_under(EnrollmentRequest {
        registry: TRACKING_REGISTRY,
        owner: owner.pubkey(),
        signer: owner,
        data,
        quote,
    })
}

struct EnrollmentRequest<'a> {
    registry: Address,
    owner: Address,
    signer: &'a Keypair,
    data: Vec<u8>,
    quote: RelayQuote,
}

fn enrollment_under(request: EnrollmentRequest<'_>) -> PrepareRelayRequest {
    let inputs = RelayEnrollInputs {
        ring_program_id: RING,
        owner: request.owner,
        tracking_registry: request.registry,
        instruction_data: request.data,
    };
    PrepareRelayRequest {
        ring: RING.into(),
        quote: request.quote,
        intent: RelayIntent::Enroll {
            proof_inputs: ProofInputBytes::new(zeroize::Zeroizing::new(
                inputs.encode().expect("encode"),
            )),
            owner_signature: request.signer.sign_message(&inputs.request_digest()).into(),
        },
        co_signers: Vec::new(),
    }
}

/// Rent and one signature for each of the payer and the owner.
const ENROLLMENT_LAMPORTS: u64 = RENT_LAMPORTS + ENROLLMENT_FEES;
const ENROLLMENT_FEES: u64 = 2 * 5_000;

/// A wallet with no SOL enrolls, the relay pays and the owner's signature authorizes.
#[tokio::test]
async fn an_enrollment_relays_through_the_owners_signature() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let request = enrollment(&owner, vec![6, 1, 2, 3], quote);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(
        sent.message.static_account_keys()[..2],
        [fixture.fee_payer, owner.pubkey()]
    );
    assert!(signers_verify(&sent));
    let keys = sent.message.static_account_keys();
    let instruction = sent
        .message
        .instructions()
        .iter()
        .find(|instruction| {
            keys[usize::from(instruction.program_id_index)]
                == custom_ring_interface::STORAGE_PROGRAM_ID
        })
        .expect("the enrollment");
    assert_eq!(instruction.data, [6, 1, 2, 3]);
}

#[tokio::test]
async fn an_enrollment_whose_proof_fails_holds_no_budget() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let request = enrollment(&owner, vec![6, 1, 2, 3], quote);
    fixture
        .prover
        .refuse_enrollment
        .store(true, Ordering::Relaxed);

    let refused = fixture.prepare(&request).await;

    assert!(
        refused_with(&refused, RelayError::InvalidEnrollment),
        "{refused:?}"
    );
    assert_eq!(fixture.committed().await, 0);
    assert_eq!(fixture.row_count().await, 0);

    fixture
        .prover
        .refuse_enrollment
        .store(false, Ordering::Relaxed);
    fixture.prepare(&request).await.expect("a verified proof");
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn an_enrollment_the_chain_simulation_refuses_holds_no_budget_and_sends_nothing() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let request = enrollment(&owner, vec![6, 1, 2, 3], quote);
    *fixture.chain.simulation_refusal.lock().expect("refusal") =
        Some("TransactProofVerificationFailed".to_owned());

    let refused = fixture.prepare(&request).await;

    let code = RelayError::EnrollmentRefused {
        reason: String::new(),
    }
    .code();
    assert!(
        matches!(&refused, Err(jsonrpsee::MethodsError::JsonRpc(object)) if object.code() == code),
        "{refused:?}"
    );
    assert_eq!(fixture.committed().await, 0);
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.row_count().await, 0);
    assert!(fixture.sent().is_empty());

    *fixture.chain.simulation_refusal.lock().expect("refusal") = None;
    fixture
        .prepare(&request)
        .await
        .expect("a passing simulation");
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);
}

fn refused_with(refused: &Result<RelayStep, jsonrpsee::MethodsError>, error: RelayError) -> bool {
    matches!(
        refused,
        Err(jsonrpsee::MethodsError::JsonRpc(object)) if object.code() == error.code()
    )
}

/// Either bound at zero refuses ahead of a proof the prover would refuse.
#[tokio::test]
async fn a_disabled_budget_refuses_an_enrollment_before_any_row_or_proof_check() {
    let owner = Keypair::new_from_array([42; 32]);
    for budget in [
        RelayBudget::default(),
        RelayBudget {
            total_lamports: ENROLLMENT_LAMPORTS,
            signer_lamports: 0,
        },
    ] {
        let fixture = Fixture::with_budgets(budget).await;
        fixture
            .prover
            .refuse_enrollment
            .store(true, Ordering::Relaxed);
        let quote = fixture.quote(RelayOperation::Enroll).await;

        let refused = fixture
            .prepare(&enrollment(&owner, vec![6, 1], quote))
            .await;

        assert!(
            refused_with(&refused, RelayError::BudgetUnset),
            "{refused:?}"
        );
        assert_eq!(fixture.row_count().await, 0);
        assert_eq!(fixture.committed().await, 0);
        assert!(fixture.sent().is_empty());
    }
}

/// The landed charge stays in the total and the signer's share returns.
#[tokio::test]
async fn an_enrollment_holds_its_reservation_until_it_settles() {
    let fixture = Fixture::with_budgets(RelayBudget {
        total_lamports: 2 * ENROLLMENT_LAMPORTS,
        signer_lamports: ENROLLMENT_LAMPORTS,
    })
    .await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    assert_eq!(fixture.row_count().await, 1);
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);

    let status: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id,
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;

    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    assert_eq!(fixture.row_count().await, 0);
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
    let next = fixture
        .prepare(&enrollment(&owner, vec![6, 2], quote))
        .await;
    assert!(next.is_ok(), "the share returned, got {next:?}");
}

/// An enrolled owner's rotation creates no account, the budget pays its fees alone.
#[tokio::test]
async fn a_settled_rotation_spends_only_its_fees_from_the_budget() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let (authorization, _) = custom_ring_interface::tracking::TrackingAuthorization::find_address(
        &TRACKING_REGISTRY,
        &owner.pubkey(),
    );
    fixture
        .chain
        .filled
        .lock()
        .expect("filled")
        .push(authorization);
    let remaining = |committed: i64| ENROLLMENT_LAMPORTS as i64 - committed;
    let before = remaining(fixture.committed().await);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote))
        .await
        .expect("the rotation");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its rotation, got {step:?}");
    };
    assert_eq!(fixture.outstanding().await, ENROLLMENT_FEES as i64);

    let status: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id,
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;

    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(
        remaining(fixture.committed().await),
        before - ENROLLMENT_FEES as i64
    );
}

/// The signer's share and the total each refuse at funding.
#[tokio::test]
async fn an_enrollment_past_the_allowance_refuses_before_any_send() {
    let fixture = Fixture::with_budgets(RelayBudget {
        total_lamports: 2 * ENROLLMENT_LAMPORTS,
        signer_lamports: ENROLLMENT_LAMPORTS,
    })
    .await;
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let [first, second, third] = [42, 43, 44].map(|seed| Keypair::new_from_array([seed; 32]));
    let held = fixture
        .prepare(&enrollment(&first, vec![6, 1], quote.clone()))
        .await;
    assert!(held.is_ok(), "{held:?}");

    let over_signer = fixture
        .prepare(&enrollment(&first, vec![6, 2], quote.clone()))
        .await;
    assert!(
        refused_with(&over_signer, RelayError::SignerBudget),
        "{over_signer:?}"
    );
    let filled = fixture
        .prepare(&enrollment(&second, vec![6, 1], quote.clone()))
        .await;
    assert!(filled.is_ok(), "{filled:?}");
    let over_total = fixture
        .prepare(&enrollment(&third, vec![6, 1], quote))
        .await;
    assert!(
        refused_with(&over_total, RelayError::Budget),
        "{over_total:?}"
    );

    assert!(fixture.sent().is_empty());
    assert_eq!(fixture.row_count().await, 2);
    assert_eq!(
        fixture.outstanding().await,
        (2 * ENROLLMENT_LAMPORTS) as i64
    );
}

/// Nobody spends a wallet's share without its key.
#[tokio::test]
async fn an_unsigned_enrollment_consumes_nothing_and_a_retry_is_charged_once() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let stranger = Keypair::new_from_array([43; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let forged = enrollment_under(EnrollmentRequest {
        registry: TRACKING_REGISTRY,
        owner: owner.pubkey(),
        signer: &stranger,
        data: vec![6, 1],
        quote: quote.clone(),
    });
    let refused = fixture.prepare(&forged).await;
    assert!(
        refused_with(&refused, RelayError::EnrollmentSignature),
        "{refused:?}"
    );
    assert_eq!(fixture.outstanding().await, 0);

    let signed = enrollment(&owner, vec![6, 1], quote);
    assert!(fixture.prepare(&signed).await.is_ok());
    let retried = fixture.prepare(&signed).await;
    assert!(retried.is_ok(), "{retried:?}");
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn the_relay_forwards_no_other_storage_instruction_and_never_enrolls_itself() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    for request in [
        enrollment(&owner, vec![7, 1, 2, 3], quote.clone()),
        enrollment(&owner, Vec::new(), quote.clone()),
        enrollment_under(EnrollmentRequest {
            registry: Address::new_from_array([0x72; 32]),
            owner: owner.pubkey(),
            signer: &owner,
            data: vec![6, 1, 2, 3],
            quote: quote.clone(),
        }),
        enrollment_under(EnrollmentRequest {
            registry: TRACKING_REGISTRY,
            owner: fixture.fee_payer,
            signer: &owner,
            data: vec![6, 1, 2, 3],
            quote,
        }),
    ] {
        let serde_json::Value::Object(params) = serde_json::to_value(&request).expect("json")
        else {
            panic!("request is no object");
        };
        let refused = fixture
            .module
            .call::<_, RelayStep>(PREPARE_RELAY, params)
            .await;
        assert!(
            matches!(
                &refused,
                Err(jsonrpsee::MethodsError::JsonRpc(error))
                    if error.code() == RelayError::InvalidEnrollment.code()
            ),
            "{refused:?}"
        );
    }
    assert!(fixture.sent().is_empty());
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
    let proof_inputs = ProofInputBytes::new(merge.encode().expect("encode"));
    let owner_signature = owner_wallet()
        .sign_message(&proof_inputs.merge_request_digest())
        .into();
    let signed_by = |owner_signature| PrepareRelayRequest {
        ring: RING.into(),
        quote: quote.clone(),
        intent: RelayIntent::Merge {
            proof_inputs: proof_inputs.clone(),
            owner_signature,
        },
        co_signers: Vec::new(),
    };
    let stranger = Keypair::new_from_array([43; 32])
        .sign_message(&proof_inputs.merge_request_digest())
        .into();

    let refused = fixture.prepare(&signed_by(stranger)).await;
    assert!(
        refused_with(&refused, RelayError::OwnerSignature),
        "{refused:?}"
    );
    assert!(fixture.prover.requests.lock().expect("requests").is_empty());

    let step: RelayStep = fixture
        .call(PREPARE_RELAY, &signed_by(owner_signature))
        .await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("a signed merge sends at once, got {step:?}");
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

/// Past one transaction the frame refuses under its own code, nothing is sent or charged.
#[tokio::test]
async fn a_frame_past_one_transaction_is_refused_before_any_send_or_charge() {
    use custom_ring_interface::tag as ring_tag;
    for frame_tag in [ring_tag::TRANSFER, ring_tag::AUTHORITY_TRANSFER] {
        let fixture = Fixture::with_budget(FRAME_BUDGET).await;
        *fixture.prover.frame.lock().expect("frame") = Some(wide_frame(frame_tag));
        let quote = fixture.quote(RelayOperation::Anonymous).await;
        let request = signed_request(quote, &proof_inputs(RING, anonymous_rail()));
        let refused = fixture.prepare(&request).await;
        let oversized = RelayError::Oversized {
            reason: String::new(),
        };
        assert!(refused_with(&refused, oversized), "{refused:?}");
        assert!(fixture.sent().is_empty());
        assert_eq!(fixture.outstanding().await, 0);
        assert_eq!(fixture.committed().await, 0);
    }
}

const FRAME_BUDGET: u64 = 1_000_000;

/// Landed rent and fees never return, only the operator's budget ends a repeated enrollment.
#[tokio::test]
async fn repeated_landed_enrollments_stop_at_the_budget() {
    let fixture = Fixture::with_budget(2 * ENROLLMENT_LAMPORTS).await;
    let quote = fixture.quote(RelayOperation::Enroll).await;
    for seed in [41, 42] {
        let owner = Keypair::new_from_array([seed; 32]);
        let step = fixture
            .prepare(&enrollment(&owner, vec![6, seed], quote.clone()))
            .await
            .expect("within the budget");
        let RelayStep::SignMessage { relay_id, message } = step else {
            panic!("the owner signs its enrollment, got {step:?}");
        };
        let _: RelayStatus = fixture
            .call(
                SUBMIT_RELAY,
                SubmitRelayRequest {
                    relay_id: relay_id.clone(),
                    signer: owner.pubkey().into(),
                    signature: owner.sign_message(&message.0).into(),
                },
            )
            .await;
        let status: RelayStatus = fixture
            .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
            .await;
        assert!(
            matches!(status, RelayStatus::Confirmed { .. }),
            "{status:?}"
        );
    }
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, (2 * ENROLLMENT_LAMPORTS) as i64);
    let next = Keypair::new_from_array([43; 32]);
    let refused = fixture
        .prepare(&enrollment(&next, vec![6, 43], quote))
        .await;
    assert!(refused_with(&refused, RelayError::Budget), "{refused:?}");
}

#[tokio::test]
async fn an_enrollment_never_signed_returns_its_whole_charge_past_the_window() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote))
        .await
        .expect("within the budget");
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);

    fixture
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    fixture
        .chain
        .slot
        .store(SLOT + ABANDONED_AFTER_SLOTS + 1, Ordering::Relaxed);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.committed().await, 0);
}

/// The named key signs what an owner signs on the other rails.
fn delegate_request(
    quote: RelayQuote,
    proof_inputs: &RelayProofInputs,
    signer: &Keypair,
) -> PrepareRelayRequest {
    let digest = proof_inputs
        .spp_proof_inputs(quote.fee_payer.0)
        .message_hash()
        .expect("message hash");
    PrepareRelayRequest {
        ring: proof_inputs.ring_program_id.into(),
        quote,
        intent: RelayIntent::Delegate {
            proof_inputs: ProofInputBytes::new(proof_inputs.encode().expect("encode")),
            delegate_signature: signer.sign_message(&digest).into(),
            token_account_setup: Vec::new(),
        },
        co_signers: Vec::new(),
    }
}

fn delegate_inputs(delegate: Address) -> RelayProofInputs {
    proof_inputs(
        RING,
        RelayRail::Delegate {
            delegate,
            plan: None,
        },
    )
}

#[tokio::test]
async fn a_delegate_frame_relays_under_the_delegates_signature() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let delegate = ring_delegate();
    let quote = fixture.quote(RelayOperation::Delegate).await;
    let request = delegate_request(quote, &delegate_inputs(delegate.pubkey()), &delegate);

    let step = fixture.prepare(&request).await.expect("the delegate relay");

    assert!(matches!(step, RelayStep::SignMessage { .. }), "{step:?}");
    assert!(fixture.sent().is_empty());
    assert_eq!(fixture.outstanding().await, 0);
    let connection = fixture.store.connection();
    let signer: Vec<u8> = connection
        .query_one(Statement::from_string(
            connection.get_database_backend(),
            "SELECT signer FROM relay_reservations".to_owned(),
        ))
        .await
        .expect("read")
        .expect("reservation")
        .try_get("", "signer")
        .expect("signer");
    assert_eq!(signer, delegate.pubkey().to_bytes());
}

#[tokio::test]
async fn an_unsigned_or_foreign_delegate_request_consumes_nothing() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let delegate = ring_delegate();
    let stranger = Keypair::new_from_array([52; 32]);
    let quote = fixture.quote(RelayOperation::Delegate).await;
    for (named, signer) in [
        (delegate.pubkey(), &stranger),
        (stranger.pubkey(), &stranger),
    ] {
        let request = delegate_request(quote.clone(), &delegate_inputs(named), signer);
        let refused = fixture.prepare(&request).await;
        assert!(
            refused_with(&refused, RelayError::DelegateSignature),
            "{refused:?}"
        );
    }
    assert!(fixture.prover.requests.lock().expect("requests").is_empty());
    assert!(fixture.sent().is_empty());
    assert_eq!(fixture.committed().await, 0);
}

/// The relay's fee payer funds the create, only a missing account costs rent and holds the tree fees.
#[tokio::test]
async fn token_account_setup_reserves_the_rent_of_a_missing_account() {
    let mint = Address::new_from_array([0x61; 32]);
    let token_owner = Address::new_from_array([0x62; 32]);
    for (budget, exists) in [(0, false), (0, true), (FRAME_BUDGET, false)] {
        let fixture = Fixture::with_budget(budget).await;
        let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
        let token_account = CreateAssociatedTokenAccount {
            payer: fixture.fee_payer,
            owner: token_owner,
            mint,
            token_program,
        }
        .address();
        if exists {
            fixture
                .chain
                .accounts
                .lock()
                .expect("accounts")
                .push(token_account);
        }
        let mut inputs = proof_inputs(RING, RelayRail::Confidential);
        inputs
            .external_data
            .interface_transfers
            .push(SettlementTransfer::Spl {
                mint,
                is_deposit: false,
                amount: 15,
                user_spl_token: token_account,
            });
        inputs
            .interface_transfer_accounts
            .push(TransactInterfaceTransferAccounts::SplWithdrawal(
                TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: spr_interface::pda::spl_interface(&mint),
                    user_token_account: token_account,
                    token_program,
                },
            ));
        let quote = fixture.quote(RelayOperation::Confidential).await;
        let mut request = signed_request(quote, &inputs);
        let RelayIntent::Confidential {
            token_account_setup,
            ..
        } = &mut request.intent
        else {
            panic!("a confidential request");
        };
        token_account_setup.push(TokenAccountSetup {
            mint: mint.into(),
            owner: token_owner.into(),
        });

        let prepared = fixture.prepare(&request).await;

        if budget == 0 && !exists {
            assert!(
                refused_with(&prepared, RelayError::BudgetUnset),
                "{prepared:?}"
            );
            assert!(fixture.sent().is_empty());
            continue;
        }
        let RelayStep::Submitted { relay_id } = prepared.expect("relayed") else {
            panic!("the owner signed");
        };
        let _: RelayStatus = fixture
            .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
            .await;
        assert_eq!(fixture.outstanding().await, 0);
        // A live account takes no create, an owner closing it later finds no rent to spend.
        assert_eq!(
            fixture.sent()[0].message.instructions().len(),
            if exists { 1 } else { 2 }
        );
        let fee = i64::from(fixture.sent()[0].message.header().num_required_signatures) * 5_000;
        let kept = if exists {
            0
        } else {
            RENT_LAMPORTS as i64 + TREE_FEES as i64 + fee
        };
        assert_eq!(fixture.committed().await, kept);
    }
}
