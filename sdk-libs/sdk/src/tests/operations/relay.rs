//! Relayed transfers against a stub Ring RPC.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_indexer_api::SerializablePubkey;
use spr_keypair::ShieldedKeypair;
use spr_program::instruction::{TransactInterfaceTransferAccounts, TransactSolTransferAccounts};
use spr_transaction::{instructions::transact::ConfidentialTransaction, Mint, SppProofOutputUtxo};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
    PrepareRelayRequest, RelayIntent, RelayProofInputs, RelayQuote, RelayStatus, RelayStep,
    SubmitRelayRequest, TokenAccountSetup,
};
use zolana_ring_keys::RingAddress;

use super::super::Assembled;
use crate::client::RingClient;
use crate::tests::{
    pipeline_rules,
    support::{keypair, ring, ring_utxo, Chain, Registry, RingSettings},
};
use crate::{
    AnonymousPayment, AnonymousTransfer, CustomRingTransfer, CustomRingTransferInput,
    RelayedTransferInput, RingError, RingRelay, RingTransfer, SealRow,
};

#[derive(Default)]
struct StubRelay {
    prepared: Mutex<Vec<PrepareRelayRequest>>,
    asks_signature: bool,
    /// What a relay that asks returns, a garbled message unset.
    message: Vec<u8>,
    submitted: Mutex<Vec<SubmitRelayRequest>>,
}

#[async_trait]
impl RingRelay for StubRelay {
    async fn get_relay_quote(
        &self,
        _request: GetRelayQuoteRequest,
    ) -> Result<RelayQuote, RingError> {
        unreachable!("the test holds its quote")
    }

    async fn prepare_relay(&self, request: PrepareRelayRequest) -> Result<RelayStep, RingError> {
        let relay_id = request.relay_id()?;
        self.prepared.lock().unwrap().push(request);
        Ok(match self.asks_signature {
            true => RelayStep::SignMessage {
                relay_id,
                message: match self.message.is_empty() {
                    true => vec![1].into(),
                    false => self.message.clone().into(),
                },
            },
            false => RelayStep::Submitted { relay_id },
        })
    }

    async fn prepare_authority_transfer(
        &self,
        _request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError> {
        unreachable!("the wallet names no delegate")
    }

    async fn submit_relay(&self, request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        let signature = request.signature;
        self.submitted.lock().unwrap().push(request);
        Ok(RelayStatus::Sent { signature })
    }

    async fn get_relay_status(
        &self,
        _request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError> {
        unreachable!("the test reads no status")
    }
}

/// Ring RPC stored the relay and sent it, the answer to the first prepare never arrived.
#[derive(Default)]
struct LostAnswer {
    prepared: Mutex<usize>,
}

#[async_trait]
impl RingRelay for LostAnswer {
    async fn get_relay_quote(
        &self,
        _request: GetRelayQuoteRequest,
    ) -> Result<RelayQuote, RingError> {
        unreachable!("the test holds its quote")
    }

    async fn prepare_relay(&self, _request: PrepareRelayRequest) -> Result<RelayStep, RingError> {
        *self.prepared.lock().unwrap() += 1;
        Err(RingError::RelayIdMismatch)
    }

    async fn prepare_authority_transfer(
        &self,
        _request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError> {
        unreachable!("the wallet names no delegate")
    }

    async fn submit_relay(&self, _request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        unreachable!("the relay asks no signature")
    }

    async fn get_relay_status(
        &self,
        _request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError> {
        Ok(RelayStatus::Sent {
            signature: spr_indexer_api::SerializableSignature(Default::default()),
        })
    }
}

const RELAY_FEE_PAYER: Address = Address::new_from_array([0x44; 32]);

fn anonymous_chain(sender: &ShieldedKeypair, recipient: &ShieldedKeypair) -> Chain {
    Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Anonymous)
    })
    .with_registry(
        Registry::new(&[(sender, 1), (recipient, 1)]),
        &pipeline_rules(),
    )
}

/// 4 of the sender's 10 to `recipient`, the 6 of change back to the sender.
fn anonymous_payment<'a>(
    sender: &'a ShieldedKeypair,
    recipient: &ShieldedKeypair,
) -> AnonymousTransfer<'a> {
    let transaction = ConfidentialTransaction::new_with_ring(
        vec![ring_utxo(sender, Mint::SOL, 10, 0)],
        RELAY_FEE_PAYER,
        ring().program_id(),
    )
    .unwrap();
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_anonymous_signer(&sender.signing_key)
    .with_payment(AnonymousPayment {
        to: RingAddress {
            recipient: recipient.shielded_address().unwrap(),
            ring_program_id: ring().program_id(),
            list_salt: [7; 32],
        },
        asset: Mint::SOL,
        amount: 4,
        reply: None,
        data: crate::NoteData::default(),
    })
    .unwrap()
}

fn relay_quote() -> RelayQuote {
    RelayQuote {
        fee_payer: SerializablePubkey(RELAY_FEE_PAYER),
        valid_until_slot: u64::MAX,
    }
}

#[tokio::test]
async fn an_anonymous_relay_sends_no_path_or_record_request_and_signs_the_message_hash() {
    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = RELAY_FEE_PAYER;
    let chain = anonymous_chain(&sender, &recipient);
    let transfer = anonymous_payment(&sender, &recipient);
    let quote = relay_quote();
    let relay = StubRelay::default();
    let relay_id = transfer
        .prepare_relay(&chain, quote)
        .await
        .unwrap()
        .sign()
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();

    assert!(chain.proof_requests.lock().unwrap().is_empty());
    assert!(chain.witness_requests.lock().unwrap().is_empty());
    assert!(chain.record_requests.lock().unwrap().is_empty());
    let request = {
        let prepared = relay.prepared.lock().unwrap();
        let [request] = prepared.as_slice() else {
            panic!("one prepareRelay call");
        };
        request.clone()
    };
    assert_eq!(request.relay_id().unwrap(), relay_id);
    let RelayIntent::Anonymous {
        proof_inputs,
        owner_signature,
        ..
    } = &request.intent
    else {
        panic!("the anonymous intent");
    };
    let sent = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
    let message_hash = sent.spp_proof_inputs(fee_payer).message_hash().unwrap();
    assert!(sender
        .signing_pubkey()
        .verify_message(&message_hash, owner_signature.0.as_array()));

    // A signature the wallet never expected has nothing to check against.
    let asking = StubRelay {
        asks_signature: true,
        ..StubRelay::default()
    };
    let crate::RelaySent::SignMessage(pending) = crate::PreparedRelay::new(request)
        .send(&asking)
        .await
        .unwrap()
    else {
        panic!("the relay asks a signature");
    };
    assert!(matches!(
        pending.verify(Address::new_from_array(
            sender.signing_pubkey().as_ed25519().unwrap()
        )),
        Err(RingError::RelayMessage(crate::MessageMismatch::Unrequested))
    ));
}

#[tokio::test]
async fn a_confidential_relay_carries_its_token_account_setup() {
    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let mut transaction = ConfidentialTransaction::new_with_ring(
        vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
        fee_payer,
        ring().program_id(),
    )
    .unwrap();
    transaction
        .transfer_sol(&recipient.shielded_address().unwrap(), 4)
        .unwrap();
    let setup = vec![TokenAccountSetup {
        owner: SerializablePubkey(Address::new_from_array([0x55; 32])),
        mint: SerializablePubkey(Address::new_from_array([0x66; 32])),
    }];
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_in_proof_owner(&sender.signing_key)
    .with_token_account_setup(setup.clone());
    let quote = RelayQuote {
        fee_payer: SerializablePubkey(fee_payer),
        valid_until_slot: u64::MAX,
    };

    let relay = StubRelay::default();
    transfer
        .prepare_relay(&chain, quote)
        .await
        .unwrap()
        .sign()
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();

    let prepared = relay.prepared.lock().unwrap();
    let [PrepareRelayRequest {
        intent:
            RelayIntent::Confidential {
                token_account_setup,
                ..
            },
        ..
    }] = prepared.as_slice()
    else {
        panic!("one confidential prepareRelay call");
    };
    assert_eq!(token_account_setup, &setup);
}

/// What a relay rebuilds from the wallet's request, its proof inputs and the frame it assembles.
async fn relay_round_trip(
    client: &RingClient<Chain, Chain>,
    transfer: &CustomRingTransfer<'_>,
    fee_payer: Address,
) -> (RelayProofInputs, Assembled) {
    let (inputs, assembled) = relay_attempt(client, transfer, fee_payer).await;
    (inputs, assembled.unwrap())
}

/// The relay's assembly of the wallet's seal, a refusal left for the caller to read.
async fn relay_attempt(
    client: &RingClient<Chain, Chain>,
    transfer: &CustomRingTransfer<'_>,
    fee_payer: Address,
) -> (RelayProofInputs, Result<Assembled, RingError>) {
    let relay = StubRelay::default();
    transfer
        .prepare_relay(
            client.zolana(),
            RelayQuote {
                fee_payer: SerializablePubkey(fee_payer),
                valid_until_slot: u64::MAX,
            },
        )
        .await
        .unwrap()
        .sign()
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();
    let (inputs, signature) = {
        let prepared = relay.prepared.lock().unwrap();
        let [PrepareRelayRequest {
            intent:
                RelayIntent::Confidential {
                    proof_inputs,
                    owner_signature,
                    ..
                },
            ..
        }] = prepared.as_slice()
        else {
            panic!("one confidential prepareRelay call");
        };
        (
            RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap(),
            owner_signature.0,
        )
    };
    let assembled = RingTransfer::relayed(RelayedTransferInput {
        ring: ring(),
        proof_inputs: &inputs,
        fee_payer,
    })
    .with_owner_signature(signature.into())
    .assemble(client)
    .await;
    (inputs, assembled)
}

/// A frame at its shape's limit, one ring data hash on every slot, every leg paying its own owner.
struct FullLoad {
    sender: ShieldedKeypair,
    recipients: Vec<ShieldedKeypair>,
    destinations: Vec<ShieldedKeypair>,
    notes: u64,
}

const FULL_LOAD_PAYER: Address = Address::new_from_array([0x44; 32]);

impl FullLoad {
    fn new(notes: u64, outputs: u8, legs: u8) -> Self {
        Self {
            sender: keypair(1),
            recipients: (0..outputs).map(|slot| keypair(10 + slot)).collect(),
            destinations: (0..legs).map(|leg| keypair(40 + leg)).collect(),
            notes,
        }
    }

    fn everyone(&self) -> impl Iterator<Item = &ShieldedKeypair> {
        core::iter::once(&self.sender)
            .chain(&self.recipients)
            .chain(&self.destinations)
    }

    fn registry(&self) -> Registry {
        let owners: Vec<(&ShieldedKeypair, u64)> =
            self.everyone().map(|owner| (owner, 1)).collect();
        Registry::new(&owners)
    }

    fn transfer(&self) -> CustomRingTransfer<'_> {
        let utxos = (0..self.notes)
            .map(|leaf| ring_utxo(&self.sender, Mint::SOL, 100, leaf))
            .collect();
        let mut transaction =
            ConfidentialTransaction::new_with_ring(utxos, FULL_LOAD_PAYER, ring().program_id())
                .unwrap();
        let paid = (self.recipients.len() - 1 + self.destinations.len()) as u64;
        for (slot, recipient) in self.recipients.iter().enumerate() {
            transaction
                .add_output_utxo(SppProofOutputUtxo {
                    owner_address: Some(recipient.shielded_address().unwrap()),
                    asset: Mint::SOL,
                    amount: match slot {
                        0 => self.notes * 100 - paid,
                        _ => 1,
                    },
                    ring_program_id: Some(ring().program_id()),
                    ring_data_hash: Some([3; 32]),
                    ..Default::default()
                })
                .unwrap();
        }
        let accounts = self
            .destinations
            .iter()
            .map(|destination| {
                let recipient = destination
                    .shielded_address()
                    .unwrap()
                    .solana_address()
                    .unwrap();
                transaction.withdraw_sol(1, recipient).unwrap();
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient })
            })
            .collect();
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(accounts)
        .with_in_proof_owner(&self.sender.signing_key)
    }
}

/// With no salted list the wallet's counts are all selection reads.
#[tokio::test]
async fn relay_and_submission_pick_one_key_at_full_load() {
    for (notes, outputs, legs, wide) in [
        (24, 2, 4, false),
        (24, 4, 4, false),
        (2, 8, 4, false),
        (2, 8, 5, true),
    ] {
        let load = FullLoad::new(notes, outputs, legs);
        let client = Chain::ring(RingSettings {
            has_policy: true,
            ..RingSettings::new(RingMode::Confidential)
        })
        .with_registry(load.registry(), &pipeline_rules())
        .client();
        let transfer = load.transfer();
        let (inputs, relayed) = relay_round_trip(&client, &transfer, FULL_LOAD_PAYER).await;
        let submitted = transfer.frame(&client).await.unwrap();
        let shape = (notes, outputs);
        assert_eq!(inputs.wide_owners, wide, "{shape:?}");
        assert_eq!(relayed.frame.parts.wide_owners, wide, "{shape:?}");
        assert_eq!(submitted.frame.parts.wide_owners, wide, "{shape:?}");
    }
}

/// Past the narrow row's tracking only if every destination holds a row, a read the wallet cannot make.
#[tokio::test]
async fn a_salted_read_raises_the_flag_on_a_frame_of_one_stream() {
    use custom_ring_interface::domain;
    use zolana_ring_policy::{ListId, Member, Rule, RuleTable, Subject};

    let salt = [7; 32];
    let load = FullLoad::new(5, 8, 4);
    let rules = RuleTable::builder()
        .rule(Rule::forbid(Subject::Sender, ListId::PrivateBlock))
        .build();
    let addresses: Vec<_> = load
        .everyone()
        .map(|owner| owner.shielded_address().unwrap())
        .collect();
    let client = Chain::ring(RingSettings::new(RingMode::Confidential))
        .with_registry(load.registry(), &rules)
        .with_tracking_tag(&addresses, domain::list_tag(&salt).unwrap())
        .client();
    let transfer = addresses.iter().fold(load.transfer(), |transfer, address| {
        let member =
            Member::from_bytes(address.signing_pubkey.owner_proof_input_hash().unwrap()).unwrap();
        transfer.with_list_salt(member, salt)
    });
    let (inputs, relayed) = relay_round_trip(&client, &transfer, FULL_LOAD_PAYER).await;
    let submitted = transfer.frame(&client).await.unwrap();
    assert!(!inputs.wide_owners);
    assert!(relayed.frame.parts.wide_owners);
    assert!(submitted.frame.parts.wide_owners);
    assert_eq!(
        relayed.frame.policy.circuit(),
        submitted.frame.policy.circuit()
    );
    // The relay proves the owner's signed auditor message as sealed.
    assert_eq!(
        relayed.frame.proof_inputs.external_data.messages.last(),
        inputs.external_data.messages.last()
    );
}

/// The exact approval opening spans `N` and binds the seal to its row.
#[tokio::test]
async fn a_salted_read_of_another_stream_refuses_until_the_owner_reseals() {
    use custom_ring_interface::domain;
    use zolana_ring_policy::{ListId, Member, Rule, RuleTable, Subject};

    let salt = [7; 32];
    let load = FullLoad::new(24, 2, 4);
    let rules = RuleTable::builder()
        .rule(Rule::forbid(Subject::Sender, ListId::PrivateBlock))
        .build();
    let addresses: Vec<_> = load
        .everyone()
        .map(|owner| owner.shielded_address().unwrap())
        .collect();
    let client = Chain::ring(RingSettings::new(RingMode::Confidential))
        .with_registry(load.registry(), &rules)
        .with_tracking_tag(&addresses, domain::list_tag(&salt).unwrap())
        .client();
    let transfer = addresses.iter().fold(
        load.transfer().with_exact_approval(),
        |transfer, address| {
            let member =
                Member::from_bytes(address.signing_pubkey.owner_proof_input_hash().unwrap())
                    .unwrap();
            transfer.with_list_salt(member, salt)
        },
    );
    let (inputs, refused) = relay_attempt(&client, &transfer, FULL_LOAD_PAYER).await;
    assert!(!inputs.wide_owners);
    let Err(RingError::ResealRequired { row }) = refused else {
        panic!("the relay refuses a seal its read moves");
    };
    assert_eq!(row, SealRow::Wide);

    let resealed = transfer.with_seal_row(row);
    let (inputs, relayed) = relay_round_trip(&client, &resealed, FULL_LOAD_PAYER).await;
    let submitted = resealed.frame(&client).await.unwrap();
    assert!(inputs.wide_owners);
    assert!(submitted.frame.parts.wide_owners);
    assert_eq!(
        relayed.frame.policy.circuit(),
        submitted.frame.policy.circuit()
    );
}

/// A policy entry past two outputs stays on its own key, the wide entry key takes two outputs alone.
#[tokio::test]
async fn an_unread_entry_takes_its_capacity_from_its_outputs() {
    use crate::tests::support::{payer, wallet, TREE_ID};
    use spr_transaction::{Data, Utxo};

    for (notes, outputs) in [(6, 4), (2, 8), (4, 8)] {
        // The hidden owner's change takes the first output.
        let load = FullLoad::new(notes, outputs - 1, 0);
        let client = Chain::ring(RingSettings {
            has_policy: true,
            ..RingSettings::new(RingMode::Anonymous)
        })
        .with_registry(load.registry(), &pipeline_rules())
        .client();
        let utxos = (0..notes)
            .map(|leaf| {
                wallet(
                    Utxo {
                        owner: load.sender.signing_pubkey(),
                        asset: Mint::SOL,
                        amount: 100,
                        blinding: spr_keypair::random_blinding(),
                        ring_program_id: None,
                        data: Data::default(),
                    },
                    &load.sender.nullifier_key,
                    TREE_ID,
                    leaf,
                )
            })
            .collect();
        let transaction =
            ConfidentialTransaction::new_with_ring(utxos, payer(), ring().program_id()).unwrap();
        let transfer = load.recipients.iter().fold(
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender: &load.sender,
                nullifier_key: Some(&load.sender.nullifier_key),
                transaction,
            })
            .with_anonymous_signer(&load.sender.signing_key),
            |transfer, recipient| {
                transfer
                    .with_payment(public_signers::pay(recipient, 1))
                    .unwrap()
            },
        );
        let sealed = transfer.seal_unread(client.zolana()).await.unwrap();
        assert!(!sealed.policy.key.wide, "{notes}x{outputs}");
        let submitted = transfer.frame(&client).await.unwrap();
        assert!(!submitted.frame.parts.wide_owners, "{notes}x{outputs}");
        assert!(submitted.frame.parts.entry, "{notes}x{outputs}");
    }
}

/// The Go golden test solves the relayed tail.
#[tokio::test]
async fn a_relayed_spend_proves_on_the_key_its_owner_sealed() {
    use custom_ring_interface::key_catalog::RingCircuit;

    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&recipient, 1)]),
        &pipeline_rules(),
    )
    .client();
    let relayed = |notes: u64, data: Option<[u8; 32]>| {
        let client = &client;
        let (sender, recipient) = (&sender, &recipient);
        async move {
            let utxos = (0..notes)
                .map(|leaf| ring_utxo(sender, Mint::SOL, 1, leaf))
                .collect();
            let mut transaction =
                ConfidentialTransaction::new_with_ring(utxos, fee_payer, ring().program_id())
                    .unwrap();
            transaction
                .add_output_utxo(SppProofOutputUtxo {
                    owner_address: Some(recipient.shielded_address().unwrap()),
                    asset: Mint::SOL,
                    amount: notes,
                    ring_program_id: Some(ring().program_id()),
                    ring_data_hash: data,
                    ..Default::default()
                })
                .unwrap();
            let transfer = CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
            .with_in_proof_owner(&sender.signing_key);
            let (inputs, assembled) = relay_round_trip(client, &transfer, fee_payer).await;
            assert_eq!(assembled.frame.parts.wide_owners, inputs.wide_owners);
            let request = assembled.request().unwrap();
            let body = serde_json::to_value(
                crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
            )
            .unwrap();
            (inputs.wide_owners, request.circuit, body)
        }
    };
    let shape = |circuit| match circuit {
        RingCircuit::Transfer {
            outputs,
            inputs,
            wide,
            ..
        } => (outputs, inputs, wide),
        _ => panic!("a transfer key"),
    };

    let (wide, circuit, _) = relayed(2, None).await;
    assert_eq!((wide, shape(circuit)), (false, (2, 24, false)));
    let (wide, circuit, _) = relayed(25, None).await;
    assert_eq!((wide, shape(circuit)), (true, (2, 40, true)));
    let (wide, circuit, _) = relayed(2, Some([3; 32])).await;
    assert_eq!((wide, shape(circuit)), (false, (2, 24, false)));
    let (wide, circuit, built) = relayed(25, Some([3; 32])).await;
    assert_eq!((wide, shape(circuit)), (true, (2, 40, true)));

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-transfer-relayed-wide-data.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    assert!(path.exists());
}

/// Each published slot's record, opened under the transaction key and the key it seals to.
fn opened_records(
    data: &custom_ring_interface::RingTransactData<'_>,
    opened: &zolana_ring_client::OpenedAudit,
) -> Vec<custom_ring_interface::OutputRecord> {
    let tx_key = &opened.tx_viewing_key;
    let keys = opened.recipient_keys(data.recipient_keys).unwrap();
    let first_nullifier = data.first_nullifier().unwrap();
    data.outputs
        .iter()
        .zip(keys)
        .zip(0u32..)
        .map(|((output, key), slot)| {
            let secret = custom_ring_interface::stream::DeliveredSlot {
                agreement: &tx_key.ecdh(&key).unwrap(),
                tx_viewing_pk: tx_key.pubkey().as_bytes(),
                recipient_viewing_pk: key.as_bytes(),
                salt: data.salt,
                output_index: slot,
                first_nullifier,
            }
            .secret()
            .unwrap();
            zolana_ring_transaction::open_recipient_body(output.record, &secret)
                .unwrap()
                .record
        })
        .collect()
}

mod delegate_message {
    //! The transfer a delegate signs, refused when it pays an unnamed owner or charges the delegate.

    use std::sync::Mutex;

    use custom_ring_interface::{
        compute_unit_limit, tag, InstructionTag, RingRail, RingTransactData,
    };
    use solana_instruction::Instruction;
    use solana_signer::Signer;
    use spr_indexer_api::{Base64String, SerializableSignature};
    use spr_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey};
    use spr_transaction::{AssetRegistry, WalletUtxo};
    use zolana_ring_client::rpc::{
        AuthorityPayment, AuthorityTransfer, AuthorityWithdrawal, SerializableShieldedAddress,
        TxViewingSecret,
    };

    use super::*;
    use crate::{
        delegate_source::tests::allowed_as_pinned,
        relay_message::ExpectedDelegate,
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        AllowedNullifiers, CoOwner, CustomRingConfig, DelegateMove, DelegateOutput,
        DelegatePayment, DelegateSource, DelegateSourceError, DelegateWithdrawal, MessageMismatch,
        RelaySent, RelayedTransferInput, RequestedAuthorityTransfer, ResolvedSource, RingTransfer,
        SourceEnrollment,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::AuthorityTransfer);
    const MOVED: u64 = 4;
    const USDC: Mint = Mint {
        asset: Address::new_from_array([0x31; 32]),
        asset_id: 2,
    };
    const EURC: Mint = Mint {
        asset: Address::new_from_array([0x32; 32]),
        asset_id: 3,
    };

    #[derive(Clone, Copy)]
    enum Answer {
        Honest,
        SwappedRecipient,
        DelegateWritable,
        ExtraSystemTransfer,
        DelegatePaysFee,
    }

    impl Answer {
        const ALL: [Self; 5] = [
            Self::Honest,
            Self::SwappedRecipient,
            Self::DelegateWritable,
            Self::ExtraSystemTransfer,
            Self::DelegatePaysFee,
        ];

        /// Fixed here, never read back from the check.
        fn case(self) -> (&'static str, &'static str) {
            match self {
                Self::Honest => ("honest", "Accepted"),
                Self::SwappedRecipient => ("swappedRecipient", "Recipients"),
                Self::DelegateWritable => ("delegateWritable", "Accounts"),
                Self::ExtraSystemTransfer => ("extraSystemTransfer", "Instructions"),
                Self::DelegatePaysFee => ("delegatePaysFee", "FeePayer"),
            }
        }

        fn message(self, honest: &Instruction, delegate: Address) -> Base64String {
            let stranger = stranger();
            let send = |instruction: Instruction| relay_message(&FEE_PAYER, &[instruction], UNITS);
            match self {
                Self::Honest => send(honest.clone()),
                Self::SwappedRecipient => send(paying(honest, 0, stranger)),
                Self::DelegateWritable => {
                    let mut widened = honest.clone();
                    widened
                        .accounts
                        .iter_mut()
                        .filter(|meta| meta.pubkey == delegate)
                        .for_each(|meta| meta.is_writable = true);
                    send(widened)
                }
                Self::ExtraSystemTransfer => relay_message(
                    &FEE_PAYER,
                    &[
                        honest.clone(),
                        solana_system_interface::instruction::transfer(
                            &delegate,
                            &Address::new_from_array([0x63; 32]),
                            1_000,
                        ),
                    ],
                    UNITS,
                ),
                Self::DelegatePaysFee => {
                    relay_message(&delegate, std::slice::from_ref(honest), UNITS)
                }
            }
        }
    }

    fn stranger() -> [u8; 32] {
        keypair(3)
            .shielded_address()
            .unwrap()
            .signing_pubkey
            .owner_proof_input_hash()
            .unwrap()
    }

    fn rewritten(
        honest: &Instruction,
        rail: RingRail,
        change: impl for<'a> FnOnce(&mut custom_ring_interface::RingTransactData<'a>),
    ) -> Instruction {
        let parsed = RingTransactData::parse(&honest.data[1..], rail).unwrap();
        let mut data = parsed.into_data();
        change(&mut data);
        Instruction {
            data: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
            ..honest.clone()
        }
    }

    /// The honest data with output `slot` published under `owner_tag`.
    fn paying(honest: &Instruction, slot: usize, owner_tag: [u8; 32]) -> Instruction {
        let parsed = RingTransactData::parse(&honest.data[1..], RingRail::Delegate).unwrap();
        let mut data = parsed.into_data();
        data.outputs[slot].owner_tag = custom_ring_interface::stream::slot_tag(owner_tag);
        Instruction {
            data: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
            ..honest.clone()
        }
    }

    /// Ring RPC's authority transfer path without its proof, answering with one `Answer`.
    struct DelegateRelay {
        client: crate::RingClient<Chain, Chain>,
        /// Every member with the notes the service opened for it.
        members: Vec<(ShieldedKeypair, Vec<WalletUtxo>)>,
        delegate: Address,
        answer: Answer,
        honest: Mutex<Option<Instruction>>,
        submitted: Mutex<Vec<SubmitRelayRequest>>,
    }

    impl DelegateRelay {
        fn new(answer: Answer, delegate: Address) -> Self {
            Self::on_mode(answer, delegate, RingMode::Confidential)
        }

        fn on_mode(answer: Answer, delegate: Address, mode: RingMode) -> Self {
            let member = keypair(1);
            let own = keypair(7);
            let other = keypair(3);
            let chain = Chain::ring(RingSettings {
                has_policy: true,
                delegate: Some(delegate),
                ..RingSettings::new(mode)
            })
            .with_registry(
                Registry::new(&[(&member, 1), (&keypair(2), 1), (&other, 1), (&own, 1)]),
                &pipeline_rules(),
            );
            Self {
                client: chain.client(),
                members: vec![
                    (member.clone(), vec![ring_utxo(&member, Mint::SOL, 10, 0)]),
                    (other.clone(), vec![ring_utxo(&other, Mint::SOL, 10, 1)]),
                    (own.clone(), vec![ring_utxo(&own, Mint::SOL, 10, 2)]),
                ],
                delegate,
                answer,
                honest: Mutex::new(None),
                submitted: Mutex::new(Vec::new()),
            }
        }

        /// `seal_delegate` then `prove` as `SdkRelayProver` runs them, the proofs zeroed.
        async fn build(
            &self,
            transfer: &AuthorityTransfer,
            tx_viewing_key: &TxViewingSecret,
        ) -> Result<Instruction, RingError> {
            let proof_inputs = self.seal(transfer, tx_viewing_key).await?;
            let assembled = RingTransfer::relayed(RelayedTransferInput {
                ring: ring(),
                proof_inputs: &proof_inputs,
                fee_payer: FEE_PAYER,
            })
            .assemble(&self.client)
            .await?;
            let frame = &assembled.frame;
            frame
                .accounts
                .instruction(frame.ring, &assembled.config, &frame.parts)
        }

        async fn settlement_frame(
            &self,
            transfer: &AuthorityTransfer,
            tx_viewing_key: &TxViewingSecret,
        ) -> Result<Instruction, RingError> {
            let proof_inputs = self.seal(transfer, tx_viewing_key).await?;
            let transfer = RingTransfer::relayed(RelayedTransferInput {
                ring: ring(),
                proof_inputs: &proof_inputs,
                fee_payer: FEE_PAYER,
            });
            let framed = transfer.frame(&self.client).await?;
            let frame = &framed.frame;
            frame
                .accounts
                .instruction(frame.ring, framed.config.account(), &frame.parts)
        }

        async fn seal(
            &self,
            transfer: &AuthorityTransfer,
            tx_viewing_key: &TxViewingSecret,
        ) -> Result<RelayProofInputs, RingError> {
            let mut assets = AssetRegistry::default();
            assets.insert(USDC.asset_id, USDC.asset).unwrap();
            assets.insert(EURC.asset_id, EURC.asset).unwrap();
            DelegateMove {
                exits: transfer.exits.iter().copied().map(Into::into).collect(),
                withdrawals: transfer
                    .withdrawals
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect(),
                ring: ring(),
                delegate: self.delegate,
                payer: FEE_PAYER,
                sources: transfer
                    .sources
                    .iter()
                    .map(|source| {
                        let (member, notes) = self
                            .members
                            .iter()
                            .find(|(member, _)| member.shielded_address().unwrap() == source.0)
                            .unwrap();
                        DelegateSource {
                            address: source.0,
                            nullifier_key: &member.nullifier_key,
                            utxos: notes,
                        }
                    })
                    .collect(),
                payments: transfer
                    .payments
                    .iter()
                    .map(|payment| DelegatePayment {
                        recipient: payment.recipient.0,
                        mint: payment.mint.0,
                        amount: payment.amount,
                    })
                    .collect(),
                assets: &assets,
                tx_viewing_key: tx_viewing_key.key()?,
            }
            .select(&self.client)
            .await?
            .relay_proof_inputs(self.client.zolana())
            .await
        }

        /// A move the request never named, built on the member's note.
        async fn moved(
            &self,
            tx_viewing_key: &TxViewingSecret,
            shape: spr_client::Shape,
            change: impl FnOnce(crate::DelegateTransfer<'_>) -> crate::DelegateTransfer<'_>,
        ) -> Instruction {
            let assets = AssetRegistry::default();
            let (member, notes) = &self.members[0];
            let source = member.shielded_address().unwrap();
            let transfer = change(
                crate::DelegateTransfer::new(crate::DelegateTransferInput {
                    ring: ring(),
                    delegate: self.delegate,
                    payer: FEE_PAYER,
                    source,
                    source_nullifier_key: &member.nullifier_key,
                    inputs: notes.clone(),
                    outputs: Vec::new(),
                })
                .with_assets(&assets)
                .with_tx_viewing_key(tx_viewing_key.key().unwrap())
                .with_shape(shape)
                .unwrap(),
            );
            // The exit keys are absent from the catalog here, the frame needs no witness.
            let framed = transfer.frame(&self.client).await.ok().unwrap();
            let frame = &framed.frame;
            frame
                .accounts
                .instruction(frame.ring, framed.config.account(), &frame.parts)
                .unwrap()
        }
    }

    /// Each member's escrowed key as the delegate reads it, the move's own notes stay the test's.
    struct Escrow<'a>(&'a [(ShieldedKeypair, Vec<WalletUtxo>)]);

    #[async_trait]
    impl SourceEnrollment for Escrow<'_> {
        type Error = DelegateSourceError;

        async fn escrowed_key(
            &self,
            source: &ShieldedAddress,
        ) -> Result<Option<spr_keypair::NullifierKey>, DelegateSourceError> {
            Ok(self
                .0
                .iter()
                .find(|(member, _)| member.shielded_address().unwrap() == *source)
                .map(|(member, _)| member.nullifier_key.clone()))
        }
    }

    impl DelegateRelay {
        async fn allowed(&self, transfer: &AuthorityTransfer) -> AllowedNullifiers {
            let mut allowed = AllowedNullifiers::default();
            for source in &transfer.sources {
                let resolved = ResolvedSource::resolve(source.0, &Escrow(&self.members))
                    .await
                    .unwrap();
                let (_, notes) = self
                    .members
                    .iter()
                    .find(|(member, _)| member.shielded_address().unwrap() == source.0)
                    .unwrap();
                allowed.admit(&resolved, notes).unwrap();
            }
            allowed
        }

        async fn expected(
            &self,
            asked: &PrepareAuthorityTransferRequest,
            config: &CustomRingConfig,
        ) -> ExpectedDelegate {
            ExpectedDelegate::new(&RequestedAuthorityTransfer {
                request: asked.clone(),
                quote: &quote(),
                config,
                allowed: self.allowed(&asked.transfer).await,
            })
            .unwrap()
        }

        /// `victim`'s note funds the requested payment and its change returns to `source`, every
        /// output exactly as asked.
        async fn victim_funded(
            &self,
            asked: &PrepareAuthorityTransferRequest,
            source: &ShieldedKeypair,
            victim: &ShieldedKeypair,
        ) -> Instruction {
            let assets = AssetRegistry::default();
            let (_, notes) = self
                .members
                .iter()
                .find(|(member, _)| member.pubkey() == victim.pubkey())
                .unwrap();
            let payment = &asked.transfer.payments[0];
            let source_address = source.shielded_address().unwrap();
            let transfer = crate::DelegateTransfer::new(crate::DelegateTransferInput {
                ring: ring(),
                delegate: self.delegate,
                payer: FEE_PAYER,
                source: source_address,
                source_nullifier_key: &source.nullifier_key,
                inputs: notes.clone(),
                outputs: vec![
                    DelegateOutput {
                        recipient: payment.recipient.0,
                        asset: payment.mint.0,
                        amount: payment.amount,
                    },
                    DelegateOutput {
                        recipient: source_address,
                        asset: payment.mint.0,
                        amount: 10 - payment.amount,
                    },
                ],
            })
            .with_co_source(CoOwner {
                owner: victim.pubkey(),
                nullifier_key: &victim.nullifier_key,
            })
            .with_assets(&assets)
            .with_tx_viewing_key(asked.tx_viewing_key.key().unwrap());
            let framed = transfer.frame(&self.client).await.ok().unwrap();
            let frame = &framed.frame;
            frame
                .accounts
                .instruction(frame.ring, framed.config.account(), &frame.parts)
                .unwrap()
        }
    }

    #[async_trait]
    impl RingRelay for DelegateRelay {
        async fn get_relay_quote(
            &self,
            _request: GetRelayQuoteRequest,
        ) -> Result<RelayQuote, RingError> {
            unreachable!("the test holds its quote")
        }

        async fn prepare_relay(
            &self,
            _request: PrepareRelayRequest,
        ) -> Result<RelayStep, RingError> {
            unreachable!("the delegate prepares an authority transfer")
        }

        async fn prepare_authority_transfer(
            &self,
            request: PrepareAuthorityTransferRequest,
        ) -> Result<RelayStep, RingError> {
            let honest = self
                .build(&request.transfer, &request.tx_viewing_key)
                .await?;
            let message = self.answer.message(&honest, self.delegate);
            *self.honest.lock().unwrap() = Some(honest);
            Ok(RelayStep::SignMessage {
                relay_id: request.relay_id()?,
                message,
            })
        }

        async fn submit_relay(
            &self,
            request: SubmitRelayRequest,
        ) -> Result<RelayStatus, RingError> {
            let signature = request.signature;
            self.submitted.lock().unwrap().push(request);
            Ok(RelayStatus::Sent { signature })
        }

        async fn get_relay_status(
            &self,
            _request: GetRelayStatusRequest,
        ) -> Result<RelayStatus, RingError> {
            unreachable!("the test reads no status")
        }
    }

    fn quote() -> RelayQuote {
        RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: 0,
        }
    }

    /// The delegate's signature over the request is Ring RPC's to check, the message check reads none.
    fn request(delegate: Address) -> PrepareAuthorityTransferRequest {
        PrepareAuthorityTransferRequest {
            ring: SerializablePubkey(ring().program_id()),
            delegate: SerializablePubkey(delegate),
            transfer: AuthorityTransfer {
                exits: Vec::new(),
                withdrawals: Vec::new(),
                sources: vec![SerializableShieldedAddress(
                    keypair(1).shielded_address().unwrap(),
                )],
                payments: vec![AuthorityPayment {
                    recipient: SerializableShieldedAddress(keypair(2).shielded_address().unwrap()),
                    mint: SerializablePubkey(Mint::SOL.asset),
                    amount: MOVED,
                }],
            },
            tx_viewing_key: TxViewingSecret::from(&ViewingKey::from_bytes(&[9; 32])),
            timestamp: 0,
            nonce: Base64String(vec![4; 32]),
            signature: SerializableSignature(Default::default()),
        }
    }

    async fn relayed_signature(answer: Answer) -> (DelegateRelay, Result<RelayStatus, RingError>) {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(answer, delegate.pubkey());
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let asked = request(delegate.pubkey());
        let prepared = RequestedAuthorityTransfer {
            allowed: relay.allowed(&asked.transfer).await,
            request: asked,
            quote: &quote(),
            config: &config,
        }
        .prepare()
        .unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the delegate signs the move");
        };
        let signed = pending.sign(&relay, &delegate).await;
        (relay, signed)
    }

    #[tokio::test]
    async fn a_delegate_message_with_a_swapped_recipient_is_refused() {
        let (relay, signed) = relayed_signature(Answer::SwappedRecipient).await;
        assert!(matches!(
            signed,
            Err(RingError::RelayMessage(MessageMismatch::Recipients))
        ));
        assert!(relay.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_authority_transfer_the_relay_builds_is_signed() {
        let (relay, signed) = relayed_signature(Answer::Honest).await;
        signed.unwrap();
        let honest = relay.honest.lock().unwrap().clone().unwrap();
        let message = Answer::Honest.message(&honest, relay.delegate);
        let submitted = relay.submitted.lock().unwrap();
        let [submitted] = submitted.as_slice() else {
            panic!("one signature");
        };
        assert_eq!(submitted.signer.0, relay.delegate);
        assert!(submitted
            .signature
            .0
            .verify(relay.delegate.as_ref(), &message.0));
    }

    fn thief() -> ShieldedAddress {
        keypair(3).shielded_address().unwrap()
    }

    fn payee() -> ShieldedAddress {
        keypair(2).shielded_address().unwrap()
    }

    /// The frame keeps the payee's tag while its note pays another owner.
    async fn thief_under_payee_tag(
        relay: &DelegateRelay,
        asked: &PrepareAuthorityTransferRequest,
    ) -> Instruction {
        let mut stolen = asked.transfer.clone();
        stolen.payments[0].recipient = SerializableShieldedAddress(thief());
        let frame = relay.build(&stolen, &asked.tx_viewing_key).await.unwrap();
        match RingTransactData::parse(&frame.data[1..], RingRail::Delegate) {
            Ok(_) => paying(&frame, 0, payee().viewing_pubkey.u()),
            Err(_) => frame,
        }
    }

    /// Each slot's owner in frame order, opened under the request's transaction key.
    fn slot_owners(
        frame: &Instruction,
        rail: RingRail,
        expected: &ExpectedDelegate,
    ) -> Vec<[u8; 32]> {
        let parsed = RingTransactData::parse(&frame.data[1..], rail).unwrap();
        let data = parsed.data();
        let opened = zolana_ring_client::AuditEnvelope {
            eph_u: *data.tx_viewing_u,
            salt: data.salt,
            ciphertext: data.envelope,
        }
        .open_sealed(
            &expected.tx_viewing_key.key().unwrap(),
            &expected.auditor,
            parsed.audit_stream(),
        )
        .unwrap();
        opened_records(data, &opened)
            .into_iter()
            .map(|record| record.owner_key)
            .collect()
    }

    /// An unproved tag binds nothing, the proven records name every owner, mint and amount.
    #[tokio::test]
    async fn a_delegate_signs_only_the_move_the_proven_records_show_on_both_rails() {
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let delegate = keypair(7);
            let relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let asked = request(delegate.pubkey());
            let config = ring().require_config(relay.client.zolana()).await.unwrap();
            let expected = relay.expected(&asked, &config).await;
            let verdict_of = |frame: Instruction| {
                expected
                    .check(&relay_message(&FEE_PAYER, &[frame], UNITS).0)
                    .map(drop)
            };
            let build = |transfer: AuthorityTransfer, key: TxViewingSecret| {
                let relay = &relay;
                async move { relay.build(&transfer, &key).await.unwrap() }
            };

            let honest = build(asked.transfer.clone(), asked.tx_viewing_key.clone()).await;
            assert_eq!(verdict_of(honest.clone()), Ok(()), "{mode:?}");
            let source = keypair(1).shielded_address().unwrap();
            let owner =
                |address: ShieldedAddress| address.signing_pubkey.confidential_view_tag().unwrap();
            let order = match mode {
                RingMode::Confidential => [owner(payee()), owner(source)],
                RingMode::Anonymous => [owner(source), owner(payee())],
            };
            assert_eq!(
                slot_owners(&honest, expected.rail, &expected)[..2],
                order,
                "{mode:?}"
            );

            assert_eq!(
                verdict_of(thief_under_payee_tag(&relay, &asked).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut more = asked.transfer.clone();
            more.payments[0].amount = MOVED + 1;
            assert_eq!(
                verdict_of(build(more, asked.tx_viewing_key.clone()).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut extra = asked.transfer.clone();
            extra.payments.push(AuthorityPayment {
                recipient: SerializableShieldedAddress(thief()),
                mint: SerializablePubkey(Mint::SOL.asset),
                amount: 1,
            });
            assert_eq!(
                verdict_of(build(extra, asked.tx_viewing_key.clone()).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut other_mint = asked.clone();
            other_mint.transfer.payments[0].mint = SerializablePubkey(USDC.asset);
            assert_eq!(
                relay
                    .expected(&other_mint, &config)
                    .await
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&honest), UNITS).0)
                    .map(drop),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let parsed = RingTransactData::parse(&honest.data[1..], expected.rail).unwrap();
            let shape = spr_client::Shape::new(
                usize::from(parsed.data().n_in),
                usize::from(parsed.data().n_out),
            );
            let exit = relay
                .moved(&asked.tx_viewing_key, shape, |transfer| {
                    transfer.with_exit(DelegateOutput {
                        recipient: payee(),
                        asset: Mint::SOL.asset,
                        amount: MOVED,
                    })
                })
                .await;
            assert_eq!(
                verdict_of(exit),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let leg = relay
                .moved(&asked.tx_viewing_key, shape, |transfer| {
                    transfer.with_withdrawal(DelegateWithdrawal {
                        asset: Mint::SOL.asset,
                        amount: 1,
                        recipient: Address::new_from_array([0x62; 32]),
                        token_program: None,
                    })
                })
                .await;
            assert_eq!(verdict_of(leg), Err(MessageMismatch::Data), "{mode:?}");

            let payloads = rewritten(&honest, expected.rail, |data| {
                data.has_data = true;
                for output in &mut data.outputs {
                    if let custom_ring_interface::SlotBody::Recipient(body) = output.body {
                        let padded = [body, &[0; 3][..]].concat();
                        output.body =
                            custom_ring_interface::SlotBody::Recipient(Box::leak(padded.into()));
                    }
                }
            });
            assert_eq!(slot_owners(&payloads, expected.rail, &expected)[..2], order);
            assert_eq!(verdict_of(payloads), Err(MessageMismatch::Data), "{mode:?}");

            let mut unclamped = asked.clone();
            unclamped.tx_viewing_key =
                serde_json::from_value(serde_json::json!(Base64String(vec![1; 32]))).unwrap();
            assert_eq!(
                relay
                    .expected(&unclamped, &config)
                    .await
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&honest), UNITS).0)
                    .map(drop),
                Err(MessageMismatch::TransactionKey),
                "{mode:?}"
            );

            let other_key = TxViewingSecret::from(&ViewingKey::from_bytes(&[8; 32]));
            assert_eq!(
                verdict_of(build(asked.transfer.clone(), other_key).await),
                Err(MessageMismatch::TransactionKey),
                "{mode:?}"
            );
        }
    }

    /// Owner against delegate is no rule, change returns to an input's owner.
    #[tokio::test]
    async fn a_delegate_moves_its_own_another_and_several_members_notes_on_both_rails() {
        let delegate = keypair(7);
        let member = keypair(1);
        let other = keypair(3);
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            for (sources, moved) in [
                (vec![&delegate], MOVED),
                (vec![&member], MOVED),
                (vec![&member, &other], 15),
            ] {
                let relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
                let mut asked = request(delegate.pubkey());
                asked.transfer.sources = sources
                    .iter()
                    .map(|source| SerializableShieldedAddress(source.shielded_address().unwrap()))
                    .collect();
                asked.transfer.payments[0].amount = moved;
                let frame = relay
                    .build(&asked.transfer, &asked.tx_viewing_key)
                    .await
                    .unwrap();
                let config = ring().require_config(relay.client.zolana()).await.unwrap();
                let expected = relay.expected(&asked, &config).await;
                expected
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&frame), UNITS).0)
                    .map(drop)
                    .unwrap();

                // The auditor's own key opens every published slot.
                let parsed = RingTransactData::parse(&frame.data[1..], expected.rail).unwrap();
                let data = parsed.data();
                let opened = zolana_ring_client::AuditEnvelope {
                    eph_u: *data.tx_viewing_u,
                    salt: data.salt,
                    ciphertext: data.envelope,
                }
                .open(&crate::tests::support::auditor(), parsed.audit_stream())
                .unwrap();
                let records = super::opened_records(data, &opened);
                let spent = u64::try_from(sources.len()).unwrap() * 10;
                let total: u64 = records.iter().map(|record| record.amount).sum();
                assert_eq!(total, spent, "{mode:?} {}", sources.len());
                let owner_key = |owner: &ShieldedKeypair| {
                    owner
                        .shielded_address()
                        .unwrap()
                        .signing_pubkey
                        .confidential_view_tag()
                        .unwrap()
                };
                let payee_key = owner_key(&keypair(2));
                assert!(records
                    .iter()
                    .filter(|record| record.kind == custom_ring_interface::RecordKind::Ring)
                    .all(|record| record.owner_key == payee_key
                        || sources
                            .iter()
                            .any(|source| owner_key(source) == record.owner_key)));
            }
        }
    }

    fn payment_of(mint: Mint, amount: u64) -> AuthorityPayment {
        AuthorityPayment {
            recipient: SerializableShieldedAddress(payee()),
            mint: SerializablePubkey(mint.asset),
            amount,
        }
    }

    /// Each mint's change returns to the owner of the note it came from.
    #[tokio::test]
    async fn a_move_across_owners_and_mints_returns_each_change_to_its_owner() {
        let delegate = keypair(7);
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let mut relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let (member, other) = (keypair(1), keypair(3));
            relay.members[1].1 = vec![ring_utxo(&other, USDC, 10, 1)];
            let mut asked = request(delegate.pubkey());
            asked.transfer.sources = [&member, &other]
                .map(|source| SerializableShieldedAddress(source.shielded_address().unwrap()))
                .into();
            asked.transfer.payments = vec![payment_of(Mint::SOL, 4), payment_of(USDC, 3)];
            let frame = relay
                .build(&asked.transfer, &asked.tx_viewing_key)
                .await
                .unwrap();
            let config = ring().require_config(relay.client.zolana()).await.unwrap();
            let expected = relay.expected(&asked, &config).await;
            expected
                .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&frame), UNITS).0)
                .map(drop)
                .unwrap();
            let parsed = RingTransactData::parse(&frame.data[1..], expected.rail).unwrap();
            let data = parsed.data();
            let opened = zolana_ring_client::AuditEnvelope {
                eph_u: *data.tx_viewing_u,
                salt: data.salt,
                ciphertext: data.envelope,
            }
            .open(&crate::tests::support::auditor(), parsed.audit_stream())
            .unwrap();
            let moved: Vec<([u8; 32], [u8; 32], u64)> = super::opened_records(data, &opened)
                .into_iter()
                .filter(|record| record.kind == custom_ring_interface::RecordKind::Ring)
                .map(|record| (record.owner_key, record.mint, record.amount))
                .filter(|(_, _, amount)| *amount > 0)
                .collect();
            let key =
                |address: ShieldedAddress| address.signing_pubkey.confidential_view_tag().unwrap();
            let (sol, usdc) = (Mint::SOL.asset.to_bytes(), USDC.asset.to_bytes());
            for held in [
                (key(payee()), sol, 4),
                (key(payee()), usdc, 3),
                (key(member.shielded_address().unwrap()), sol, 6),
                (key(other.shielded_address().unwrap()), usdc, 7),
            ] {
                assert!(moved.contains(&held), "{mode:?} {moved:?}");
            }
            assert_eq!(moved.len(), 4, "{mode:?}");
        }
    }

    /// The anonymous frame's bundle holds one cell per change output of any mint.
    #[tokio::test]
    async fn one_owners_change_on_two_spl_mints_fits_both_frames() {
        let delegate = keypair(7);
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let mut relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let member = keypair(1);
            relay.members[0].1 = vec![
                ring_utxo(&member, USDC, 10, 0),
                ring_utxo(&member, EURC, 10, 3),
            ];
            let mut asked = request(delegate.pubkey());
            asked.transfer.payments = vec![payment_of(USDC, 3), payment_of(EURC, 3)];
            relay
                .build(&asked.transfer, &asked.tx_viewing_key)
                .await
                .unwrap_or_else(|error| panic!("{mode:?} {error:?}"));
        }
    }

    /// Every output pays exactly what the request asks and returns the change to its source, the
    /// note spent is still another member's.
    #[tokio::test]
    async fn a_victims_note_under_the_requested_outputs_is_refused_on_both_rails() {
        let delegate = keypair(7);
        let (member, victim) = (keypair(1), keypair(3));
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let asked = request(delegate.pubkey());
            let config = ring().require_config(relay.client.zolana()).await.unwrap();
            let expected = relay.expected(&asked, &config).await;
            let stolen = relay.victim_funded(&asked, &member, &victim).await;

            let mut paid = expected.clone();
            paid.allowed = relay
                .allowed(&AuthorityTransfer {
                    exits: Vec::new(),
                    withdrawals: Vec::new(),
                    sources: vec![SerializableShieldedAddress(
                        victim.shielded_address().unwrap(),
                    )],
                    payments: Vec::new(),
                })
                .await;
            assert_eq!(
                paid.check(&relay_message(&FEE_PAYER, std::slice::from_ref(&stolen), UNITS).0)
                    .map(drop),
                Ok(()),
                "{mode:?} the outputs alone match the request"
            );
            assert_eq!(
                expected
                    .check(&relay_message(&FEE_PAYER, &[stolen], UNITS).0)
                    .map(drop),
                Err(MessageMismatch::SpendsUnrequestedNote),
                "{mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_allowed_set_for_other_sources_is_refused() {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let asked = request(delegate.pubkey());
        let mut other = asked.transfer.clone();
        other.sources = vec![SerializableShieldedAddress(
            keypair(3).shielded_address().unwrap(),
        )];

        let refused = RequestedAuthorityTransfer {
            allowed: relay.allowed(&other).await,
            request: asked,
            quote: &quote(),
            config: &config,
        }
        .prepare();

        assert!(matches!(
            refused,
            Err(RingError::DelegateSource(
                DelegateSourceError::SourcesMismatch
            ))
        ));
    }

    /// The honest frame's spent notes, the authority rail publishes notes ahead of its padding.
    fn honest_spends(
        message: &[u8],
        tx_viewing_key: &TxViewingSecret,
        auditor: &spr_keypair::X25519Pubkey,
    ) -> Vec<[u8; 32]> {
        let message: solana_message::VersionedMessage = wincode::deserialize(message).unwrap();
        let data = message
            .instructions()
            .iter()
            .find_map(|instruction| {
                let (tag, data) = instruction.data.split_first()?;
                (*tag == tag::AUTHORITY_TRANSFER).then_some(data)
            })
            .unwrap();
        let parsed = RingTransactData::parse(data, RingRail::Delegate).unwrap();
        let spent = crate::relay_message::open_stream(&parsed, tx_viewing_key, auditor)
            .unwrap()
            .real_inputs;
        parsed.data().nullifiers[..usize::from(spent)].to_vec()
    }

    #[tokio::test]
    async fn a_move_past_its_sources_value_is_refused() {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        let mut asked = request(delegate.pubkey());
        asked.transfer.payments[0].amount = 11;
        assert!(relay
            .build(&asked.transfer, &asked.tx_viewing_key)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_source_named_twice_is_refused() {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        let mut asked = request(delegate.pubkey());
        let source = asked.transfer.sources[0];
        asked.transfer.sources.push(source);
        assert!(matches!(
            relay.build(&asked.transfer, &asked.tx_viewing_key).await,
            Err(RingError::RepeatedDelegateSource)
        ));
    }

    fn settlement_request(delegate: Address, mint: Mint) -> PrepareAuthorityTransferRequest {
        let mut asked = request(delegate);
        asked.transfer.payments = vec![payment_of(mint, 2)];
        asked.transfer.exits = vec![payment_of(mint, 3)];
        asked.transfer.withdrawals = vec![AuthorityWithdrawal {
            recipient: Address::new_from_array([0x62; 32]).into(),
            mint: mint.asset.into(),
            amount: 2,
            token_program: (mint != Mint::SOL)
                .then(|| Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID).into()),
        }];
        asked
    }

    #[tokio::test]
    async fn hosted_delegate_frames_bind_payments_exits_and_withdrawals() {
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            for mint in [Mint::SOL, USDC] {
                let delegate = keypair(7);
                let mut relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
                relay.members[0].1 = vec![ring_utxo(&keypair(1), mint, 10, 0)];
                let asked = settlement_request(delegate.pubkey(), mint);
                let frame = relay
                    .settlement_frame(&asked.transfer, &asked.tx_viewing_key)
                    .await
                    .unwrap();
                let config = ring().require_config(relay.client.zolana()).await.unwrap();
                let expected = relay.expected(&asked, &config).await;
                let bytes = relay_message(&FEE_PAYER, std::slice::from_ref(&frame), UNITS);
                assert_eq!(
                    expected.check(&bytes.0).map(drop),
                    Ok(()),
                    "{mode:?} {mint:?}"
                );

                let mut redirected = asked.clone();
                redirected.transfer.withdrawals[0].recipient =
                    Address::new_from_array([0x63; 32]).into();
                assert_eq!(
                    relay
                        .expected(&redirected, &config)
                        .await
                        .check(&bytes.0)
                        .map(drop),
                    Err(MessageMismatch::Data)
                );
                let mut amount = asked.clone();
                amount.transfer.withdrawals[0].amount += 1;
                assert_eq!(
                    relay
                        .expected(&amount, &config)
                        .await
                        .check(&bytes.0)
                        .map(drop),
                    Err(MessageMismatch::Data)
                );
                let mut asset = asked.clone();
                asset.transfer.withdrawals[0].mint = EURC.asset.into();
                asset.transfer.withdrawals[0].token_program =
                    Some(Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID).into());
                assert_eq!(
                    relay
                        .expected(&asset, &config)
                        .await
                        .check(&bytes.0)
                        .map(drop),
                    Err(MessageMismatch::Data)
                );
                let mut kind = asked.clone();
                kind.transfer.payments.append(&mut kind.transfer.exits);
                assert_eq!(
                    relay
                        .expected(&kind, &config)
                        .await
                        .check(&bytes.0)
                        .map(drop),
                    Err(MessageMismatch::Recipients)
                );
                let mut extra = asked.clone();
                extra.transfer.withdrawals[0].amount = 11;
                assert!(relay
                    .settlement_frame(&extra.transfer, &extra.tx_viewing_key)
                    .await
                    .is_err());
            }
        }
    }

    #[tokio::test]
    async fn shared_delegate_settlement_frames_bind_all_legs() {
        let delegate = keypair(7);
        let mut relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        relay.members[0].1 = vec![ring_utxo(&keypair(1), USDC, 10, 0)];
        let asked = settlement_request(delegate.pubkey(), USDC);
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let honest = relay
            .settlement_frame(&asked.transfer, &asked.tx_viewing_key)
            .await
            .unwrap();
        let mut cases = vec![MessageCase {
            name: "honest".into(),
            message: relay_message(&FEE_PAYER, std::slice::from_ref(&honest), UNITS),
            verdict: "Accepted".into(),
        }];
        for (name, position) in [
            ("withdrawalMint", 1),
            ("withdrawalRecipient", 3),
            ("withdrawalProgram", 4),
        ] {
            let mut changed = honest.clone();
            let start = changed.accounts.len() - 5;
            changed.accounts[start + position].pubkey = Address::new_from_array([0x63; 32]);
            cases.push(MessageCase {
                name: name.into(),
                message: relay_message(&FEE_PAYER, &[changed], UNITS),
                verdict: "Data".into(),
            });
        }
        let changed = rewritten(&honest, RingRail::Delegate, |data| {
            data.interface_transfers[0] =
                spr_interface::instruction::InterfaceTransfer::SplWithdrawal {
                    amount: 3,
                    spl_interface_bump: spr_interface::pda::spl_interface_bump(
                        USDC.asset.as_array(),
                    ),
                };
        });
        cases.push(MessageCase {
            name: "withdrawalAmount".into(),
            message: relay_message(&FEE_PAYER, &[changed], UNITS),
            verdict: "Data".into(),
        });
        for (name, change) in [("exitKind", 0), ("exitRecipient", 1), ("exitAmount", 2)] {
            let mut transfer = asked.transfer.clone();
            match change {
                0 => transfer.payments.append(&mut transfer.exits),
                1 => transfer.exits[0].recipient = thief().into(),
                _ => transfer.exits[0].amount += 1,
            }
            let frame = relay
                .settlement_frame(&transfer, &asked.tx_viewing_key)
                .await
                .unwrap();
            cases.push(MessageCase {
                name: name.into(),
                message: relay_message(&FEE_PAYER, &[frame], UNITS),
                verdict: "Recipients".into(),
            });
        }
        let fresh = MessageVector {
            description: "Delegate payments, exits and withdrawals bind their signed destinations and amounts.".into(),
            request: DelegateRequest { prepare: asked, fee_payer: FEE_PAYER.into(), auditor: Base64String(config.auditor_pubkey.as_bytes().to_vec()) },
            cases,
        };
        let vector = pinned_vector("relay_delegate_settlement_messages.json", fresh);
        let sources: Vec<_> = vector
            .request
            .prepare
            .transfer
            .sources
            .iter()
            .map(|source| source.0)
            .collect();
        let spends = honest_spends(
            &vector.cases[0].message.0,
            &vector.request.prepare.tx_viewing_key,
            &config.auditor_pubkey,
        );
        let expected = ExpectedDelegate::new(&RequestedAuthorityTransfer {
            request: vector.request.prepare,
            quote: &quote(),
            config: &config,
            allowed: allowed_as_pinned(&sources, spends),
        })
        .unwrap();
        for case in vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DelegateRequest {
        prepare: PrepareAuthorityTransferRequest,
        fee_payer: SerializablePubkey,
        /// The ring account's key, the stream a delegate reads seals to it.
        auditor: Base64String,
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[tokio::test]
    async fn the_shared_delegate_messages_keep_their_verdicts() {
        let (relay, signed) = relayed_signature(Answer::Honest).await;
        signed.unwrap();
        let honest = relay.honest.lock().unwrap().clone().unwrap();
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let asked = request(relay.delegate);
        let stolen = thief_under_payee_tag(&relay, &asked).await;
        let fresh = MessageVector {
            description: "One authority transfer the ring delegate asks Ring RPC for, moving 4 \
                          of the member's SOL to a second member with the change back, and the \
                          messages Ring RPC could answer with. The honest message is the relay's \
                          delegate path with zeroed proofs, each other case changes one thing. \
                          verdict names the MessageMismatch the Rust ExpectedDelegate::check and \
                          the TypeScript checkDelegateMessage return."
                .to_owned(),
            request: DelegateRequest {
                prepare: asked.clone(),
                fee_payer: SerializablePubkey(FEE_PAYER),
                auditor: Base64String(config.auditor_pubkey.as_bytes().to_vec()),
            },
            cases: Answer::ALL
                .map(|answer| {
                    let (name, verdict) = answer.case();
                    MessageCase {
                        name: name.to_owned(),
                        message: answer.message(&honest, relay.delegate),
                        verdict: verdict.to_owned(),
                    }
                })
                .into_iter()
                .chain([MessageCase {
                    name: "thiefUnderPayeeTag".to_owned(),
                    message: relay_message(&FEE_PAYER, &[stolen], UNITS),
                    verdict: "Recipients".to_owned(),
                }])
                .collect(),
        };
        let vector = pinned_vector("relay_delegate_messages.json", fresh);
        let quote = RelayQuote {
            fee_payer: vector.request.fee_payer,
            valid_until_slot: 0,
        };
        assert_eq!(vector.request.auditor.0, config.auditor_pubkey.as_bytes());
        let honest_nullifiers = vector
            .cases
            .iter()
            .find(|case| case.name == "honest")
            .map(|case| {
                honest_spends(
                    &case.message.0,
                    &vector.request.prepare.tx_viewing_key,
                    &config.auditor_pubkey,
                )
            })
            .unwrap();
        let sources: Vec<ShieldedAddress> = vector
            .request
            .prepare
            .transfer
            .sources
            .iter()
            .map(|source| source.0)
            .collect();
        let expected = ExpectedDelegate::new(&RequestedAuthorityTransfer {
            request: vector.request.prepare.clone(),
            quote: &quote,
            config: &config,
            allowed: allowed_as_pinned(&sources, honest_nullifiers),
        })
        .unwrap();
        assert_eq!(vector.cases.len(), Answer::ALL.len() + 1);
        for case in &vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
    }
}

mod public_signers {
    //! The public owners of a relayed transfer, each rebuilds its own slots against the frame.

    use custom_ring_interface::{
        cosign::ApprovalMask, tag, CoSignScope, InstructionTag, RingRail, RingTransactData,
    };
    use solana_instruction::Instruction;
    use spr_keypair::ShieldedKeypair;
    use spr_transaction::WalletUtxo;
    use zolana_ring_client::rpc::RelayId;

    use super::*;
    use crate::{
        tests::support::relay_message, ApplicationData, ApprovalLimit, ApprovalOpening, CoOwner,
        CoSignerApproval, CoSignerRule, CustomRingConfig, ExactApproval, FundedLeg, FunderApproval,
        MessageMismatch, NoteData, OwnerApproval, PendingSignature, PreparedRelay,
        RelayFunderTerms, RelaySent, RelayTransferTerms, RingTransfer, SlotOpening,
    };

    pub(super) const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = custom_ring_interface::compute_unit_limit(InstructionTag::Transfer);

    pub(super) fn address(owner: &ShieldedKeypair) -> Address {
        Address::new_from_array(owner.signing_pubkey().as_ed25519().unwrap())
    }

    pub(super) fn chain(
        mode: RingMode,
        co_signer: Option<Address>,
        owners: &[&ShieldedKeypair],
    ) -> Chain {
        let owners: Vec<(&ShieldedKeypair, u64)> = owners.iter().map(|owner| (*owner, 1)).collect();
        Chain::ring(RingSettings {
            has_policy: true,
            co_signer: co_signer.map(|signer| (signer, CoSignScope::TRANSFERS)),
            ..RingSettings::new(mode)
        })
        .with_registry(Registry::new(&owners), &pipeline_rules())
    }

    pub(super) fn transfer<'a>(
        sender: &'a ShieldedKeypair,
        notes: Vec<WalletUtxo>,
    ) -> CustomRingTransfer<'a> {
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: ConfidentialTransaction::new_with_ring(
                notes,
                FEE_PAYER,
                ring().program_id(),
            )
            .unwrap(),
        })
    }

    pub(super) fn pay(to: &ShieldedKeypair, amount: u64) -> AnonymousPayment {
        AnonymousPayment {
            to: RingAddress {
                recipient: to.shielded_address().unwrap(),
                ring_program_id: ring().program_id(),
                list_salt: [7; 32],
            },
            asset: Mint::SOL,
            amount,
            reply: None,
            data: NoteData::default(),
        }
    }

    pub(super) fn quote() -> RelayQuote {
        RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: u64::MAX,
        }
    }

    pub(super) struct Sent {
        pub request: PrepareRelayRequest,
        pub relay_id: RelayId,
        pub pending: PendingSignature,
    }

    /// `prepare_relay` sets the expectation, a relay that asks reaches a wallet holding terms.
    pub(super) async fn sent(prepared: PreparedRelay) -> Sent {
        let relay = StubRelay {
            asks_signature: true,
            ..StubRelay::default()
        };
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the relay asks a signature");
        };
        let request = relay.prepared.lock().unwrap().pop().unwrap();
        Sent {
            relay_id: pending.relay_id().clone(),
            pending,
            request,
        }
    }

    /// `SdkRelayProver` over the wire bytes, the proofs zeroed.
    async fn frame(
        client: &crate::RingClient<Chain, Chain>,
        request: &PrepareRelayRequest,
    ) -> Instruction {
        let assembled = assembled(client, request).await;
        let frame = &assembled.frame;
        frame
            .accounts
            .instruction(frame.ring, &assembled.config, &frame.parts)
            .unwrap()
    }

    pub(super) async fn assembled(
        client: &crate::RingClient<Chain, Chain>,
        request: &PrepareRelayRequest,
    ) -> crate::pipeline::Assembled {
        let (RelayIntent::Anonymous {
            proof_inputs,
            owner_signature,
            ..
        }
        | RelayIntent::Confidential {
            proof_inputs,
            owner_signature,
            ..
        }) = &request.intent
        else {
            panic!("a wallet relay");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        let mut relayed = RingTransfer::relayed(crate::RelayedTransferInput {
            ring: ring(),
            proof_inputs: &inputs,
            fee_payer: FEE_PAYER,
        })
        .with_owner_signature(<[u8; 64]>::from(owner_signature.0));
        for co_signer in &request.co_signers {
            relayed = relayed.with_co_signer(co_signer.0);
        }
        relayed.assemble(client).await.unwrap()
    }

    /// The terms cross to the signer's wallet as JSON.
    fn pending_for(
        relay_id: &RelayId,
        message: Vec<u8>,
        terms: &RelayTransferTerms,
        config: &CustomRingConfig,
    ) -> PendingSignature {
        approval(relay_id, message, terms, config, &[])
    }

    fn approval(
        relay_id: &RelayId,
        message: Vec<u8>,
        terms: &RelayTransferTerms,
        config: &CustomRingConfig,
        known_notes: &[WalletUtxo],
    ) -> PendingSignature {
        OwnerApproval {
            relay_id: relay_id.clone(),
            message,
            terms: serde_json::from_str(&serde_json::to_string(terms).unwrap()).unwrap(),
            config,
            known_notes,
        }
        .pending()
    }

    async fn signs(pending: &PendingSignature, signer: &ShieldedKeypair) {
        let relay = StubRelay::default();
        pending.sign(&relay, signer).await.unwrap();
        let submitted = relay.submitted.lock().unwrap();
        assert_eq!(submitted[0].signer.0, address(signer));
    }

    fn refused(pending: &PendingSignature, signer: &ShieldedKeypair, mismatch: MessageMismatch) {
        let verdict = pending.verify(address(signer));
        assert!(
            matches!(&verdict, Err(RingError::RelayMessage(found)) if *found == mismatch),
            "{:?}",
            verdict.map(drop)
        );
    }

    fn data_payment(to: &ShieldedKeypair) -> AnonymousPayment {
        pay(to, 4).with_data(NoteData {
            ring_data_hash: None,
            application: Some(ApplicationData {
                hash: [4; 32],
                bytes: b"app".to_vec(),
            }),
        })
    }

    #[tokio::test]
    async fn a_reply_that_claims_another_sender_moves_no_verdict() {
        let (sender, payee, thief) = (keypair(1), keypair(2), keypair(3));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &thief]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let claimed = thief.shielded_address().unwrap();
        let forged = zolana_ring_transaction::ReplyMetadata {
            viewing_key: claimed.viewing_pubkey,
            owner_key: claimed.signing_pubkey.as_ed25519().unwrap(),
            nullifier_pk: claimed.nullifier_pubkey,
            data: spr_transaction::Data::default(),
        };
        for reply in [None, Some(forged)] {
            let replied = reply.is_some();
            let asked = sent(
                transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                    .with_anonymous_signer(&sender.signing_key)
                    .with_payment(AnonymousPayment {
                        reply,
                        ..data_payment(&payee)
                    })
                    .unwrap()
                    .prepare_relay(client.zolana(), quote())
                    .await
                    .unwrap()
                    .sign()
                    .unwrap(),
            )
            .await;
            let terms = asked
                .pending
                .transfer_terms(address(&payee))
                .unwrap()
                .clone();
            let built = frame(&client, &asked.request).await;
            let parsed = RingTransactData::parse(&built.data[1..], RingRail::Anonymous).unwrap();
            assert_eq!(parsed.data().replies.is_some(), replied);
            let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
            let pending = pending_for(&asked.relay_id, message, &terms, &config);
            signs(&pending, &payee).await;
            refused(&pending, &thief, MessageMismatch::Unrequested);
        }
    }

    #[tokio::test]
    async fn a_data_recipient_reads_every_slot_and_signs() {
        let (sender, payee, thief) = (keypair(1), keypair(2), keypair(3));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &thief]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let paying = |to: &ShieldedKeypair| {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(data_payment(to))
                .unwrap()
        };
        let honest = paying(&payee);
        let asked = sent(
            honest
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        assert!(terms.nullifiers.is_empty());
        let own = terms
            .slots
            .iter()
            .position(|opening| opening.owner.0 == address(&payee))
            .expect("the payee's slot");
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let pending = pending_for(&asked.relay_id, message.clone(), &terms, &config);
        signs(&pending, &payee).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);

        let mut false_opening = terms.clone();
        false_opening.slots[own].amount += 1;
        let mut another_owner = terms.clone();
        another_owner.slots[own].owner = SerializablePubkey(address(&thief));
        for altered in [false_opening, another_owner] {
            refused(
                &pending_for(&asked.relay_id, message.clone(), &altered, &config),
                &payee,
                MessageMismatch::Recipients,
            );
        }

        let stolen = paying(&thief);
        let forged = sent(
            stolen
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let forged_frame = frame(&client, &forged.request).await;
        refused(
            &pending_for(
                &asked.relay_id,
                relay_message(&FEE_PAYER, &[forged_frame], UNITS).0,
                &terms,
                &config,
            ),
            &payee,
            MessageMismatch::Recipients,
        );
    }

    async fn relayed_co_owners(mode: RingMode) -> Vec<Address> {
        let (sender, payee, spending, idle) = (keypair(1), keypair(2), keypair(3), keypair(5));
        let client = chain(mode, None, &[&sender, &payee, &spending, &idle]).client();
        let notes = vec![
            ring_utxo(&sender, Mint::SOL, 10, 0),
            ring_utxo(&spending, Mint::SOL, 10, 1),
        ];
        let held = |owner| CoOwner {
            owner: address(owner),
            nullifier_key: &owner.nullifier_key,
        };
        let prepared = match mode {
            RingMode::Anonymous => transfer(&sender, notes)
                .with_anonymous_signer(&sender.signing_key)
                .with_co_owner(held(&idle))
                .with_co_owner(held(&spending))
                .with_payment(pay(&payee, 4))
                .unwrap()
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
            RingMode::Confidential => {
                let mut transaction =
                    ConfidentialTransaction::new_with_ring(notes, FEE_PAYER, ring().program_id())
                        .unwrap();
                transaction
                    .transfer_sol(&payee.shielded_address().unwrap(), 4)
                    .unwrap();
                CustomRingTransfer::new(CustomRingTransferInput {
                    ring: ring(),
                    sender: &sender,
                    nullifier_key: Some(&sender.nullifier_key),
                    transaction,
                })
                .with_in_proof_owner(&sender.signing_key)
                .with_co_owner(held(&idle))
                .with_co_owner(held(&spending))
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap()
            }
        };
        let (RelayIntent::Anonymous { proof_inputs, .. }
        | RelayIntent::Confidential { proof_inputs, .. }) = sent(prepared).await.request.intent
        else {
            panic!("a wallet relay");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        inputs.co_owners.iter().map(|held| held.owner).collect()
    }

    #[tokio::test]
    async fn a_relay_carries_a_spending_co_owner_key_and_no_idle_one_on_both_rails() {
        for mode in [RingMode::Anonymous, RingMode::Confidential] {
            assert_eq!(
                relayed_co_owners(mode).await,
                [address(&keypair(3))],
                "{mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_public_co_owner_crosses_the_wire_with_its_key_and_signs_for_its_notes() {
        let (sender, payee, co_owner) = (keypair(1), keypair(2), keypair(3));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &co_owner]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let spent = ring_utxo(&co_owner, Mint::SOL, 10, 1);
        let kept = ring_utxo(&co_owner, Mint::SOL, 10, 2);
        let transaction = transfer(
            &sender,
            vec![ring_utxo(&sender, Mint::SOL, 10, 0), spent.clone()],
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_payment(pay(&payee, 4))
        .unwrap();
        let asked = sent(
            transaction
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&co_owner))
            .unwrap()
            .clone();
        assert_eq!(terms.nullifiers.len(), 1);
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let known = [spent.clone(), kept.clone()];
        signs(
            &approval(&asked.relay_id, message.clone(), &terms, &config, &known),
            &co_owner,
        )
        .await;

        // No list stands behind the check, the note the terms name is not the wallet's.
        refused(
            &approval(&asked.relay_id, message, &terms, &config, &[]),
            &co_owner,
            MessageMismatch::Data,
        );

        // The relay holds the key, its frame spends a second note the terms do not name.
        let rewritten = |nullifiers: &[[u8; 32]]| {
            let parsed = RingTransactData::parse(&built.data[1..], RingRail::Anonymous).unwrap();
            let mut data = parsed.into_data();
            data.nullifiers = nullifiers;
            relay_message(
                &FEE_PAYER,
                &[Instruction {
                    data: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
                    ..built.clone()
                }],
                UNITS,
            )
            .0
        };
        let also_kept = [kept.nullifier, spent.nullifier];
        refused(
            &approval(
                &asked.relay_id,
                rewritten(&also_kept),
                &terms,
                &config,
                &known,
            ),
            &co_owner,
            MessageMismatch::SpendsUnnamedNote,
        );
        let others = [[9; 32], [8; 32]];
        refused(
            &approval(&asked.relay_id, rewritten(&others), &terms, &config, &known),
            &co_owner,
            MessageMismatch::Data,
        );
    }

    #[tokio::test]
    async fn a_data_recipient_of_a_relayed_in_proof_transfer_signs() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Confidential, None, &[&sender, &payee]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        transaction
            .add_output_utxo(
                spr_transaction::SppProofOutputUtxo::new(
                    Mint::SOL,
                    4,
                    payee.shielded_address().unwrap(),
                )
                .unwrap()
                .with_ring_program_id(ring().program_id())
                .with_utxo_data(b"app".to_vec(), [4; 32]),
            )
            .unwrap();
        let in_proof = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_in_proof_owner(&sender.signing_key);
        let asked = sent(
            in_proof
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let built = frame(&client, &asked.request).await;
        let pending = pending_for(
            &asked.relay_id,
            relay_message(&FEE_PAYER, &[built], UNITS).0,
            &terms,
            &config,
        );
        signs(&pending, &payee).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct OwnerCase {
        name: String,
        terms: RelayTransferTerms,
        known_nullifiers: Vec<spr_indexer_api::Hash>,
        message: spr_indexer_api::Base64String,
        verdict: String,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct OwnerMessages {
        description: String,
        cases: Vec<OwnerCase>,
    }

    fn owner_case(
        name: &str,
        terms: &RelayTransferTerms,
        known: &[[u8; 32]],
        message: &[u8],
        verdict: &str,
    ) -> OwnerCase {
        OwnerCase {
            name: name.to_owned(),
            terms: terms.clone(),
            known_nullifiers: known.iter().copied().map(spr_indexer_api::Hash).collect(),
            message: message.to_vec().into(),
            verdict: verdict.to_owned(),
        }
    }

    /// The fee payer signs what the relay sends, a leg naming it would fund the wallet from the relay.
    #[tokio::test]
    async fn a_relayed_deposit_leg_its_fee_payer_would_fund_is_refused() {
        use spr_program::instruction::{
            TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        };
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        transaction.deposit_sol(5, FEE_PAYER).unwrap();
        let paying = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: FEE_PAYER,
            },
        )])
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(pay(&payee, 4))
        .unwrap();
        let asked = sent(
            paying
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let RelayIntent::Anonymous {
            proof_inputs,
            owner_signature,
            ..
        } = &asked.request.intent
        else {
            panic!("a wallet relay");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        let relayed = RingTransfer::relayed(crate::RelayedTransferInput {
            ring: ring(),
            proof_inputs: &inputs,
            fee_payer: FEE_PAYER,
        })
        .with_owner_signature(<[u8; 64]>::from(owner_signature.0));
        assert!(matches!(
            relayed.assemble(&client).await,
            Err(RingError::RelayFeePayerFundsDeposit)
        ));
    }

    /// The TypeScript check reads the same frames and reaches the same verdicts, `UPDATE_RELAY_MESSAGES=1` rewrites them.
    #[tokio::test]
    async fn the_shared_owner_messages_keep_their_verdicts() {
        let (sender, payee, thief, co_owner) = (keypair(1), keypair(2), keypair(4), keypair(3));
        let client = chain(
            RingMode::Anonymous,
            None,
            &[&sender, &payee, &thief, &co_owner],
        )
        .client();
        let paying = |to: &ShieldedKeypair| {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(data_payment(to))
                .unwrap()
        };
        let honest = paying(&payee);
        let asked = sent(
            honest
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let message = relay_message(&FEE_PAYER, &[frame(&client, &asked.request).await], UNITS).0;
        let stolen = paying(&thief);
        let forged = sent(
            stolen
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let forged_message =
            relay_message(&FEE_PAYER, &[frame(&client, &forged.request).await], UNITS).0;
        let mut false_opening = terms.clone();
        false_opening.slots[0].amount += 1;

        let spent = ring_utxo(&co_owner, Mint::SOL, 10, 1);
        let kept = ring_utxo(&co_owner, Mint::SOL, 10, 2);
        let shared = transfer(
            &sender,
            vec![ring_utxo(&sender, Mint::SOL, 10, 0), spent.clone()],
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_payment(pay(&payee, 4))
        .unwrap();
        let co_asked = sent(
            shared
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let co_terms = co_asked
            .pending
            .transfer_terms(address(&co_owner))
            .unwrap()
            .clone();
        let built = frame(&client, &co_asked.request).await;
        let co_message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let parsed = RingTransactData::parse(&built.data[1..], RingRail::Anonymous).unwrap();
        let mut data = parsed.into_data();
        let also_kept = [kept.nullifier, spent.nullifier];
        data.nullifiers = &also_kept;
        let unnamed = relay_message(
            &FEE_PAYER,
            &[Instruction {
                data: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
                ..built.clone()
            }],
            UNITS,
        )
        .0;
        let known = [spent.nullifier, kept.nullifier];

        let lead_note = ring_utxo(&co_owner, Mint::SOL, 10, 3);
        let recipient_note = ring_utxo(&payee, Mint::SOL, 10, 4);
        let repeating = transfer(
            &sender,
            vec![
                ring_utxo(&sender, Mint::SOL, 10, 0),
                lead_note,
                recipient_note.clone(),
            ],
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_co_owner(CoOwner {
            owner: address(&payee),
            nullifier_key: &payee.nullifier_key,
        })
        .with_payment(data_payment(&payee))
        .unwrap();
        let repeat_asked = sent(
            repeating
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let repeat_terms = repeat_asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let omitted_terms = RelayTransferTerms {
            slots: Vec::new(),
            ..repeat_terms.clone()
        };
        let mut repeated = frame(&client, &repeat_asked.request).await;
        let lead = repeated
            .accounts
            .iter()
            .position(|meta| meta.pubkey == address(&co_owner))
            .unwrap();
        repeated
            .accounts
            .insert(lead, repeated.accounts[lead].clone());
        let repeated_message = relay_message(&FEE_PAYER, &[repeated], UNITS).0;
        let recipient_known = [recipient_note.nullifier];

        let exit_note = ring_utxo(&co_owner, Mint::SOL, 10, 5);
        let mut exiting = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0), exit_note.clone()],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        exiting
            .transfer_with_ring(&co_owner.shielded_address().unwrap(), Mint::SOL, 3, None)
            .unwrap();
        let exit_transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: exiting,
        })
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_payment(pay(&payee, 4))
        .unwrap();
        let exit_asked = sent(
            exit_transfer
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let exit_terms = exit_asked
            .pending
            .transfer_terms(address(&co_owner))
            .unwrap()
            .clone();
        assert!(exit_terms.slots.len() > 1);
        assert!(exit_terms
            .slots
            .iter()
            .zip(0u32..)
            .all(|(opening, slot)| opening.slot == slot));
        let exit_message = relay_message(
            &FEE_PAYER,
            &[frame(&client, &exit_asked.request).await],
            UNITS,
        )
        .0;
        let exit_known = [exit_note.nullifier];

        let fresh = OwnerMessages {
            description: "Relayed anonymous transfers a public owner signs. A signer reads \
                          every published slot opened, a co-owner names its notes against the notes its \
                          wallet holds. Each case holds the owner's terms, what its wallet knows, \
                          the message Ring RPC answers with, and the MessageMismatch the Rust \
                          ExpectedPublicOwner and the TypeScript check return. Frames carry \
                          zeroed proofs."
                .to_owned(),
            cases: vec![
                owner_case("recipientHonest", &terms, &[], &message, "Accepted"),
                owner_case("thief", &terms, &[], &forged_message, "Recipients"),
                owner_case("falseOpening", &false_opening, &[], &message, "Recipients"),
                owner_case("coOwnerHonest", &co_terms, &known, &co_message, "Accepted"),
                owner_case(
                    "unnamedNote",
                    &co_terms,
                    &known,
                    &unnamed,
                    "SpendsUnnamedNote",
                ),
                owner_case("noList", &co_terms, &[], &co_message, "Data"),
                owner_case(
                    "repeatedSignerHonest",
                    &repeat_terms,
                    &recipient_known,
                    &repeated_message,
                    "Accepted",
                ),
                owner_case(
                    "repeatedSignerOmitsOutputs",
                    &omitted_terms,
                    &recipient_known,
                    &repeated_message,
                    "UnopenedOutput",
                ),
                owner_case(
                    "exitHonest",
                    &exit_terms,
                    &exit_known,
                    &exit_message,
                    "Accepted",
                ),
            ],
        };
        let vector = crate::tests::support::pinned_vector("relay_transfer_messages.json", fresh);
        for case in &vector.cases {
            let expected = crate::relay_message::ExpectedPublicOwner::new(
                case.terms.clone(),
                RingMode::Anonymous,
                case.known_nullifiers.iter().map(|hash| hash.0).collect(),
            );
            let checked = crate::relay_message::ExpectedMessage::PublicOwner(expected)
                .check(&case.message.0, case.terms.signer.0);
            assert_eq!(
                crate::tests::support::verdict(checked),
                case.verdict,
                "{}",
                case.name
            );
        }
    }

    /// The terms name each create, one with no withdrawal to pay has none.
    #[tokio::test]
    async fn an_owners_terms_refuse_a_setup_naming_no_withdrawal() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_token_account_setup(vec![TokenAccountSetup {
                owner: SerializablePubkey(Address::new_from_array([0x55; 32])),
                mint: SerializablePubkey(Address::new_from_array([0x66; 32])),
            }])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(data_payment(&payee))
            .unwrap();
        assert!(matches!(
            transaction.prepare_relay(client.zolana(), quote()).await,
            Err(RingError::TokenAccountSetup(_))
        ));
    }

    /// No sender slot is opened, and the plain wallet check names no terms for a co-signer.
    #[tokio::test]
    async fn an_outside_co_signer_holds_no_owner_terms() {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Anonymous,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_co_signer(address(&co_signer))
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(pay(&payee, 4))
            .unwrap();
        let asked = sent(
            transaction
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        assert!(asked.pending.transfer_terms(address(&co_signer)).is_none());
        assert!(asked.pending.approval_opening().is_none());
        refused(&asked.pending, &co_signer, MessageMismatch::Unrequested);
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct LimitCase {
        mint: SerializablePubkey,
        peak: String,
        outflow: String,
        gross: String,
    }

    /// `opening` unset is the threshold rule, `accepts` then names its bits.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct CoSignerCase {
        name: String,
        accepts: u8,
        opening: Option<ApprovalOpening>,
        limits: Vec<LimitCase>,
        seen_blinders: Vec<spr_indexer_api::Hash>,
        message: spr_indexer_api::Base64String,
        verdict: String,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct CoSignerMessages {
        description: String,
        ring: SerializablePubkey,
        fee_payer: SerializablePubkey,
        signer: SerializablePubkey,
        cases: Vec<CoSignerCase>,
    }

    fn limit(mint: Mint, peak: u128, outflow: u128) -> LimitCase {
        LimitCase {
            mint: SerializablePubkey(mint.asset),
            peak: peak.to_string(),
            outflow: outflow.to_string(),
            gross: outflow.to_string(),
        }
    }

    impl CoSignerCase {
        fn rule(&self) -> CoSignerRule {
            match &self.opening {
                None => CoSignerRule::Threshold {
                    accepts: ApprovalMask::new(self.accepts).unwrap(),
                },
                Some(opening) => CoSignerRule::Exact(ExactApproval {
                    opening: opening.clone(),
                    limits: self
                        .limits
                        .iter()
                        .map(|limit| ApprovalLimit {
                            mint: limit.mint.0,
                            peak: limit.peak.parse().unwrap(),
                            outflow: limit.outflow.parse().unwrap(),
                            gross: limit.gross.parse().unwrap(),
                        })
                        .collect(),
                    seen_blinders: self.seen_blinders.clone(),
                }),
            }
        }
    }

    fn co_signer_pending(
        relay_id: &RelayId,
        message: Vec<u8>,
        signer: Address,
        rule: CoSignerRule,
        config: &CustomRingConfig,
    ) -> PendingSignature {
        CoSignerApproval {
            relay_id: relay_id.clone(),
            message,
            ring: ring().program_id(),
            fee_payer: FEE_PAYER,
            signer,
            config,
            setup: Vec::new(),
            rule,
        }
        .pending()
    }

    #[tokio::test]
    async fn a_signer_signs_only_once_every_published_output_opens() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let paying = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 20, 0)])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(data_payment(&payee))
            .unwrap()
            .with_payment(pay(&payee, 1))
            .unwrap()
            .with_shape(spr_interface::shape::Shape::new(1, 4))
            .unwrap();
        let asked = sent(
            paying
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let pending = |terms: &RelayTransferTerms| {
            pending_for(&asked.relay_id, message.clone(), terms, &config)
        };
        // The terms open the sender's change and the padding dummy beside both payments.
        let dummy = terms
            .slots
            .iter()
            .find(|opening| opening.owner.0 == Address::default())
            .expect("a dummy slot")
            .clone();
        assert!(terms
            .slots
            .iter()
            .any(|opening| opening.owner.0 == address(&sender)));
        signs(&pending(&terms), &payee).await;

        let with_slots = |slots: Vec<SlotOpening>| RelayTransferTerms {
            slots,
            ..terms.clone()
        };
        let own: Vec<SlotOpening> = terms
            .slots
            .iter()
            .filter(|opening| opening.owner.0 == address(&payee))
            .cloned()
            .collect();
        let mut repeated = terms.slots.clone();
        let last = repeated.len() - 1;
        repeated[last] = repeated[0].clone();
        let mut reordered = terms.slots.clone();
        reordered.swap(0, 1);
        for short in [
            with_slots(own),
            with_slots(terms.slots[1..].to_vec()),
            with_slots(repeated),
            with_slots(reordered),
        ] {
            refused(&pending(&short), &payee, MessageMismatch::UnopenedOutput);
        }

        // A dummy opens to its blinding alone, a field beside it would open no published slot.
        let mut padded = terms.clone();
        let at = dummy.slot as usize;
        padded.slots[at].amount = 1;
        refused(&pending(&padded), &payee, MessageMismatch::Recipients);
        let mut blinded = terms.clone();
        blinded.slots[at].blinding.0[31] ^= 1;
        refused(&pending(&blinded), &payee, MessageMismatch::Recipients);
    }

    #[tokio::test]
    async fn an_exact_opening_holds_the_keys_rows_under_a_nonzero_blinder() {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Confidential,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        transaction
            .transfer_with_ring(
                &payee.shielded_address().unwrap(),
                Mint::SOL,
                4,
                Some(ring().program_id()),
            )
            .unwrap();
        let attempt = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_co_signer(address(&co_signer))
        .with_exact_approval()
        .with_in_proof_owner(&sender.signing_key);
        let asked = sent(
            attempt
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let opening = asked.pending.approval_opening().unwrap().clone();
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let rule = |opening: ApprovalOpening| {
            CoSignerRule::Exact(ExactApproval {
                opening,
                limits: vec![ApprovalLimit {
                    mint: Mint::SOL.asset,
                    peak: 4,
                    outflow: 4,
                    gross: 0,
                }],
                seen_blinders: Vec::new(),
            })
        };
        let pending = |opening: ApprovalOpening| {
            co_signer_pending(
                &asked.relay_id,
                message.clone(),
                address(&co_signer),
                rule(opening),
                &config,
            )
        };

        let mut short_public = opening.clone();
        short_public.public.pop();
        refused(
            &pending(short_public),
            &co_signer,
            MessageMismatch::ApprovalOpeningLayout,
        );
        let mut long_outputs = opening.clone();
        long_outputs.outputs.push(opening.outputs[0].clone());
        refused(
            &pending(long_outputs),
            &co_signer,
            MessageMismatch::ApprovalOpeningLayout,
        );
        let zero_blinder = ApprovalOpening {
            blinder: spr_indexer_api::Hash([0; 32]),
            ..opening.clone()
        };
        refused(
            &pending(zero_blinder),
            &co_signer,
            MessageMismatch::ZeroApprovalBlinder,
        );
        signs(&pending(opening), &co_signer).await;
    }

    #[tokio::test]
    async fn a_funder_signs_its_own_deposit_legs_and_nothing_else() {
        use spr_program::instruction::{
            TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        };
        let (sender, payee, funder) = (keypair(1), keypair(2), keypair(4));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &funder]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        transaction.deposit_sol(5, address(&funder)).unwrap();
        let paying = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts {
                recipient: address(&funder),
            },
        )])
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(pay(&payee, 4))
        .unwrap();
        let asked = sent(
            paying
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .funder_terms(address(&funder))
            .unwrap()
            .clone();
        assert_eq!(
            terms.legs,
            [FundedLeg {
                mint: None,
                amount: 5
            }]
        );
        assert!(asked.pending.transfer_terms(address(&funder)).is_none());
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let pending = |terms: RelayFunderTerms| {
            FunderApproval {
                relay_id: asked.relay_id.clone(),
                message: message.clone(),
                terms,
                config: &config,
            }
            .pending()
        };
        signs(&pending(terms.clone()), &funder).await;
        refused(
            &pending(terms.clone()),
            &payee,
            MessageMismatch::Unrequested,
        );
        let understated = RelayFunderTerms {
            legs: vec![FundedLeg {
                mint: None,
                amount: 4,
            }],
            ..terms.clone()
        };
        refused(&pending(understated), &funder, MessageMismatch::FunderLegs);
        let extra_leg = RelayFunderTerms {
            legs: vec![terms.legs[0], terms.legs[0]],
            ..terms.clone()
        };
        refused(&pending(extra_leg), &funder, MessageMismatch::FunderLegs);
        let no_legs = RelayFunderTerms {
            legs: Vec::new(),
            ..terms.clone()
        };
        refused(&pending(no_legs), &funder, MessageMismatch::Unrequested);
    }

    /// The TypeScript check reads the same frames, neither rule opens a slot.
    #[tokio::test]
    async fn the_shared_co_signer_messages_keep_their_verdicts() {
        const GROSS: u64 = 5;
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Anonymous,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let build = || {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_co_signer(address(&co_signer))
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 4))
                .unwrap()
        };
        let exact = build().with_exact_approval();
        let disclosed = sent(
            exact
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let opening = disclosed.pending.approval_opening().unwrap().clone();
        let digested = frame(&client, &disclosed.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&digested), UNITS).0;
        let plain_transfer = build();
        let plain = sent(
            plain_transfer
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        assert!(plain.pending.approval_opening().is_none());
        let plain_message =
            relay_message(&FEE_PAYER, &[frame(&client, &plain.request).await], UNITS).0;

        // The extension stays out of what SPP hashes.
        let parsed = RingTransactData::parse(&digested.data[1..], RingRail::Anonymous).unwrap();
        let mut stripped = parsed.into_data();
        let with_digest = stripped.external_data_hash(config.account(), &[]).unwrap();
        assert!(stripped.extensions.approval_totals.is_some());
        stripped.extensions.approval_totals = None;
        assert_eq!(
            with_digest,
            stripped.external_data_hash(config.account(), &[]).unwrap()
        );

        // A frame over a mask the co-signer does not accept.
        let parsed = RingTransactData::parse(&digested.data[1..], RingRail::Anonymous).unwrap();
        let mut masked = parsed.into_data();
        masked.approval = ApprovalMask::OUTFLOW;
        let masked_message = relay_message(
            &FEE_PAYER,
            &[Instruction {
                data: [vec![tag::TRANSFER], masked.encode().unwrap()].concat(),
                ..digested.clone()
            }],
            UNITS,
        )
        .0;

        let mut false_opening = opening.clone();
        false_opening.outputs[0].charged_outflow = "1".to_owned();

        // Another key funds the withdrawal and the one spent note holds no value, so no owner debits
        // the mint and the public row's gross alone shows the size.
        let spl = Mint {
            asset: Address::new_from_array([0x47; 32]),
            asset_id: 7,
        };
        let token_account = Address::new_from_array([0x48; 32]);
        let token_program = Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID);
        let spl_deposit = |authority: Address| {
            TransactInterfaceTransferAccounts::SplDeposit(
                spr_program::instruction::TransactSplDepositAccounts {
                    mint: spl.asset,
                    spl_interface: spr_interface::pda::spl_interface(&spl.asset),
                    token_authority: authority,
                    user_token_account: token_account,
                    token_program,
                },
            )
        };
        let spl_ring = |scope| {
            Chain::ring(RingSettings {
                has_policy: true,
                co_signer: Some((address(&co_signer), scope)),
                ..RingSettings::new(RingMode::Anonymous)
            })
            .with_registry(
                Registry::new(&[(&sender, 1), (&payee, 1), (&co_signer, 1)])
                    .with_mint(spl.asset, Default::default()),
                &pipeline_rules(),
            )
            .with(
                spr_interface::pda::associated_token_address_with_program(
                    &address(&payee),
                    &spl.asset,
                    &token_program,
                ),
                crate::tests::support::account(
                    token_program,
                    &spl_token_2022_interface::pod::PodAccount {
                        mint: spl.asset.to_bytes().into(),
                        owner: address(&payee).to_bytes().into(),
                        state: spr_interface::SPL_TOKEN_ACCOUNT_INITIALIZED,
                        ..Default::default()
                    },
                ),
            )
            .client()
        };
        let funder = keypair(7);
        let through_client = spl_ring(CoSignScope::TRANSFERS);
        let mut moving = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, spl, 0, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        moving.deposit(spl, GROSS + 1, token_account).unwrap();
        let withdrawal = moving
            .withdraw_to(spl.asset, GROSS, address(&payee), Some(token_program))
            .unwrap();
        let through = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: moving,
        })
        .with_interface_transfer_accounts(vec![spl_deposit(address(&funder)), withdrawal])
        .with_co_signer(address(&co_signer))
        .with_anonymous_signer(&sender.signing_key)
        .with_exit_token_owner(address(&payee))
        .with_payment(AnonymousPayment {
            asset: spl,
            ..pay(&payee, 1)
        })
        .unwrap()
        .with_exact_approval();
        let through_asked = sent(
            through
                .prepare_relay(through_client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let through_opening = through_asked.pending.approval_opening().unwrap().clone();
        let through_message = relay_message(
            &FEE_PAYER,
            &[frame(&through_client, &through_asked.request).await],
            UNITS,
        )
        .0;
        // Every other reading of the row stays inside these, only the gross bound decides.
        let gross_limits = |gross: u64| {
            vec![
                LimitCase {
                    gross: gross.to_string(),
                    ..limit(spl, 0, 0)
                },
                LimitCase {
                    gross: gross.to_string(),
                    ..limit(Mint::SOL, 1, 1)
                },
            ]
        };

        // A ring asking the co-signer for an approval bit alone, mask 0 names it nowhere in the prefix.
        let approval_client = spl_ring(CoSignScope::APPROVALS);
        let mut funding = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        funding.deposit(spl, 5, token_account).unwrap();
        let funded = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: funding,
        })
        .with_interface_transfer_accounts(vec![spl_deposit(address(&co_signer))])
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(AnonymousPayment {
            asset: spl,
            ..pay(&payee, 5)
        })
        .unwrap();
        let funded_asked = sent(
            funded
                .prepare_relay(approval_client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let funded_message = relay_message(
            &FEE_PAYER,
            &[frame(&approval_client, &funded_asked.request).await],
            UNITS,
        )
        .0;
        let owning = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(data_payment(&co_signer))
            .unwrap();
        let owning_asked = sent(
            owning
                .prepare_relay(approval_client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let owning_message = relay_message(
            &FEE_PAYER,
            &[frame(&approval_client, &owning_asked.request).await],
            UNITS,
        )
        .0;
        let bounds = vec![limit(Mint::SOL, 4, 4)];
        let exact_case =
            |name: &str, opening: &ApprovalOpening, limits, seen, verdict: &str| CoSignerCase {
                name: name.to_owned(),
                accepts: 0,
                opening: Some(opening.clone()),
                limits,
                seen_blinders: seen,
                message: message.clone().into(),
                verdict: verdict.to_owned(),
            };
        let threshold_case =
            |name: &str, accepts: u8, message: &[u8], verdict: &str| CoSignerCase {
                name: name.to_owned(),
                accepts,
                opening: None,
                limits: Vec::new(),
                seen_blinders: Vec::new(),
                message: message.to_vec().into(),
                verdict: verdict.to_owned(),
            };
        let fresh = CoSignerMessages {
            description: "One relayed anonymous transfer an outside co-signer signs, read by \
                          proven bits or by an opening of the frame's approval digest. Each \
                          verdict names the MessageMismatch the Rust and TypeScript checks \
                          return, no case opens a slot. Frames carry zeroed proofs."
                .to_owned(),
            ring: SerializablePubkey(ring().program_id()),
            fee_payer: SerializablePubkey(FEE_PAYER),
            signer: SerializablePubkey(address(&co_signer)),
            cases: vec![
                exact_case("exactHonest", &opening, bounds, Vec::new(), "Accepted"),
                exact_case(
                    "falseOpening",
                    &false_opening,
                    vec![limit(Mint::SOL, 4, 4)],
                    Vec::new(),
                    "FalseApprovalOpening",
                ),
                exact_case(
                    "reusedBlinder",
                    &opening,
                    vec![limit(Mint::SOL, 4, 4)],
                    vec![opening.blinder.clone()],
                    "ReusedApprovalBlinder",
                ),
                exact_case(
                    "peakOverLimit",
                    &opening,
                    vec![limit(Mint::SOL, 3, 4)],
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                exact_case(
                    "outflowOverLimit",
                    &opening,
                    vec![limit(Mint::SOL, 4, 3)],
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                exact_case(
                    "noLimit",
                    &opening,
                    Vec::new(),
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                CoSignerCase {
                    message: plain_message.clone().into(),
                    ..exact_case(
                        "missingDigest",
                        &opening,
                        vec![limit(Mint::SOL, 4, 4)],
                        Vec::new(),
                        "MissingApprovalDigest",
                    )
                },
                threshold_case("thresholdHonest", 0, &plain_message, "Accepted"),
                threshold_case("thresholdWithDigest", 0, &message, "Accepted"),
                threshold_case(
                    "maskUnaccepted",
                    0,
                    &masked_message,
                    "ApprovalMaskUnaccepted",
                ),
                threshold_case(
                    "maskAccepted",
                    ApprovalMask::OUTFLOW.bits(),
                    &masked_message,
                    "Accepted",
                ),
                CoSignerCase {
                    message: through_message.clone().into(),
                    ..exact_case(
                        "grossAtLimit",
                        &through_opening,
                        gross_limits(GROSS),
                        Vec::new(),
                        "Accepted",
                    )
                },
                CoSignerCase {
                    message: through_message.clone().into(),
                    ..exact_case(
                        "grossOverLimit",
                        &through_opening,
                        gross_limits(GROSS - 1),
                        Vec::new(),
                        "ApprovalOverLimit",
                    )
                },
                threshold_case("coSignerFundsLeg", 0, &funded_message, "Accounts"),
                threshold_case("coSignerInOwnerRun", 0, &owning_message, "Accounts"),
            ],
        };
        let vector = crate::tests::support::pinned_vector("relay_co_signer_messages.json", fresh);
        for case in &vector.cases {
            let pending = co_signer_pending(
                &disclosed.relay_id,
                case.message.0.clone(),
                vector.signer.0,
                case.rule(),
                &config,
            );
            let checked = match pending.verify(vector.signer.0) {
                Ok(verified) => Ok(verified),
                Err(RingError::RelayMessage(mismatch)) => Err(mismatch),
                Err(other) => panic!("{}: {other:?}", case.name),
            };
            assert_eq!(
                crate::tests::support::verdict(checked),
                case.verdict,
                "{}",
                case.name
            );
        }

        let rule = vector.cases[0].rule();
        let pending = co_signer_pending(
            &disclosed.relay_id,
            vector.cases[0].message.0.clone(),
            vector.signer.0,
            rule,
            &config,
        );
        signs(&pending, &co_signer).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);
    }

    #[tokio::test]
    async fn an_exact_co_signer_of_a_relayed_in_proof_transfer_signs_and_each_attempt_draws_afresh()
    {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Confidential,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let attempt = || {
            let mut transaction = ConfidentialTransaction::new_with_ring(
                vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
                FEE_PAYER,
                ring().program_id(),
            )
            .unwrap();
            transaction
                .transfer_with_ring(
                    &payee.shielded_address().unwrap(),
                    Mint::SOL,
                    4,
                    Some(ring().program_id()),
                )
                .unwrap();
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender: &sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
            .with_co_signer(address(&co_signer))
            .with_exact_approval()
            .with_in_proof_owner(&sender.signing_key)
        };
        let first = attempt();
        let asked = sent(
            first
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let opening = asked.pending.approval_opening().unwrap().clone();
        let again = attempt();
        let retried = sent(
            again
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        assert_ne!(
            opening.blinder,
            retried.pending.approval_opening().unwrap().blinder
        );
        let built = frame(&client, &asked.request).await;
        let rule = CoSignerRule::Exact(ExactApproval {
            opening: opening.clone(),
            limits: vec![ApprovalLimit {
                mint: Mint::SOL.asset,
                peak: 4,
                outflow: 4,
                gross: 0,
            }],
            seen_blinders: Vec::new(),
        });
        signs(
            &co_signer_pending(
                &asked.relay_id,
                relay_message(&FEE_PAYER, &[built], UNITS).0,
                address(&co_signer),
                rule,
                &config,
            ),
            &co_signer,
        )
        .await;
    }

    async fn request_json(
        client: &crate::RingClient<Chain, Chain>,
        transfer: crate::AnonymousTransfer<'_>,
    ) -> (serde_json::Value, Option<ApprovalOpening>) {
        let assembled = transfer.assemble(client).await.unwrap();
        let request = assembled.request().unwrap();
        (
            serde_json::to_value(&*request.body).unwrap(),
            assembled.frame.approval_opening.clone(),
        )
    }

    /// `prover/ring/params.go` reads both fields, a plain frame sends neither.
    #[tokio::test]
    async fn the_prover_request_names_the_digest_only_when_the_frame_discloses() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let build = || {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 4))
                .unwrap()
        };
        let (plain, none) = request_json(&client, build()).await;
        assert!(none.is_none());
        assert!(plain.get("approvalTotals").is_none());
        assert!(plain.get("approvalBlinder").is_none());
        let (disclosed, opening) = request_json(&client, build().with_exact_approval()).await;
        let opening = opening.unwrap();
        assert!(disclosed["approvalTotals"].is_string());
        assert_eq!(
            disclosed["approvalBlinder"].as_str().unwrap(),
            format!("0x{}", hex::encode(opening.blinder.0))
        );
    }

    /// Padding and repeats in the rows reach no total, the frame commits one layout.
    #[tokio::test]
    async fn the_totals_read_the_same_past_padded_rows() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(pay(&payee, 4))
            .unwrap();
        let asked = sent(
            transaction
                .with_exact_approval()
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let RelayIntent::Anonymous { proof_inputs, .. } = &asked.request.intent else {
            panic!("the anonymous intent");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        let owner = sender.signing_pubkey().owner_proof_input_hash().unwrap();
        let assets = [[0; 32]; spr_interface::N_PUBLIC_SLOTS];
        let gross = [0; spr_interface::N_PUBLIC_SLOTS];
        let totals = |senders: &[[u8; 32]]| {
            crate::limits::Outflows {
                senders,
                inputs: &inputs.inputs,
                outputs: &inputs.outputs,
                public_assets: &assets,
                public_gross: &gross,
            }
            .approval_totals(inputs.outputs.len())
            .unwrap()
        };
        assert_eq!(
            totals(&[owner]).commitment(&[7; 32]).unwrap(),
            totals(&[owner, [0; 32], owner, [0; 32]])
                .commitment(&[7; 32])
                .unwrap()
        );
    }
}

mod request_fixtures {
    //! Requests the normal SDK path writes, `prover/ring` solves each with no key.

    use custom_ring_interface::key_catalog::RingCircuit;
    use custom_ring_interface::stream::DeliveredSlot;
    use spr_keypair::{random_blinding, ShieldedKeypair, X25519Pubkey};
    use spr_transaction::{Data, Utxo};

    use super::public_signers::{assembled, chain, pay, quote, sent, transfer};
    use super::*;
    use crate::{
        relay_message::ApprovalOpening,
        tests::support::{wallet, TREE_ID},
    };

    /// `UPDATE_PROVER_JSON=1` writes the file, `TestGoldenRequestsAssignTheRecordedWitness` solves what it holds.
    fn pinned(
        name: &str,
        assembled: &crate::pipeline::Assembled,
    ) -> (serde_json::Value, RingCircuit) {
        let request = assembled.request().unwrap();
        let built = serde_json::to_value(
            crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
        )
        .unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/custom-ring-transfer-{name}.json"));
        if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
            std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
        }
        assert!(path.exists());
        (built, request.circuit)
    }

    /// The first message, opened under the sender's viewing key at the index past every slot.
    fn sender_bundle(
        assembled: &crate::pipeline::Assembled,
        sender: &ShieldedKeypair,
    ) -> custom_ring_interface::SenderBundle {
        let inputs = &assembled.frame.proof_inputs;
        let external = &inputs.external_data;
        let layout = custom_ring_interface::BundleLayout {
            outputs: external.outputs.len(),
        };
        let tx_viewing_pk = X25519Pubkey::from_bytes(external.tx_viewing_pk).unwrap();
        let secret = DeliveredSlot {
            agreement: &sender.viewing_key.ecdh(&tx_viewing_pk).unwrap(),
            tx_viewing_pk: tx_viewing_pk.as_bytes(),
            recipient_viewing_pk: sender.viewing_pubkey().as_bytes(),
            salt: &external.salt,
            output_index: layout.outputs as u32,
            first_nullifier: &inputs.input_utxos[0].nullifier(),
        }
        .secret()
        .unwrap();
        let body =
            custom_ring_interface::ring_sender_bundle_output_body(&external.messages[0].data)
                .unwrap();
        zolana_ring_transaction::open_sender_bundle(body, &secret, layout).unwrap()
    }

    fn assert_opens(built: &serde_json::Value, opening: &ApprovalOpening) {
        let digest = built["approvalTotals"].as_str().unwrap();
        assert_eq!(
            built["approvalBlinder"].as_str().unwrap(),
            format!("0x{}", hex::encode(opening.blinder.0))
        );
        assert_eq!(digest.len(), 66);
        assert_ne!(digest, format!("0x{}", hex::encode([0; 32])));
    }

    #[tokio::test]
    async fn an_exact_approval_writes_a_digest_its_opening_rebuilds_on_both_paths() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let build = || {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_exact_approval()
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 4))
                .unwrap()
        };
        let direct = build().assemble(&client).await.unwrap();
        let (built, _) = pinned("exact-approval", &direct);
        assert_opens(&built, direct.frame.approval_opening.as_ref().unwrap());

        let relay = build();
        let asked = sent(
            relay
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let opening = asked.pending.approval_opening().unwrap().clone();
        let relayed = assembled(&client, &asked.request).await;
        let (built, _) = pinned("relayed-exact-approval", &relayed);
        assert_opens(&built, &opening);
        assert_eq!(relayed.frame.approval_opening.as_ref(), Some(&opening));
    }

    /// A default note of 40 enters 25, the sender's 15 returns into the ring.
    #[tokio::test]
    async fn an_anonymous_entry_returns_its_change_into_the_ring_on_both_paths() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let entry = wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 40,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            TREE_ID,
            0,
        );
        let build = || {
            transfer(&sender, vec![entry.clone()])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 25))
                .unwrap()
        };
        let ring_id = ring().program_id();
        let check = |assembled: &crate::pipeline::Assembled, circuit: RingCircuit| {
            let RingCircuit::Transfer { entry, .. } = circuit else {
                panic!("a transfer key");
            };
            assert!(entry);
            let outputs = &assembled.frame.proof_inputs.output_utxos;
            let live: Vec<_> = outputs
                .iter()
                .filter(|output| !output.is_dummy())
                .map(|output| (output.owner_address, output.ring_program_id, output.amount))
                .collect();
            assert_eq!(
                live,
                [
                    (sender.shielded_address().ok(), Some(ring_id), 15),
                    (payee.shielded_address().ok(), Some(ring_id), 25),
                ]
            );
            let bundle = sender_bundle(assembled, &sender);
            assert_eq!(bundle.recipient_keys[0], sender.viewing_pubkey().u());
            assert_eq!(bundle.recipient_keys[1], payee.viewing_pubkey().u());
        };
        let direct = build().assemble(&client).await.unwrap();
        let (_, circuit) = pinned("anonymous-entry", &direct);
        check(&direct, circuit);

        let relay = build();
        let asked = sent(
            relay
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap()
                .sign()
                .unwrap(),
        )
        .await;
        let relayed = assembled(&client, &asked.request).await;
        let (_, circuit) = pinned("relayed-anonymous-entry", &relayed);
        check(&relayed, circuit);
    }
}

mod enroll_message {
    //! The enrollment an owner with no SOL signs, read against what it proved.

    use solana_instruction::Instruction;
    use solana_signer::Signer;
    use zolana_ring_client::rpc::{RelayEnrollInputs, ENROLL_COMPUTE_UNITS};

    use super::*;
    use crate::{
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        EnrollInstruction, EnrollRelay, MessageMismatch, RelaySent,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const REGISTRY: Address = Address::new_from_array([0x55; 32]);

    fn inputs(owner: Address) -> RelayEnrollInputs {
        RelayEnrollInputs {
            ring_program_id: ring().program_id(),
            owner,
            tracking_registry: REGISTRY,
            instruction_data: vec![
                custom_ring_interface::storage_instruction::tag::ENROLL,
                1,
                2,
            ],
        }
    }

    async fn signed(answer: Instruction) -> Result<RelayStatus, RingError> {
        let owner = keypair(1);
        let quote = RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: u64::MAX,
        };
        let relay = StubRelay {
            asks_signature: true,
            message: relay_message(&FEE_PAYER, &[answer], ENROLL_COMPUTE_UNITS).0,
            ..StubRelay::default()
        };
        let prepared = EnrollRelay {
            inputs: inputs(owner.pubkey()),
            owner: &owner,
        }
        .prepare(quote)
        .unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the owner signs the enrollment");
        };
        pending.sign(&relay, &owner).await
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct EnrollRequest {
        ring_program_id: SerializablePubkey,
        owner: SerializablePubkey,
        tracking_registry: SerializablePubkey,
        instruction_data: spr_indexer_api::Base64String,
        fee_payer: SerializablePubkey,
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[test]
    fn the_shared_enroll_messages_keep_their_verdicts() {
        let owner = keypair(1).pubkey();
        let asked = inputs(owner);
        let honest = asked.instruction(FEE_PAYER);
        let mut swapped = honest.clone();
        swapped.accounts[2].pubkey = Address::new_from_array([0x56; 32]);
        let mut rewritten = honest.clone();
        rewritten.data[1] ^= 1;
        let case = |name: &str, payer: &Address, answer: Instruction, verdict: &str| MessageCase {
            name: name.to_owned(),
            message: relay_message(payer, &[answer], ENROLL_COMPUTE_UNITS),
            verdict: verdict.to_owned(),
        };
        let fresh = MessageVector {
            description: "One relayed enrollment the owner proved and signed, and the messages \
                          Ring RPC could answer with. Each verdict names the MessageMismatch the \
                          Rust ExpectedEnroll and the TypeScript check return."
                .to_owned(),
            request: EnrollRequest {
                ring_program_id: SerializablePubkey(asked.ring_program_id),
                owner: SerializablePubkey(asked.owner),
                tracking_registry: SerializablePubkey(asked.tracking_registry),
                instruction_data: asked.instruction_data.clone().into(),
                fee_payer: SerializablePubkey(FEE_PAYER),
            },
            cases: vec![
                case("honest", &FEE_PAYER, honest.clone(), "Accepted"),
                case("swappedRegistry", &FEE_PAYER, swapped, "Accounts"),
                case("rewrittenData", &FEE_PAYER, rewritten, "Data"),
                case("ownerPaysFee", &owner, honest, "FeePayer"),
            ],
        };
        let vector = pinned_vector("relay_enroll_messages.json", fresh);
        let expected = crate::relay_message::ExpectedEnroll {
            fee_payer: vector.request.fee_payer.0,
            inputs: RelayEnrollInputs {
                ring_program_id: vector.request.ring_program_id.0,
                owner: vector.request.owner.0,
                tracking_registry: vector.request.tracking_registry.0,
                instruction_data: vector.request.instruction_data.0.clone(),
            },
        };
        assert_eq!(vector.cases.len(), 4);
        for case in &vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
    }

    #[tokio::test]
    async fn the_enrollment_the_owner_proved_is_signed() {
        let honest = inputs(keypair(1).pubkey()).instruction(FEE_PAYER);
        assert!(matches!(
            signed(honest.clone()).await,
            Ok(RelayStatus::Sent { .. })
        ));
        let built = EnrollInstruction {
            payer: FEE_PAYER,
            owner: keypair(1).pubkey(),
            tracking_registry: REGISTRY,
            request: Vec::new(),
        }
        .instruction();
        assert_eq!(honest.accounts, built.accounts);
        assert_eq!(honest.program_id, built.program_id);
    }

    #[tokio::test]
    async fn a_relay_that_swaps_an_account_or_a_byte_is_refused() {
        let honest = inputs(keypair(1).pubkey()).instruction(FEE_PAYER);
        let mut swapped = honest.clone();
        swapped.accounts[2].pubkey = Address::new_from_array([0x56; 32]);
        assert!(matches!(
            signed(swapped).await,
            Err(RingError::RelayMessage(MessageMismatch::Accounts))
        ));
        let mut rewritten = honest;
        rewritten.data[1] ^= 1;
        assert!(matches!(
            signed(rewritten).await,
            Err(RingError::RelayMessage(MessageMismatch::Data))
        ));
    }
}

#[tokio::test]
async fn each_owner_charge_reads_before_the_owner_signs_the_relay() {
    let (sender, recipient) = (keypair(1), keypair(2));
    let chain = anonymous_chain(&sender, &recipient);
    let transfer = anonymous_payment(&sender, &recipient);
    let unsigned = transfer.prepare_relay(&chain, relay_quote()).await.unwrap();
    let owner = sender
        .shielded_address()
        .unwrap()
        .signing_pubkey
        .owner_proof_input_hash()
        .unwrap();
    let charged: Vec<_> = unsigned
        .charged_outflows()
        .iter()
        .map(|flow| (flow.owner, flow.debit, flow.charge, flow.charged_outflow))
        .collect();
    assert_eq!(charged, [(owner, 4, 0, 4)]);
    let shown = unsigned.charged_outflows().to_vec();
    assert_eq!(unsigned.sign().unwrap().charged_outflows(), shown);
}

#[tokio::test]
async fn a_relay_resent_after_a_lost_answer_reconciles_by_its_id() {
    let (sender, recipient) = (keypair(1), keypair(2));
    let chain = anonymous_chain(&sender, &recipient);
    let prepared = anonymous_payment(&sender, &recipient)
        .prepare_relay(&chain, relay_quote())
        .await
        .unwrap()
        .sign()
        .unwrap();
    let relay = LostAnswer::default();
    assert!(prepared.send(&relay).await.is_err());
    let resent = prepared.send(&relay).await.unwrap().submitted().unwrap();
    assert_eq!(resent, prepared.relay_id().unwrap());
    assert_eq!(*relay.prepared.lock().unwrap(), 1);
}
