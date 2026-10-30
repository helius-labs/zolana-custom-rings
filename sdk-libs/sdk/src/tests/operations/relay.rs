//! Relayed transfers against a stub Ring RPC.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_indexer_api::SerializablePubkey;
use spr_transaction::{instructions::transact::ConfidentialTransaction, Mint};
use zolana_ring_client::{
    rpc::{
        GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
        PrepareRelayRequest, RelayIntent, RelayProofInputs, RelayQuote, RelayStatus, RelayStep,
        SubmitRelayRequest, TokenAccountSetup,
    },
    FirstContact,
};
use zolana_ring_keys::RingAddress;

use crate::tests::{
    pipeline_rules,
    support::{history, keypair, ring, ring_utxo, Chain, Registry, RingSettings},
};
use crate::{AnonymousPayment, CustomRingTransfer, CustomRingTransferInput, RingError, RingRelay};

#[derive(Default)]
struct StubRelay {
    prepared: Mutex<Vec<PrepareRelayRequest>>,
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
        Ok(RelayStep::Submitted { relay_id })
    }

    async fn prepare_authority_transfer(
        &self,
        _request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError> {
        unreachable!("the wallet names no delegate")
    }

    async fn submit_relay(&self, _request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        unreachable!("a wallet relay signs inside the proof")
    }

    async fn get_relay_status(
        &self,
        _request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError> {
        unreachable!("the test reads no status")
    }
}

#[tokio::test]
async fn an_anonymous_relay_sends_no_path_or_record_request_and_signs_the_message_hash() {
    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Anonymous)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&recipient, 1)]),
        &pipeline_rules(),
    );
    let state = history(&sender);
    let transaction = ConfidentialTransaction::new_with_ring(
        vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
        fee_payer,
        ring().program_id(),
    )
    .unwrap();
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_anonymous_signer(&sender.signing_key, &state)
    .with_payment(AnonymousPayment {
        to: RingAddress {
            recipient: recipient.shielded_address().unwrap(),
            ring_program_id: ring().program_id(),
        },
        first_contact: FirstContact::Bootstrap,
        asset: Mint::SOL,
        amount: 4,
    })
    .unwrap();
    let quote = RelayQuote {
        fee_payer: SerializablePubkey(fee_payer),
        valid_until_slot: u64::MAX,
    };
    let relay = StubRelay::default();
    let relay_id = transfer
        .prepare_relay(&chain, quote)
        .await
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();

    assert!(chain.proof_requests.lock().unwrap().is_empty());
    assert!(chain.witness_requests.lock().unwrap().is_empty());
    assert!(chain.record_requests.lock().unwrap().is_empty());
    let prepared = relay.prepared.lock().unwrap();
    let [request] = prepared.as_slice() else {
        panic!("one prepareRelay call");
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

mod delegate_message {
    //! The transfer a delegate signs, refused when it pays an unnamed owner or charges the delegate.

    use std::sync::Mutex;

    use custom_ring_interface::{
        compute_unit_limit, tag, InstructionTag, PolicyProof, PolicyRecipients, RingRail,
        RingTransactData,
    };
    use solana_instruction::Instruction;
    use solana_signer::Signer;
    use spr_indexer_api::{Base64String, SerializableSignature};
    use spr_keypair::ShieldedKeypair;
    use spr_transaction::{AssetRegistry, WalletUtxo};
    use zolana_ring_client::rpc::{
        AuthorityPayment, AuthorityTransfer, SerializableShieldedAddress,
    };

    use super::*;
    use crate::{
        relay_message::ExpectedDelegate,
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        DelegateMove, DelegatePayment, MessageMismatch, PreparedAuthorityTransfer, RelaySent,
        RelayedTransferInput, RingTransfer,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::AuthorityTransfer);
    const MOVED: u64 = 4;

    #[derive(Clone, Copy)]
    enum Answer {
        Honest,
        SwappedRecipient,
        ChangeToStranger,
        DelegateWritable,
        ExtraSystemTransfer,
        DelegatePaysFee,
    }

    impl Answer {
        const ALL: [Self; 6] = [
            Self::Honest,
            Self::SwappedRecipient,
            Self::ChangeToStranger,
            Self::DelegateWritable,
            Self::ExtraSystemTransfer,
            Self::DelegatePaysFee,
        ];

        /// Fixed here, never read back from the check.
        fn case(self) -> (&'static str, &'static str) {
            match self {
                Self::Honest => ("honest", "Accepted"),
                Self::SwappedRecipient => ("swappedRecipient", "Recipients"),
                Self::ChangeToStranger => ("changeToStranger", "Recipients"),
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
                Self::ChangeToStranger => send(paying(honest, 1, stranger)),
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

    /// The honest data with output `slot` published as paying `owner`.
    fn paying(honest: &Instruction, slot: usize, owner: [u8; 32]) -> Instruction {
        let parsed = RingTransactData::parse(&honest.data[1..], RingRail::Delegate).unwrap();
        let mut data = parsed.into_data();
        let mut recipients = data.policy_recipients().unwrap();
        recipients[slot] = owner;
        let policy = data.policy.unwrap();
        data.policy = Some(PolicyProof {
            recipients: PolicyRecipients::Framed(&recipients),
            ..policy
        });
        Instruction {
            data: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
            ..honest.clone()
        }
    }

    /// Ring RPC's authority transfer path without its proof, answering with one `Answer`.
    struct DelegateRelay {
        client: crate::RingClient<Chain, Chain>,
        member: ShieldedKeypair,
        delegate: Address,
        notes: Vec<WalletUtxo>,
        answer: Answer,
        honest: Mutex<Option<Instruction>>,
        submitted: Mutex<Vec<SubmitRelayRequest>>,
    }

    impl DelegateRelay {
        fn new(answer: Answer, delegate: Address) -> Self {
            let member = keypair(1);
            let chain = Chain::ring(RingSettings {
                has_policy: true,
                delegate: Some(delegate),
                ..RingSettings::new(RingMode::ConfidentialEscrow)
            })
            .with_registry(
                Registry::new(&[(&member, 1), (&keypair(2), 1)]),
                &pipeline_rules(),
            );
            Self {
                client: chain.client(),
                notes: vec![ring_utxo(&member, Mint::SOL, 10, 0)],
                member,
                delegate,
                answer,
                honest: Mutex::new(None),
                submitted: Mutex::new(Vec::new()),
            }
        }

        /// `seal_delegate` then `prove` as `SdkRelayProver` runs them, the proofs zeroed.
        async fn build(&self, transfer: &AuthorityTransfer) -> Result<Instruction, RingError> {
            let assets = AssetRegistry::default();
            let proof_inputs = DelegateMove {
                ring: ring(),
                delegate: self.delegate,
                payer: FEE_PAYER,
                source: transfer.source.0,
                source_nullifier_key: &self.member.nullifier_key,
                utxos: &self.notes,
                mint: transfer.mint.0,
                payments: transfer
                    .payments
                    .iter()
                    .map(|payment| DelegatePayment {
                        recipient: payment.recipient.0,
                        amount: payment.amount,
                    })
                    .collect(),
                assets: &assets,
                co_signer: None,
            }
            .select(&self.client)
            .await?
            .relay_proof_inputs(self.client.zolana())
            .await?;
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
            let honest = self.build(&request.transfer).await?;
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
            let signature = request.signature.clone();
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
                source: SerializableShieldedAddress(keypair(1).shielded_address().unwrap()),
                mint: SerializablePubkey(Mint::SOL.asset),
                payments: vec![AuthorityPayment {
                    recipient: SerializableShieldedAddress(keypair(2).shielded_address().unwrap()),
                    amount: MOVED,
                }],
            },
            timestamp: 0,
            nonce: Base64String(vec![4; 32]),
            signature: SerializableSignature(Default::default()),
        }
    }

    async fn relayed_signature(answer: Answer) -> (DelegateRelay, Result<RelayStatus, RingError>) {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(answer, delegate.pubkey());
        let prepared =
            PreparedAuthorityTransfer::new(request(delegate.pubkey()), &quote()).unwrap();
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

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DelegateRequest {
        prepare: PrepareAuthorityTransferRequest,
        fee_payer: SerializablePubkey,
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[tokio::test]
    async fn the_shared_delegate_messages_keep_their_verdicts() {
        let (relay, signed) = relayed_signature(Answer::Honest).await;
        signed.unwrap();
        let honest = relay.honest.lock().unwrap().clone().unwrap();
        let fresh = MessageVector {
            description: "One authority transfer the ring delegate asks Ring RPC for, moving 4 \
                          of the member's SOL to a second member with the change back, and the \
                          messages Ring RPC could answer with. The honest message is the relay's \
                          delegate path with zeroed proofs, each other case changes one thing. \
                          verdict names the MessageMismatch the Rust ExpectedDelegate::check and \
                          the TypeScript checkDelegateMessage return."
                .to_owned(),
            request: DelegateRequest {
                prepare: request(relay.delegate),
                fee_payer: SerializablePubkey(FEE_PAYER),
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
                .into(),
        };
        let vector = pinned_vector("relay_delegate_messages.json", fresh);
        let quote = RelayQuote {
            fee_payer: vector.request.fee_payer,
            valid_until_slot: 0,
        };
        let expected = ExpectedDelegate::new(&vector.request.prepare, &quote).unwrap();
        assert_eq!(vector.cases.len(), Answer::ALL.len());
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
