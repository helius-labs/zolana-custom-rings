use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use solana_address::Address;
use spr_interface::pda;
use zolana_ring_client::{FirstContact, PaymentRecipient, StreamCounter, TransferTagging};
use zolana_ring_keys::RingAddress;

use crate::{
    tests::support::{
        history, keypair, owner_identity, ring, Chain, Registry, RingSettings, TREE_ID,
    },
    DepositAsset, DepositRecipient, RingDeposit, RingError,
};

fn deposit<'a>(
    payer: &'a (dyn solana_signer::Signer + Sync),
    recipient: DepositRecipient<'a>,
) -> RingDeposit<'a> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient,
        tree: pda::tree(TREE_ID),
        asset: DepositAsset::Sol,
        amount: 5,
        cosigner: None,
    }
}

#[tokio::test]
async fn an_anonymous_ring_takes_deposits_only_for_the_depositors_hidden_owner() {
    let member = keypair(1);
    let payer = keypair(9);
    let anonymous = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let confidential = Chain::ring(RingSettings::new(RingMode::Confidential));
    let address = member.shielded_address().unwrap();
    let history = history(&member);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        history: &history,
    };
    assert!(matches!(
        deposit(&payer, DepositRecipient::Confidential(address))
            .prepare(&anonymous)
            .await,
        Err(RingError::Program(CustomRingError::AnonymousRingRefused))
    ));
    assert!(matches!(
        deposit(&payer, hidden).prepare(&confidential).await,
        Err(RingError::NotAnonymousRing)
    ));
    assert!(matches!(
        deposit(&member, hidden).prepare(&anonymous).await,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let prepared = deposit(&payer, hidden).prepare(&anonymous).await.unwrap();
    assert_eq!(
        (prepared.utxo().owner, prepared.utxo().amount),
        (member.signing_pubkey(), 5)
    );
}

#[tokio::test]
async fn an_escrowed_ring_refuses_a_deposit_to_a_member_without_an_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&registered, 1)]),
        &crate::tests::pipeline_rules(),
    );
    let client = chain.client();
    let prepared = deposit(
        &payer,
        DepositRecipient::Confidential(stranger.shielded_address().unwrap()),
    )
    .prepare(client.zolana())
    .await
    .unwrap();
    let owner = owner_identity(&stranger);
    assert!(matches!(
        prepared.prove(&client).await,
        Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
    ));
}

#[tokio::test]
async fn a_deposit_names_the_co_signer_a_deposit_scope_demands() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let chain = Chain::ring(RingSettings {
        co_signer: Some((
            solana_signer::Signer::pubkey(&co_signer),
            CoSignScope::DEPOSITS,
        )),
        ..RingSettings::new(RingMode::Confidential)
    });
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    assert!(matches!(
        deposit(&payer, recipient).prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
    let named = RingDeposit {
        cosigner: Some(&co_signer),
        ..deposit(&payer, recipient)
    };
    assert!(named.prepare(&chain).await.is_ok());
    let stranger = keypair(7);
    let wrong = RingDeposit {
        cosigner: Some(&stranger),
        ..deposit(&payer, recipient)
    };
    assert!(matches!(
        wrong.prepare(&chain).await,
        Err(RingError::Program(CustomRingError::InvalidCoSignerRecord))
    ));
}

#[tokio::test]
async fn a_co_signer_outside_the_deposit_scope_does_not_sign() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    for (scope, signs) in [
        (CoSignScope::WITHDRAWALS, false),
        (CoSignScope::DEPOSITS, true),
    ] {
        let chain = Chain::ring(RingSettings {
            co_signer: Some((solana_signer::Signer::pubkey(&co_signer), scope)),
            ..RingSettings::new(RingMode::Confidential)
        });
        let named = RingDeposit {
            cosigner: Some(&co_signer),
            ..deposit(&payer, recipient)
        };
        let prepared = named.prepare(&chain).await.unwrap();
        assert_eq!(named.signers(&prepared).len(), 1 + usize::from(signs));
    }
}

fn publishes(prepared: &crate::PreparedRingDeposit, tag: &[u8; 32]) -> bool {
    prepared
        .spp
        .data
        .windows(tag.len())
        .any(|bytes| bytes == tag)
}

#[tokio::test]
async fn an_own_deposit_takes_the_sender_tag_at_tx_count_and_advances_it() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let hidden = deposit(
        &payer,
        DepositRecipient::Anonymous {
            keys: &member,
            history: &history,
        },
    );
    let prepared = hidden.prepare(&chain).await.unwrap();
    assert!(publishes(
        &prepared,
        &member.get_sender_view_tag(0).unwrap()
    ));
    let advanced = prepared.viewing_history().unwrap();
    assert_eq!(advanced.current().tx_count(), 1);
    assert_eq!(hidden.viewing_history().unwrap().as_ref(), Some(advanced));
}

#[tokio::test]
async fn a_deposit_from_the_stored_history_takes_the_next_sender_tag() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let own = |history| {
        deposit(
            &payer,
            DepositRecipient::Anonymous {
                keys: &member,
                history,
            },
        )
    };
    let stored = own(&history).viewing_history().unwrap().unwrap();
    let next = own(&stored).prepare(&chain).await.unwrap();
    assert!(publishes(&next, &member.get_sender_view_tag(1).unwrap()));
    assert!(!publishes(&next, &member.get_sender_view_tag(0).unwrap()));
    assert_eq!(next.viewing_history().unwrap().current().tx_count(), 2);
}

#[tokio::test]
async fn a_deposit_to_another_member_takes_a_first_contact_tag_until_a_transfer_pairs() {
    let member = keypair(1);
    let recipient = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let to = RingAddress {
        recipient: recipient.shielded_address().unwrap(),
        ring_program_id: ring().program_id(),
    };
    let request = recipient.get_recipient_request_view_tag(0).unwrap();
    let history = history(&member);
    let paid = |history, first_contact| {
        deposit(
            &payer,
            DepositRecipient::AnonymousPayment {
                keys: &member,
                history,
                to: &to,
                first_contact,
            },
        )
    };
    let bootstrap = paid(&history, FirstContact::Bootstrap)
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(&bootstrap, &recipient.viewing_pubkey().u()));
    let requested = paid(&history, FirstContact::Request(request))
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(&requested, &request));
    let unpaired = bootstrap.viewing_history().unwrap().clone();
    assert_eq!(
        unpaired.current().tx_count(),
        0,
        "a deposit spends no sender tag"
    );
    assert!(
        unpaired.current().known_recipients().is_empty(),
        "a deposit names no sender, so it pairs nothing"
    );
    let paired = TransferTagging {
        keys: &member,
        history: &unpaired,
        recipients: &[PaymentRecipient {
            viewing_pubkey: recipient.viewing_pubkey(),
            first_contact: FirstContact::Bootstrap,
        }],
    }
    .plan()
    .unwrap()
    .history;
    let shared = paid(&paired, FirstContact::Request(request))
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(
        &shared,
        &member
            .get_send_shared_view_tag(&recipient.viewing_pubkey(), 0)
            .unwrap()
    ));
    assert_eq!(
        shared
            .viewing_history()
            .unwrap()
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(1)
    );
}

#[tokio::test]
async fn a_deposit_refuses_an_address_of_another_ring() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let other = Address::new_from_array([0x47; 32]);
    let to = RingAddress {
        recipient: keypair(2).shielded_address().unwrap(),
        ring_program_id: other,
    };
    let history = history(&member);
    let paid = DepositRecipient::AnonymousPayment {
        keys: &member,
        history: &history,
        to: &to,
        first_contact: FirstContact::Bootstrap,
    };
    assert!(matches!(
        deposit(&payer, paid).prepare(&chain).await,
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == other && paid == ring().program_id()
    ));
}

mod relay_message {
    //! The deposit message a depositor signs, refused when it moves more than the request.

    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytemuck::Zeroable;
    use custom_ring_interface::{compute_unit_limit, CustomRingProof, InstructionTag};
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{legacy, VersionedMessage};
    use solana_signer::Signer;
    use spr_event::EncryptedRingDepositData;
    use spr_indexer_api::{Base64String, SerializablePubkey};
    use spr_keypair::ShieldedKeypair;
    use spr_program::instruction::{DepositAsset, RingAssetDeposit};
    use zolana_ring_client::rpc::{
        GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
        PrepareRelayRequest, RelayDepositInputs, RelayQuote, RelayStatus, RelayStep,
        SubmitRelayRequest,
    };

    use super::*;
    use crate::{
        relay_message::ExpectedDeposit,
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        CustomRing, MessageMismatch, RelaySent, RelayedDeposit, RingRelay,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::Deposit);

    #[derive(Clone, Copy)]
    enum Answer {
        Honest,
        ExtraSplTransfer,
        ExtraSystemTransfer,
        DepositorPaysFee,
        AlteredDeposit,
        DepositorInRingPrefix,
        BudgetAboveDeposit,
        ForeignProgram,
        Legacy,
        TrailingByte,
        DuplicateAddress,
        ReadonlyFeePayer,
    }

    impl Answer {
        const ALL: [Self; 12] = [
            Self::Honest,
            Self::ExtraSplTransfer,
            Self::ExtraSystemTransfer,
            Self::DepositorPaysFee,
            Self::AlteredDeposit,
            Self::DepositorInRingPrefix,
            Self::BudgetAboveDeposit,
            Self::ForeignProgram,
            Self::Legacy,
            Self::TrailingByte,
            Self::DuplicateAddress,
            Self::ReadonlyFeePayer,
        ];

        /// Fixed here, never read back from the check.
        fn case(self) -> (&'static str, &'static str) {
            match self {
                Self::Honest => ("honest", "Accepted"),
                Self::ExtraSplTransfer => ("extraSplTransfer", "Instructions"),
                Self::ExtraSystemTransfer => ("extraSystemTransfer", "Instructions"),
                Self::DepositorPaysFee => ("depositorPaysFee", "FeePayer"),
                Self::AlteredDeposit => ("alteredDeposit", "Data"),
                Self::DepositorInRingPrefix => ("depositorInRingPrefix", "Accounts"),
                Self::BudgetAboveDeposit => ("budgetAboveDeposit", "Budget"),
                Self::ForeignProgram => ("foreignProgram", "Program"),
                Self::Legacy => ("legacy", "NotV1"),
                Self::TrailingByte => ("trailingByte", "Undecodable"),
                Self::DuplicateAddress => ("duplicateAddress", "Undecodable"),
                Self::ReadonlyFeePayer => ("readonlyFeePayer", "Undecodable"),
            }
        }

        fn message(self, honest: &Instruction, depositor: Address) -> Base64String {
            let taken = Address::new_from_array([0x63; 32]);
            let with =
                |extra: Instruction| relay_message(&FEE_PAYER, &[honest.clone(), extra], UNITS);
            match self {
                Self::Honest => relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS),
                Self::ExtraSplTransfer => with(
                    spl_token_2022_interface::instruction::transfer_checked(
                        &spl_token_2022_interface::ID,
                        &Address::new_from_array([0x61; 32]),
                        &Address::new_from_array([0x62; 32]),
                        &taken,
                        &depositor,
                        &[],
                        1_000,
                        6,
                    )
                    .unwrap(),
                ),
                Self::ExtraSystemTransfer => with(solana_system_interface::instruction::transfer(
                    &depositor, &taken, 1_000,
                )),
                Self::DepositorPaysFee => {
                    relay_message(&depositor, std::slice::from_ref(honest), UNITS)
                }
                Self::AlteredDeposit => {
                    let mut altered = honest.clone();
                    *altered.data.last_mut().unwrap() ^= 1;
                    relay_message(&FEE_PAYER, &[altered], UNITS)
                }
                Self::DepositorInRingPrefix => {
                    let mut widened = honest.clone();
                    widened
                        .accounts
                        .insert(1, AccountMeta::new_readonly(depositor, false));
                    relay_message(&FEE_PAYER, &[widened], UNITS)
                }
                Self::BudgetAboveDeposit => {
                    relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS + 1)
                }
                Self::ForeignProgram => {
                    let foreign = Instruction {
                        program_id: Address::new_from_array([0x64; 32]),
                        ..honest.clone()
                    };
                    relay_message(&FEE_PAYER, &[foreign], UNITS)
                }
                Self::Legacy => VersionedMessage::Legacy(legacy::Message::new(
                    std::slice::from_ref(honest),
                    Some(&FEE_PAYER),
                ))
                .serialize()
                .into(),
                Self::TrailingByte => {
                    let mut bytes =
                        relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS).0;
                    bytes.push(0);
                    bytes.into()
                }
                Self::DuplicateAddress | Self::ReadonlyFeePayer => {
                    let honest = relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS);
                    let Ok(VersionedMessage::V1(mut message)) = wincode::deserialize(&honest.0)
                    else {
                        unreachable!("the relay compiles v1 messages");
                    };
                    match self {
                        Self::DuplicateAddress => message.account_keys.push(depositor),
                        _ => {
                            message.header.num_readonly_signed_accounts =
                                message.header.num_required_signatures
                        }
                    }
                    message.serialize().into()
                }
            }
        }
    }

    /// Ring RPC's deposit path without its proof, answering with one `Answer`.
    struct DepositRelay {
        chain: Chain,
        answer: Answer,
        honest: Mutex<Option<(Instruction, RelayDepositInputs)>>,
        submitted: Mutex<Vec<SubmitRelayRequest>>,
    }

    impl DepositRelay {
        fn new(answer: Answer) -> Self {
            Self {
                chain: Chain::ring(RingSettings::new(RingMode::Confidential)),
                answer,
                honest: Mutex::new(None),
                submitted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RingRelay for DepositRelay {
        async fn get_relay_quote(
            &self,
            _request: GetRelayQuoteRequest,
        ) -> Result<RelayQuote, RingError> {
            unreachable!("the test holds its quote")
        }

        async fn prepare_relay(
            &self,
            request: PrepareRelayRequest,
        ) -> Result<RelayStep, RingError> {
            let inputs = RelayDepositInputs::decode(request.intent.proof_inputs().as_bytes())?;
            let honest = RelayedDeposit {
                ring: ring(),
                inputs: &inputs,
                fee_payer: FEE_PAYER,
                co_signer: None,
            }
            .prepare(&self.chain)
            .await?
            .instruction(CustomRingProof::zeroed(), None)?;
            let message = self.answer.message(&honest, inputs.depositor);
            *self.honest.lock().unwrap() = Some((honest, inputs));
            Ok(RelayStep::SignMessage {
                relay_id: request.relay_id()?,
                message,
            })
        }

        async fn prepare_authority_transfer(
            &self,
            _request: PrepareAuthorityTransferRequest,
        ) -> Result<RelayStep, RingError> {
            unreachable!("a deposit names no delegate")
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

    async fn relayed_signature(
        relay: &DepositRelay,
        depositor: &ShieldedKeypair,
    ) -> Result<RelayStatus, RingError> {
        let recipient = DepositRecipient::Confidential(keypair(1).shielded_address().unwrap());
        let quote = RelayQuote {
            fee_payer: FEE_PAYER.into(),
            valid_until_slot: 0,
        };
        let prepared = deposit(depositor, recipient)
            .prepare_relay(&relay.chain, quote)
            .await
            .unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(relay).await.unwrap() else {
            panic!("a relayed deposit waits for the depositor");
        };
        pending.sign(relay, depositor).await
    }

    #[tokio::test]
    async fn a_deposit_message_with_an_extra_spl_transfer_from_the_depositor_is_refused() {
        let relay = DepositRelay::new(Answer::ExtraSplTransfer);
        assert!(matches!(
            relayed_signature(&relay, &keypair(9)).await,
            Err(RingError::RelayMessage(MessageMismatch::Instructions))
        ));
        assert!(relay.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_deposit_message_the_relay_builds_is_signed() {
        let relay = DepositRelay::new(Answer::Honest);
        let depositor = keypair(9);
        relayed_signature(&relay, &depositor).await.unwrap();
        let honest = relay.honest.lock().unwrap().as_ref().unwrap().0.clone();
        let message = Answer::Honest.message(&honest, depositor.pubkey());
        let [submitted] = <[SubmitRelayRequest; 1]>::try_from(std::mem::take(
            &mut *relay.submitted.lock().unwrap(),
        ))
        .unwrap();
        assert_eq!(submitted.signer.0, depositor.pubkey());
        assert!(submitted
            .signature
            .0
            .verify(depositor.pubkey().as_ref(), &message.0));
    }

    /// A SOL deposit request, every field the depositor's own.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DepositRequest {
        ring: SerializablePubkey,
        fee_payer: SerializablePubkey,
        tree: SerializablePubkey,
        depositor: SerializablePubkey,
        view_tag: String,
        owner_utxo_hash: String,
        amount: u64,
        ring_data_hash: String,
        tx_viewing_pk: String,
        salt: String,
        ciphertext: Base64String,
    }

    impl DepositRequest {
        fn of(inputs: &RelayDepositInputs, owner_utxo_hash: [u8; 32]) -> Self {
            Self {
                ring: inputs.ring_program_id.into(),
                fee_payer: FEE_PAYER.into(),
                tree: inputs.tree.into(),
                depositor: inputs.depositor.into(),
                view_tag: hex::encode(inputs.view_tag),
                owner_utxo_hash: hex::encode(owner_utxo_hash),
                amount: inputs.amount,
                ring_data_hash: hex::encode([0u8; 32]),
                tx_viewing_pk: hex::encode(inputs.encrypted.tx_viewing_pk),
                salt: hex::encode(inputs.encrypted.salt),
                ciphertext: inputs.encrypted.ciphertext.clone().into(),
            }
        }

        fn expected(&self) -> ExpectedDeposit {
            let bytes = |text: &str| hex::decode(text).unwrap().try_into().unwrap();
            let deposit = RingAssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: bytes(&self.view_tag),
                owner_utxo_hash: bytes(&self.owner_utxo_hash),
                amount: self.amount,
                ring_data_hash: bytes(&self.ring_data_hash),
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: hex::decode(&self.tx_viewing_pk)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    salt: bytes16(&self.salt),
                    ciphertext: self.ciphertext.0.clone(),
                },
            };
            ExpectedDeposit {
                ring: CustomRing::new(self.ring.0),
                fee_payer: self.fee_payer.0,
                depositor: self.depositor.0,
                spp: spr_program::instruction::RingDeposit {
                    tree: self.tree.0,
                    depositor: self.depositor.0,
                    ring_program_id: self.ring.0,
                    deposits: vec![deposit],
                }
                .instruction()
                .unwrap(),
            }
        }
    }

    fn bytes16(text: &str) -> [u8; 16] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[tokio::test]
    async fn the_shared_deposit_messages_keep_their_verdicts() {
        let relay = DepositRelay::new(Answer::Honest);
        relayed_signature(&relay, &keypair(9)).await.unwrap();
        let (honest, inputs) = relay.honest.lock().unwrap().take().unwrap();
        let owner_utxo_hash = spr_transaction::owner_utxo_hash(
            &inputs.recipient.owner_hash().unwrap(),
            &custom_ring_interface::domain::deposit_blinding(&inputs.blinding_secret).unwrap(),
        )
        .unwrap();
        let fresh = MessageVector {
            description: "One relayed SOL deposit of 5 into a confidential ring and the messages \
                          Ring RPC could answer with. The honest message is the relay's deposit \
                          path with a zeroed proof, each other case changes one thing. verdict \
                          names the MessageMismatch the Rust ExpectedDeposit::check and the \
                          TypeScript checkDepositMessage return."
                .to_owned(),
            request: DepositRequest::of(&inputs, owner_utxo_hash),
            cases: Answer::ALL
                .map(|answer| {
                    let (name, verdict) = answer.case();
                    MessageCase {
                        name: name.to_owned(),
                        message: answer.message(&honest, inputs.depositor),
                        verdict: verdict.to_owned(),
                    }
                })
                .into(),
        };
        let vector = pinned_vector("relay_deposit_messages.json", fresh);
        let expected = vector.request.expected();
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
