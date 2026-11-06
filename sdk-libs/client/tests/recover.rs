#[path = "common/history_page.rs"]
pub mod history_page;
#[path = "common/origin.rs"]
mod origin_fixture;
#[path = "common/transfer.rs"]
pub mod transfer;

use custom_ring_interface::{AuditRecord, OpeningRecord, RecordKind, RingMode};
use std::{cell::Cell, sync::Mutex};

use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    GetShieldedTransactionsByTagsResponse, HistoryFilters, IndexerRpcConfig, PaginationToken,
};
use spr_event::{
    encode_merge_output_data, merge_output::MERGE_OUTPUT_CIPHERTEXT_LEN, MergeOutputDataRef,
};
use spr_hasher::primitives::right_align;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{NullifierKey, ShieldedAddress, ShieldedKeypair, ViewingKey, X25519Keypair};
use spr_transaction::{
    instructions::merge::{MergeSeed, MergeTransaction},
    Data, DataRecord, Mint, OutputContext, OutputSlot, ShieldedTransaction, SppProofOutputUtxo,
    Utxo, WalletUtxo,
};
use zolana_ring_client::{
    AuditError, ConfirmedMergeDisclosure, MemberRecovery, MergeRecordSeal, RecoveredNotes,
    RecoveryStep, RingOrigin, RingRecovery, SourceMember, TransactionOrigin,
};
use zolana_ring_transaction::RingAssets;

use history_page::EventsPage;
use transfer::{field, x25519_u, Frame, Output, Publish, Rail, Transfer, UtxoFields};

const RING: Address = Address::new_from_array([42; 32]);
const SALT: [u8; 16] = [7; 16];

struct Fixture {
    mode: RingMode,
    member: ShieldedKeypair,
    address: ShieldedAddress,
    auditor: X25519Keypair,
    sequence: Cell<u8>,
    frames: Mutex<Vec<(Signature, Vec<u8>)>>,
    merges: Mutex<Vec<(Signature, zolana_ring_client::ConfirmedMergeDisclosure)>>,
}

impl Fixture {
    fn new() -> Self {
        Self::in_mode(RingMode::Confidential)
    }

    fn anonymous() -> Self {
        Self::in_mode(RingMode::Anonymous)
    }

    fn in_mode(mode: RingMode) -> Self {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        Self {
            mode,
            address: member.shielded_address().expect("address"),
            member,
            auditor: X25519Keypair::new(),
            sequence: Cell::new(0),
            frames: Mutex::new(Vec::new()),
            merges: Mutex::new(Vec::new()),
        }
    }

    fn owner_key(&self) -> [u8; 32] {
        self.address.confidential_view_tag().expect("owner key")
    }

    fn signature(&self) -> Signature {
        let next = self.sequence.get() + 1;
        self.sequence.set(next);
        Signature::from([next; 64])
    }

    fn recovery(&self) -> MemberRecovery<'_> {
        RingRecovery::new(RING, &self.auditor)
            .with_mode(self.mode)
            .for_member(SourceMember {
                address: &self.address,
                nullifier_key: &self.member.nullifier_key,
            })
    }

    async fn run(
        &self,
        recovery: MemberRecovery<'_>,
        history: &History,
    ) -> Result<RecoveredNotes, AuditError> {
        self.step(recovery, history).await.map(complete)
    }

    async fn step(
        &self,
        recovery: MemberRecovery<'_>,
        history: &History,
    ) -> Result<RecoveryStep, AuditError> {
        *history.frames.lock().unwrap() = self.frames.lock().unwrap().clone();
        *history.merges.lock().unwrap() = self.merges.lock().unwrap().clone();
        recovery
            .run(history, history, &RingAssets::new([]).unwrap())
            .await
    }

    fn output(&self, amount: u64) -> SppProofOutputUtxo {
        SppProofOutputUtxo::new(Mint::SOL, amount, self.address)
            .expect("output")
            .with_ring_program_id(RING)
    }

    fn held(&self, output: &SppProofOutputUtxo, tree_id: u16) -> WalletUtxo {
        let hash = output.hash(tree_id).expect("commitment");
        let utxo = Utxo {
            owner: self.address.signing_pubkey,
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        };
        WalletUtxo {
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: hash,
            nullifier: utxo
                .nullifier(&hash, &self.member.nullifier_key)
                .expect("nullifier"),
            tx_viewing_key: None,
            utxo,
            data_hash: output.data_hash,
            ring_data_hash: output.ring_data_hash,
            tree_id,
            leaf_index: u64::from(self.sequence.get()),
            latest_tree_id: None,
            slot: u64::from(self.sequence.get()),
            tx_signature: Signature::from([0; 64]),
            slot_index: 0,
        }
    }

    fn encrypt(
        &self,
        output: SppProofOutputUtxo,
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        self.encrypt_beside(output, tree_id, Beside::Alone)
    }

    fn encrypt_beside(
        &self,
        output: SppProofOutputUtxo,
        tree_id: u16,
        beside: Beside,
    ) -> (WalletUtxo, ShieldedTransaction) {
        self.deliver(output, tree_id, beside, Inputs::Spent)
    }

    /// A deposit, a transfer whose every input is a dummy.
    fn deposit(
        &self,
        output: SppProofOutputUtxo,
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        self.deliver(output, tree_id, Beside::Alone, Inputs::Dummy)
    }

    /// A delivered transfer of `output` to the member, its blinding the one the ring derives.
    fn deliver(
        &self,
        mut output: SppProofOutputUtxo,
        tree_id: u16,
        beside: Beside,
        inputs: Inputs,
    ) -> (WalletUtxo, ShieldedTransaction) {
        let signature = self.signature();
        let first_nullifier = right_align(&[0x70, self.sequence.get()]);
        let transfer = Transfer {
            tx_key: ViewingKey::new(),
            ring: RING,
            first_nullifier,
            salt: SALT,
            tree_id,
            nullifiers: vec![first_nullifier],
        };
        let ring_output = Output::Ring {
            utxo: UtxoFields {
                owner_key: self.owner_key(),
                nullifier_pk: self.address.nullifier_pubkey,
                asset_address: output.asset.asset,
                amount: output.amount,
                data_hash: output.data_hash.unwrap_or_default(),
                ring_data_hash: output.ring_data_hash.unwrap_or_default(),
            },
            recipient_u: self.address.viewing_pubkey.u(),
            tag: None,
        };
        let slot = transfer.slot(0, &ring_output);
        output.blinding = slot.blinding;
        let mut held = self.held(&output, tree_id);
        held.tx_signature = signature;
        let mut published = slot.output;
        published.output_context = output_context(&held);
        let (outputs, slots) = match beside {
            Beside::Alone => {
                let mut dummy = transfer.slot(1, &Output::Dummy).output;
                dummy.output_context.leaf_index = held.leaf_index + 1;
                (vec![ring_output, Output::Dummy], vec![published, dummy])
            }
            Beside::OtherMember(other) => {
                let other = Output::Ring {
                    utxo: UtxoFields {
                        asset_address: output.asset.asset,
                        amount: 1,
                        ..other
                    },
                    recipient_u: x25519_u(0x77),
                    tag: None,
                };
                let mut paid = transfer.slot(1, &other).output;
                paid.output_context.leaf_index = held.leaf_index + 1;
                (vec![ring_output, other], vec![published, paid])
            }
        };
        let rail = match self.mode {
            RingMode::Anonymous => Rail::Anonymous,
            RingMode::Confidential => Rail::Delivered,
        };
        let mut disclosure = transfer.disclosure(rail, &outputs);
        if inputs == Inputs::Dummy {
            disclosure.real_inputs = 0;
        }
        let mut transaction = transfer.publish(Publish {
            slots,
            disclosure: &disclosure,
            auditor: &self.auditor.pubkey(),
            rail,
        });
        transaction.slot = u64::from(self.sequence.get());
        transaction.tx_signature = signature;
        let frame = transfer.frame(Frame {
            tx: &transaction,
            disclosure: &disclosure,
            rail,
        });
        self.frames.lock().unwrap().push((signature, frame));
        (held, transaction)
    }

    fn merge(&self, inputs: &[WalletUtxo], tree_id: u16) -> (WalletUtxo, ShieldedTransaction) {
        let prepared = MergeTransaction::new_with_ring(inputs.to_vec(), RING, None)
            .expect("merge")
            .with_output_tree_id(tree_id)
            .encrypt(&self.member)
            .expect("encrypt merge");
        let first = prepared
            .input_utxos
            .first()
            .expect("merge input")
            .nullifier();
        let nullifiers = prepared
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .map(|input| input.nullifier())
            .collect();
        let signature = self.signature();
        let mut held = self.held(&prepared.output_utxo, tree_id);
        held.ring_data_hash = Some(held.ring_data_hash.unwrap_or_default());
        held.tx_signature = signature;
        let transaction = ShieldedTransaction {
            slot: u64::from(self.sequence.get()),
            tx_signature: signature,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: first,
                output_context: output_context(&held),
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &prepared.output_ciphertext_salt,
                    ciphertext: &prepared.output_ciphertext,
                    prefix: &[prepared.output_utxo.ring_data_hash.unwrap_or_default()],
                }),
            }],
            messages: Vec::new(),
            nullifiers,
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        (held, transaction)
    }

    fn audited_merge(
        &self,
        inputs: &[WalletUtxo],
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        let (held, mut transaction) = self.merge(inputs, tree_id);
        let sealed = MergeRecordSeal {
            record: OpeningRecord {
                record: self.record(&held.utxo),
                secret: right_align(&self.member.nullifier_key.secret()),
            },
        }
        .seal(&self.auditor.pubkey())
        .unwrap();
        self.merges.lock().unwrap().push((
            transaction.tx_signature,
            ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                ciphertext: sealed.ciphertext,
            },
        ));
        *transaction.output_slots[0].payload.last_mut().unwrap() ^= 1;
        (held, transaction)
    }

    /// A zero-key merge under a private seed and its sealed record, its body opens under no key.
    fn zero_key_merge(&self, amount: u64, tree_id: u16) -> (ZeroKeyMerge, ShieldedTransaction) {
        let seed = field(0x5a);
        let first = field(0x61);
        let ring_data_hash = field(0x05);
        let blinding = MergeSeed::from_bytes(seed)
            .unwrap()
            .output_blinding(&first)
            .unwrap();
        let utxo = Utxo {
            owner: self.address.signing_pubkey,
            asset: Mint::SOL,
            amount,
            blinding,
            ring_program_id: Some(RING),
            data: Data::default(),
        };
        let commitment = utxo
            .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &ring_data_hash, tree_id)
            .unwrap();
        let sealed = MergeRecordSeal {
            record: OpeningRecord {
                record: AuditRecord {
                    nullifier_pk: ZERO_NULLIFIER_PUBKEY,
                    ..self.record(&utxo)
                },
                secret: seed,
            },
        }
        .seal(&self.auditor.pubkey())
        .unwrap();
        let signature = self.signature();
        self.merges.lock().unwrap().push((
            signature,
            ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                ciphertext: sealed.ciphertext,
            },
        ));
        let transaction = ShieldedTransaction {
            slot: u64::from(self.sequence.get()),
            tx_signature: signature,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: self
                    .address
                    .signing_pubkey
                    .owner_proof_input_hash()
                    .unwrap(),
                output_context: OutputContext {
                    hash: commitment,
                    tree_id,
                    leaf_index: 9,
                },
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &[3; 16],
                    ciphertext: &[[0xff; 32], [0; 32], [0; 32]],
                    prefix: &[ring_data_hash],
                }),
            }],
            messages: Vec::new(),
            nullifiers: vec![first, field(0x07)],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        let merge = ZeroKeyMerge {
            commitment,
            nullifier: NullifierKey::from_secret([0; 31])
                .nullifier(&commitment, &blinding)
                .unwrap(),
        };
        (merge, transaction)
    }

    fn record(&self, utxo: &Utxo) -> AuditRecord {
        AuditRecord {
            kind: RecordKind::Ring,
            amount: utxo.amount,
            owner_key: self.owner_key(),
            mint: utxo.asset.asset.to_bytes(),
            nullifier_pk: self.address.nullifier_pubkey,
        }
    }

    /// An anonymous transfer of `spent`, its change back to the member.
    fn anonymous_spend(
        &self,
        spent: &[&WalletUtxo],
        change: u64,
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        let signature = self.signature();
        let nullifiers: Vec<[u8; 32]> = spent.iter().map(|held| held.nullifier).collect();
        let first_nullifier = nullifiers[0];
        let transfer = Transfer {
            tx_key: ViewingKey::new(),
            ring: RING,
            first_nullifier,
            salt: SALT,
            tree_id,
            nullifiers,
        };
        let mut output = self.output(change);
        let outputs = vec![
            Output::Ring {
                utxo: UtxoFields {
                    owner_key: self.owner_key(),
                    nullifier_pk: self.address.nullifier_pubkey,
                    asset_address: output.asset.asset,
                    amount: output.amount,
                    ..UtxoFields::default()
                },
                recipient_u: self.address.viewing_pubkey.u(),
                tag: Some(field(0x5c)),
            },
            Output::Dummy,
        ];
        let slots = transfer.slots(&outputs);
        output.blinding = slots[0].blinding;
        let mut held = self.held(&output, tree_id);
        held.tx_signature = signature;
        let mut published: Vec<OutputSlot> = slots.into_iter().map(|slot| slot.output).collect();
        published[0].output_context = output_context(&held);
        published[1].output_context.leaf_index = held.leaf_index + 1;
        let disclosure = transfer.disclosure(Rail::Anonymous, &outputs);
        let mut transaction = transfer.publish(Publish {
            slots: published,
            disclosure: &disclosure,
            auditor: &self.auditor.pubkey(),
            rail: Rail::Anonymous,
        });
        transaction.slot = u64::from(self.sequence.get());
        transaction.tx_signature = signature;
        let frame = transfer.frame(Frame {
            tx: &transaction,
            disclosure: &disclosure,
            rail: Rail::Anonymous,
        });
        self.frames.lock().unwrap().push((signature, frame));
        (held, transaction)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Inputs {
    Spent,
    Dummy,
}

/// Who else the transfer pays.
#[derive(Clone, Copy)]
enum Beside {
    Alone,
    OtherMember(UtxoFields),
}

fn output_context(note: &WalletUtxo) -> OutputContext {
    OutputContext {
        hash: note.utxo_hash,
        tree_id: note.tree_id,
        leaf_index: note.leaf_index,
    }
}

struct ZeroKeyMerge {
    commitment: [u8; 32],
    nullifier: [u8; 32],
}

#[derive(Default)]
struct History {
    transactions: Vec<ShieldedTransaction>,
    queried: Mutex<Vec<Vec<[u8; 32]>>>,
    frames: Mutex<Vec<(Signature, Vec<u8>)>>,
    merges: Mutex<Vec<(Signature, zolana_ring_client::ConfirmedMergeDisclosure)>>,
    foreign: Vec<Signature>,
    confirmed_events: std::collections::HashMap<Signature, zolana_ring_client::ConfirmedEvent>,
    required_slots: Mutex<Vec<Option<u64>>>,
    /// Signatures whose origin read fails.
    unread: Vec<Signature>,
    /// Signatures whose confirmed call does not decode.
    undecodable: Vec<Signature>,
    additional_history: Vec<ShieldedTransaction>,
    discovery_unavailable: bool,
}

const INDEXED: u64 = 100;

impl History {
    fn read(&self, config: Option<IndexerRpcConfig>) -> Result<(), ClientError> {
        let required = config.and_then(|config| config.require_slot);
        self.required_slots.lock().unwrap().push(required);
        match required {
            Some(required) if required > INDEXED => Err(ClientError::IndexerNotCaughtUp {
                required,
                indexed: INDEXED,
                attempts: 1,
            }),
            _ => Ok(()),
        }
    }

    fn page(&self, rows: Vec<ShieldedTransaction>) -> GetShieldedTransactionsByTagsResponse {
        EventsPage {
            context: Context {
                block_time: 0,
                slot: INDEXED,
            },
            output_tree_id: None,
            rows,
            more: false,
        }
        .response()
    }
}

#[async_trait::async_trait]
impl AsyncRpc for History {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: spr_client::RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read(config)?;
        assert_eq!(options.ring_program_id, RING);
        let mut rows = self.transactions.clone();
        rows.extend(self.additional_history.clone());
        rows.sort_by_key(history_page::position);
        rows.retain(|row| {
            options
                .pagination_token
                .is_none_or(|token| history_page::position(row) > token)
        });
        let limit = options.limit.map_or(usize::MAX, |limit| limit as usize);
        let more = rows.len() > limit;
        rows.truncate(limit);
        Ok(EventsPage {
            context: Context {
                block_time: 0,
                slot: INDEXED,
            },
            output_tree_id: None,
            rows,
            more,
        }
        .response())
    }
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        _filters: HistoryFilters,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        if self.discovery_unavailable {
            return Err(ClientError::Rpc("discovery disabled".to_owned()));
        }
        self.read(config)?;
        Ok(self.page(
            self.transactions
                .iter()
                .filter(|tx| {
                    tx.messages
                        .iter()
                        .any(|message| tags.contains(&message.view_tag))
                        || tx
                            .output_slots
                            .iter()
                            .any(|slot| tags.contains(&slot.view_tag))
                })
                .cloned()
                .collect(),
        ))
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        _filters: HistoryFilters,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        if self.discovery_unavailable {
            return Err(ClientError::Rpc("discovery disabled".to_owned()));
        }
        self.read(config)?;
        self.queried.lock().unwrap().push(nullifiers.clone());
        Ok(self.page(
            self.transactions
                .iter()
                .chain(&self.additional_history)
                .filter(|tx| {
                    tx.nullifiers
                        .iter()
                        .any(|nullifier| nullifiers.contains(nullifier))
                })
                .cloned()
                .collect(),
        ))
    }
}

impl TransactionOrigin for History {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        if self.unread.contains(&signature) {
            return Err(AuditError::Unavailable {
                signature,
                message: "no origin read".to_owned(),
            });
        }
        if self.undecodable.contains(&signature) {
            return Err(AuditError::InvalidTransactData("forged".to_owned()));
        }
        Ok(RingOrigin {
            event: self
                .confirmed_events
                .get(&signature)
                .cloned()
                .unwrap_or_else(|| {
                    origin_fixture::event(
                        self.transactions
                            .iter()
                            .find(|tx| tx.tx_signature == signature)
                            .expect("confirmed event"),
                    )
                }),
            ring_invoked: !self.foreign.contains(&signature),
            signers: Vec::new(),
            pool_accounts: Vec::new(),
            withdrawals: Vec::new(),
            merge_disclosure: self
                .merges
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| *key == signature)
                .map(|(_, disclosure)| disclosure.clone()),
            transact: self
                .frames
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| *key == signature)
                .map(|(_, frame)| frame.clone()),
        })
    }
}

#[tokio::test]
async fn a_transfer_recovers_the_member_beside_another_owner() {
    let fixture = Fixture::new();
    let other = UtxoFields {
        owner_key: [0x66; 32],
        nullifier_pk: field(0x67),
        ..UtxoFields::default()
    };
    let (held, tx) = fixture.encrypt_beside(fixture.output(4), 2, Beside::OtherMember(other));
    let history = History {
        transactions: vec![tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, [held]);
}

#[tokio::test]
async fn a_merge_tag_collision_does_not_require_transfer_disclosure() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, mut merge_tx) = fixture.merge(&[first, second], 7);
    merge_tx.output_slots[0].view_tag =
        zolana_ring_client::auditor_view_tag(&fixture.auditor.pubkey());
    assert!(merge_tx.messages.is_empty());
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, [merged]);
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn a_delivered_slot_of_an_unregistered_mint_stays_unopened_beside_the_rest() {
    let fixture = Fixture::new();
    let fresh = Mint::new(Address::new_from_array([0xee; 32]), 9);
    let output = SppProofOutputUtxo::new(fresh, 4, fixture.address)
        .expect("output")
        .with_ring_program_id(RING);
    let (unopened, fresh_tx) = fixture.encrypt(output, 2);
    let (kept, kept_tx) = fixture.encrypt(fixture.output(5), 2);
    let history = History {
        transactions: vec![fresh_tx, kept_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, [kept]);
    assert_eq!(recovered.unopened, [unopened.utxo_hash]);
}

#[tokio::test]
async fn a_row_that_does_not_decode_fails_the_recovery_it_leaves_incomplete() {
    let fixture = Fixture::new();
    let (_, tx) = fixture.encrypt(fixture.output(4), 2);
    let history = History {
        undecodable: vec![tx.tx_signature],
        transactions: vec![tx],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::InvalidTransactData(_))
    ));
}

#[tokio::test]
async fn the_spend_read_goes_past_a_row_that_does_not_decode_and_the_recovery_then_fails() {
    let fixture = Fixture::new();
    let (held, tx) = fixture.encrypt(fixture.output(4), 2);
    let spender = |byte: u8| {
        let (_, mut spend) = fixture.encrypt(fixture.output(5), 2);
        spend.tx_signature = Signature::from([byte; 64]);
        spend.nullifiers = vec![held.nullifier];
        spend
    };
    let (bad, unreachable) = (spender(0xd5), spender(0xd6));
    // A failed read past the bad row proves the read went on.
    let history = History {
        transactions: vec![tx.clone()],
        undecodable: vec![bad.tx_signature],
        unread: vec![unreachable.tx_signature],
        additional_history: vec![bad.clone(), unreachable],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::Unavailable { .. })
    ));
    let history = History {
        transactions: vec![tx],
        undecodable: vec![bad.tx_signature],
        additional_history: vec![bad],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::InvalidTransactData(_))
    ));
}

#[tokio::test]
async fn missing_or_invalid_mandatory_disclosure_never_returns_a_partial_balance() {
    for missing in [true, false] {
        let fixture = Fixture::new();
        let (_, mut tx) = fixture.encrypt(fixture.output(4), 2);
        tx.output_slots[0].view_tag =
            zolana_ring_client::auditor_view_tag(&fixture.auditor.pubkey());
        if missing {
            tx.messages.clear();
        } else {
            // A flipped record byte rebuilds no commitment.
            let message = &mut tx.messages.last_mut().expect("auditor message").data;
            let slot_0 = message.len() - 2 * custom_ring_interface::AUDIT_RECORD_LEN;
            message[slot_0 + 20] ^= 1;
        }
        let history = History {
            transactions: vec![tx],
            ..Default::default()
        };
        let error = fixture
            .run(fixture.recovery(), &history)
            .await
            .err()
            .expect("mandatory disclosure failure");
        assert!(matches!(
            error,
            AuditError::MissingAuditorMessage | AuditError::UnopenedOutput { slot: 0, .. }
        ));
    }
}

#[tokio::test]
async fn follows_chained_merges_across_trees_and_keeps_only_the_live_successor() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (third, third_tx) = fixture.encrypt(fixture.output(6), 7);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let (successor, successor_tx) = fixture.merge(&[merged, third], 9);
    let history = History {
        transactions: vec![successor_tx, merge_tx, third_tx, second_tx, first_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![successor.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(history.queried.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_spend_row_of_another_ring_never_reaches_the_origin_read() {
    let fixture = Fixture::new();
    let (held, held_tx) = fixture.encrypt(fixture.output(4), 2);
    let mut outsider = held_tx.clone();
    outsider.tx_signature = fixture.signature();
    outsider.nullifiers = vec![held.nullifier];
    outsider.output_slots.clear();
    outsider.ring_program_id = None;
    let history = History {
        unread: vec![outsider.tx_signature],
        transactions: vec![held_tx, outsider],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![held]);
}

#[tokio::test]
async fn checks_whether_a_rebuilt_successor_was_spent_without_an_auditor_message() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut burn = merge_tx.clone();
    burn.tx_signature = fixture.signature();
    burn.nullifiers = vec![merged.nullifier];
    burn.output_slots.clear();
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx, burn],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn a_merge_found_through_one_held_input_decrypts_with_the_whole_total() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    for known in [first_tx, second_tx] {
        let history = History {
            transactions: vec![known, merge_tx.clone()],
            ..Default::default()
        };
        let recovered = fixture
            .run(fixture.recovery(), &history)
            .await
            .expect("recover");
        assert_eq!(recovered.utxos, vec![merged.clone()]);
        assert_eq!(merged.utxo.amount, 9);
        assert!(recovered.unopened.is_empty());
    }
}

#[tokio::test]
async fn a_forged_merge_leaf_never_becomes_a_spendable_note() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, mut merge_tx) = fixture.merge(&[first, second], 7);
    merge_tx.output_slots[0].output_context.hash = [8; 32];
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![[8; 32]]);
}

#[tokio::test]
async fn a_merge_from_another_program_cannot_supply_recovery_outputs() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, merge_tx) = fixture.merge(&[first.clone(), second.clone()], 7);
    let history = History {
        foreign: vec![merge_tx.tx_signature],
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![first, second]);
}

#[tokio::test]
async fn every_read_requires_the_slot_and_an_indexer_behind_it_fails_the_recovery() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovery = |slot| {
        RingRecovery::new(RING, &fixture.auditor)
            .with_indexer_config(IndexerRpcConfig::at_slot(slot))
            .for_member(SourceMember {
                address: &fixture.address,
                nullifier_key: &fixture.member.nullifier_key,
            })
    };

    let recovered = fixture
        .run(recovery(INDEXED), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![merged]);
    let required = std::mem::take(&mut *history.required_slots.lock().unwrap());
    assert_eq!(required, [Some(INDEXED)]);
    assert!(required.iter().all(|slot| *slot == Some(INDEXED)));

    assert!(matches!(
        fixture.run(recovery(INDEXED + 1), &history).await,
        Err(AuditError::Client(ClientError::IndexerNotCaughtUp { .. }))
    ));
}

#[tokio::test]
async fn a_terminal_history_page_recovers_merge_successors_at_the_page_cap() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovery = RingRecovery::new(RING, &fixture.auditor)
        .with_max_pages(std::num::NonZeroUsize::MIN)
        .for_member(SourceMember {
            address: &fixture.address,
            nullifier_key: &fixture.member.nullifier_key,
        });
    let recovered = fixture.run(recovery, &history).await.unwrap();
    assert_eq!(recovered.utxos, [merged]);
    assert!(history.queried.lock().unwrap().is_empty());
}

/// A merge of two notes, and a spend that sorts ahead of its note inside one slot.
fn paged_history(fixture: &Fixture) -> (WalletUtxo, Vec<ShieldedTransaction>) {
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (third, third_tx) = fixture.encrypt(fixture.output(6), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut spend = merge_tx.clone();
    spend.tx_signature = Signature::from([0; 64]);
    spend.slot = third_tx.slot;
    spend.nullifiers = vec![third.nullifier];
    spend.output_slots.clear();
    (merged, vec![first_tx, second_tx, spend, third_tx, merge_tx])
}

fn paged(fixture: &Fixture, max_pages: usize) -> MemberRecovery<'_> {
    RingRecovery::new(RING, &fixture.auditor)
        .with_page_size(std::num::NonZeroU32::MIN)
        .with_max_pages(std::num::NonZeroUsize::new(max_pages).unwrap())
        .for_member(SourceMember {
            address: &fixture.address,
            nullifier_key: &fixture.member.nullifier_key,
        })
}

fn complete(step: RecoveryStep) -> RecoveredNotes {
    match step {
        RecoveryStep::Complete(notes) => notes,
        RecoveryStep::Paused(_) => panic!("the recovery paused"),
    }
}

fn paused(step: RecoveryStep) -> zolana_ring_client::RecoveryProgress {
    match step {
        RecoveryStep::Paused(progress) => progress,
        RecoveryStep::Complete(_) => panic!("the recovery completed"),
    }
}

fn summary(mut notes: RecoveredNotes) -> RecoveredNotes {
    notes.utxos.sort_by_key(|note| note.utxo_hash);
    notes.unopened.sort_unstable();
    notes
}

fn assert_same(left: RecoveredNotes, right: RecoveredNotes) {
    let (left, right) = (summary(left), summary(right));
    assert_eq!(left.utxos, right.utxos);
    assert_eq!(left.unopened, right.unopened);
    assert_eq!(left.unknown_mints, right.unknown_mints);
    assert_eq!(left.unseen_inputs, right.unseen_inputs);
    assert_eq!(left.unseen_input_count, right.unseen_input_count);
}

#[tokio::test]
async fn a_recovery_split_over_three_calls_equals_one_full_recovery() {
    let fixture = Fixture::new();
    let (merged, transactions) = paged_history(&fixture);
    let history = History {
        transactions,
        ..Default::default()
    };
    let full = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(full.utxos, [merged]);

    let first = paused(fixture.step(paged(&fixture, 2), &history).await.unwrap());
    let second = paused(
        fixture
            .step(paged(&fixture, 2).with_progress(first), &history)
            .await
            .unwrap(),
    );
    let split = fixture
        .run(paged(&fixture, 2).with_progress(second), &history)
        .await
        .unwrap();
    assert_same(split, full);
}

#[tokio::test]
async fn a_resumed_recovery_reads_no_row_before_its_cursor() {
    let fixture = Fixture::new();
    let (merged, transactions) = paged_history(&fixture);
    let read = transactions[..2]
        .iter()
        .map(|row| row.tx_signature)
        .collect::<Vec<_>>();
    let history = History {
        transactions: transactions.clone(),
        ..Default::default()
    };
    let progress = paused(fixture.step(paged(&fixture, 2), &history).await.unwrap());
    let cursor = progress.cursor().to_string();
    assert!(cursor.starts_with(&format!("{RING}:ring:1:")), "{cursor}");

    // Every row already read now fails its origin read, a second read of one refuses the recovery.
    let refusing = History {
        transactions,
        undecodable: read,
        ..Default::default()
    };
    assert!(fixture.run(paged(&fixture, 2), &refusing).await.is_err());
    let resumed = fixture
        .run(paged(&fixture, 8).with_progress(progress), &refusing)
        .await
        .unwrap();
    assert_eq!(resumed.utxos, [merged]);
    assert!(resumed.unopened.is_empty());
}

#[tokio::test]
async fn another_member_cannot_resume_a_progress() {
    let fixture = Fixture::new();
    let (_, transactions) = paged_history(&fixture);
    let history = History {
        transactions,
        ..Default::default()
    };
    let progress = paused(fixture.step(paged(&fixture, 2), &history).await.unwrap());
    let stranger = ShieldedKeypair::new_ed25519().unwrap();
    let address = stranger.shielded_address().unwrap();
    let foreign = RingRecovery::new(RING, &fixture.auditor)
        .for_member(SourceMember {
            address: &address,
            nullifier_key: &stranger.nullifier_key,
        })
        .with_progress(progress);
    assert!(matches!(
        fixture.step(foreign, &history).await,
        Err(AuditError::RecoveryProgressMismatch)
    ));
}

#[tokio::test]
async fn audited_deposits_seed_merge_recovery_and_successor_spend_checks() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut history = History {
        transactions: vec![first_tx, second_tx, merge_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![merged.clone()]);
    let mut spent = merge_tx;
    spent.tx_signature = fixture.signature();
    spent.nullifiers = vec![merged.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn an_indexer_cannot_attach_a_new_valid_disclosure_to_a_confirmed_transfer() {
    let fixture = Fixture::new();
    let (_, confirmed) = fixture.encrypt(fixture.output(4), 2);
    let (_, mut forged) = fixture.encrypt(fixture.output(999), 2);
    forged.tx_signature = confirmed.tx_signature;
    let history = History {
        transactions: vec![forged],
        confirmed_events: std::collections::HashMap::from([(
            confirmed.tx_signature,
            origin_fixture::event(&confirmed),
        )]),
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[tokio::test]
async fn an_indexer_cannot_invent_a_spend_of_a_recoverable_utxo() {
    let fixture = Fixture::new();
    let (held, transaction) = fixture.encrypt(fixture.output(4), 2);
    let mut unrelated = transaction.clone();
    unrelated.tx_signature = fixture.signature();
    unrelated.messages.clear();
    unrelated.output_slots.clear();
    unrelated.tx_viewing_pk = None;
    unrelated.salt = None;
    unrelated.nullifiers = vec![[55; 32]];
    let confirmed = origin_fixture::event(&unrelated);
    unrelated.nullifiers = vec![held.nullifier];
    let history = History {
        confirmed_events: std::collections::HashMap::from([(unrelated.tx_signature, confirmed)]),
        transactions: vec![unrelated, transaction],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[tokio::test]
async fn a_foreign_invocation_cannot_mark_a_ring_utxo_spent() {
    let fixture = Fixture::new();
    let (held, transaction) = fixture.encrypt(fixture.output(4), 2);
    let mut forged = transaction.clone();
    forged.tx_signature = fixture.signature();
    forged.messages.clear();
    forged.output_slots.clear();
    forged.tx_viewing_pk = None;
    forged.salt = None;
    forged.nullifiers = vec![held.nullifier];
    let history = History {
        foreign: vec![forged.tx_signature],
        transactions: vec![forged, transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![held]);
}

#[tokio::test]
async fn unknown_merge_mints_remain_unresolved_and_still_follow_spends() {
    let fixture = Fixture::new();
    let mint = Mint::new(Address::new_from_array([71; 32]), 2);
    let mut output = fixture.output(4);
    output.asset = mint;
    let (first, first_tx) = fixture.deposit(output.clone(), 2);
    output.amount = 5;
    let (second, _) = fixture.deposit(output, 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut history = History {
        transactions: vec![first_tx, merge_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![merged.utxo_hash]);
    assert_eq!(recovered.unknown_mints, [mint.asset].into_iter().collect());
    assert!(history.queried.lock().unwrap().is_empty());
    let assets = RingAssets::new([mint]).unwrap();
    let recovered = complete(
        fixture
            .recovery()
            .run(&history, &history, &assets)
            .await
            .unwrap(),
    );
    assert_eq!(recovered.utxos, vec![merged.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unknown_mints.is_empty());

    let mut spent = merge_tx;
    spent.tx_signature = fixture.signature();
    spent.nullifiers = vec![merged.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn unproved_recipient_metadata_cannot_block_plain_utxo_recovery_or_merge() {
    let fixture = Fixture::new();
    let mut output = fixture.output(9);
    output.data = Data::new(vec![
        DataRecord::UtxoData(vec![8]),
        DataRecord::Memo(vec![9]),
    ]);
    let (mut held, transaction) = fixture.encrypt(output, 7);
    assert!(MergeTransaction::new_with_ring(vec![held.clone()], RING, None).is_err());
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    held.utxo.data = Data::default();
    assert_eq!(recovered.utxos, vec![held]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.utxos[0].data_hash.is_none());
    assert!(MergeTransaction::new_with_ring(recovered.utxos, RING, None).is_ok());
}

/// A spend of two deposits leaves the change, an unseen second deposit reads as an unseen input and stops nothing.
#[tokio::test]
async fn an_anonymous_spend_of_deposits_under_the_commitment_key_leaves_the_change() {
    let fixture = Fixture::anonymous();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (change, spend_tx) = fixture.anonymous_spend(&[&first, &second], 9, 3);
    let history = History {
        transactions: vec![first_tx.clone(), second_tx, spend_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, std::slice::from_ref(&change));
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unseen_inputs.is_empty());
    let unseen_nullifier = spend_tx.nullifiers[1];
    let unseen = History {
        transactions: vec![first_tx, spend_tx],
        ..Default::default()
    };
    let gap = fixture.run(fixture.recovery(), &unseen).await.unwrap();
    assert_eq!(gap.utxos, [change]);
    assert_eq!(gap.unseen_inputs, [unseen_nullifier]);
    assert_eq!(gap.unseen_input_count, 1);
}

#[tokio::test]
async fn unmatched_inputs_keep_a_bounded_sample_and_a_complete_count() {
    let fixture = Fixture::anonymous();
    let mut transactions = Vec::new();
    let mut nullifiers = Vec::new();
    for slot in 0..70 {
        let (input, _) = fixture.deposit(fixture.output(4), 2);
        let (_, mut transaction) = fixture.anonymous_spend(&[&input], 3, 3);
        transaction.slot = slot;
        nullifiers.push(input.nullifier);
        transactions.push(transaction);
    }
    let history = History {
        transactions,
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.unseen_inputs.len(), 64);
    assert_eq!(recovered.unseen_input_count, 70);
    assert!(recovered
        .unseen_inputs
        .iter()
        .all(|input| nullifiers.contains(input)));
}

#[tokio::test]
async fn complete_history_recovers_proved_merge_chains_with_invalid_native_ciphertext() {
    for reverse in [false, true] {
        let fixture = Fixture::anonymous();
        let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
        let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
        let (third, third_tx) = fixture.deposit(fixture.output(6), 7);
        let (merged, merge_tx) = fixture.audited_merge(&[first, second], 7);
        let (successor, successor_tx) = fixture.audited_merge(&[merged, third], 9);
        let mut transactions = vec![first_tx, second_tx, third_tx, merge_tx, successor_tx];
        if reverse {
            transactions.reverse();
        }
        let history = History {
            transactions,
            discovery_unavailable: true,
            ..Default::default()
        };
        let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
        assert_eq!(recovered.utxos, [successor]);
        assert!(recovered.unopened.is_empty());
        assert!(history.queried.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_noncanonical_native_merge_ciphertext_does_not_block_checked_recovery() {
    let fixture = Fixture::anonymous();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (merged, mut merge_tx) = fixture.audited_merge(&[first, second], 7);
    let payload = &mut merge_tx.output_slots[0].payload;
    let ciphertext = payload.len() - MERGE_OUTPUT_CIPHERTEXT_LEN;
    payload[ciphertext..].fill(0xff);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        discovery_unavailable: true,
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, [merged]);
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn a_transfer_after_a_proved_merge_resolves_its_input_from_complete_history() {
    let fixture = Fixture::anonymous();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.audited_merge(&[first, second], 7);
    let (change, spend_tx) = fixture.anonymous_spend(&[&merged], 9, 7);
    let history = History {
        transactions: vec![spend_tx, merge_tx, second_tx, first_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, [change]);
    assert!(recovered.unseen_inputs.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn a_merge_record_off_the_confirmed_output_fails_the_recovery() {
    let fixture = Fixture::anonymous();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (_, mut merge_tx) = fixture.audited_merge(&[first, second], 7);
    merge_tx.output_slots[0].output_context.hash = field(91);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::MergeDisclosureMismatch)
    ));
}

#[tokio::test]
async fn a_wiped_wallet_restores_a_zero_key_merge_from_its_record_and_a_stranger_keeps_nothing() {
    let fixture = Fixture::new();
    let (merge, merge_tx) = fixture.zero_key_merge(6, 7);
    let history = History {
        transactions: vec![merge_tx],
        discovery_unavailable: true,
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    let restored: Vec<_> = recovered
        .utxos
        .iter()
        .map(|note| {
            (
                note.utxo_hash,
                note.nullifier_pubkey,
                note.nullifier,
                note.utxo.amount,
            )
        })
        .collect();
    assert_eq!(
        restored,
        [(merge.commitment, ZERO_NULLIFIER_PUBKEY, merge.nullifier, 6)]
    );
    assert!(recovered.unopened.is_empty());

    let stranger = ShieldedKeypair::new_ed25519().unwrap();
    let address = stranger.shielded_address().unwrap();
    let foreign = RingRecovery::new(RING, &fixture.auditor).for_member(SourceMember {
        address: &address,
        nullifier_key: &stranger.nullifier_key,
    });
    let recovered = fixture.run(foreign, &history).await.unwrap();
    assert!(recovered.utxos.is_empty() && recovered.unopened.is_empty());
}
