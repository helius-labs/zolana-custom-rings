//! `AnonymousSync` and the spec view tag selection against an in-memory indexer, every transfer
//! sealed by the anonymous rail.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use async_trait::async_trait;
use custom_ring_interface::{
    encode_anonymous_recipient_output, encode_anonymous_sender_output, RingDepositAuditCapsule,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
    IndexerRpcConfig, OutputContext, OutputSlot, ShieldedTransaction,
};
use spr_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositData,
    EncryptedRingDepositOutput, MergeOutputDataRef, MessageData,
};
use spr_keypair::{
    random_salt, viewing_key::ViewTag, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
    X25519Pubkey,
};
use spr_transaction::{
    instructions::{
        merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
        transact::ConfidentialTransaction,
    },
    owner_utxo_hash, verify_spendable, Data, Mint, Utxo, WalletUtxo,
};
use zolana_ring_client::{
    AnonymousError, AnonymousScan, AnonymousStream, AnonymousSync, FirstContact, PaymentRecipient,
    SentCheck, StreamCounter, TagSelection, TransferTagging, ViewingHistory, TAGS_PER_REQUEST,
    TAG_GAP, VIEWING_HISTORY_VERSION,
};
use zolana_ring_transaction::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, RingAssets,
    RingDelivery, RingDepositPlaintext, RingOutputRail, UnverifiedRecipientPlaintext,
    UnverifiedSenderPlaintext, VerifiedRecipientPlaintext, VerifiedSenderPlaintext,
    RECIPIENT_BODY_LEN,
};

const RING: Address = Address::new_from_array([4; 32]);
const TREE: u16 = 2;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

#[derive(Default)]
struct Indexer {
    transactions: Mutex<Vec<ShieldedTransaction>>,
    deposits: Mutex<Vec<EncryptedUtxoMatch>>,
    next_leaf: Mutex<u64>,
    tag_reads: AtomicUsize,
    tags_read: AtomicUsize,
}

impl Indexer {
    fn publish(&self, transaction: ShieldedTransaction) {
        self.transactions.lock().unwrap().push(transaction);
    }

    /// Leaves in append order, every published output takes the next.
    fn leaves(&self, count: usize) -> u64 {
        let mut next = self.next_leaf.lock().unwrap();
        let first = *next;
        *next += count as u64;
        first
    }

    /// The tag reads and the tags they named since the last call.
    fn take_tag_reads(&self) -> (usize, usize) {
        (
            self.tag_reads.swap(0, Ordering::Relaxed),
            self.tags_read.swap(0, Ordering::Relaxed),
        )
    }

    fn context() -> Context {
        Context {
            block_time: 0,
            slot: u64::MAX,
        }
    }
}

#[async_trait]
impl AsyncRpc for Indexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.tag_reads.fetch_add(1, Ordering::Relaxed);
        self.tags_read.fetch_add(tags.len(), Ordering::Relaxed);
        let transactions = self.transactions.lock().unwrap();
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Self::context(),
            output_tree_id: Some(TREE),
            transactions: transactions
                .iter()
                .filter(|tx| {
                    let outputs = tx.output_slots.iter().map(|slot| &slot.view_tag);
                    let messages = tx.messages.iter().map(|message| &message.view_tag);
                    outputs.chain(messages).any(|tag| tags.contains(tag))
                })
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: Self::context(),
            output_tree_id: Some(TREE),
            matches: self
                .deposits
                .lock()
                .unwrap()
                .iter()
                .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        let transactions = self.transactions.lock().unwrap();
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: Self::context(),
            output_tree_id: Some(TREE),
            transactions: transactions
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|n| nullifiers.contains(n)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

/// A wallet whose viewing history is stored before every send.
struct Wallet {
    keys: ShieldedKeypair,
    history: ViewingHistory,
    /// Notes it spends, never published, the sync of another wallet never reads them.
    funding: Vec<WalletUtxo>,
}

/// One payment of a transfer, `request` set when the recipient minted a request tag.
struct Pay<'a> {
    to: &'a ShieldedAddress,
    request: Option<ViewTag>,
    amount: u64,
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let keys = keypair(seed);
        let history = ViewingHistory::new(keys.viewing_pubkey(), 0);
        let funding = (0..4)
            .map(|index| funding_utxo(&keys, seed, index))
            .collect();
        Self {
            keys,
            history,
            funding,
        }
    }

    fn address(&self) -> ShieldedAddress {
        self.keys.shielded_address().unwrap()
    }

    /// Seals one anonymous transfer from the next funding note and publishes it.
    fn pay(&mut self, indexer: &Indexer, payments: &[Pay<'_>]) -> ShieldedTransaction {
        let tx = self.seal(indexer, payments);
        indexer.publish(tx.clone());
        tx
    }

    /// Seals one anonymous transfer, its leaves taken, without publishing it.
    fn seal(&mut self, indexer: &Indexer, payments: &[Pay<'_>]) -> ShieldedTransaction {
        let recipients: Vec<PaymentRecipient> = payments
            .iter()
            .map(|pay| PaymentRecipient {
                viewing_pubkey: pay.to.viewing_pubkey,
                first_contact: pay
                    .request
                    .map_or(FirstContact::Bootstrap, FirstContact::Request),
            })
            .collect();
        let tags = TransferTagging {
            keys: &self.keys,
            history: &self.history,
            recipients: &recipients,
        }
        .plan()
        .unwrap();
        self.history = tags.history.clone();
        let plan = tags.anonymous_plan();
        let input = self.funding.remove(0);
        let first_nullifier = input.nullifier;
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![input],
            self.address().solana_address().unwrap(),
            RING,
        )
        .unwrap()
        .with_output_tree_id(TREE)
        .unwrap();
        for pay in payments {
            transaction
                .transfer_with_ring(pay.to, Mint::SOL, pay.amount, Some(RING))
                .unwrap();
        }
        let tx_key = self
            .keys
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        let rail = RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(plan)));
        let proof = rail.encrypt(transaction, &self.address()).unwrap();
        let external = &proof.external_data;
        let leaf = indexer.leaves(external.outputs.len());
        ShieldedTransaction {
            slot: leaf + 1,
            tx_signature: Signature::from(signature(leaf)),
            event_index: Some(0),
            tx_viewing_pk: Some(rail.tx_viewing_key().pubkey()),
            salt: Some(rail.salt()),
            output_slots: external
                .outputs
                .iter()
                .zip(&external.resolved_owner_tags)
                .zip(leaf..)
                .map(|((output, tag), leaf_index)| OutputSlot {
                    view_tag: *tag,
                    output_context: OutputContext {
                        hash: output.utxo_hash,
                        tree_id: TREE,
                        leaf_index,
                    },
                    payload: output.data.clone().unwrap_or_default(),
                })
                .collect(),
            messages: external.messages.clone(),
            nullifiers: proof
                .input_utxos
                .iter()
                .map(|input| input.nullifier())
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    async fn sync(&self, indexer: &Indexer, history: &ViewingHistory) -> AnonymousScan {
        self.sync_holding(indexer, history, &[]).await
    }

    /// Resumes from the watermarks, `held` the notes earlier syncs found.
    async fn sync_holding(
        &self,
        indexer: &Indexer,
        history: &ViewingHistory,
        held: &[WalletUtxo],
    ) -> AnonymousScan {
        AnonymousSync::new(&self.keys, &assets())
            .with_held_notes(held)
            .fetch(indexer, history)
            .await
            .unwrap()
    }
}

fn assets() -> RingAssets {
    RingAssets::new([]).unwrap()
}

fn signature(leaf: u64) -> [u8; 64] {
    let mut bytes = [0x5a; 64];
    bytes[..8].copy_from_slice(&leaf.to_be_bytes());
    bytes
}

/// A held ring note of `owner`, its nullifier canonical as every real one is.
fn funding_utxo(owner: &ShieldedKeypair, seed: u8, index: u8) -> WalletUtxo {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 100,
        blinding: field(seed, index),
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = owner.shielded_address().unwrap().nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: u64::from(index),
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::from([seed; 64]),
        slot_index: 0,
    }
}

/// A canonical field value distinct per pair.
fn field(seed: u8, index: u8) -> [u8; 32] {
    let mut value = [0x11; 32];
    value[30] = seed;
    value[31] = index;
    value
}

fn stream(scan: &AnonymousScan, utxo_hash: [u8; 32]) -> AnonymousStream {
    scan.utxos
        .iter()
        .find(|utxo| utxo.utxo_hash == utxo_hash)
        .map(|utxo| utxo.stream)
        .unwrap_or_else(|| panic!("note {utxo_hash:?} not found"))
}

/// The hash of the output at `position`.
fn output(tx: &ShieldedTransaction, position: usize) -> [u8; 32] {
    tx.output_slots[position].output_context.hash
}

fn fresh(wallet: &Wallet) -> ViewingHistory {
    ViewingHistory::new(wallet.keys.viewing_pubkey(), 0)
}

/// The next index of a counterparty's stream.
trait NextIndex {
    fn next_of(&self, key: &X25519Pubkey) -> Option<u64>;
}

impl NextIndex for HashMap<X25519Pubkey, StreamCounter> {
    fn next_of(&self, key: &X25519Pubkey) -> Option<u64> {
        self.get(key).map(StreamCounter::next)
    }
}

#[tokio::test]
async fn a_bootstrap_payment_pairs_and_the_next_one_takes_the_shared_tag() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let first = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: None,
            amount: 30,
        }],
    );
    assert_eq!(
        first.output_slots[1].view_tag,
        bob.keys.viewing_pubkey().u()
    );

    let scanned = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(
        stream(&scanned, output(&first, 1)),
        AnonymousStream::Bootstrap
    );
    let pair = alice.keys.viewing_pubkey();
    let entry = scanned.history.current();
    assert_eq!(entry.known_senders().next_of(&pair), Some(0));

    let second = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: None,
            amount: 40,
        }],
    );
    assert_eq!(
        second.output_slots[1].view_tag,
        bob.keys.get_recipient_shared_view_tag(&pair, 0).unwrap()
    );
    let rescanned = bob.sync(&indexer, &scanned.history).await;
    assert_eq!(
        stream(&rescanned, output(&second, 1)),
        AnonymousStream::Shared {
            sender: pair,
            index: 0
        }
    );
    assert_eq!(
        rescanned.history.current().known_senders().next_of(&pair),
        Some(1)
    );
    assert_eq!(
        alice
            .history
            .current()
            .known_recipients()
            .next_of(&bob.keys.viewing_pubkey()),
        Some(1)
    );
}

#[tokio::test]
async fn a_request_payment_is_found_under_its_request_tag() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let mut bob = Wallet::new(2);
    let minted = bob.history.request_tag(&bob.keys).unwrap();
    bob.history = minted.history;
    assert_eq!(
        minted.tag,
        bob.keys.get_recipient_request_view_tag(0).unwrap()
    );
    let paid = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: Some(minted.tag),
            amount: 25,
        }],
    );
    assert_eq!(paid.output_slots[1].view_tag, minted.tag);
    let scanned = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(
        stream(&scanned, output(&paid, 1)),
        AnonymousStream::Request { index: 0 }
    );
    let entry = scanned.history.current();
    assert_eq!(entry.request_count(), 1);
    assert_eq!(
        entry.known_senders().next_of(&alice.keys.viewing_pubkey()),
        Some(0)
    );
}

#[tokio::test]
async fn change_is_found_under_the_sender_tag() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: None,
            amount: 30,
        }],
    );
    assert_eq!(
        paid.output_slots[0].view_tag,
        alice.keys.get_sender_view_tag(0).unwrap()
    );
    let scanned = alice.sync(&indexer, &fresh(&alice)).await;
    assert_eq!(
        stream(&scanned, output(&paid, 0)),
        AnonymousStream::Sender { index: 0 }
    );
    let change = &scanned.decrypted.utxos[0];
    assert_eq!(
        (change.utxo.amount, change.utxo.ring_program_id),
        (70, Some(RING))
    );
    let entry = scanned.history.current();
    assert_eq!(entry.tx_count(), 1);
    assert_eq!(
        entry.known_recipients().next_of(&bob.keys.viewing_pubkey()),
        Some(0)
    );
}

/// A sync from the mnemonic alone reaches the counters and counterparties the live wallets hold.
#[tokio::test]
async fn a_resync_rebuilds_the_counters_and_both_counterparty_maps() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let mut bob = Wallet::new(2);
    for amount in [10, 11, 12] {
        alice.pay(
            &indexer,
            &[Pay {
                to: &bob.address(),
                request: None,
                amount,
            }],
        );
    }
    bob.history = bob.sync(&indexer, &bob.history).await.history;
    bob.pay(
        &indexer,
        &[Pay {
            to: &alice.address(),
            request: None,
            amount: 5,
        }],
    );
    let alice_restored = alice.sync(&indexer, &fresh(&alice)).await;
    let bob_restored = bob.sync(&indexer, &fresh(&bob)).await;
    let restored = alice_restored.history.current();
    let live = alice.history.current();
    assert_eq!(restored.tx_count(), 3);
    assert_eq!(restored.tx_count(), live.tx_count());
    assert_eq!(
        restored
            .known_recipients()
            .next_of(&bob.keys.viewing_pubkey()),
        live.known_recipients().next_of(&bob.keys.viewing_pubkey())
    );
    assert_eq!(
        restored.known_senders().next_of(&bob.keys.viewing_pubkey()),
        Some(0)
    );
    let restored = bob_restored.history.current();
    assert_eq!(restored.tx_count(), 1);
    assert_eq!(
        restored
            .known_senders()
            .next_of(&alice.keys.viewing_pubkey()),
        Some(2)
    );
    assert_eq!(
        restored
            .known_recipients()
            .next_of(&alice.keys.viewing_pubkey()),
        Some(0)
    );
    let notes: Vec<u64> = verify_spendable(&bob.keys, &bob_restored.decrypted)
        .unwrap()
        .utxos()
        .map(|utxo| utxo.utxo.amount)
        .collect();
    assert_eq!(notes.iter().sum::<u64>(), 10 + 11 + 12 + 95);
}

/// The body under the recipient's tag is sealed to a stranger, its commitment refuses it.
#[tokio::test]
async fn a_body_sealed_to_another_key_is_skipped_and_the_sync_goes_on() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let stranger = ShieldedAddress {
        viewing_pubkey: keypair(9).viewing_pubkey(),
        ..bob.address()
    };
    let misrouted = alice.pay(
        &indexer,
        &[Pay {
            to: &stranger,
            request: Some(bob.keys.viewing_pubkey().u()),
            amount: 9,
        }],
    );
    assert_eq!(
        misrouted.output_slots[1].view_tag,
        bob.keys.viewing_pubkey().u()
    );
    let paid = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: None,
            amount: 30,
        }],
    );
    let scanned = bob.sync(&indexer, &fresh(&bob)).await;
    let found: Vec<[u8; 32]> = scanned.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(found, [output(&paid, 1)]);
    assert_eq!(
        scanned
            .history
            .current()
            .known_senders()
            .next_of(&alice.keys.viewing_pubkey()),
        Some(0)
    );
}

/// A sync reads past each watermark only, a full rescan reads every stream from index 0.
#[tokio::test]
async fn a_sync_resumes_from_each_watermark_and_a_rescan_reads_from_index_0() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let pay = |alice: &mut Wallet, amount| {
        let to = bob.address();
        alice.pay(
            &indexer,
            &[Pay {
                to: &to,
                request: None,
                amount,
            }],
        )
    };
    let first = pay(&mut alice, 10);
    let second = pay(&mut alice, 11);
    let sent = alice.history.current();
    assert_eq!((sent.tx_count(), sent.tx_stream().scanned()), (2, 0));

    let held = bob.sync(&indexer, &fresh(&bob)).await;
    let pair = alice.keys.viewing_pubkey();
    let counter = &held.history.current().known_senders()[&pair];
    assert_eq!((counter.next(), counter.scanned()), (1, 1));
    let third = pay(&mut alice, 12);

    let resumed = bob.sync(&indexer, &held.history).await;
    let found: Vec<[u8; 32]> = resumed.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
    assert!(found.contains(&output(&third, 1)));
    assert!(
        !found.contains(&output(&second, 1)),
        "the shared stream resumes past index 0"
    );
    assert_eq!(
        resumed.history.current().known_senders().next_of(&pair),
        Some(2)
    );

    let rescanned = AnonymousSync::new(&bob.keys, &assets())
        .with_full_rescan()
        .fetch(&indexer, &resumed.history)
        .await
        .unwrap();
    let mut found: Vec<[u8; 32]> = rescanned.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
    found.sort();
    let mut every = vec![output(&first, 1), output(&second, 1), output(&third, 1)];
    every.sort();
    assert_eq!(found, every);
}

/// A forged sender costs one gap of tags and never crowds out a real pair.
#[tokio::test]
async fn forged_senders_never_crowd_out_a_real_pair() {
    const FORGED: usize = 4096;
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut stored: serde_json::Value = serde_json::from_str(&fresh(&bob).to_json()).unwrap();
    stored["viewingHistory"][0]["knownSenders"] = (0..FORGED)
        .map(|_| {
            serde_json::json!({
                "pubkey": hex::encode(ViewingKey::new().pubkey().as_bytes()),
                "next": 0,
                "scanned": 0,
                "pending": [],
            })
        })
        .collect();
    let forged = ViewingHistory::from_json(&stored.to_string()).unwrap();
    let pay = [Pay {
        to: &bob.address(),
        request: None,
        amount: 30,
    }];
    let first_round = (FORGED + 3) * TAG_GAP as usize + 1;
    let within_bound = |(reads, tags): (usize, usize)| {
        assert!(tags <= first_round + 2 * TAG_GAP as usize, "{tags} tags");
        assert!(
            reads <= first_round.div_ceil(TAGS_PER_REQUEST) + 1,
            "{reads} reads"
        );
    };

    alice.pay(&indexer, &pay);
    let paired = bob.sync(&indexer, &forged).await;
    within_bound(indexer.take_tag_reads());
    let sender = alice.keys.viewing_pubkey();
    let known = paired.history.current().known_senders();
    assert_eq!((known.len(), known.next_of(&sender)), (FORGED + 1, Some(0)));

    let shared = alice.pay(&indexer, &pay);
    let found = bob.sync(&indexer, &paired.history).await;
    within_bound(indexer.take_tag_reads());
    assert_eq!(
        stream(&found, output(&shared, 1)),
        AnonymousStream::Shared { sender, index: 0 }
    );
}

/// Transfer `n` lands after `n + 1` and after a sync passed it, the next sync reads it again.
#[tokio::test]
async fn a_transfer_landing_behind_the_watermark_is_found_by_the_next_sync() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let to = bob.address();
    let pay = |amount| {
        [Pay {
            to: &to,
            request: None,
            amount,
        }]
    };
    alice.pay(&indexer, &pay(10));
    let paired = bob.sync(&indexer, &fresh(&bob)).await;
    let late = alice.seal(&indexer, &pay(11));
    let landed = alice.pay(&indexer, &pay(12));
    let sender = alice.keys.viewing_pubkey();
    let pending =
        |counter: &StreamCounter| (counter.scanned(), counter.pending().collect::<Vec<_>>());

    let passed = bob.sync(&indexer, &paired.history).await;
    let shared = &passed.history.current().known_senders()[&sender];
    assert_eq!(pending(shared), (2, vec![0]));
    assert_eq!(
        stream(&passed, output(&landed, 1)),
        AnonymousStream::Shared { sender, index: 1 }
    );
    let own = alice.sync(&indexer, &alice.history).await;
    assert_eq!(pending(own.history.current().tx_stream()), (3, vec![1]));

    indexer.publish(late.clone());
    let caught = bob.sync(&indexer, &passed.history).await;
    assert_eq!(
        stream(&caught, output(&late, 1)),
        AnonymousStream::Shared { sender, index: 0 }
    );
    let shared = &caught.history.current().known_senders()[&sender];
    assert_eq!(pending(shared), (2, Vec::new()));
    let own = alice.sync(&indexer, &own.history).await;
    assert_eq!(
        stream(&own, output(&late, 0)),
        AnonymousStream::Sender { index: 1 }
    );
    assert_eq!(pending(own.history.current().tx_stream()), (3, Vec::new()));
}

/// A sent row verifies only under a held address naming both the owner and the nullifier key.
#[tokio::test]
async fn the_change_lists_every_payment_and_a_held_address_verifies_its_row() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2).address();
    let carol = Wallet::new(3).address();
    let paid = alice.pay(
        &indexer,
        &[
            Pay {
                to: &bob,
                request: None,
                amount: 30,
            },
            Pay {
                to: &carol,
                request: None,
                amount: 20,
            },
        ],
    );
    let forged = ShieldedAddress {
        nullifier_pubkey: Wallet::new(4).address().nullifier_pubkey,
        ..carol
    };
    let held = [bob, forged];
    let scan = AnonymousSync::new(&alice.keys, &assets())
        .with_recipient_addresses(&held)
        .fetch(&indexer, &fresh(&alice))
        .await
        .unwrap();
    let rows: Vec<_> = scan
        .sent
        .iter()
        .map(|row| {
            (
                row.position,
                row.recipient_viewing_pubkey,
                row.owner_pubkey,
                row.amount,
                row.check,
                row.utxo_hash,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                1,
                bob.viewing_pubkey,
                bob.signing_pubkey,
                30,
                SentCheck::Verified { mint: Mint::SOL },
                output(&paid, 1),
            ),
            (
                2,
                carol.viewing_pubkey,
                carol.signing_pubkey,
                20,
                SentCheck::Unverified,
                output(&paid, 2),
            ),
        ]
    );
    assert!(scan
        .sent
        .iter()
        .all(|row| row.tx_signature == paid.tx_signature));
    let unheld = alice.sync(&indexer, &fresh(&alice)).await;
    assert!(unheld
        .sent
        .iter()
        .all(|row| row.check == SentCheck::Unverified));
    assert_eq!(unheld.sent.len(), 2);
}

/// A listed payment whose body opens to nothing leaves no row, the sync and the change go on.
#[tokio::test]
async fn a_sent_body_that_fails_to_open_leaves_no_row() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2).address();
    let mut paid = alice.seal(
        &indexer,
        &[Pay {
            to: &bob,
            request: None,
            amount: 30,
        }],
    );
    let payload = &mut paid.output_slots[1].payload;
    let last = payload.len() - 1;
    payload.truncate(last);
    payload[1..5].copy_from_slice(&u32::try_from(last - 5).unwrap().to_le_bytes());
    indexer.publish(paid.clone());
    let scan = alice.sync(&indexer, &fresh(&alice)).await;
    assert!(scan.sent.is_empty());
    assert_eq!(
        stream(&scan, output(&paid, 0)),
        AnonymousStream::Sender { index: 0 }
    );
}

/// Bodies a stranger publishes under the bootstrap tag open to nothing, the sync carries on.
#[tokio::test]
async fn sender_chosen_garbage_under_a_tag_never_fails_the_sync() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let tx_key = ViewingKey::new();
    let salt = random_salt();
    let mut noise = vec![0x5c; RECIPIENT_BODY_LEN];
    noise[0] = 0x01;
    // Names bob, its blinding outside the field fails the hash rebuild.
    let named = AnonymousTransferRecipientPlaintext {
        verified: VerifiedRecipientPlaintext {
            owner_pubkey: bob.address().signing_pubkey,
            mint: Mint::SOL.asset,
            amount: 5,
        },
        unverified: UnverifiedRecipientPlaintext {
            sender_pubkey: keypair(7).viewing_pubkey(),
            blinding: [0xff; 32],
            data: Data::default(),
        },
    }
    .serialize()
    .unwrap();
    let bundle = AnonymousTransferSenderPlaintext {
        verified: VerifiedSenderPlaintext {
            owner_pubkey: bob.address().signing_pubkey,
            spl_mint: Address::default(),
            spl_amount: 0,
            sol_amount: 5,
            recipient_viewing_pks: vec![keypair(8).viewing_pubkey()],
        },
        unverified: UnverifiedSenderPlaintext {
            blinding_seed: [0x0b; 32],
            spl_data: Data::default(),
            sol_data: Data::default(),
        },
    }
    .serialize()
    .unwrap();
    let seal = |body: &[u8], slot| {
        tx_key
            .encrypt_slot(&bob.keys.viewing_pubkey(), body, salt, slot)
            .unwrap()
    };
    let bodies = [&noise, &named];
    let leaf = indexer.leaves(bodies.len());
    let unmatched_hash = [0x0c; 32];
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0x77; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: bodies
            .iter()
            .zip(0u32..)
            .zip(leaf..)
            .map(|((body, position), leaf_index)| OutputSlot {
                view_tag: bob.keys.viewing_pubkey().u(),
                output_context: OutputContext {
                    hash: unmatched_hash,
                    tree_id: TREE,
                    leaf_index,
                },
                payload: encode_anonymous_recipient_output(&seal(body, position)).unwrap(),
            })
            .collect(),
        messages: vec![MessageData {
            view_tag: bob.keys.viewing_pubkey().u(),
            data: encode_anonymous_sender_output(&seal(&bundle, 2)).unwrap(),
        }],
        nullifiers: vec![field(9, 9)],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    // A bundle with no output to rebuild.
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0x78; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: Vec::new(),
        messages: vec![MessageData {
            view_tag: bob.keys.viewing_pubkey().u(),
            data: encode_anonymous_sender_output(&seal(&bundle, 0)).unwrap(),
        }],
        nullifiers: vec![field(9, 8)],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let paid = alice.pay(
        &indexer,
        &[Pay {
            to: &bob.address(),
            request: None,
            amount: 30,
        }],
    );
    let scanned = bob.sync(&indexer, &fresh(&bob)).await;
    let found: Vec<[u8; 32]> = scanned.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(found, [output(&paid, 1)]);
    assert_eq!(scanned.unmatched, [unmatched_hash; 2]);
    assert_eq!(
        scanned.history.current().known_senders().len(),
        1,
        "only a body that rebuilds its hash names a sender"
    );
    assert!(scanned.history.current().known_recipients().is_empty());
}

#[test]
fn the_two_directions_of_a_pair_take_disjoint_tags() {
    let alice = keypair(1);
    let bob = keypair(2);
    let to_bob = alice
        .get_send_shared_view_tag(&bob.viewing_pubkey(), 0)
        .unwrap();
    let to_alice = bob
        .get_send_shared_view_tag(&alice.viewing_pubkey(), 0)
        .unwrap();
    assert_ne!(to_bob, to_alice);
    assert_eq!(
        bob.get_recipient_shared_view_tag(&alice.viewing_pubkey(), 0)
            .unwrap(),
        to_bob
    );
}

#[test]
fn the_selection_takes_shared_then_request_then_bootstrap() {
    let alice = Wallet::new(1);
    let bob = keypair(2).viewing_pubkey();
    let carol = keypair(3).viewing_pubkey();
    let tags = TransferTagging {
        keys: &alice.keys,
        history: &alice.history,
        recipients: &[
            PaymentRecipient {
                viewing_pubkey: bob,
                first_contact: FirstContact::Bootstrap,
            },
            PaymentRecipient {
                viewing_pubkey: bob,
                first_contact: FirstContact::Request([3; 32]),
            },
            PaymentRecipient {
                viewing_pubkey: carol,
                first_contact: FirstContact::Request([3; 32]),
            },
        ],
    }
    .plan()
    .unwrap();
    let selections: Vec<TagSelection> = tags.payments.iter().map(|tag| tag.selection).collect();
    assert_eq!(
        selections,
        [
            TagSelection::Bootstrap,
            TagSelection::Shared { index: 0 },
            TagSelection::Request
        ]
    );
    assert_eq!(tags.payments[0].payment.tag, bob.u());
    assert_eq!(tags.payments[2].payment.tag, [3; 32]);
    let entry = tags.history.current();
    assert_eq!(entry.tx_count(), 1);
    assert_eq!(entry.known_recipients().next_of(&bob), Some(1));
    assert_eq!(entry.known_recipients().next_of(&carol), Some(0));
    assert_eq!(
        alice.history.current().tx_count(),
        0,
        "the stored history is a copy"
    );
}

/// A merge spends the wallet's notes, the next sync opens its output from the spend.
#[tokio::test]
async fn a_merge_of_the_wallets_notes_is_found_and_marks_them_spent() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    for amount in [70, 30] {
        alice.pay(
            &indexer,
            &[Pay {
                to: &bob.address(),
                request: None,
                amount,
            }],
        );
    }
    let held = bob.sync(&indexer, &fresh(&bob)).await;
    let notes = &held.decrypted.utxos;
    let nullifiers: Vec<[u8; 32]> = notes.iter().map(|utxo| utxo.nullifier).collect();
    let first = nullifiers[0];
    let owner = bob.address();
    let nullifier_key = &bob.keys.nullifier_key;
    let merged = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 100,
        blinding: merge_output_blinding(nullifier_key, &first).unwrap(),
        ring_program_id: Some(RING),
        data: Default::default(),
    };
    let merged_hash = merged
        .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let salt = [8; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: 100,
        mint: Mint::SOL.asset,
    }
    .encrypt(&merge_output_key(nullifier_key, &first).unwrap(), &salt)
    .unwrap();
    indexer.publish(ShieldedTransaction {
        slot: 99,
        tx_signature: Signature::from([0x99; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: first,
            output_context: OutputContext {
                hash: merged_hash,
                tree_id: TREE,
                leaf_index: indexer.leaves(1),
            },
            payload: encode_merge_output_data(MergeOutputDataRef {
                salt: &salt,
                ciphertext: &ciphertext,
                prefix: &[[0; 32]],
            }),
        }],
        messages: Vec::new(),
        nullifiers,
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let next = bob
        .sync_holding(&indexer, &held.history, &held.decrypted.utxos)
        .await;
    assert_eq!(
        stream(&next, merged_hash),
        AnonymousStream::Merge {
            first_nullifier: first
        }
    );
    let unspent: Vec<[u8; 32]> = verify_spendable(&bob.keys, &next.decrypted)
        .unwrap()
        .utxos()
        .map(|utxo| utxo.utxo_hash)
        .collect();
    assert_eq!(unspent, [merged_hash]);
}

/// A deposit to the wallet's own note takes its next sender tag, a malformed capsule opens to nothing.
#[tokio::test]
async fn an_own_deposit_is_found_on_the_sender_tag_and_moves_tx_count() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let truncated = alice.history.sender_tag(&alice.keys).unwrap();
    alice.history = truncated.history;
    let kept = alice.history.sender_tag(&alice.keys).unwrap();
    alice.history = kept.history;
    let owner = alice.address();
    for (tag, capsule, blinding) in [
        (truncated.tag, false, field(7, 1)),
        (kept.tag, true, field(7, 2)),
    ] {
        indexer
            .deposits
            .lock()
            .unwrap()
            .push(deposit_row(&owner, tag, capsule, blinding));
    }
    let scanned = alice.sync(&indexer, &fresh(&alice)).await;
    let found: Vec<AnonymousStream> = scanned.utxos.iter().map(|utxo| utxo.stream).collect();
    assert_eq!(found, [AnonymousStream::Sender { index: 1 }]);
    assert_eq!(scanned.history.current().tx_count(), 2);
}

fn deposit_row(
    owner: &ShieldedAddress,
    tag: ViewTag,
    capsule: bool,
    blinding: [u8; 32],
) -> EncryptedUtxoMatch {
    let encrypted = RingDepositPlaintext {
        blinding,
        utxo_data: None,
        memo: None,
        ring_data: Vec::new(),
    }
    .encrypt(&owner.viewing_pubkey)
    .unwrap();
    let ciphertext = match capsule {
        true => RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: &[2; 33],
            ciphertext: &[0; 96],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode(),
        false => b"CRDEP001".to_vec(),
    };
    let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
        owner_utxo_hash: owner_utxo_hash(&owner.owner_hash().unwrap(), &blinding).unwrap(),
        asset: Mint::SOL.asset.to_bytes(),
        amount: 25,
        data_hash: None,
        ring_program_id: RING.to_bytes(),
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            ciphertext,
            ..encrypted
        },
    });
    let hash = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 25,
        blinding,
        ring_program_id: Some(RING),
        data: Default::default(),
    }
    .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
    .unwrap();
    EncryptedUtxoMatch {
        slot: 1,
        tx_signature: Signature::from([blinding[31]; 64]),
        output_slot: OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: 500 + u64::from(blinding[31]),
            },
            payload,
        },
        tx_viewing_pk: None,
        salt: None,
    }
}

#[test]
fn a_history_round_trips_and_refuses_another_version() {
    let alice = Wallet::new(1);
    let bob = keypair(2).viewing_pubkey();
    let tags = TransferTagging {
        keys: &alice.keys,
        history: &alice.history,
        recipients: &[PaymentRecipient {
            viewing_pubkey: bob,
            first_contact: FirstContact::Bootstrap,
        }],
    }
    .plan()
    .unwrap();
    let rotated = tags
        .history
        .with_rotated_key(keypair(3).viewing_pubkey(), 5)
        .unwrap();
    let json = rotated.to_json();
    assert_eq!(ViewingHistory::from_json(&json).unwrap(), rotated);
    let mut stored: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(stored["version"], VIEWING_HISTORY_VERSION);
    stored["version"] = 6.into();
    assert!(matches!(
        ViewingHistory::from_json(&stored.to_string()),
        Err(AnonymousError::ViewingHistoryVersion { version: 6 })
    ));
    assert!(matches!(
        rotated.with_rotated_key(keypair(4).viewing_pubkey(), 5),
        Err(AnonymousError::RotatedKeyNotNewer)
    ));
}

#[test]
fn a_history_prints_no_counterparty() {
    let alice = Wallet::new(1);
    let bob = keypair(2).viewing_pubkey();
    let tags = TransferTagging {
        keys: &alice.keys,
        history: &alice.history,
        recipients: &[PaymentRecipient {
            viewing_pubkey: bob,
            first_contact: FirstContact::Bootstrap,
        }],
    }
    .plan()
    .unwrap();
    let printed = format!("{:?}", tags.history);
    assert!(!printed.contains(&format!("{bob:?}")), "{printed}");
    assert!(printed.contains("<redacted>"));
}

#[test]
fn a_deposit_first_contact_pairs_nothing_and_a_transfer_one_does() {
    let alice = Wallet::new(1);
    let bob = PaymentRecipient {
        viewing_pubkey: keypair(2).viewing_pubkey(),
        first_contact: FirstContact::Bootstrap,
    };
    let deposit = alice.history.deposit_tag(&alice.keys, &bob).unwrap();
    assert_eq!(deposit.tag.selection, TagSelection::Bootstrap);
    assert!(deposit.history.current().known_recipients().is_empty());
    let again = deposit.history.deposit_tag(&alice.keys, &bob).unwrap();
    assert_eq!(again.tag.selection, TagSelection::Bootstrap);
    let transfer = TransferTagging {
        keys: &alice.keys,
        history: &again.history,
        recipients: std::slice::from_ref(&bob),
    }
    .plan()
    .unwrap();
    assert!(transfer
        .history
        .current()
        .known_recipients()
        .contains_key(&bob.viewing_pubkey));
}
