//! The anonymous half of `WalletScan` against an in-memory indexer.

use std::sync::Mutex;

use crate::ZolanaServices;
use custom_ring_interface::{
    blinding::ring_blinding_seed, encode_ring_body_output, encode_ring_sender_bundle_output,
    stream::DeliveredSlot, OutputRecord, RecordKind, SenderBundle,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncProverClient, ClientError,
    Context as Page, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetShieldedTransactionsByTagsResponse, HistoryFilters, OutputContext, OutputSlot,
    PaginationToken, RingHistoryOptions, ShieldedTransaction, TransactionOutputs, WitnessReader,
};
use spr_event::{encode_merge_output_data, MergeOutputDataRef, MessageData};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{viewing_key::ViewTag, ShieldedAddress, ShieldedKeypair};
use spr_transaction::{
    instructions::merge::MergeOutputPlaintext,
    serialization::proofless::{Proofless, ProoflessEncode},
    utxo::blinding::derive_transact_output_blinding,
    AssetRegistry, Data, Mint, OwnerCx, Utxo, UtxoSerialization,
};
use zolana_ring_keys::{MergeSeedHolder, MergeSeedRequest};
use zolana_ring_transaction::{seal_recipient_body, seal_sender_bundle, OutputBlindings};

use super::{
    fixtures::{keypair, Member, RING},
    *,
};

#[path = "../../../../sdk-libs/client/tests/common/history_page.rs"]
mod history_page;

use history_page::EventsPage;

const TREE: u16 = 2;
const SALT: [u8; 16] = [7; 16];
const SEED: [u8; 32] = [0x0b; 32];
const CAUGHT_UP: Page = Page {
    block_time: 0,
    slot: u64::MAX,
};

/// Serves what the asked tags or nullifiers reach, in one page.
#[derive(Default)]
struct Ledger {
    transactions: Vec<ShieldedTransaction>,
    deposits: Vec<EncryptedUtxoMatch>,
    queried: Mutex<Vec<[u8; 32]>>,
    mints: Vec<Mint>,
}

struct DepositedUtxo {
    hash: [u8; 32],
    nullifier: [u8; 32],
}

fn slot_secret(
    tx: &spr_keypair::ViewingKey,
    owner: &ShieldedAddress,
    first_nullifier: &[u8; 32],
    output_index: u32,
) -> custom_ring_interface::stream::SlotSecret {
    DeliveredSlot {
        agreement: &tx.ecdh(&owner.viewing_pubkey).unwrap(),
        tx_viewing_pk: tx.pubkey().as_bytes(),
        recipient_viewing_pk: owner.viewing_pubkey.as_bytes(),
        salt: &SALT,
        output_index,
        first_nullifier,
    }
    .secret()
    .unwrap()
}

/// The ring body of `sealed` at slot 0, its record alone.
fn ring_body(
    sealed: &Sealed<'_>,
    owner: &ShieldedAddress,
    blinding: [u8; 32],
    secret: &custom_ring_interface::stream::SlotSecret,
) -> Vec<u8> {
    let record = OutputRecord {
        kind: RecordKind::Ring,
        amount: sealed.amount,
        owner_key: owner.signing_pubkey.confidential_view_tag().unwrap(),
        mint: sealed.asset.asset.to_bytes(),
        nullifier_pk: owner.nullifier_pubkey,
        blinding,
    };
    let ciphertext = seal_recipient_body(&record, None, secret).unwrap();
    encode_ring_body_output(&ciphertext, &[]).unwrap()
}

/// One ring output, sealed at slot 0 as the anonymous rail seals it.
struct Sealed<'a> {
    sender: &'a ShieldedKeypair,
    owner: &'a ShieldedKeypair,
    first_nullifier: [u8; 32],
    asset: Mint,
    amount: u64,
    leaf: u64,
}

impl Ledger {
    /// A default-ring note, the plain scan finds it under the owner's viewing tag.
    fn deposit(&mut self, owner: &ShieldedKeypair, amount: u64) -> DepositedUtxo {
        let address = owner.shielded_address().unwrap();
        let mut blinding = [0; 32];
        blinding[31] = 9;
        let utxo = Utxo {
            owner: address.signing_pubkey,
            asset: Mint::SOL,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let hash = utxo
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let assets = AssetRegistry::default();
        let message = Proofless::encode(
            std::slice::from_ref(&utxo),
            &OwnerCx {
                owner: address.signing_pubkey,
                assets: &assets,
                ring_program_id: None,
                first_nullifier: None,
            },
            [0; 32],
            &ProoflessEncode {
                owner_hash: address.owner_hash().unwrap(),
                data_hash: None,
                ring_data_hash: None,
            },
        )
        .unwrap();
        self.deposits.push(EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::from([0xd0; 64]),
            output_slot: OutputSlot {
                view_tag: custom_ring_interface::stream::slot_tag(address.viewing_pubkey.u()),
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: 1,
                },
                payload: message.data,
            },
            tx_viewing_pk: None,
            salt: None,
        });
        DepositedUtxo {
            hash,
            nullifier: owner.nullifier(&hash, &utxo.blinding).unwrap(),
        }
    }

    /// A payment from `sealed.sender` to `sealed.owner`, its ring body at output 0.
    fn payment(&mut self, sealed: Sealed<'_>) -> [u8; 32] {
        let owner = sealed.owner.shielded_address().unwrap();
        let tx = sealed
            .sender
            .viewing_key
            .get_transaction_viewing_key(&sealed.first_nullifier)
            .unwrap();
        let blinding = derive_transact_output_blinding(&sealed.first_nullifier, &SEED, 0).unwrap();
        let secret = slot_secret(&tx, &owner, &sealed.first_nullifier, 0);
        let payload = ring_body(&sealed, &owner, blinding, &secret);
        let tag = custom_ring_interface::stream::slot_tag(secret.recipient_tag().unwrap());
        self.publish(&sealed, &owner, blinding, payload, tag, Vec::new())
    }

    /// The sender's change at output 0 under a zero tag, its bundle the first message names it.
    fn change(&mut self, sealed: Sealed<'_>) -> [u8; 32] {
        let owner = sealed.owner.shielded_address().unwrap();
        let tx = sealed
            .sender
            .viewing_key
            .get_transaction_viewing_key(&sealed.first_nullifier)
            .unwrap();
        let seed = ring_blinding_seed(&tx.secret_bytes(), &SALT).unwrap();
        let blindings = OutputBlindings::new(&sealed.first_nullifier, &seed).unwrap();
        let blinding = blindings.at(0).unwrap();
        let payload = ring_body(
            &sealed,
            &owner,
            blinding,
            &slot_secret(&tx, &owner, &sealed.first_nullifier, 0),
        );
        let secret = slot_secret(&tx, &owner, &sealed.first_nullifier, 1);
        let ciphertext = seal_sender_bundle(
            &SenderBundle {
                output_seed: *blindings.output_seed(),
                recipient_keys: vec![owner.viewing_pubkey.u()],
            },
            &secret,
        )
        .unwrap();
        let bundle = MessageData {
            view_tag: secret.sender_tag().unwrap(),
            data: encode_ring_sender_bundle_output(&ciphertext).unwrap(),
        };
        self.publish(&sealed, &owner, blinding, payload, [0; 32], vec![bundle])
    }

    fn publish(
        &mut self,
        sealed: &Sealed<'_>,
        owner: &ShieldedAddress,
        blinding: [u8; 32],
        payload: Vec<u8>,
        tag: ViewTag,
        messages: Vec<MessageData>,
    ) -> [u8; 32] {
        let hash = Utxo {
            owner: owner.signing_pubkey,
            asset: sealed.asset,
            amount: sealed.amount,
            blinding,
            ring_program_id: Some(RING),
            data: Data::default(),
        }
        .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
        let tx_viewing_pk = sealed
            .sender
            .viewing_key
            .get_transaction_viewing_key(&sealed.first_nullifier)
            .unwrap()
            .pubkey();
        self.transactions.push(ShieldedTransaction {
            slot: 5,
            tx_signature: Signature::from([sealed.leaf as u8 + 1; 64]),
            event_index: Some(0),
            tx_viewing_pk: Some(tx_viewing_pk),
            salt: Some(SALT),
            output_slots: vec![OutputSlot {
                view_tag: tag,
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: sealed.leaf,
                },
                payload,
            }],
            messages,
            nullifiers: vec![sealed.first_nullifier],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        });
        hash
    }

    fn client(self) -> Zolana<NoRpc, Self> {
        ZolanaServices {
            rpc: NoRpc,
            indexer: self,
            prover: AsyncProverClient::local(),
            ring_prover: AsyncProverClient::local(),
        }
        .connect()
    }
}

impl Ledger {
    fn page(
        &self,
        filters: HistoryFilters,
        matches: impl Fn(&ShieldedTransaction) -> bool,
    ) -> GetShieldedTransactionsByTagsResponse {
        EventsPage {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            rows: self
                .transactions
                .iter()
                .filter(|tx| filters.slot.contains(tx.slot) && matches(tx))
                .cloned()
                .collect(),
            more: false,
        }
        .response()
    }
}

impl WitnessReader for Ledger {}

impl Rpc for Ledger {
    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(self.page(options.filters, |tx| {
            tx.ring_program_id == Some(options.ring_program_id)
        }))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.queried.lock().unwrap().extend(&tags);
        Ok(self.page(filters, |tx| {
            tx.output_slots
                .iter()
                .any(|slot| tags.contains(&slot.view_tag))
        }))
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        // One terminal page, rows of one transaction grouped as Photon groups them.
        let mut data: Vec<TransactionOutputs<_, _>> = Vec::new();
        let rows = self.deposits.iter().filter(|deposit| {
            filters.slot.contains(deposit.slot) && tags.contains(&deposit.output_slot.view_tag)
        });
        for row in rows {
            match data.last_mut() {
                Some(last) if last.slot == row.slot && last.signature == row.tx_signature => {
                    last.outputs.push(row.clone())
                }
                _ => data.push(TransactionOutputs {
                    slot: row.slot,
                    signature: row.tx_signature,
                    outputs: vec![row.clone()],
                }),
            }
        }
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            data,
            pagination_token: None,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(self.page(filters, |tx| {
            tx.nullifiers.iter().any(|spent| nullifiers.contains(spent))
        }))
    }
}

struct NoRpc;

impl Rpc for NoRpc {}

impl Member {
    fn scan(&self, zolana: &Zolana<NoRpc, Ledger>) -> Vec<[u8; 32]> {
        self.scan_in(zolana, RingMode::Anonymous)
            .spendable
            .utxos()
            .map(|utxo| utxo.utxo_hash)
            .collect()
    }

    /// Registers nothing up front, the chain's assets name the ledger's mints.
    fn scan_in(&self, zolana: &Zolana<NoRpc, Ledger>, mode: RingMode) -> WalletNotes {
        let assets = RingAssets::new([]).unwrap();
        ScanAt {
            keys: &zolana_ring_keys::RotatingRingKeys::new(&self.keys).unwrap(),
            assets: &assets,
            chain_assets: &|| Ok(RingAssets::new(zolana.indexer().mints.clone())?),
            slot: 9,
            store: &self.store,
            mode,
            ring: RING,
        }
        .fetch(zolana)
        .unwrap()
    }

    fn confidential_scan(&self, zolana: &Zolana<NoRpc, Ledger>) -> Vec<[u8; 32]> {
        self.scan_in(zolana, RingMode::Confidential)
            .spendable
            .utxos()
            .map(|utxo| utxo.utxo_hash)
            .collect()
    }

    /// Moves each payment to the confidential 8 B slot tag.
    fn confidential_tags(&self, ledger: &mut Ledger) {
        let tag = custom_ring_interface::stream::slot_tag(self.keys.viewing_pubkey().u());
        for tx in &mut ledger.transactions {
            tx.output_slots[0].view_tag = tag;
        }
    }

    fn payment_from_2(&self, ledger: &mut Ledger, asset: Mint) -> [u8; 32] {
        ledger.payment(Sealed {
            sender: &keypair(2),
            owner: &self.keys,
            first_nullifier: [0x11; 32],
            asset,
            amount: 70,
            leaf: 10,
        })
    }
}

/// A canonical first nullifier distinct per `seed`.
fn nullifier(seed: u8) -> [u8; 32] {
    let mut value = [0x11; 32];
    value[31] = seed;
    value
}

#[test]
fn an_anonymous_scan_adds_payments_and_the_change_of_a_default_ring_spend() {
    let wallet = Member::new(1, "anonymous-scan");
    let mut ledger = Ledger::default();
    let paid = wallet.payment_from_2(&mut ledger, Mint::SOL);
    let deposited = ledger.deposit(&wallet.keys, 40);
    let change = ledger.change(Sealed {
        sender: &wallet.keys,
        owner: &wallet.keys,
        first_nullifier: deposited.nullifier,
        asset: Mint::SOL,
        amount: 30,
        leaf: 20,
    });
    let held = wallet.scan(&ledger.client());
    assert!(held.contains(&paid), "the payment");
    assert!(held.contains(&change), "the change of the deposit's spend");
    assert!(!held.contains(&deposited.hash), "the spent deposit");
    assert_eq!(held.len(), 2);
    let stored = wallet.store.load().unwrap();
    let current = stored.history().current();
    assert_eq!(current.ring_positions()[&RING], Some(u64::MAX));
    // A body names no sender, only a reply the wallet confirms records one.
    assert!(current.known_senders().is_empty());
}

/// A confidential ring keeps a ledger, each slot publishes the 8 B tag alone.
#[test]
fn a_confidential_ring_wallet_finds_a_payment_under_its_slot_tag_and_resumes_past_it() {
    let wallet = Member::new(1, "confidential-scan");
    let mut ledger = Ledger::default();
    let paid = wallet.payment_from_2(&mut ledger, Mint::SOL);
    wallet.confidential_tags(&mut ledger);
    let zolana = ledger.client();
    assert_eq!(wallet.confidential_scan(&zolana), [paid]);
    let stored = wallet.store.load().unwrap();
    assert_eq!(stored.history().current().tag_position(), Some(u64::MAX));
    assert!(stored.history().current().ring_positions().is_empty());
    assert_eq!(
        wallet.confidential_scan(&zolana),
        [paid],
        "the ledger answers past its position"
    );
}

/// A zero-key merge under the owner's tag, its commitment.
fn publish_owner_merge(ledger: &mut Ledger, owner: &ShieldedKeypair, first: [u8; 32]) -> [u8; 32] {
    let seed = zolana_ring_keys::RotatingRingKeys::new(owner)
        .unwrap()
        .merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: owner.viewing_pubkey(),
            ring_program_id: RING,
            first_nullifier: first,
        }])
        .unwrap()
        .remove(0);
    let hash = Utxo {
        owner: owner.signing_key.pubkey(),
        asset: Mint::SOL,
        amount: 100,
        blinding: seed.output_blinding(&first).unwrap(),
        ring_program_id: Some(RING),
        data: Data::default(),
    }
    .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], TREE)
    .unwrap();
    let salt = [8; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: 100,
        mint: Mint::SOL.asset,
    }
    .encrypt(&seed.output_key(&first).unwrap(), &salt)
    .unwrap();
    ledger.transactions.push(ShieldedTransaction {
        slot: 5,
        tx_signature: Signature::from([first[0]; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: owner.signing_key.pubkey().owner_proof_input_hash().unwrap(),
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: 30,
            },
            payload: encode_merge_output_data(MergeOutputDataRef {
                salt: &salt,
                ciphertext: &ciphertext,
                prefix: &[[0; 32]],
            }),
        }],
        messages: Vec::new(),
        nullifiers: vec![first],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    hash
}

#[test]
fn a_seeded_merge_reads_exposed_once_on_either_ring_mode() {
    let owner = keypair(1);
    let mut ledger = Ledger::default();
    let merged = publish_owner_merge(&mut ledger, &owner, nullifier(40));
    let zolana = ledger.client();
    for (mode, test) in [
        (RingMode::Confidential, "seeded-merge-confidential"),
        (RingMode::Anonymous, "seeded-merge-anonymous"),
    ] {
        let notes = Member::new(1, test).scan_in(&zolana, mode);
        let exposed: Vec<[u8; 32]> = notes
            .exposed_if_spent
            .iter()
            .map(|utxo| utxo.utxo_hash)
            .collect();
        assert_eq!(exposed, [merged]);
        assert!(notes.spendable.utxos().next().is_none());
    }
}

#[test]
fn a_note_in_a_mint_registered_after_the_registry_read_is_kept() {
    let wallet = Member::new(1, "late-mint");
    let mint = Mint {
        asset: Address::new_from_array([0x6d; 32]),
        asset_id: 9,
    };
    let mut ledger = Ledger {
        mints: vec![mint],
        ..Ledger::default()
    };
    let paid = wallet.payment_from_2(&mut ledger, mint);
    let zolana = ledger.client();
    assert_eq!(wallet.scan(&zolana), [paid]);
    assert_eq!(wallet.scan(&zolana), [paid], "a second scan");
}

#[test]
fn a_confidential_note_in_a_mint_registered_after_the_registry_read_is_kept() {
    let wallet = Member::new(1, "late-mint-confidential");
    let mint = Mint {
        asset: Address::new_from_array([0x6d; 32]),
        asset_id: 9,
    };
    let mut ledger = Ledger {
        mints: vec![mint],
        ..Ledger::default()
    };
    let paid = wallet.payment_from_2(&mut ledger, mint);
    wallet.confidential_tags(&mut ledger);
    let zolana = ledger.client();
    assert_eq!(wallet.confidential_scan(&zolana), [paid]);
    assert!(wallet.store.load().unwrap().pending_notes().is_empty());
    assert_eq!(wallet.confidential_scan(&zolana), [paid], "a second scan");
}

#[test]
fn a_restored_wallet_rebuilds_its_notes_from_the_rings_start() {
    let wallet = Member::new(1, "restored-scan");
    let mut ledger = Ledger::default();
    let paid = wallet.payment_from_2(&mut ledger, Mint::SOL);
    let change = ledger.change(Sealed {
        sender: &wallet.keys,
        owner: &wallet.keys,
        first_nullifier: nullifier(3),
        asset: Mint::SOL,
        amount: 5,
        leaf: 30,
    });
    let zolana = ledger.client();
    let first = wallet.scan(&zolana);
    let synced = wallet.store.load().unwrap();
    fs::remove_file(wallet.state_file()).unwrap();
    let restored = wallet.scan(&zolana);
    assert_eq!(first, restored);
    assert!(restored.contains(&paid) && restored.contains(&change));
    let rebuilt = wallet.store.load().unwrap();
    let (rebuilt, synced) = (rebuilt.history().current(), synced.history().current());
    assert_eq!(rebuilt.tx_count(), synced.tx_count());
    assert_eq!(rebuilt.known_senders(), synced.known_senders());
}
