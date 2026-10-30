//! The anonymous half of `WalletScan` against an in-memory indexer.

use std::sync::Mutex;

use crate::ZolanaServices;
use custom_ring_interface::{
    blinding::ring_blinding_seed, encode_anonymous_recipient_output, encode_anonymous_sender_output,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncProverClient, ClientError,
    Context as Page, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetShieldedTransactionsByTagsResponse, OutputContext, OutputSlot, ShieldedTransaction,
    WitnessReader,
};
use spr_event::MessageData;
use spr_keypair::{viewing_key::ViewTag, ShieldedAddress};
use spr_transaction::{
    serialization::proofless::{Proofless, ProoflessEncode},
    utxo::blinding::derive_transact_output_blinding,
    AssetRegistry, Data, Mint, OwnerCx, Utxo, UtxoSerialization,
};
use zolana_ring_transaction::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, OutputBlindings,
    UnverifiedRecipientPlaintext, UnverifiedSenderPlaintext, VerifiedRecipientPlaintext,
    VerifiedSenderPlaintext,
};

use super::{
    fixtures::{keypair, Member, RING},
    *,
};

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

/// One ring output under `tag`, sealed at slot 0 as the anonymous rail seals it.
struct Sealed<'a> {
    sender: &'a ShieldedKeypair,
    owner: &'a ShieldedKeypair,
    first_nullifier: [u8; 32],
    tag: ViewTag,
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
                view_tag: address.viewing_pubkey.u(),
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

    /// A payment from `sealed.sender` to `sealed.owner`, its scheme 1 body at output 0.
    fn payment(&mut self, sealed: Sealed<'_>) -> [u8; 32] {
        let owner = sealed.owner.shielded_address().unwrap();
        let tx = sealed
            .sender
            .viewing_key
            .get_transaction_viewing_key(&sealed.first_nullifier)
            .unwrap();
        let blinding = derive_transact_output_blinding(&sealed.first_nullifier, &SEED, 0).unwrap();
        let body = AnonymousTransferRecipientPlaintext {
            verified: VerifiedRecipientPlaintext {
                owner_pubkey: owner.signing_pubkey,
                mint: sealed.asset.asset,
                amount: sealed.amount,
            },
            unverified: UnverifiedRecipientPlaintext {
                sender_pubkey: sealed.sender.viewing_pubkey(),
                blinding,
                data: Data::default(),
            },
        }
        .serialize()
        .unwrap();
        let ciphertext = tx
            .encrypt_slot(&owner.viewing_pubkey, &body, SALT, 0)
            .unwrap();
        let payload = encode_anonymous_recipient_output(&ciphertext).unwrap();
        self.publish(&sealed, &owner, blinding, payload, Vec::new())
    }

    /// The sender's change at output 0 with no body, its bundle the first message.
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
        let sol = sealed.asset == Mint::SOL;
        let body = AnonymousTransferSenderPlaintext {
            verified: VerifiedSenderPlaintext {
                owner_pubkey: owner.signing_pubkey,
                spl_mint: if sol {
                    Default::default()
                } else {
                    sealed.asset.asset
                },
                spl_amount: if sol { 0 } else { sealed.amount },
                sol_amount: if sol { sealed.amount } else { 0 },
                recipient_viewing_pks: Vec::new(),
            },
            unverified: UnverifiedSenderPlaintext {
                blinding_seed: *blindings.output_seed(),
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
        }
        .serialize()
        .unwrap();
        let ciphertext = tx
            .encrypt_slot(&owner.viewing_pubkey, &body, SALT, 1)
            .unwrap();
        let bundle = MessageData {
            view_tag: sealed.tag,
            data: encode_anonymous_sender_output(&ciphertext).unwrap(),
        };
        self.publish(&sealed, &owner, blinding, Vec::new(), vec![bundle])
    }

    fn publish(
        &mut self,
        sealed: &Sealed<'_>,
        owner: &ShieldedAddress,
        blinding: [u8; 32],
        payload: Vec<u8>,
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
                view_tag: sealed.tag,
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

impl WitnessReader for Ledger {}

impl Rpc for Ledger {
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.queried.lock().unwrap().extend(&tags);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            transactions: self
                .transactions
                .iter()
                .filter(|tx| {
                    tx.output_slots
                        .iter()
                        .any(|slot| tags.contains(&slot.view_tag))
                })
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            matches: self
                .deposits
                .iter()
                .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            transactions: self
                .transactions
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|spent| nullifiers.contains(spent)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

struct NoRpc;

impl Rpc for NoRpc {}

impl Member {
    fn scan(&self, zolana: &Zolana<NoRpc, Ledger>) -> Vec<[u8; 32]> {
        let assets = RingAssets::new([]).unwrap();
        ScanAt {
            keys: &self.keys,
            assets: &assets,
            chain_assets: &|| Ok(RingAssets::new(zolana.indexer().mints.clone())?),
            slot: 9,
            store: Some(&self.store),
        }
        .fetch(zolana)
        .unwrap()
        .utxos()
        .map(|utxo| utxo.utxo_hash)
        .collect()
    }

    fn bootstrap_payment(&self, ledger: &mut Ledger, asset: Mint) -> [u8; 32] {
        ledger.payment(Sealed {
            sender: &keypair(2),
            owner: &self.keys,
            first_nullifier: [0x11; 32],
            tag: self.keys.recipient_bootstrap_view_tag(),
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
    let paid = wallet.bootstrap_payment(&mut ledger, Mint::SOL);
    let deposited = ledger.deposit(&wallet.keys, 40);
    let change = ledger.change(Sealed {
        sender: &wallet.keys,
        owner: &wallet.keys,
        first_nullifier: deposited.nullifier,
        tag: wallet.keys.get_sender_view_tag(0).unwrap(),
        asset: Mint::SOL,
        amount: 30,
        leaf: 20,
    });
    let held = wallet.scan(&ledger.client());
    assert!(held.contains(&paid), "the bootstrap payment");
    assert!(held.contains(&change), "the change of the deposit's spend");
    assert!(!held.contains(&deposited.hash), "the spent deposit");
    assert_eq!(held.len(), 2);
    let stored = wallet.store.load().unwrap();
    let current = stored.current();
    assert_eq!(current.tx_count(), 1);
    let pair = keypair(2).viewing_pubkey();
    assert_eq!(
        current
            .known_senders()
            .get(&pair)
            .map(|counter| counter.next()),
        Some(0)
    );
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
    let paid = wallet.bootstrap_payment(&mut ledger, mint);
    let zolana = ledger.client();
    assert_eq!(wallet.scan(&zolana), [paid]);
    assert_eq!(wallet.scan(&zolana), [paid], "a second scan");
}

#[test]
fn a_restored_wallet_rebuilds_its_notes_and_counters_from_index_0() {
    let wallet = Member::new(1, "restored-scan");
    let mut ledger = Ledger::default();
    let paid = wallet.bootstrap_payment(&mut ledger, Mint::SOL);
    let change = ledger.change(Sealed {
        sender: &wallet.keys,
        owner: &wallet.keys,
        first_nullifier: nullifier(3),
        tag: wallet.keys.get_sender_view_tag(0).unwrap(),
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
    assert_eq!(rebuilt.current().tx_count(), synced.current().tx_count());
    assert_eq!(
        rebuilt.current().known_senders(),
        synced.current().known_senders()
    );
}
