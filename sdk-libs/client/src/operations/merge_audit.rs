use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::{MergeRecord, RecordKind};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, RingHistoryOptions,
    ShieldedTransaction,
};
use spr_event::{
    split_merge_output_body, OutputDataEncoding, MERGE_OUTPUT_BODY_LEN, MERGE_OUTPUT_SCHEME,
};
use spr_hasher::primitives::{hash_bytes, is_canonical_bn254_scalar_be};
use spr_indexer_api::Context;
use spr_interface::instruction::instruction_data::merge_transact::merge_circuit_width;
use spr_keypair::{X25519Keypair, X25519Pubkey};
use spr_transaction::{instructions::merge::MergeSeed, OutputSlot};

use crate::{
    encryption::{open_merge_record, SealedMergeCiphertexts},
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream, PageEnd},
    merge_ledger::{ConfirmedMerge, MergeRecordOutput},
    origin::{ConfirmedEventKind, ConfirmedMergeDisclosure, RingOrigin, TransactionOrigin},
    scan::{RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    types::{KnownUtxo, UtxoOwner},
    AuditError,
};

/// The cursor names the last Solana transaction the page examined.
pub struct MergeAuditPage {
    pub context: Context,
    pub merges: Vec<ConfirmedMerge>,
    pub next_cursor: Option<HistoryCursor>,
}

/// An incomplete scan aborts.
#[must_use = "run or discard the merge audit explicitly"]
pub struct MergeAudit<'a> {
    ring: Address,
    auditor: &'a X25519Keypair,
    cursor: Option<HistoryCursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// One confirmed merge output, its body length and fields checked.
pub(crate) struct MergeOutput {
    pub(crate) commitment: [u8; 32],
    pub(crate) tree_id: u16,
    pub(crate) leaf_index: u64,
    pub(crate) first_nullifier: [u8; 32],
    pub(crate) ring_data_hash: [u8; 32],
}

#[derive(Default)]
struct OpenedPage {
    merges: Vec<ConfirmedMerge>,
}

impl<'a> MergeAudit<'a> {
    pub fn new(ring: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring,
            auditor,
            cursor: None,
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_cursor(mut self, cursor: Option<HistoryCursor>) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    /// Every confirmed merge from the cursor on, in history order.
    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<Vec<ConfirmedMerge>, AuditError> {
        let mut position = self.query().position(self.cursor)?;
        let mut merges = Vec::new();
        let mut seen = HashSet::new();
        for _ in 0..self.max_pages.get() {
            let (response, end) = self.read_history_page(indexer, &mut position).await?;
            let page = self
                .open_transactions(rows(response), origin, &mut seen)
                .await?;
            merges.extend(page.merges);
            if let PageEnd::Terminal(_) = end {
                return Ok(merges);
            }
        }
        Err(AuditError::IncompleteScan)
    }

    /// Open one ring-history page for an authenticated RPC reader.
    pub async fn page<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<MergeAuditPage, AuditError> {
        let query = self.query();
        let mut position = query.position(self.cursor)?;
        let (response, _) = self.read_history_page(indexer, &mut position).await?;
        let context = response.context;
        let mut seen = HashSet::new();
        let page = self
            .open_transactions(rows(response), origin, &mut seen)
            .await?;
        Ok(MergeAuditPage {
            context,
            merges: page.merges,
            next_cursor: query.next_cursor(&position),
        })
    }

    const fn query(&self) -> HistoryQuery {
        HistoryQuery {
            ring: self.ring,
            stream: HistoryStream::Ring,
        }
    }

    async fn read_history_page<I: AsyncRpc>(
        &self,
        indexer: &I,
        position: &mut HistoryPosition,
    ) -> Result<(GetShieldedTransactionsByTagsResponse, PageEnd), AuditError> {
        let response = indexer
            .get_shielded_transactions_by_ring(
                RingHistoryOptions {
                    ring_program_id: self.ring,
                    pagination_token: position.token(),
                    limit: Some(self.page_size.get()),
                    filters: position.filters(),
                },
                self.indexer_config,
            )
            .await?;
        let end = position
            .advance(&response, self.page_size.get())
            .map_err(|_| AuditError::InvalidHistoryPage)?;
        Ok((response, end))
    }

    async fn open_transactions<O: TransactionOrigin>(
        &self,
        transactions: Vec<ShieldedTransaction>,
        origin: &O,
        seen: &mut HashSet<(Signature, u16)>,
    ) -> Result<OpenedPage, AuditError> {
        let mut page = OpenedPage::default();
        for mut tx in transactions {
            if tx.ring_program_id != Some(self.ring) {
                continue;
            }
            let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
            let confirmed = origin
                .origin(tx.tx_signature, event_index, self.ring)
                .await?;
            if !confirmed.ring_invoked || confirmed.event.kind() != ConfirmedEventKind::Merge {
                continue;
            }
            confirmed.bind_transaction(&mut tx, self.ring)?;
            remember_merge(seen, tx.tx_signature, event_index)?;
            page.merges
                .extend(confirmed_merge(&tx, event_index, &confirmed, self.auditor)?);
        }
        Ok(page)
    }
}

fn rows(response: GetShieldedTransactionsByTagsResponse) -> Vec<ShieldedTransaction> {
    response
        .data
        .into_iter()
        .flat_map(|item| item.events)
        .collect()
}

/// `None` on a frame with no disclosure.
pub fn confirmed_merge(
    transaction: &ShieldedTransaction,
    event_index: u16,
    origin: &RingOrigin,
    auditor: &X25519Keypair,
) -> Result<Option<ConfirmedMerge>, AuditError> {
    let Some(disclosure) = &origin.merge_disclosure else {
        return Ok(None);
    };
    let output = MergeOutput::of(transaction)?;
    let disclosed = output.disclose(auditor, disclosure, transaction)?;
    Ok(Some(ConfirmedMerge {
        slot: transaction.slot,
        tx_signature: transaction.tx_signature,
        event_index,
        output_commitment: output.commitment,
        tree_id: output.tree_id,
        leaf_index: output.leaf_index,
        first_nullifier: output.first_nullifier,
        ring_data_hash: output.ring_data_hash,
        disclosed,
    }))
}

pub(crate) struct RingMergeBody {
    pub(crate) ring_data_hash: [u8; 32],
    pub(crate) encrypted: Vec<u8>,
}

impl RingMergeBody {
    pub(crate) fn of(slot: &OutputSlot) -> Option<Self> {
        let (OutputDataEncoding::Encrypted(blob) | OutputDataEncoding::VerifiablyEncrypted(blob)) =
            slot.output_data()?
        else {
            return None;
        };
        let (&MERGE_OUTPUT_SCHEME, body) = blob.split_first()? else {
            return None;
        };
        let (Some(ring_data_hash), encrypted) = split_merge_output_body(body)? else {
            return None;
        };
        Some(Self {
            ring_data_hash: *ring_data_hash,
            encrypted: encrypted.to_vec(),
        })
    }
}

impl MergeOutput {
    /// A malformed confirmed field is an audit error.
    pub(crate) fn of(tx: &ShieldedTransaction) -> Result<Self, AuditError> {
        let [slot] = tx.output_slots.as_slice() else {
            return Err(invalid_merge());
        };
        let first_nullifier = *tx.nullifiers.first().ok_or_else(invalid_merge)?;
        merge_circuit_width(tx.nullifiers.len()).ok_or_else(invalid_merge)?;
        let body = RingMergeBody::of(slot).ok_or_else(invalid_merge)?;
        let commitment = slot.output_context.hash;
        if body.encrypted.len() != MERGE_OUTPUT_BODY_LEN {
            return Err(invalid_merge());
        }
        if ![first_nullifier, commitment, body.ring_data_hash]
            .iter()
            .all(is_canonical_bn254_scalar_be)
        {
            return Err(invalid_merge());
        }
        Ok(Self {
            commitment,
            tree_id: slot.output_context.tree_id,
            leaf_index: slot.output_context.leaf_index,
            first_nullifier,
            ring_data_hash: body.ring_data_hash,
        })
    }

    fn disclose(
        &self,
        auditor: &X25519Keypair,
        disclosure: &ConfirmedMergeDisclosure,
        transaction: &ShieldedTransaction,
    ) -> Result<MergeRecordOutput, AuditError> {
        let ConfirmedMergeDisclosure {
            eph_pk,
            envelope,
            record,
        } = disclosure;
        let record = open_merge_record(
            auditor,
            &SealedMergeCiphertexts {
                eph_pk: &X25519Pubkey::from_bytes(*eph_pk)?,
                envelope,
                record,
                first_nullifier: &self.first_nullifier,
            },
        )?;
        let ring = transaction
            .ring_program_id
            .ok_or(AuditError::MissingRingProgram)?;
        self.rebuild(record, ring, &transaction.nullifiers)
    }

    /// Accepted only when the record and its seed's blinding hash to the published output.
    fn rebuild(
        &self,
        opened: MergeRecord,
        ring: Address,
        nullifiers: &[[u8; 32]],
    ) -> Result<MergeRecordOutput, AuditError> {
        let MergeRecord {
            record,
            seed: secret,
        } = opened;
        if record.kind != RecordKind::Ring || !is_canonical_bn254_scalar_be(&record.nullifier_pk) {
            return Err(AuditError::DisclosureField);
        }
        let seed = MergeSeed::from_bytes(secret).map_err(|_| AuditError::DisclosureField)?;
        let rebuilt = KnownUtxo {
            owner_key: record.owner_key,
            owner: UtxoOwner::Keyed {
                nullifier_pk: record.nullifier_pk,
            },
            asset: hash_bytes(&record.mint)?,
            mint: Some(Address::new_from_array(record.mint)),
            amount: record.amount,
            blinding: seed.output_blinding(&self.first_nullifier)?,
            data_hash: Some([0; 32]),
            ring_data_hash: Some(self.ring_data_hash),
            tree_id: self.tree_id,
        };
        if rebuilt.commitment(Some(ring))? != Some(self.commitment) {
            return Err(AuditError::MergeDisclosureMismatch);
        }
        let mut real_nullifiers = Vec::with_capacity(nullifiers.len());
        for (slot_index, nullifier) in (0u8..).zip(nullifiers) {
            if *nullifier != seed.dummy_nullifier(&self.first_nullifier, slot_index)? {
                real_nullifiers.push(*nullifier);
            }
        }
        Ok(MergeRecordOutput {
            owner_key: record.owner_key,
            nullifier_pk: record.nullifier_pk,
            mint: Address::new_from_array(record.mint),
            amount: record.amount,
            seed: *seed.as_bytes(),
            real_nullifiers,
        })
    }
}

fn invalid_merge() -> AuditError {
    AuditError::InvalidConfirmedEvent("ring merge output is malformed".to_owned())
}

fn remember_merge(
    seen: &mut HashSet<(Signature, u16)>,
    signature: Signature,
    event_index: u16,
) -> Result<(), AuditError> {
    if !seen.insert((signature, event_index)) {
        return Err(AuditError::InvalidConfirmedEvent(
            "duplicate confirmed ring merge".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::OutputRecord;
    use spr_client::rpc::PaginationToken;
    use spr_event::{encode_merge_output_data, MergeOutputDataRef};
    use spr_interface::ZERO_NULLIFIER_PUBKEY;
    use spr_transaction::{OutputContext, OutputSlot};

    use super::*;
    use crate::{encryption::MergeRecordSeal, origin::RingOrigin};

    const RING: Address = Address::new_from_array([9; 32]);
    const FIRST: [u8; 32] = [4; 32];
    const OWNER: [u8; 32] = [0xb1; 32];
    const MINT: [u8; 32] = [0xc1; 32];
    const RING_DATA: [u8; 32] = [0; 32];

    fn merge_row(hash: [u8; 32], nullifiers: Vec<[u8; 32]>) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: [4; 32],
                output_context: OutputContext {
                    hash,
                    tree_id: 1,
                    leaf_index: 0,
                },
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &[5; 16],
                    ciphertext: &[[0; 32]; 3],
                    prefix: &[RING_DATA],
                }),
            }],
            messages: Vec::new(),
            nullifiers,
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn merged_note(nullifier_pk: [u8; 32], seed: [u8; 32]) -> (MergeRecord, [u8; 32]) {
        let blinding = MergeSeed::from_bytes(seed)
            .unwrap()
            .output_blinding(&FIRST)
            .unwrap();
        let commitment = KnownUtxo {
            owner_key: OWNER,
            owner: UtxoOwner::Keyed { nullifier_pk },
            asset: hash_bytes(&MINT).unwrap(),
            mint: None,
            amount: 12,
            blinding,
            data_hash: Some([0; 32]),
            ring_data_hash: Some(RING_DATA),
            tree_id: 1,
        }
        .commitment(Some(RING))
        .unwrap()
        .expect("data hashes");
        let record = MergeRecord {
            record: OutputRecord {
                kind: RecordKind::Ring,
                amount: 12,
                owner_key: OWNER,
                mint: MINT,
                nullifier_pk,
                blinding,
            },
            seed,
        };
        (record, commitment)
    }

    fn sealed(auditor: &X25519Keypair, record: MergeRecord) -> RingOrigin {
        let opening = MergeRecordSeal {
            record,
            recipient: X25519Keypair::new().pubkey(),
            first_nullifier: FIRST,
        }
        .seal(&auditor.pubkey())
        .unwrap();
        origin_with(ConfirmedMergeDisclosure {
            eph_pk: *opening.eph_pk.as_bytes(),
            envelope: opening.envelope,
            record: opening.record,
        })
    }

    fn origin_with(disclosure: ConfirmedMergeDisclosure) -> RingOrigin {
        RingOrigin {
            merge_disclosure: Some(disclosure),
            ..empty_origin()
        }
    }

    fn empty_origin() -> RingOrigin {
        RingOrigin {
            ring_invoked: true,
            event: crate::ConfirmedEvent::new(
                ConfirmedEventKind::Merge,
                spr_event::GeneralEvent {
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    messages: Vec::new(),
                    tx_viewing_pk: [0; 33],
                    salt: [0; 16],
                    first_output_leaf_index: 0,
                    output_tree: [0; 32],
                    spl_transfers: Vec::new(),
                },
            ),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            merge_disclosure: None,
            transact: None,
            pool_accounts: Vec::new(),
        }
    }

    #[test]
    fn a_record_rebuilds_its_output_and_its_seed_classifies_the_padding_in_both_modes() {
        let auditor = X25519Keypair::new();
        let seed = [0x13; 32].map(|byte: u8| byte & 0x1f);
        for nullifier_pk in [[0x07; 32], ZERO_NULLIFIER_PUBKEY] {
            let (record, commitment) = merged_note(nullifier_pk, seed);
            let derived = MergeSeed::from_bytes(seed).unwrap();
            let nullifiers = vec![
                FIRST,
                [6; 32],
                derived.dummy_nullifier(&FIRST, 2).unwrap(),
                derived.dummy_nullifier(&FIRST, 3).unwrap(),
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
            ];
            let row = merge_row(commitment, nullifiers);
            let merge = confirmed_merge(&row, 0, &sealed(&auditor, record), &auditor)
                .unwrap()
                .unwrap();
            let output = merge.disclosed;
            assert_eq!(output.nullifier_pk, nullifier_pk);
            assert_eq!(output.owner_key, OWNER);
            assert_eq!(output.mint, Address::new_from_array(MINT));
            assert_eq!(output.amount, 12);
            assert_eq!(output.real_nullifiers[..2], [FIRST, [6; 32]]);
            assert!(!output
                .real_nullifiers
                .contains(&derived.dummy_nullifier(&FIRST, 2).unwrap()));
        }
    }

    #[test]
    fn each_record_field_changed_fails_the_rebuild() {
        let auditor = X25519Keypair::new();
        let (record, commitment) = merged_note([0x07; 32], [0x13; 32].map(|byte: u8| byte & 0x1f));
        let row = merge_row(commitment, vec![FIRST; 8]);
        let opens =
            |spoiled: MergeRecord| confirmed_merge(&row, 0, &sealed(&auditor, spoiled), &auditor);
        assert!(opens(record).is_ok());
        type Spoil = fn(&mut MergeRecord);
        let spoils: [Spoil; 5] = [
            |opened| opened.record.amount += 1,
            |opened| opened.record.owner_key[0] ^= 1,
            |opened| opened.record.mint[0] ^= 1,
            |opened| opened.record.nullifier_pk[31] ^= 1,
            |opened| opened.seed[31] ^= 1,
        ];
        for spoil in spoils {
            let mut spoiled = record;
            spoil(&mut spoiled);
            assert!(matches!(
                opens(spoiled),
                Err(AuditError::MergeDisclosureMismatch)
            ));
        }
        let mut exit = record;
        exit.record.kind = RecordKind::Exit;
        assert!(matches!(opens(exit), Err(AuditError::DisclosureField)));
        let mut unseeded = record;
        unseeded.seed = [0; 32];
        assert!(matches!(opens(unseeded), Err(AuditError::DisclosureField)));
    }

    struct History {
        pagination_token: Option<PaginationToken>,
    }

    #[async_trait::async_trait]
    impl AsyncRpc for History {
        async fn get_shielded_transactions_by_ring(
            &self,
            _options: RingHistoryOptions,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: spr_client::Context {
                    slot: 1,
                    block_time: 0,
                },
                output_tree_id: None,
                data: Vec::new(),
                pagination_token: self.pagination_token,
            })
        }
    }

    #[tokio::test]
    async fn a_terminal_history_page_ends_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(RING, &auditor);
        let indexer = History {
            pagination_token: None,
        };
        let mut position = HistoryPosition::default();
        let (response, end) = audit
            .read_history_page(&indexer, &mut position)
            .await
            .unwrap();
        assert_eq!(end, PageEnd::Terminal(response.context));
    }

    #[tokio::test]
    async fn a_token_with_no_row_behind_it_fails_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(RING, &auditor);
        let indexer = History {
            pagination_token: Some(PaginationToken::new(1, Signature::default())),
        };
        let mut position = HistoryPosition::default();
        assert!(matches!(
            audit.read_history_page(&indexer, &mut position).await,
            Err(AuditError::InvalidHistoryPage)
        ));
        assert_eq!(position, HistoryPosition::default());
    }

    #[tokio::test]
    async fn a_cursor_of_another_stream_is_refused_before_any_read() {
        let auditor = X25519Keypair::new();
        let ring = RING;
        let cursor = HistoryCursor {
            query: HistoryQuery {
                ring,
                stream: HistoryStream::Tags,
            },
            token: PaginationToken::new(1, Signature::default()),
        };
        let indexer = History {
            pagination_token: None,
        };
        assert!(matches!(
            MergeAudit::new(ring, &auditor)
                .with_cursor(Some(cursor))
                .page(&indexer, &UnreadOrigin)
                .await,
            Err(AuditError::HistoryCursor(_))
        ));
    }

    #[test]
    fn a_confirmed_merge_cannot_be_counted_twice_across_history_pages() {
        let mut seen = HashSet::new();
        let signature = Signature::default();
        remember_merge(&mut seen, signature, 1).unwrap();
        remember_merge(&mut seen, signature, 2).unwrap();
        assert!(matches!(
            remember_merge(&mut seen, signature, 1),
            Err(AuditError::InvalidConfirmedEvent(_))
        ));
    }

    struct UnreadOrigin;

    impl TransactionOrigin for UnreadOrigin {
        async fn origin(
            &self,
            signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            Err(AuditError::Unavailable {
                signature,
                message: "no origin read".to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn a_row_of_another_ring_never_reaches_the_origin_read() {
        let ring = RING;
        let auditor = X25519Keypair::new();
        let outsider = ShieldedTransaction {
            slot: 0,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        };
        let page = MergeAudit::new(ring, &auditor)
            .open_transactions(vec![outsider], &UnreadOrigin, &mut HashSet::new())
            .await
            .unwrap();
        assert!(page.merges.is_empty());
    }
}
