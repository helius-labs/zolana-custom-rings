//! One document holds a wallet's scan progress and everything it covers, one write stores both.
//!
//! [`AnonymousWallet::absorb`] stores a whole sync of either mode or refuses it, a crash before it loses only the read.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use solana_address::Address;
use spr_keypair::{x25519::X25519_PUBKEY_LEN, X25519Pubkey};
use spr_transaction::{DecryptionResult, Mint, WalletUtxo};
use zolana_ring_transaction::RingAssets;

use crate::anonymous::{RecoverySession, RecoveryUpdate};

use crate::{
    is_zero_key, mint_balances, note_state, AnonymousError, AnonymousScan, MintBalance, NoteState,
    SenderClaim, ViewingHistory,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WalletRevision {
    sequence: u64,
    stamp: [u8; 16],
}

impl WalletRevision {
    fn advance(&mut self) {
        self.sequence = self.sequence.wrapping_add(1);
        self.stamp = spr_keypair::random_salt();
    }
}

/// Notes stay listed once spent, their nullifiers mark them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousWallet {
    revision: WalletRevision,
    recovery: Option<RecoverySession>,
    history: ViewingHistory,
    notes: Vec<WalletUtxo>,
    spent_nullifiers: BTreeSet<[u8; 32]>,
    pending: Vec<PendingNote>,
    claims: Vec<PendingClaim>,
    /// Spent by a merge whose output named an unregistered mint, each confidential sync reads the spend again.
    merge_retries: BTreeSet<[u8; 32]>,
}

/// One sync, stored whole by [`AnonymousWallet::absorb`] or not at all.
pub struct ScanCommit {
    pub(crate) recovery: RecoveryUpdate,
    pub(crate) starting_history: ViewingHistory,
    pub(crate) history: ViewingHistory,
    pub(crate) decrypted: DecryptionResult,
    pub(crate) pending: Vec<PendingNote>,
    pub(crate) claims: Vec<PendingClaim>,
    /// Stored retries whose spend the sync read again, a lagging indexer keeps the rest stored.
    pub(crate) retried: BTreeSet<[u8; 32]>,
    /// Spends whose merge still names an unregistered mint.
    pub(crate) unresolved: BTreeSet<[u8; 32]>,
}

impl ScanCommit {
    pub fn history(&self) -> &ViewingHistory {
        &self.history
    }

    /// `unknown_mints` names each unregistered mint the sync met, of a pending note or of a merge left to retry.
    pub fn decrypted(&self) -> &DecryptionResult {
        &self.decrypted
    }

    pub fn pending_notes(&self) -> &[PendingNote] {
        &self.pending
    }
}

pub trait LedgerScan: sealed::Sealed {}

impl LedgerScan for AnonymousScan {}

impl LedgerScan for ScanCommit {}

mod sealed {
    use super::{AnonymousScan, AnonymousWallet, BTreeSet, PendingClaim, ScanCommit};

    pub trait Sealed {
        /// `None` unless the scan read from `stored`.
        fn commit_on(self, stored: &AnonymousWallet) -> Option<ScanCommit>;
    }

    impl Sealed for AnonymousScan {
        fn commit_on(mut self, stored: &AnonymousWallet) -> Option<ScanCommit> {
            if !self.starts_from(stored.history())
                || self
                    .expected_revision()
                    .is_some_and(|revision| revision != stored.revision())
                || (self.expected_revision().is_none() && stored.recovery_session().is_some())
            {
                return None;
            }
            let recovery = self.take_recovery();
            let retried = self.take_retried();
            let (history, decrypted, pending, claims) = self.into_stored();
            Some(ScanCommit {
                recovery,
                starting_history: stored.history().clone(),
                history,
                decrypted,
                pending,
                claims: claims.iter().map(PendingClaim::of).collect(),
                retried,
                unresolved: BTreeSet::new(),
            })
        }
    }

    impl Sealed for ScanCommit {
        fn commit_on(self, stored: &AnonymousWallet) -> Option<ScanCommit> {
            let compatible = stored.recovery_session().is_none_or(|session| {
                self.history == *stored.history()
                    && session.target_slot.is_some_and(|target| {
                        self.decrypted.utxos.iter().all(|note| note.slot <= target)
                            && self
                                .pending
                                .iter()
                                .all(|note| note.opening().slot <= target)
                    })
            });
            (self.starting_history == *stored.history() && compatible).then_some(self)
        }
    }
}

/// Rebuilt under a mint the registry does not name, only [`AnonymousWallet::resolve_pending`] makes it spendable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PendingNote(WalletUtxo);

impl PendingNote {
    pub(crate) const fn new(note: WalletUtxo) -> Self {
        Self(note)
    }

    pub fn mint(&self) -> Address {
        self.0.utxo.asset.asset
    }

    pub fn amount(&self) -> u64 {
        self.0.utxo.amount
    }

    pub fn utxo_hash(&self) -> [u8; 32] {
        self.0.utxo_hash
    }

    pub(crate) fn opening(&self) -> &WalletUtxo {
        &self.0
    }

    pub(crate) fn nullifier(&self) -> [u8; 32] {
        self.0.nullifier
    }

    fn into_registered(self, asset: Mint) -> WalletUtxo {
        let mut note = self.0;
        note.utxo.asset = asset;
        note
    }
}

/// A reply read from a note, what a sender wrote about itself and nothing the proof binds.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingClaim {
    pub utxo_hash: [u8; 32],
    pub claimed_viewing_key: X25519Pubkey,
    pub claimed_owner_key: [u8; 32],
    pub claimed_nullifier_pk: [u8; 32],
}

impl PendingClaim {
    fn of(claim: &SenderClaim) -> Self {
        let reply = claim.claim.claimed();
        Self {
            utxo_hash: claim.utxo_hash,
            claimed_viewing_key: reply.viewing_key,
            claimed_owner_key: reply.owner_key,
            claimed_nullifier_pk: reply.nullifier_pk,
        }
    }
}

impl fmt::Debug for PendingClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingClaim")
            .field("utxo_hash", &self.utxo_hash)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WalletJson {
    #[serde(default)]
    revision: WalletRevision,
    #[serde(default)]
    recovery: Option<RecoverySession>,
    history: Value,
    notes: Vec<WalletUtxo>,
    spent_nullifiers: Vec<String>,
    pending_notes: Vec<PendingNote>,
    claims: Vec<ClaimJson>,
    merge_retries: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaimJson {
    utxo_hash: String,
    claimed_viewing_key: String,
    claimed_owner_key: String,
    claimed_nullifier_pk: String,
}

impl AnonymousWallet {
    pub fn new(history: ViewingHistory) -> Self {
        Self {
            revision: WalletRevision::default(),
            recovery: None,
            history,
            notes: Vec::new(),
            spent_nullifiers: BTreeSet::new(),
            pending: Vec::new(),
            claims: Vec::new(),
            merge_retries: BTreeSet::new(),
        }
    }

    pub fn history(&self) -> &ViewingHistory {
        &self.history
    }

    pub(crate) fn revision(&self) -> WalletRevision {
        self.revision
    }

    pub(crate) fn recovery_session(&self) -> Option<&RecoverySession> {
        self.recovery.as_ref()
    }

    pub fn recovery_status(&self) -> crate::anonymous::RecoveryStatus {
        if self.recovery.is_some() {
            crate::anonymous::RecoveryStatus::Paused
        } else {
            crate::anonymous::RecoveryStatus::Complete
        }
    }

    pub fn funding_notes(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.checked_notes()
            .filter(|note| !is_zero_key(note) && !self.spent_nullifiers.contains(&note.nullifier))
    }

    fn checked_notes(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.notes.iter().filter(|note| {
            self.recovery
                .as_ref()
                .is_none_or(|session| session.checked.contains(&note.nullifier))
        })
    }

    pub fn require_complete(&self) -> Result<(), AnonymousError> {
        if self.recovery.is_some() {
            Err(AnonymousError::SyncIncomplete)
        } else {
            Ok(())
        }
    }

    pub fn notes(&self) -> &[WalletUtxo] {
        &self.notes
    }

    pub(crate) fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }

    pub(crate) fn merge_retries(&self) -> &BTreeSet<[u8; 32]> {
        &self.merge_retries
    }

    pub fn note_state(&self, note: &WalletUtxo) -> NoteState {
        if !self.spent_nullifiers.contains(&note.nullifier)
            && self
                .recovery
                .as_ref()
                .is_some_and(|session| !session.checked.contains(&note.nullifier))
        {
            return NoteState::PendingSpendCheck;
        }
        note_state(note, |nullifier| self.spent_nullifiers.contains(nullifier))
    }

    /// Unspent zero-key notes, spent only through an explicit public spend.
    pub fn exposed_notes(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.checked_notes()
            .filter(|note| is_zero_key(note) && !self.spent_nullifiers.contains(&note.nullifier))
    }

    pub fn balances(&self) -> BTreeMap<Address, MintBalance> {
        mint_balances(self.checked_notes(), |nullifier| {
            self.spent_nullifiers.contains(nullifier)
        })
    }

    /// Verified notes under a mint with no registration, never among [`Self::notes`].
    pub fn pending_notes(&self) -> &[PendingNote] {
        &self.pending
    }

    /// Admits every pending note `assets` now names, nothing is read from history.
    pub fn resolve_pending(&mut self, assets: &RingAssets) {
        let (registered, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .map(|note| (assets.by_mint(&note.mint()), note))
            .partition(|(asset, _)| asset.is_some());
        self.pending = waiting.into_iter().map(|(_, note)| note).collect();
        if !registered.is_empty() {
            self.revision.advance();
        }
        self.notes.extend(
            registered
                .into_iter()
                .filter_map(|(asset, note)| asset.map(|asset| note.into_registered(asset))),
        );
    }

    /// Replies the wallet has not confirmed, none reads as a verified sender.
    pub fn pending_claims(&self) -> &[PendingClaim] {
        &self.claims
    }

    /// The wallet's own decision to trust a claimed sender, nothing else confirms one.
    pub fn confirm_claim(&mut self, claimed: X25519Pubkey) -> Result<(), AnonymousError> {
        if self.recovery.is_some() {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        if !self
            .claims
            .iter()
            .any(|claim| claim.claimed_viewing_key == claimed)
        {
            return Err(AnonymousError::UnknownSenderClaim);
        }
        self.history.confirm_sender(claimed)?;
        self.revision.advance();
        self.claims
            .retain(|claim| claim.claimed_viewing_key != claimed);
        Ok(())
    }

    /// Rejects a scan if the wallet history changed.
    pub fn absorb(&mut self, scan: impl LedgerScan) -> Result<(), AnonymousError> {
        let scan = scan
            .commit_on(self)
            .ok_or(AnonymousError::ScanHistoryChanged)?;
        let mut changed = self.history != scan.history;
        let mut held: HashSet<[u8; 32]> = self.notes.iter().map(|note| note.utxo_hash).collect();
        self.notes
            .extend(scan.decrypted.utxos.into_iter().filter(|note| {
                let inserted = held.insert(note.utxo_hash);
                changed |= inserted;
                inserted
            }));
        self.pending.retain(|note| {
            let retained = !held.contains(&note.utxo_hash());
            changed |= !retained;
            retained
        });
        held.extend(self.pending.iter().map(PendingNote::utxo_hash));
        self.pending.extend(scan.pending.into_iter().filter(|note| {
            let inserted = held.insert(note.utxo_hash());
            changed |= inserted;
            inserted
        }));
        for nullifier in scan.decrypted.spent_nullifiers {
            changed |= self.spent_nullifiers.insert(nullifier);
        }
        let mut claimed: HashSet<[u8; 32]> =
            self.claims.iter().map(|claim| claim.utxo_hash).collect();
        self.claims.extend(scan.claims.into_iter().filter(|claim| {
            let inserted = claimed.insert(claim.utxo_hash);
            changed |= inserted;
            inserted
        }));
        for nullifier in scan.retried.difference(&scan.unresolved) {
            changed |= self.merge_retries.remove(nullifier);
        }
        for nullifier in scan.unresolved {
            changed |= self.merge_retries.insert(nullifier);
        }
        self.history = scan.history;
        match scan.recovery {
            RecoveryUpdate::Keep => {}
            RecoveryUpdate::Paused(session) => {
                changed |= self.recovery.as_ref() != Some(session.as_ref());
                self.recovery = Some(*session);
            }
            RecoveryUpdate::Complete => changed |= self.recovery.take().is_some(),
        }
        if changed {
            self.revision.advance();
        }
        Ok(())
    }

    /// A tag counter or an added key, a stored position or watermark never moves here.
    pub fn update_history(&mut self, updated: ViewingHistory) -> Result<(), AnonymousError> {
        if self.recovery.is_some() && updated != self.history {
            return Err(AnonymousError::RecoveryScopeChanged);
        }
        if !updated.progress_matches(&self.history) {
            return Err(AnonymousError::ScanProgressMoved);
        }
        if self.history != updated {
            self.history = updated;
            self.revision.advance();
        }
        Ok(())
    }

    /// The held notes and spends as a scan reports them.
    pub fn decrypted(&self) -> DecryptionResult {
        DecryptionResult {
            utxos: self.checked_notes().cloned().collect(),
            spent_nullifiers: self.spent_nullifiers.iter().copied().collect(),
            ..DecryptionResult::default()
        }
    }

    /// Its notes open the wallet's funds, store it as key material under one atomic replace.
    pub fn to_json(&self) -> String {
        let wallet = WalletJson {
            revision: self.revision,
            recovery: self.recovery.clone(),
            history: self.history.to_json_value(),
            notes: self.notes.clone(),
            spent_nullifiers: self.spent_nullifiers.iter().map(hex::encode).collect(),
            pending_notes: self.pending.clone(),
            claims: self
                .claims
                .iter()
                .map(|claim| ClaimJson {
                    utxo_hash: hex::encode(claim.utxo_hash),
                    claimed_viewing_key: hex::encode(claim.claimed_viewing_key.as_bytes()),
                    claimed_owner_key: hex::encode(claim.claimed_owner_key),
                    claimed_nullifier_pk: hex::encode(claim.claimed_nullifier_pk),
                })
                .collect(),
            merge_retries: self.merge_retries.iter().map(hex::encode).collect(),
        };
        serde_json::to_string(&wallet)
            .expect("a struct of strings, integers and vectors serializes")
    }

    pub fn from_json(text: &str) -> Result<Self, AnonymousError> {
        let wallet: WalletJson = serde_json::from_str(text).map_err(unparsed)?;
        let spent_nullifiers = wallet
            .spent_nullifiers
            .iter()
            .map(|text| field(text))
            .collect::<Result<_, _>>()?;
        let claims = wallet
            .claims
            .iter()
            .map(|claim| {
                let key = <[u8; X25519_PUBKEY_LEN]>::try_from(
                    hex::decode(&claim.claimed_viewing_key).unwrap_or_default(),
                )
                .map_err(|_| invalid("a claimed viewing key has the wrong length"))?;
                Ok(PendingClaim {
                    utxo_hash: field(&claim.utxo_hash)?,
                    claimed_viewing_key: X25519Pubkey::from_bytes(key)
                        .map_err(|_| invalid("a claimed viewing key is not tagged"))?,
                    claimed_owner_key: field(&claim.claimed_owner_key)?,
                    claimed_nullifier_pk: field(&claim.claimed_nullifier_pk)?,
                })
            })
            .collect::<Result<_, AnonymousError>>()?;
        let merge_retries = wallet
            .merge_retries
            .iter()
            .map(|text| field(text))
            .collect::<Result<_, _>>()?;
        if let Some(session) = &wallet.recovery {
            session.validate()?;
        }
        Ok(Self {
            revision: wallet.revision,
            recovery: wallet.recovery,
            history: ViewingHistory::from_json_value(wallet.history)?,
            notes: wallet.notes,
            spent_nullifiers,
            pending: wallet.pending_notes,
            claims,
            merge_retries,
        })
    }
}

fn field(text: &str) -> Result<[u8; 32], AnonymousError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| invalid("a stored value is not 32 hex bytes"))
}

fn invalid(reason: &str) -> AnonymousError {
    AnonymousError::WalletDocument(reason.to_owned())
}

/// A serde message can quote the value it refused, the position alone names the fault.
fn unparsed(error: serde_json::Error) -> AnonymousError {
    AnonymousError::WalletDocument(format!(
        "{:?} at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    ))
}
