//! The indexer matches tags without knowing rings, the confirmed call stack names the ring.

use core::future::Future;

use solana_address::Address;
use solana_signature::Signature;
use spr_event::{tag, GeneralEvent};
use spr_event_parser::{
    event_parent, reconstruct_general_event, InstructionGroup, ParsedInstruction,
};
use spr_interface::{
    instruction::{settlement_accounts, InterfaceTransfer, TransactIxDataRef},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use spr_transaction::{ShieldedTransaction, SOL_MINT};

use crate::AuditError;
use custom_ring_interface::{
    tag as ring_tag, transact_flag, AuditStreamLayout, CheckedAuthorization, CustomRingError,
    CustomRingMergeIxDataRef, InstructionTag, ParsedTransact, RingMode, RingRail, RingTransactData,
};

/// What a confirmed transaction says about its ring, its signers and the value it settled out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingOrigin {
    pub ring_invoked: bool,
    /// Contents reconstructed from the exact confirmed SPP instruction and its self-CPI event.
    pub event: ConfirmedEvent,
    /// Fee payer first, every real input owner signs.
    pub signers: Vec<Address>,
    pub withdrawals: Vec<RingWithdrawal>,
    /// The anonymous merge disclosure whose proof the direct ring caller verified.
    pub merge_disclosure: Option<ConfirmedMergeDisclosure>,
    /// `tag || data` of the ring instruction that forwarded a transfer.
    pub transact: Option<Vec<u8>>,
    /// Accounts of the SPP instruction behind `event`.
    pub pool_accounts: Vec<Address>,
}

/// Bound to the forwarded SPP body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedMergeDisclosure {
    pub eph_pk: [u8; custom_ring_interface::TAGGED_X25519_KEY_LEN],
    pub ciphertext: [u8; custom_ring_interface::OPENING_RECORD_LEN],
}

/// The confirmed instruction selects the recovery path, never indexer metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmedEventKind {
    Transfer,
    Merge,
}

/// Canonical event contents from a trusted confirmed transaction provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedEvent {
    kind: ConfirmedEventKind,
    event: GeneralEvent,
    /// Set when the origin came from a full confirmed RPC response.
    slot: Option<u64>,
}

impl ConfirmedEvent {
    /// `event` and `kind` come from the confirmed instruction, never from an indexer response.
    pub fn new(kind: ConfirmedEventKind, event: GeneralEvent) -> Self {
        Self {
            kind,
            event,
            slot: None,
        }
    }

    pub fn kind(&self) -> ConfirmedEventKind {
        self.kind
    }

    /// Bind the slot reported by the trusted confirmed transaction provider.
    pub fn with_slot(mut self, slot: u64) -> Self {
        self.slot = Some(slot);
        self
    }

    /// `None` for an input of another tree, the event names that tree by its account alone.
    pub fn input_tree_ids(&self, transaction: &ShieldedTransaction) -> Vec<Option<u16>> {
        let output_tree = transaction
            .output_slots
            .first()
            .map(|slot| slot.output_context.tree_id)
            .filter(|tree_id| {
                spr_interface::pda::tree(*tree_id).to_bytes() == self.event.output_tree
            });
        self.event
            .inputs
            .iter()
            .map(|input| output_tree.filter(|_| input.tree == self.event.output_tree))
            .collect()
    }

    /// Authenticate every field used for audit and recovery before interpreting ciphertexts.
    fn bind(&self, transaction: &mut ShieldedTransaction) -> Result<(), AuditError> {
        let event = &self.event;
        let viewing_key = transaction
            .tx_viewing_pk
            .as_ref()
            .map(|key| *key.as_bytes())
            .unwrap_or([0; 33]);
        if self.slot.is_some_and(|slot| transaction.slot != slot)
            || transaction.proofless
            || viewing_key != event.tx_viewing_pk
            || transaction.salt.unwrap_or_default() != event.salt
            || transaction.messages != event.messages
            || !transaction
                .nullifiers
                .iter()
                .eq(event.inputs.iter().map(|input| &input.nullifier))
            || transaction.output_slots.len() != event.outputs.len()
            || transaction
                .output_slots
                .iter()
                .zip(&event.outputs)
                .enumerate()
                .any(|(index, (indexed, confirmed))| {
                    indexed.view_tag != confirmed.view_tag
                        || indexed.output_context.hash != confirmed.utxo_hash
                        || indexed.payload != confirmed.data
                        || spr_interface::pda::tree(indexed.output_context.tree_id).to_bytes()
                            != event.output_tree
                        || event.first_output_leaf_index.checked_add(index as u64)
                            != Some(indexed.output_context.leaf_index)
                })
        {
            return Err(AuditError::ConfirmedEventMismatch);
        }
        // Photon may omit an all-zero salt, the confirmed transfer binds it.
        if self.kind == ConfirmedEventKind::Transfer {
            transaction.salt = Some(event.salt);
        }
        Ok(())
    }
}

impl RingOrigin {
    pub fn requires_audit(&self) -> bool {
        self.ring_invoked && self.event.kind == ConfirmedEventKind::Transfer
    }

    pub fn audit_frame(&self, mode: RingMode) -> Result<AuditStreamLayout, AuditError> {
        let frame = self
            .transact
            .as_deref()
            .ok_or(AuditError::MissingRingTransact)?;
        audit_frame_of(frame, mode)
    }

    /// The owner signers a confidential transfer binds, an owner of a data output among them may spend no input.
    pub fn spenders(&self, mode: RingMode) -> Result<Vec<Address>, AuditError> {
        let frame = self
            .transact
            .as_deref()
            .ok_or(AuditError::MissingRingTransact)?;
        let parsed = parse_frame(mode, frame)?;
        let data = parsed.data();
        let run = match parsed.authorization() {
            CheckedAuthorization::ConfidentialInProof(owner) => {
                return Ok(vec![Address::new_from_array(*owner.owner)])
            }
            CheckedAuthorization::ConfidentialSigner => {
                let accounts = &self.pool_accounts;
                let window =
                    settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
                        .ok_or(AuditError::SettlementAccounts)?;
                data.owner_signers(accounts, window.len())
                    .map_err(|error| AuditError::InvalidTransactData(error.to_string()))?
            }
            CheckedAuthorization::AnonymousHidden(_)
            | CheckedAuthorization::AnonymousPublic
            | CheckedAuthorization::Delegate
            | CheckedAuthorization::AnonymousDelegate => return Ok(Vec::new()),
        };
        Ok(run.iter().fold(Vec::new(), |mut spenders, owner| {
            if !spenders.contains(owner) {
                spenders.push(*owner);
            }
            spenders
        }))
    }

    pub fn bind_transaction(
        &self,
        transaction: &mut ShieldedTransaction,
        ring: Address,
    ) -> Result<(), AuditError> {
        if !self.ring_invoked || transaction.ring_program_id != Some(ring) {
            return Err(AuditError::ConfirmedEventMismatch);
        }
        self.event.bind(transaction)
    }
}

/// One public settlement leg out of the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingWithdrawal {
    /// The policy-screened owner from confirmed metadata, absent for audit-only frames.
    pub screened_owner: Option<Address>,
    /// A token account for an SPL leg, a wallet for a SOL leg.
    pub recipient: Address,
    pub asset: Address,
    pub amount: u64,
}

/// An implementation authenticates the signature and rebuilds the event from confirmed chain data.
pub trait TransactionOrigin: Sync {
    fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send;
}

/// The trusted event at `event_index` must come from a pool instruction `ring` called directly.
pub fn ring_event_origin_in(
    groups: &[InstructionGroup],
    event_index: u16,
    ring: Address,
) -> Result<RingOrigin, AuditError> {
    let ring_instructions = ring_instructions_in(groups, ring)?;
    let (source, emitted) = trusted_event_sources(groups)
        .nth(usize::from(event_index))
        .ok_or(AuditError::InvalidEventIndex(event_index))?;
    let ring_invoked = ring_instructions
        .iter()
        .any(|instruction| core::ptr::eq(*instruction, source));
    let kind = match source.data[0] {
        tag::MERGE_TRANSACT | tag::RING_MERGE_TRANSACT => ConfirmedEventKind::Merge,
        _ => ConfirmedEventKind::Transfer,
    };
    let event = reconstruct_general_event(source, &emitted.data)
        .map_err(|error| AuditError::InvalidConfirmedEvent(format!("{error:?}")))?;
    let transact = confirmed_transact(groups, source, ring);
    let mut withdrawals = if ring_invoked {
        ring_withdrawals_of(&[source])?
    } else {
        Vec::new()
    };
    if let Some(frame) = &transact {
        bind_withdrawal_owners(source, frame, &mut withdrawals)?;
    }
    Ok(RingOrigin {
        ring_invoked,
        event: ConfirmedEvent::new(kind, event),
        signers: Vec::new(),
        withdrawals,
        merge_disclosure: confirmed_merge_disclosure(groups, source, ring),
        transact,
        pool_accounts: source.accounts.clone(),
    })
}

/// Read checked owner snapshots from the confirmed direct caller, without RPC account reads.
fn bind_withdrawal_owners(
    source: &ParsedInstruction,
    frame: &[u8],
    withdrawals: &mut [RingWithdrawal],
) -> Result<(), AuditError> {
    if withdrawals.is_empty() {
        return Ok(());
    }
    let (spp, _) = TransactIxDataRef::parse_with_external_data_prefix(&source.data[1..])
        .map_err(|e| AuditError::InvalidTransactData(e.to_string()))?;
    let parsed = parse_frame(forwarded_mode(&spp, frame), frame)?;
    let data = parsed.data();
    if data.policy.is_none() {
        return Ok(());
    }
    if data.interface_transfers != spp.interface_transfers {
        return Err(AuditError::ConfirmedEventMismatch);
    }
    let mut owners = data.spl_withdrawal_owners.iter();
    for withdrawal in withdrawals {
        withdrawal.screened_owner = Some(if withdrawal.asset == SOL_MINT {
            withdrawal.recipient
        } else {
            Address::new_from_array(*owners.next().ok_or(AuditError::SettlementAccounts)?)
        });
    }
    if owners.next().is_some() {
        return Err(AuditError::SettlementAccounts);
    }
    Ok(())
}

fn confirmed_transact(
    groups: &[InstructionGroup],
    source: &ParsedInstruction,
    ring: Address,
) -> Option<Vec<u8>> {
    if !matches!(
        source.data.first(),
        Some(&(tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT))
    ) {
        return None;
    }
    let caller = direct_caller(groups, source)?;
    (caller.program_id == ring
        && matches!(
            caller.data.first(),
            Some(&(ring_tag::TRANSFER | ring_tag::AUTHORITY_TRANSFER))
        ))
    .then(|| caller.data.clone())
}

fn audit_frame_of(frame: &[u8], mode: RingMode) -> Result<AuditStreamLayout, AuditError> {
    parse_frame(mode, frame).map(|parsed| parsed.audit_stream())
}

fn parse_frame(mode: RingMode, frame: &[u8]) -> Result<ParsedTransact<'_>, AuditError> {
    let invalid = |error: CustomRingError| AuditError::InvalidTransactData(error.to_string());
    let (&tag, data) = frame.split_first().ok_or(AuditError::MissingRingTransact)?;
    let rail = InstructionTag::try_from(tag)
        .and_then(|tag| RingRail::of(tag, mode))
        .map_err(invalid)?;
    RingTransactData::parse(data, rail).map_err(invalid)
}

/// An in-proof confidential frame forwards `AnonymousRingEddsa`, only its `OWNER_IN_PROOF` flag names the rail.
fn forwarded_mode(spp: &TransactIxDataRef<'_>, frame: &[u8]) -> RingMode {
    let in_proof = frame
        .get(1 + transact_flag::BYTE)
        .is_some_and(|flags| flags & transact_flag::OWNER_IN_PROOF != 0);
    match spp.circuit.is_anonymous() && !in_proof {
        true => RingMode::Anonymous,
        false => RingMode::Confidential,
    }
}

/// A disclosure counts only when the ring forwarded the exact SPP body it proved against.
fn confirmed_merge_disclosure(
    groups: &[InstructionGroup],
    source: &ParsedInstruction,
    ring: Address,
) -> Option<ConfirmedMergeDisclosure> {
    let caller = direct_caller(groups, source)?;
    if caller.program_id != ring {
        return None;
    }
    let (&caller_tag, request) = caller.data.split_first()?;
    if (*source.data.first()?, caller_tag) != (tag::RING_MERGE_TRANSACT, ring_tag::MERGE) {
        return None;
    }
    let request = CustomRingMergeIxDataRef::from_bytes(request).ok()?;
    let forwarded = request.forwarded(&request.spp_merge_body().ok()?);
    (forwarded == source.data).then_some(ConfirmedMergeDisclosure {
        eph_pk: *request.eph_pk,
        ciphertext: *request.ciphertext,
    })
}

fn direct_caller<'a>(
    groups: &'a [InstructionGroup],
    source: &ParsedInstruction,
) -> Option<&'a ParsedInstruction> {
    groups.iter().find_map(|group| {
        let index = group
            .inner
            .iter()
            .position(|inner| core::ptr::eq(inner, source))?;
        event_parent(group, index)
    })
}

/// `ring_transact` needs the ring's `ring_auth` signer, so only the ring's direct callees count.
fn ring_instructions_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<&ParsedInstruction>, AuditError> {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut found = Vec::new();
    for group in groups {
        let mut callers = vec![group.outer.program_id];
        for inner in &group.inner {
            let height = inner.stack_height;
            let parent_depth = usize::try_from(height)
                .ok()
                .and_then(|height| height.checked_sub(2))
                .filter(|depth| *depth < callers.len())
                .ok_or(AuditError::InvalidStackHeight(height))?;
            if inner.program_id == pool && callers[parent_depth] == ring {
                found.push(inner);
            }
            callers.truncate(parent_depth + 1);
            callers.push(inner.program_id);
        }
    }
    Ok(found)
}

fn trusted_event_sources(
    groups: &[InstructionGroup],
) -> impl Iterator<Item = (&ParsedInstruction, &ParsedInstruction)> {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    groups.iter().flat_map(move |group| {
        group
            .inner
            .iter()
            .enumerate()
            .filter_map(move |(index, instruction)| {
                if instruction.program_id != pool
                    || instruction.data.first() != Some(&tag::EMIT_EVENT)
                {
                    return None;
                }
                let parent = event_parent(group, index)?;
                (parent.program_id == pool
                    && parent.data.first().is_some_and(|tag| {
                        matches!(
                            *tag,
                            tag::DEPOSIT
                                | tag::RING_DEPOSIT
                                | tag::TRANSACT
                                | tag::RING_TRANSACT
                                | tag::RING_AUTHORITY_TRANSACT
                                | tag::MERGE_TRANSACT
                                | tag::RING_MERGE_TRANSACT
                        )
                    }))
                .then_some((parent, instruction))
            })
    })
}

/// An SPL leg reports its group's mint and credits a token account.
fn ring_withdrawals_of(
    instructions: &[&ParsedInstruction],
) -> Result<Vec<RingWithdrawal>, AuditError> {
    let sol_interface = Address::new_from_array(SOL_INTERFACE);
    let cpi_authority = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
    let mut withdrawals = Vec::new();
    for instruction in instructions {
        let Some((&(tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT), payload)) =
            instruction.data.split_first()
        else {
            continue;
        };
        let (data, _) = TransactIxDataRef::parse_with_external_data_prefix(payload)
            .map_err(|error| AuditError::InvalidTransactData(error.to_string()))?;
        let mut settlement = settlement_accounts(
            &data.interface_transfers,
            data.circuit,
            &instruction.accounts,
        )
        .ok_or(AuditError::SettlementAccounts)?;
        for &transfer in &data.interface_transfers {
            let (group, rest) = settlement.split_at(transfer.settlement_account_count());
            settlement = rest;
            let (authority, withdrawal) = match transfer {
                InterfaceTransfer::SolWithdrawal { amount } => (
                    sol_interface,
                    RingWithdrawal {
                        screened_owner: None,
                        recipient: group[1],
                        asset: SOL_MINT,
                        amount,
                    },
                ),
                InterfaceTransfer::SplWithdrawal { amount, .. } => (
                    cpi_authority,
                    RingWithdrawal {
                        screened_owner: None,
                        recipient: group[3],
                        asset: group[1],
                        amount,
                    },
                ),
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => {
                    continue
                }
            };
            if group[0] != authority {
                return Err(AuditError::SettlementAccounts);
            }
            withdrawals.push(withdrawal);
        }
    }
    Ok(withdrawals)
}

#[cfg(all(test, feature = "solana-rpc"))]
use rpc::confirmed_origin_for;
#[cfg(feature = "solana-rpc")]
pub use rpc::{confirmed_origin, ConfirmedRingOrigins, ORIGIN_TRANSACTION_CONFIG};

#[cfg(feature = "solana-rpc")]
mod rpc {
    use std::collections::BTreeMap;

    use solana_address::Address;
    use solana_commitment_config::CommitmentConfig;
    use solana_rpc_client_api::config::RpcTransactionConfig;
    use solana_signature::Signature;
    use solana_transaction_status_client_types::{
        option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
        EncodedTransaction, UiMessage, UiTransactionEncoding,
    };
    use spr_client::{AsyncSolanaRpc, Blocking, ConfirmedInstructionGroups, SolanaRpc};

    use super::{ring_event_origin_in, trusted_event_sources, RingOrigin, TransactionOrigin};
    use crate::AuditError;

    pub struct ConfirmedRingOrigins {
        pub signature: Signature,
        pub transaction: EncodedConfirmedTransactionWithStatusMeta,
        pub ring: Address,
    }

    impl ConfirmedRingOrigins {
        pub fn read(mut self) -> Result<BTreeMap<u16, RingOrigin>, AuditError> {
            validate_signature(self.signature, &self.transaction)?;
            resolve_loaded_addresses(&mut self.transaction)?;
            let signers = signers_of(&self.transaction);
            let slot = self.transaction.slot;
            let groups = ConfirmedInstructionGroups::try_from(self.transaction)?;
            let mut origins = BTreeMap::new();
            for (index, _) in trusted_event_sources(&groups.groups).enumerate() {
                let index = u16::try_from(index).map_err(|_| {
                    AuditError::InvalidConfirmedEvent("event index exceeds its range".into())
                })?;
                let mut origin = ring_event_origin_in(&groups.groups, index, self.ring)?;
                origin.signers.clone_from(&signers);
                origin.event = origin.event.with_slot(slot);
                origins.insert(index, origin);
            }
            Ok(origins)
        }
    }

    /// A v1 transaction read back at a maximum version of 0 is an error, not the transaction.
    pub const ORIGIN_TRANSACTION_CONFIG: RpcTransactionConfig = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(1),
    };

    /// The origin of the event at `event_index` with the transaction's required signers.
    pub fn confirmed_origin(
        transaction: EncodedConfirmedTransactionWithStatusMeta,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        let signers = signers_of(&transaction);
        let slot = transaction.slot;
        let groups = ConfirmedInstructionGroups::try_from(transaction)?;
        let mut origin = RingOrigin {
            signers,
            ..ring_event_origin_in(&groups.groups, event_index, ring)?
        };
        origin.event = origin.event.with_slot(slot);
        Ok(origin)
    }

    pub fn confirmed_origin_for(
        signature: Signature,
        transaction: EncodedConfirmedTransactionWithStatusMeta,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        validate_signature(signature, &transaction)?;
        confirmed_origin(transaction, event_index, ring)
    }

    fn resolve_loaded_addresses(
        transaction: &mut EncodedConfirmedTransactionWithStatusMeta,
    ) -> Result<(), AuditError> {
        let invalid =
            || AuditError::InvalidConfirmedEvent("loaded account addresses disagree".into());
        let EncodedTransaction::Json(encoded) = &mut transaction.transaction.transaction else {
            return Err(invalid());
        };
        let UiMessage::Raw(message) = &mut encoded.message else {
            return Err(invalid());
        };
        let lookups = message.address_table_lookups.as_deref().unwrap_or_default();
        let writable = lookups
            .iter()
            .map(|lookup| lookup.writable_indexes.len())
            .sum::<usize>();
        let readonly = lookups
            .iter()
            .map(|lookup| lookup.readonly_indexes.len())
            .sum::<usize>();
        let Some(meta) = &mut transaction.transaction.meta else {
            return Err(invalid());
        };
        let loaded = match &mut meta.loaded_addresses {
            OptionSerializer::Some(loaded) => loaded,
            OptionSerializer::None | OptionSerializer::Skip if writable == 0 && readonly == 0 => {
                return Ok(())
            }
            OptionSerializer::None | OptionSerializer::Skip => return Err(invalid()),
        };
        if writable != loaded.writable.len() || readonly != loaded.readonly.len() {
            return Err(invalid());
        }
        message.account_keys.append(&mut loaded.writable);
        message.account_keys.append(&mut loaded.readonly);
        message.address_table_lookups = None;
        Ok(())
    }

    fn validate_signature(
        signature: Signature,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> Result<(), AuditError> {
        if matches!(&transaction.transaction.transaction,
            EncodedTransaction::Json(ui)
                if ui.signatures.first().is_some_and(|value| value == &signature.to_string()))
        {
            Ok(())
        } else {
            Err(unavailable(
                signature,
                "confirmed transaction signature does not match the request",
            ))
        }
    }

    /// The first `num_required_signatures` keys, an unknown encoding names no signer.
    fn signers_of(transaction: &EncodedConfirmedTransactionWithStatusMeta) -> Vec<Address> {
        let EncodedTransaction::Json(ui) = &transaction.transaction.transaction else {
            return Vec::new();
        };
        let (keys, required) = match &ui.message {
            UiMessage::Raw(raw) => (
                raw.account_keys.clone(),
                usize::from(raw.header.num_required_signatures),
            ),
            UiMessage::Parsed(parsed) => (
                parsed
                    .account_keys
                    .iter()
                    .map(|key| key.pubkey.clone())
                    .collect(),
                parsed.account_keys.iter().filter(|key| key.signer).count(),
            ),
        };
        keys.into_iter()
            .take(required)
            .filter_map(|key| key.parse().ok())
            .collect()
    }

    fn unavailable(signature: Signature, error: impl ToString) -> AuditError {
        AuditError::Unavailable {
            signature,
            message: error.to_string(),
        }
    }

    impl TransactionOrigin for AsyncSolanaRpc {
        async fn origin(
            &self,
            signature: Signature,
            event_index: u16,
            ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            let transaction = self
                .client()
                .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
                .await
                .map_err(|error| unavailable(signature, error))?;
            confirmed_origin_for(signature, transaction, event_index, ring)
        }
    }

    /// The read runs on Tokio's blocking pool, as every other `Blocking` call does.
    impl TransactionOrigin for Blocking<SolanaRpc> {
        async fn origin(
            &self,
            signature: Signature,
            event_index: u16,
            ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            let rpc = self.clone();
            let transaction = tokio::task::spawn_blocking(move || {
                rpc.inner()
                    .client()
                    .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
            })
            .await
            .map_err(|error| unavailable(signature, error))?
            .map_err(|error| unavailable(signature, error))?;
            confirmed_origin_for(signature, transaction, event_index, ring)
        }
    }
}

#[cfg(test)]
mod tests;
