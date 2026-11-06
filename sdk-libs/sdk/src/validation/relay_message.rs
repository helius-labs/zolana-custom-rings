//! The message a wallet signs for Ring RPC, checked against the request the wallet made.

use std::collections::BTreeSet;

use custom_ring_interface::cosign::ApprovalMask;
use custom_ring_interface::{
    compute_unit_limit, funder_account_position, stream::confidential_slot_tag, tag, AuditRecord,
    InstructionTag, ParsedTransact, RecordKind, RingMode, RingRail, RingTransactData,
    RING_TRANSACT_RING_CONFIG_INDEX, STORAGE_PROGRAM_ID,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v1, VersionedMessage};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::MAX_LOADED_ACCOUNTS_DATA_SIZE;
use spr_indexer_api::{Hash, SerializablePubkey};
use spr_interface::{
    instruction::{instruction_data::settlement_accounts, InterfaceTransfer},
    pda, N_PUBLIC_SLOTS,
};
use spr_keypair::{PublicKey, ShieldedAddress, X25519Pubkey};
use spr_program::instruction::CreateAssociatedTokenAccount;
use spr_transaction::{Mint, TransactionError, Utxo, WalletUtxo, SOL_MINT};
use thiserror::Error;
use zolana_ring_client::{
    rpc::{AuthorityWithdrawal, RelayEnrollInputs, RelayId, TxViewingSecret, ENROLL_COMPUTE_UNITS},
    AuditEnvelope, OpenedAudit,
};
use zolana_ring_policy::{ApprovalTotals, Member, OutputTotals, OwnerDebit, PublicTotals};

use crate::{
    pipeline::delegate_rail, AllowedNullifiers, CustomRing, CustomRingConfig, PendingSignature,
    RequestedAuthorityTransfer, RingError,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MessageMismatch {
    #[error("the message does not decode as one valid canonical message")]
    Undecodable,
    #[error("the message is not a v1 message")]
    NotV1,
    #[error("the message fee payer is the signer or not the quoted relay fee payer")]
    FeePayer,
    #[error("the message budget is outside the operation's bounds")]
    Budget,
    #[error("the message carries instructions the request did not ask for")]
    Instructions,
    #[error("the message calls a program other than the ring")]
    Program,
    #[error("the message data differs from the request")]
    Data,
    #[error("the message accounts differ from the request")]
    Accounts,
    #[error("the message pays an owner the request does not name")]
    Recipients,
    #[error("the message publishes a transaction key other than the one the request names")]
    TransactionKey,
    #[error("the proven approval bits ask more than the co-signer accepts")]
    ApprovalMaskUnaccepted,
    #[error("the frame carries no approval digest and exact approval was asked")]
    MissingApprovalDigest,
    #[error("the opening does not rebuild the frame's approval digest")]
    FalseApprovalOpening,
    #[error("the opening does not hold one row per output of the key and per public slot")]
    ApprovalOpeningLayout,
    #[error("the opening's blinder is zero and hides no total")]
    ZeroApprovalBlinder,
    #[error("the opening's blinder served an earlier attempt")]
    ReusedApprovalBlinder,
    #[error("the totals pass a limit or name an asset with no limit")]
    ApprovalOverLimit,
    #[error("the message spends a held note the terms do not name")]
    SpendsUnnamedNote,
    #[error("the message spends a note no requested source opening derives")]
    SpendsUnrequestedNote,
    #[error("the terms open another number of data outputs than the proof counts for the signer")]
    DataOutputCount,
    #[error("the deposit legs the signer funds differ from its terms")]
    FunderLegs,
    #[error("the request asks for no signature")]
    Unrequested,
    #[error("the signing key is not the key the request names")]
    Signer,
}

/// Built from the wallet's own request, never from Ring RPC's answer.
#[derive(Clone, Debug)]
pub(crate) enum ExpectedMessage {
    Delegate(ExpectedDelegate),
    /// The sealing wallet hands each signer what it reads and signs nothing itself.
    Sealed(SealedTerms),
    PublicOwner(ExpectedPublicOwner),
    Funder(ExpectedFunder),
    CoSigner(ExpectedCoSigner),
    Enroll(ExpectedEnroll),
}

/// The enrollment the owner proved and signed, the message differs from it in nothing.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedEnroll {
    pub fee_payer: Address,
    pub inputs: RelayEnrollInputs,
}

/// What one public owner agrees to, its own slots and notes alone, the sealing wallet hands it over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayTransferTerms {
    pub ring: SerializablePubkey,
    pub fee_payer: SerializablePubkey,
    pub signer: SerializablePubkey,
    /// Each rebuilds its slot's commitment, no key opens another slot.
    pub slots: Vec<SlotOpening>,
    /// The signer's notes the transfer spends.
    pub nullifiers: Vec<Hash>,
    /// The token accounts the fee payer creates ahead of the ring instruction.
    pub setup: Vec<TokenAccountCreate>,
}

/// What one public funder agrees to, its own deposit legs alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayFunderTerms {
    pub ring: SerializablePubkey,
    pub fee_payer: SerializablePubkey,
    pub signer: SerializablePubkey,
    pub legs: Vec<FundedLeg>,
    /// The token accounts the fee payer creates ahead of the ring instruction.
    pub setup: Vec<TokenAccountCreate>,
}

/// `None` on SOL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FundedLeg {
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
}

/// The preimage of one published output's `utxo_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SlotOpening {
    pub slot: u32,
    pub owner: SerializablePubkey,
    pub nullifier_pk: Hash,
    pub mint: SerializablePubkey,
    pub amount: u64,
    pub blinding: Hash,
    pub tree_id: u16,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenAccountCreate {
    pub owner: SerializablePubkey,
    pub mint: SerializablePubkey,
    pub token_program: SerializablePubkey,
}

#[derive(Clone, Debug)]
pub(crate) struct SealedTerms {
    pub owners: Vec<RelayTransferTerms>,
    pub funders: Vec<RelayFunderTerms>,
    pub approval: Option<ApprovalOpening>,
    pub charged_outflows: Vec<OwnerDebit>,
}

/// The totals and blinder a frame's digest commits, no transaction secret and no slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovalOpening {
    pub blinder: Hash,
    pub outputs: Vec<OutputTotalsOpening>,
    pub public: Vec<PublicTotalsOpening>,
}

/// Amounts are decimal text, a `u128` does not survive every JSON reader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutputTotalsOpening {
    pub asset: Hash,
    pub peak: String,
    pub charged_outflow: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicTotalsOpening {
    pub asset: Hash,
    pub peak: String,
    pub outflow: String,
    pub gross: String,
}

/// An outside co-signer reads the proven bits or the totals, never a slot.
#[must_use]
#[derive(Clone, Debug)]
pub enum CoSignerRule {
    /// The proven mask alone, no opening and no digest.
    Threshold {
        accepts: ApprovalMask,
    },
    Exact(ExactApproval),
}

#[must_use]
#[derive(Clone, Debug)]
pub struct ExactApproval {
    pub opening: ApprovalOpening,
    /// An asset the totals name with no limit here is refused.
    pub limits: Vec<ApprovalLimit>,
    /// The blinders of its earlier attempts, the only record of reuse the SDK has.
    pub seen_blinders: Vec<Hash>,
}

/// `peak` bounds one owner's outflow, `outflow` the sum over owners, `gross` each public row's
/// withdrawals with no deposit subtracted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalLimit {
    pub mint: Address,
    pub peak: u128,
    pub outflow: u128,
    pub gross: u128,
}

/// A co-signer the frame names, what it signs is the rule it holds.
#[must_use]
pub struct CoSignerApproval<'a> {
    pub relay_id: RelayId,
    pub message: Vec<u8>,
    pub ring: Address,
    pub fee_payer: Address,
    pub signer: Address,
    pub config: &'a CustomRingConfig,
    /// The public creates a relay puts ahead of the ring instruction.
    pub setup: Vec<TokenAccountCreate>,
    pub rule: CoSignerRule,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedCoSigner {
    ring: Address,
    fee_payer: Address,
    signer: Address,
    rail: RingRail,
    setup: Vec<Instruction>,
    rule: CoSignerRule,
}

/// One public owner reading its terms against the notes its wallet holds.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedPublicOwner {
    terms: RelayTransferTerms,
    setup: Vec<Instruction>,
    /// From the ring account, a frame read under the wrong rail proves nothing.
    rail: RingRail,
    known_nullifiers: Vec<[u8; 32]>,
}

/// One public funder reading the frame's deposit legs against its terms.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedFunder {
    terms: RelayFunderTerms,
    setup: Vec<Instruction>,
    rail: RingRail,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedDelegate {
    pub ring: CustomRing,
    pub fee_payer: Address,
    pub delegate: Address,
    /// From the ring account, a frame read under the wrong rail or auditor proves nothing.
    pub rail: RingRail,
    pub auditor: X25519Pubkey,
    pub tx_viewing_key: TxViewingSecret,
    /// Change returns to an input's owner.
    pub sources: Vec<ExpectedOwner>,
    pub payments: Vec<ExpectedPayment>,
    pub withdrawals: Vec<ExpectedWithdrawal>,
    /// Admitted from the delegate's own openings of exactly the requested sources.
    pub allowed: AllowedNullifiers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub viewing_u: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedPayment {
    pub kind: RecordKind,
    pub owner: ExpectedOwner,
    pub mint: Address,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedWithdrawal {
    transfer: InterfaceTransfer,
    accounts: Vec<Address>,
}

/// Only a check builds one.
#[must_use = "sign the verified message"]
#[derive(Debug)]
pub struct VerifiedMessage {
    bytes: Vec<u8>,
    signer: Address,
}

struct Envelope {
    ring: CustomRing,
    program: Address,
    units: u32,
    fee_payer: Address,
    signer: Address,
    /// Ahead of the ring instruction in list order, the relay omits one for a live account.
    setup: Vec<Instruction>,
}

impl ExpectedMessage {
    pub fn check(
        &self,
        message: &[u8],
        signer: Address,
    ) -> Result<VerifiedMessage, MessageMismatch> {
        match self {
            Self::Delegate(delegate) => delegate.check(message),
            Self::Sealed(_) => Err(MessageMismatch::Unrequested),
            Self::PublicOwner(owner) => check_message(owner, message, signer),
            Self::Funder(funder) => check_message(funder, message, signer),
            Self::CoSigner(co_signer) => check_message(co_signer, message, signer),
            Self::Enroll(enroll) => enroll.check(message),
        }
    }

    pub fn terms_for(&self, signer: Address) -> Option<&RelayTransferTerms> {
        match self {
            Self::Sealed(sealed) => sealed.owners.iter().find(|terms| terms.signer.0 == signer),
            Self::PublicOwner(owner) => (owner.terms.signer.0 == signer).then_some(&owner.terms),
            Self::Delegate(_) | Self::Enroll(_) | Self::Funder(_) | Self::CoSigner(_) => None,
        }
    }

    pub fn funder_terms_for(&self, signer: Address) -> Option<&RelayFunderTerms> {
        match self {
            Self::Sealed(sealed) => sealed.funders.iter().find(|terms| terms.signer.0 == signer),
            Self::Funder(funder) => (funder.terms.signer.0 == signer).then_some(&funder.terms),
            _ => None,
        }
    }

    pub fn approval_opening(&self) -> Option<&ApprovalOpening> {
        match self {
            Self::Sealed(sealed) => sealed.approval.as_ref(),
            _ => None,
        }
    }

    pub fn charged_outflows(&self) -> &[OwnerDebit] {
        match self {
            Self::Sealed(sealed) => &sealed.charged_outflows,
            _ => &[],
        }
    }
}

trait ExpectedFrame {
    const TAG: InstructionTag;

    fn envelope(&self, signer: Address) -> Result<Envelope, MessageMismatch>;

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch>;
}

fn check_message<E: ExpectedFrame>(
    expected: &E,
    message: &[u8],
    signer: Address,
) -> Result<VerifiedMessage, MessageMismatch> {
    let envelope = expected.envelope(signer)?;
    let instruction = envelope.open(message)?;
    expected.check_frame(signer, &instruction.data, &instruction.accounts)?;
    Ok(envelope.verified(message))
}

/// The proof binds each record to its slot under the key the frame publishes, a slot tag is an unproved hint.
fn open_stream(
    parsed: &ParsedTransact<'_>,
    tx_viewing_key: &TxViewingSecret,
    auditor: &X25519Pubkey,
) -> Result<OpenedAudit, MessageMismatch> {
    let data = parsed.data();
    let tx_viewing_key = tx_viewing_key
        .key()
        .map_err(|_| MessageMismatch::TransactionKey)?;
    if *data.tx_viewing_u != tx_viewing_key.pubkey().u() {
        return Err(MessageMismatch::TransactionKey);
    }
    AuditEnvelope {
        eph_u: *data.tx_viewing_u,
        salt: data.salt,
        ciphertext: data.envelope,
    }
    .open_sealed(&tx_viewing_key, auditor, parsed.audit_stream())
    .map_err(|_| MessageMismatch::Data)
}

/// The signer named once and read only, the ring account first.
fn check_signer(envelope: &Envelope, accounts: &[AccountMeta]) -> Result<(), MessageMismatch> {
    let mut named = accounts
        .iter()
        .filter(|meta| meta.pubkey == envelope.signer);
    let signs_once = matches!(
        (named.next(), named.next()),
        (Some(meta), None) if meta.is_signer && !meta.is_writable
    );
    if !signs_once || !envelope.reads_only(accounts.get(..1).unwrap_or_default(), &[]) {
        return Err(MessageMismatch::Accounts);
    }
    Ok(())
}

impl ExpectedEnroll {
    /// A swapped registry or authorization reads the owner's key into another account.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: CustomRing::new(self.inputs.ring_program_id),
            program: STORAGE_PROGRAM_ID,
            units: ENROLL_COMPUTE_UNITS,
            fee_payer: self.fee_payer,
            signer: self.inputs.owner,
            setup: Vec::new(),
        };
        let instruction = envelope.open(message)?;
        let expected = self.inputs.instruction(self.fee_payer);
        if instruction.accounts != expected.accounts {
            return Err(MessageMismatch::Accounts);
        }
        let signed = RelayEnrollInputs {
            instruction_data: instruction.data,
            ..self.inputs.clone()
        };
        if signed.request_digest() != self.inputs.request_digest() {
            return Err(MessageMismatch::Data);
        }
        Ok(envelope.verified(message))
    }
}

impl ExpectedDelegate {
    pub fn new(requested: &RequestedAuthorityTransfer<'_>) -> Result<Self, RingError> {
        let RequestedAuthorityTransfer {
            request,
            quote,
            config,
            allowed,
        } = requested;
        let transfer = &request.transfer;
        allowed.check_sources(transfer.sources.iter().map(|source| &source.0))?;
        Ok(Self {
            ring: CustomRing::new(request.ring.0),
            fee_payer: quote.fee_payer.0,
            delegate: request.delegate.0,
            rail: delegate_rail(config.mode),
            auditor: config.auditor_pubkey,
            tx_viewing_key: request.tx_viewing_key.clone(),
            sources: transfer
                .sources
                .iter()
                .map(|source| ExpectedOwner::of(&source.0))
                .collect::<Result<_, RingError>>()?,
            payments: transfer
                .payments
                .iter()
                .map(|payment| (RecordKind::Ring, payment))
                .chain(
                    transfer
                        .exits
                        .iter()
                        .map(|payment| (RecordKind::Exit, payment)),
                )
                .map(|(kind, payment)| {
                    Ok(ExpectedPayment {
                        kind,
                        owner: ExpectedOwner::of(&payment.recipient.0)?,
                        mint: payment.mint.0,
                        amount: payment.amount,
                    })
                })
                .collect::<Result<_, RingError>>()?,
            withdrawals: transfer
                .withdrawals
                .iter()
                .map(ExpectedWithdrawal::new)
                .collect::<Result<_, _>>()?,
            allowed: allowed.clone(),
        })
    }

    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        check_message(self, message, self.delegate)
    }

    fn check_moved(
        &self,
        parsed: &ParsedTransact<'_>,
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let data = parsed.data();
        // 1. The stream opens under the requested keys, and the legs are the requested withdrawals.
        let opened = open_stream(parsed, &self.tx_viewing_key, &self.auditor)?;
        if data.has_data {
            return Err(MessageMismatch::Data);
        }
        self.check_withdrawals(data, accounts)?;
        // 2. Matching outputs bind no input, each proven note position answers to the requested
        // openings.
        self.allowed
            .check_inputs(opened.inputs.classes().zip(data.nullifiers))
            .map_err(|_| MessageMismatch::SpendsUnrequestedNote)?;
        // 3. Each live record pays one requested payment or returns change to a requested source.
        let records = data
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, output)| opened.record(slot, output.record))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MessageMismatch::Data)?;
        let mut unpaid = self.payments.clone();
        for (output, record) in data.outputs.iter().zip(records) {
            if record.kind == RecordKind::Dummy {
                continue;
            }
            let paid = unpaid.iter().position(|payment| payment.matches(&record));
            match paid {
                Some(index) => {
                    let payment = unpaid.swap_remove(index);
                    let owner_tag = match payment.kind {
                        RecordKind::Exit => Some(payment.owner.owner_key),
                        RecordKind::Ring if !data.rail.anonymous_frame() => {
                            Some(confidential_slot_tag(payment.owner.viewing_u))
                        }
                        _ => None,
                    };
                    if owner_tag.is_some_and(|tag| output.owner_tag != tag) {
                        return Err(MessageMismatch::Recipients);
                    }
                }
                None if record.kind == RecordKind::Ring
                    && self.sources.iter().any(|source| source.owns(&record)) => {}
                None => return Err(MessageMismatch::Recipients),
            }
        }
        match unpaid.is_empty() {
            true => Ok(()),
            false => Err(MessageMismatch::Recipients),
        }
    }

    fn check_withdrawals(
        &self,
        data: &RingTransactData<'_>,
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let spp = spp_accounts(self.ring.program_id(), accounts)?;
        let mut groups = settlement_accounts(&data.interface_transfers, data.circuit(), spp)
            .ok_or(MessageMismatch::Accounts)?;
        let mut unpaid = self.withdrawals.clone();
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(MessageMismatch::Accounts)?;
            groups = rest;
            let paid = unpaid
                .iter()
                .position(|expected| {
                    expected.transfer == *transfer
                        && expected
                            .accounts
                            .iter()
                            .eq(group.iter().map(|account| &account.pubkey))
                })
                .ok_or(MessageMismatch::Data)?;
            unpaid.swap_remove(paid);
        }
        if !unpaid.is_empty() {
            return Err(MessageMismatch::Data);
        }
        Ok(())
    }
}

impl ExpectedFrame for ExpectedDelegate {
    const TAG: InstructionTag = InstructionTag::AuthorityTransfer;

    fn envelope(&self, signer: Address) -> Result<Envelope, MessageMismatch> {
        Ok(Envelope {
            ring: self.ring,
            program: self.ring.program_id(),
            units: compute_unit_limit(Self::TAG),
            fee_payer: self.fee_payer,
            signer,
            setup: Vec::new(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::AUTHORITY_TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        self.check_moved(&parsed, accounts)?;
        check_signer(&self.envelope(signer)?, accounts)
    }
}

/// A public owner's approval, its own notes are a required input since its signature is the only gate on them.
#[must_use]
pub struct OwnerApproval<'a> {
    pub relay_id: RelayId,
    pub message: Vec<u8>,
    pub terms: RelayTransferTerms,
    pub config: &'a CustomRingConfig,
    /// Every note the wallet holds, the nullifiers are the wallet's own derivation.
    pub known_notes: &'a [WalletUtxo],
}

impl OwnerApproval<'_> {
    pub fn pending(self) -> PendingSignature {
        PendingSignature::expecting(
            self.relay_id,
            self.message,
            ExpectedMessage::PublicOwner(ExpectedPublicOwner::new(
                self.terms,
                self.config.mode,
                self.known_notes.iter().map(|note| note.nullifier).collect(),
            )),
        )
    }
}

/// A funder's approval, its signature moves the legs it names and nothing else of its.
#[must_use]
pub struct FunderApproval<'a> {
    pub relay_id: RelayId,
    pub message: Vec<u8>,
    pub terms: RelayFunderTerms,
    pub config: &'a CustomRingConfig,
}

impl FunderApproval<'_> {
    pub fn pending(self) -> PendingSignature {
        PendingSignature::expecting(
            self.relay_id,
            self.message,
            ExpectedMessage::Funder(ExpectedFunder {
                setup: setup_instructions(self.terms.fee_payer.0, &self.terms.setup),
                rail: transfer_rail(self.config.mode),
                terms: self.terms,
            }),
        )
    }
}

fn setup_instructions(fee_payer: Address, setup: &[TokenAccountCreate]) -> Vec<Instruction> {
    setup
        .iter()
        .map(|create| {
            CreateAssociatedTokenAccount {
                payer: fee_payer,
                owner: create.owner.0,
                mint: create.mint.0,
                token_program: create.token_program.0,
            }
            .instruction()
        })
        .collect()
}

const fn transfer_rail(mode: RingMode) -> RingRail {
    match mode {
        RingMode::Anonymous => RingRail::Anonymous,
        RingMode::Confidential => RingRail::Confidential,
    }
}

impl ExpectedPublicOwner {
    pub fn new(terms: RelayTransferTerms, mode: RingMode, known_nullifiers: Vec<[u8; 32]>) -> Self {
        Self {
            setup: setup_instructions(terms.fee_payer.0, &terms.setup),
            rail: transfer_rail(mode),
            known_nullifiers,
            terms,
        }
    }

    /// SPP reads one signature as approval of every data-bearing output its signer owns, and each
    /// published owner tag of a ring output is zero, so no frame field names those outputs. The terms
    /// stay selective, the proof supplies only how many exist.
    fn check_moved(
        &self,
        data: &RingTransactData<'_>,
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let terms = &self.terms;
        if terms.slots.is_empty() && terms.nullifiers.is_empty() {
            return Err(MessageMismatch::Unrequested);
        }
        // 1. Each opening rebuilds the commitment published at its slot and names the signer. Past the
        // loop a slot index stands for one real output of the signer, so the count below cannot read
        // another owner's slot or a preimage the sender made up.
        for opening in &terms.slots {
            let published = data
                .outputs
                .get(opening.slot as usize)
                .ok_or(MessageMismatch::Recipients)?;
            // An exit commits no ring, a ring id here would refuse every exit the owner holds.
            let rebuilt = opening.utxo_hash((!published.is_exit()).then_some(terms.ring.0))?;
            if opening.owner != terms.signer || rebuilt != *published.hash {
                return Err(MessageMismatch::Recipients);
            }
        }
        // 2. The circuit counts the live slots the signer owns with a nonzero `data_hash`, per entry of
        // the run `signers.Chain` binds. Equality with the distinct opened slots closes the omission
        // that step 1 alone leaves open, a second data output the sender keeps out of the terms. Slots
        // dedupe a repeated opening, the filter keeps an ordinary payment from standing in for a data
        // output, and `ring_data_hash` stays outside since SPP asks no owner signature for it. A
        // member past the last packed entry reads zero and the circuit holds it to no data output.
        // The count reveals the public signers that receive data outputs and how many, never an amount.
        let opened: BTreeSet<u32> = terms
            .slots
            .iter()
            .filter(|opening| opening.data_hash.0 != [0; 32])
            .map(|opening| opening.slot)
            .collect();
        let proved = data
            .signer_data_counts()
            .count(self.run_entry(data, accounts)?);
        if opened.len() != usize::from(proved) {
            return Err(MessageMismatch::DataOutputCount);
        }
        // 3. A named note the wallet cannot place means no list stood behind the check.
        let named_and_held = terms.nullifiers.iter().all(|nullifier| {
            data.nullifiers.contains(&nullifier.0) && self.known_nullifiers.contains(&nullifier.0)
        });
        if !named_and_held {
            return Err(MessageMismatch::Data);
        }
        let spends_another = data.nullifiers.iter().any(|spent| {
            self.known_nullifiers.contains(spent)
                && !terms.nullifiers.iter().any(|named| named.0 == *spent)
        });
        match spends_another {
            true => Err(MessageMismatch::SpendsUnnamedNote),
            false => Ok(()),
        }
    }

    /// The signer's entry in the run the program hashes into `signers.Chain`. The ring auth PDA finds
    /// SPP's list with no read of the registries or co-signers ahead of it, since the program refuses
    /// a second copy anywhere in that list and neither a registry slot nor a signer slot can hold the
    /// PDA.
    fn run_entry(
        &self,
        data: &RingTransactData<'_>,
        accounts: &[AccountMeta],
    ) -> Result<usize, MessageMismatch> {
        let spp = spp_accounts(self.terms.ring.0, accounts)?;
        let settlements = settlement_accounts(&data.interface_transfers, data.circuit(), spp)
            .ok_or(MessageMismatch::Accounts)?;
        let window = data
            .owner_signers(spp, settlements.len())
            .map_err(|_| MessageMismatch::Accounts)?;
        let first = window
            .iter()
            .position(|meta| meta.pubkey == self.terms.signer.0)
            .ok_or(MessageMismatch::Accounts)?;
        // SPP and `SignerSet::new` deduplicate the window by first occurrence and the counts index
        // that run. Under `[X, X, V]` a raw position reads V past its entry, finds zero, and V signs
        // for a data output its terms leave out. The program accepts a repeat, so none is refused.
        Ok(window
            .iter()
            .take(first)
            .map(|meta| meta.pubkey)
            .collect::<BTreeSet<_>>()
            .len())
    }
}

/// SPP's forwarded list, found by the one ring auth PDA the program admits in it.
fn spp_accounts(
    ring: Address,
    accounts: &[AccountMeta],
) -> Result<&[AccountMeta], MessageMismatch> {
    let ring_auth = CustomRing::new(ring).ring_auth_pda();
    let mut copies = accounts
        .iter()
        .enumerate()
        .filter(|(_, meta)| meta.pubkey == ring_auth);
    let (Some((slot, _)), None) = (copies.next(), copies.next()) else {
        return Err(MessageMismatch::Accounts);
    };
    slot.checked_sub(RING_TRANSACT_RING_CONFIG_INDEX)
        .and_then(|start| accounts.get(start..))
        .ok_or(MessageMismatch::Accounts)
}

impl SlotOpening {
    fn utxo_hash(&self, ring: Option<Address>) -> Result<[u8; 32], MessageMismatch> {
        Utxo {
            owner: PublicKey::from_ed25519(self.owner.0.as_array()),
            asset: Mint::new(self.mint.0, 0),
            amount: self.amount,
            blinding: self.blinding.0,
            ring_program_id: ring,
            data: Default::default(),
        }
        .hash(
            &self.nullifier_pk.0,
            &self.data_hash.0,
            &self.ring_data_hash.0,
            self.tree_id,
        )
        .map_err(|_| MessageMismatch::Recipients)
    }
}

impl ExpectedFrame for ExpectedPublicOwner {
    const TAG: InstructionTag = InstructionTag::Transfer;

    /// Another key stays refused.
    fn envelope(&self, signer: Address) -> Result<Envelope, MessageMismatch> {
        if self.terms.signer.0 != signer {
            return Err(MessageMismatch::Unrequested);
        }
        Ok(Envelope {
            ring: CustomRing::new(self.terms.ring.0),
            program: self.terms.ring.0,
            units: compute_unit_limit(Self::TAG),
            fee_payer: self.terms.fee_payer.0,
            signer,
            setup: self.setup.clone(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        self.check_moved(parsed.data(), accounts)?;
        check_signer(&self.envelope(signer)?, accounts)
    }
}

impl ExpectedFrame for ExpectedFunder {
    const TAG: InstructionTag = InstructionTag::Transfer;

    fn envelope(&self, signer: Address) -> Result<Envelope, MessageMismatch> {
        if self.terms.signer.0 != signer {
            return Err(MessageMismatch::Unrequested);
        }
        Ok(Envelope {
            ring: CustomRing::new(self.terms.ring.0),
            program: self.terms.ring.0,
            units: compute_unit_limit(Self::TAG),
            fee_payer: self.terms.fee_payer.0,
            signer,
            setup: self.setup.clone(),
        })
    }

    /// The signature authorizes every position naming the key, so the check holds both sides.
    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        if self.terms.legs.is_empty() {
            return Err(MessageMismatch::Unrequested);
        }
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        let data = parsed.data();
        let spp = spp_accounts(self.terms.ring.0, accounts)?;
        let mut groups = settlement_accounts(&data.interface_transfers, data.circuit(), spp)
            .ok_or(MessageMismatch::Accounts)?;
        // 1. The legs of the frame that take the key as funder match the terms exactly, a leg the
        // sender adds would draw funds the signer never agreed to.
        let mut unfunded = self.terms.legs.clone();
        let mut funded = 0;
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(MessageMismatch::Accounts)?;
            groups = rest;
            let names_signer = funder_account_position(transfer)
                .and_then(|position| group.get(position))
                .is_some_and(|meta| meta.pubkey == signer);
            if !names_signer {
                continue;
            }
            let leg = FundedLeg {
                mint: transfer
                    .mint_account_position()
                    .and_then(|position| group.get(position))
                    .map(|meta| SerializablePubkey(meta.pubkey)),
                amount: transfer.amount(),
            };
            let held = unfunded
                .iter()
                .position(|term| *term == leg)
                .ok_or(MessageMismatch::FunderLegs)?;
            unfunded.swap_remove(held);
            funded += 1;
        }
        if !unfunded.is_empty() {
            return Err(MessageMismatch::FunderLegs);
        }
        // 2. Past the legs the key appears nowhere. A run entry would authorize its data outputs and
        // spent notes under one signature, the sharper authority the terms never name.
        let named = accounts.iter().filter(|meta| meta.pubkey == signer);
        if named.clone().count() != funded || !named.clone().all(|meta| meta.is_signer) {
            return Err(MessageMismatch::Accounts);
        }
        match self
            .envelope(signer)?
            .reads_only(accounts.get(..1).unwrap_or_default(), &[])
        {
            true => Ok(()),
            false => Err(MessageMismatch::Accounts),
        }
    }
}

impl ApprovalOpening {
    pub fn of(totals: &ApprovalTotals, blinder: &[u8; 32]) -> Self {
        Self {
            blinder: Hash(*blinder),
            outputs: totals
                .outputs
                .iter()
                .map(|slot| OutputTotalsOpening {
                    asset: Hash(slot.asset),
                    peak: slot.peak.to_string(),
                    charged_outflow: slot.charged_outflow.to_string(),
                })
                .collect(),
            public: totals
                .public
                .iter()
                .map(|slot| PublicTotalsOpening {
                    asset: Hash(slot.asset),
                    peak: slot.peak.to_string(),
                    outflow: slot.outflow.to_string(),
                    gross: slot.gross.to_string(),
                })
                .collect(),
        }
    }

    fn totals(&self) -> Option<ApprovalTotals> {
        Some(ApprovalTotals {
            outputs: self
                .outputs
                .iter()
                .map(|slot| {
                    Some(OutputTotals {
                        asset: slot.asset.0,
                        peak: slot.peak.parse().ok()?,
                        charged_outflow: slot.charged_outflow.parse().ok()?,
                    })
                })
                .collect::<Option<_>>()?,
            public: self
                .public
                .iter()
                .map(|slot| {
                    Some(PublicTotals {
                        asset: slot.asset.0,
                        peak: slot.peak.parse().ok()?,
                        outflow: slot.outflow.parse().ok()?,
                        gross: slot.gross.parse().ok()?,
                    })
                })
                .collect::<Option<_>>()?,
        })
    }
}

impl CoSignerApproval<'_> {
    pub fn pending(self) -> PendingSignature {
        PendingSignature::expecting(
            self.relay_id,
            self.message,
            ExpectedMessage::CoSigner(ExpectedCoSigner {
                ring: self.ring,
                fee_payer: self.fee_payer,
                signer: self.signer,
                rail: transfer_rail(self.config.mode),
                setup: setup_instructions(self.fee_payer, &self.setup),
                rule: self.rule,
            }),
        )
    }
}

impl ExactApproval {
    /// The digest binds the totals, the limits then read them with no slot opened. A ring with no
    /// own registry runs no outflow section and its circuit refuses a nonzero digest, so such a frame
    /// reads as `MissingApprovalDigest` and exact approval stays out of reach there, the proven bits
    /// remain the only rule a co-signer can apply to it.
    fn check(&self, digest: Option<&[u8; 32]>, capacity: usize) -> Result<(), MessageMismatch> {
        let digest = digest.ok_or(MessageMismatch::MissingApprovalDigest)?;
        // 1. The chain hashes a flat run of three fields per output and four per public slot with no
        // length in it, so `4a` more output rows and `3a` fewer public rows rebuild the same digest
        // with every column shifted. Only the key's exact counts make the limits below read a peak
        // as a peak, and they hold ahead of hashing since the rows come from the sealing wallet.
        if self.opening.outputs.len() != capacity || self.opening.public.len() != N_PUBLIC_SLOTS {
            return Err(MessageMismatch::ApprovalOpeningLayout);
        }
        // 2. The circuit accepts any blinder, and a zero one lets anyone test guessed totals against
        // the public digest. Freshness and hiding rest on the reader's refusal alone.
        let blinder = &self.opening.blinder;
        if blinder.0 == [0; 32] {
            return Err(MessageMismatch::ZeroApprovalBlinder);
        }
        if self.seen_blinders.contains(blinder) {
            return Err(MessageMismatch::ReusedApprovalBlinder);
        }
        let totals = self
            .opening
            .totals()
            .ok_or(MessageMismatch::FalseApprovalOpening)?;
        let opens = totals
            .commitment(&blinder.0)
            .is_ok_and(|commitment| commitment == *digest);
        if !opens {
            return Err(MessageMismatch::FalseApprovalOpening);
        }
        let named = totals
            .outputs
            .iter()
            .map(|slot| slot.asset)
            .chain(totals.public.iter().map(|slot| slot.asset))
            .filter(|asset| *asset != [0; 32]);
        for asset in named {
            let limit = self
                .limits
                .iter()
                .find(|limit| {
                    Member::asset(&limit.mint).is_ok_and(|field| *field.as_bytes() == asset)
                })
                .ok_or(MessageMismatch::ApprovalOverLimit)?;
            // A deposit the sender funds offsets its own withdrawal in peak and outflow, a public
            // row's gross alone shows what leaves through it.
            let over_gross = totals
                .public
                .iter()
                .any(|slot| slot.asset == asset && slot.gross > limit.gross);
            if over_gross
                || totals.peak_of(&asset) > limit.peak
                || totals.outflow_of(&asset) > limit.outflow
            {
                return Err(MessageMismatch::ApprovalOverLimit);
            }
        }
        Ok(())
    }
}

impl ExpectedFrame for ExpectedCoSigner {
    const TAG: InstructionTag = InstructionTag::Transfer;

    fn envelope(&self, signer: Address) -> Result<Envelope, MessageMismatch> {
        if self.signer != signer {
            return Err(MessageMismatch::Unrequested);
        }
        Ok(Envelope {
            ring: CustomRing::new(self.ring),
            program: self.ring,
            units: compute_unit_limit(Self::TAG),
            fee_payer: self.fee_payer,
            signer,
            setup: self.setup.clone(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        let data = parsed.data();
        match &self.rule {
            CoSignerRule::Threshold { accepts } => {
                if data.approval.bits() & !accepts.bits() != 0 {
                    return Err(MessageMismatch::ApprovalMaskUnaccepted);
                }
            }
            CoSignerRule::Exact(exact) => exact.check(
                data.extensions.approval_totals,
                parsed.audit_stream().capacity,
            )?,
        }
        check_signer(&self.envelope(signer)?, accounts)?;
        // The rule reads an approval and nothing else. A signature named in SPP's list also moves the
        // key's own funds or authorizes its notes and data outputs, none of it in the rule.
        let in_spp = spp_accounts(self.ring, accounts)?
            .iter()
            .any(|meta| meta.pubkey == signer);
        match in_spp {
            true => Err(MessageMismatch::Accounts),
            false => Ok(()),
        }
    }
}

impl ExpectedOwner {
    fn of(address: &ShieldedAddress) -> Result<Self, RingError> {
        Ok(Self {
            owner_key: address.signing_pubkey.confidential_view_tag()?,
            nullifier_pk: address.nullifier_pubkey,
            viewing_u: address.viewing_pubkey.u(),
        })
    }

    fn owns(&self, record: &AuditRecord) -> bool {
        record.owner_key == self.owner_key && record.nullifier_pk == self.nullifier_pk
    }
}

impl ExpectedPayment {
    fn matches(&self, record: &AuditRecord) -> bool {
        self.kind == record.kind
            && self.owner.owns(record)
            && record.mint == self.mint.to_bytes()
            && record.amount == self.amount
    }
}

impl ExpectedWithdrawal {
    fn new(withdrawal: &AuthorityWithdrawal) -> Result<Self, RingError> {
        let mint = withdrawal.mint.0;
        if mint == SOL_MINT {
            if let Some(program) = withdrawal.token_program {
                return Err(TransactionError::UnexpectedSolTokenProgram {
                    token_program: program.0,
                }
                .into());
            }
            return Ok(Self {
                transfer: InterfaceTransfer::SolWithdrawal {
                    amount: withdrawal.amount,
                },
                accounts: vec![pda::sol_interface(), withdrawal.recipient.0],
            });
        }
        let program = withdrawal
            .token_program
            .ok_or(TransactionError::MissingSplTokenProgram { mint })?
            .0;
        let (vault, bump) = pda::spl_interface_with_bump(&mint);
        Ok(Self {
            transfer: InterfaceTransfer::SplWithdrawal {
                amount: withdrawal.amount,
                spl_interface_bump: bump,
            },
            accounts: vec![
                pda::shielded_pool_cpi_authority(),
                mint,
                vault,
                pda::associated_token_address_with_program(
                    &withdrawal.recipient.0,
                    &mint,
                    &program,
                ),
                program,
            ],
        })
    }
}

impl VerifiedMessage {
    pub fn signer(&self) -> Address {
        self.signer
    }

    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, RingError> {
        if signer.try_pubkey()? != self.signer {
            return Err(MessageMismatch::Signer.into());
        }
        Ok(signer.try_sign_message(&self.bytes)?)
    }
}

impl Envelope {
    /// One canonical v1 message the quoted fee payer pays, holding only the ring instruction.
    fn open(&self, bytes: &[u8]) -> Result<Instruction, MessageMismatch> {
        let message = match wincode::deserialize(bytes) {
            Ok(VersionedMessage::V1(message)) => message,
            Ok(VersionedMessage::Legacy(_) | VersionedMessage::V0(_)) => {
                return Err(MessageMismatch::NotV1)
            }
            Err(_) => return Err(MessageMismatch::Undecodable),
        };
        if message.validate().is_err() || message.serialize() != bytes {
            return Err(MessageMismatch::Undecodable);
        }
        if message.fee_payer() != Some(&self.fee_payer) || self.fee_payer == self.signer {
            return Err(MessageMismatch::FeePayer);
        }
        let config = message.config;
        let within_budget = config
            .compute_unit_limit
            .is_some_and(|units| units <= self.units)
            && config
                .loaded_accounts_data_size_limit
                .is_some_and(|size| size <= MAX_LOADED_ACCOUNTS_DATA_SIZE)
            && config.heap_size.is_none();
        if !within_budget {
            return Err(MessageMismatch::Budget);
        }
        let (compiled, setup) = message
            .instructions
            .split_last()
            .ok_or(MessageMismatch::Instructions)?;
        let key = |index: u8| {
            message
                .account_keys
                .get(usize::from(index))
                .copied()
                .ok_or(MessageMismatch::Undecodable)
        };
        // An omitted create costs the signer nothing, a transfer to a missing account only fails.
        let mut named = self.setup.iter();
        for compiled in setup {
            let program = key(compiled.program_id_index)?;
            let accounts = compiled
                .accounts
                .iter()
                .map(|&index| key(index))
                .collect::<Result<Vec<_>, _>>()?;
            let found = named.any(|expected| {
                program == expected.program_id
                    && compiled.data == expected.data
                    && accounts
                        .iter()
                        .eq(expected.accounts.iter().map(|meta| &meta.pubkey))
            });
            if !found {
                return Err(MessageMismatch::Instructions);
            }
        }
        if key(compiled.program_id_index)? != self.program {
            return Err(MessageMismatch::Program);
        }
        let accounts = compiled
            .accounts
            .iter()
            .map(|&index| {
                Ok(AccountMeta {
                    pubkey: key(index)?,
                    is_signer: message.is_signer(usize::from(index)),
                    is_writable: requests_write(&message, usize::from(index)),
                })
            })
            .collect::<Result<_, MessageMismatch>>()?;
        Ok(Instruction {
            program_id: self.program,
            accounts,
            data: compiled.data.clone(),
        })
    }

    /// The ring account first, then accounts that never name the signer and write only where `forwarded` writes, a message holds one write role per address.
    fn reads_only(&self, prefix: &[AccountMeta], forwarded: &[AccountMeta]) -> bool {
        let forwarded_write = |meta: &AccountMeta| {
            forwarded
                .iter()
                .any(|spp| spp.pubkey == meta.pubkey && spp.is_writable)
        };
        match prefix.split_first() {
            Some((ring, rest)) => {
                *ring == AccountMeta::new_readonly(self.ring.policy_pda(), false)
                    && rest.iter().all(|meta| {
                        (!meta.is_writable || forwarded_write(meta)) && meta.pubkey != self.signer
                    })
            }
            None => false,
        }
    }

    fn verified(&self, bytes: &[u8]) -> VerifiedMessage {
        VerifiedMessage {
            bytes: bytes.to_vec(),
            signer: self.signer,
        }
    }
}

/// The header's write role, the one `compile_message` assigns.
fn requests_write(message: &v1::Message, index: usize) -> bool {
    let header = message.header;
    let signers = usize::from(header.num_required_signatures);
    match index < signers {
        true => message.is_signer_writable(index),
        false => {
            index
                < message
                    .account_keys
                    .len()
                    .saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
        }
    }
}

#[cfg(test)]
mod tests {
    use solana_message::Hash as Blockhash;
    use spr_client::{compile_message, ComputeBudgetConfig};

    use super::*;

    const FEE_PAYER: Address = Address::new_from_array([1; 32]);
    const SIGNER: Address = Address::new_from_array([2; 32]);
    const RING: Address = Address::new_from_array([3; 32]);
    const UNITS: u32 = 100_000;

    fn create(owner: u8) -> Instruction {
        CreateAssociatedTokenAccount {
            payer: FEE_PAYER,
            owner: Address::new_from_array([owner; 32]),
            mint: Address::new_from_array([4; 32]),
            token_program: Address::new_from_array([5; 32]),
        }
        .instruction()
    }

    fn opened(setup: Vec<Instruction>) -> Result<Instruction, MessageMismatch> {
        let ring_instruction = Instruction {
            program_id: RING,
            accounts: vec![AccountMeta::new_readonly(SIGNER, true)],
            data: vec![9],
        };
        let instructions: Vec<_> = setup.into_iter().chain([ring_instruction]).collect();
        let message = compile_message(
            &FEE_PAYER,
            &instructions,
            Blockhash::new_from_array([6; 32]),
            ComputeBudgetConfig::new(UNITS),
        )
        .unwrap();
        Envelope {
            ring: CustomRing::new(RING),
            program: RING,
            units: UNITS,
            fee_payer: FEE_PAYER,
            signer: SIGNER,
            setup: vec![create(7), create(8)],
        }
        .open(&message.serialize())
    }

    #[test]
    fn a_message_may_omit_a_named_create_and_nothing_else_changes() {
        assert!(opened(vec![create(7), create(8)]).is_ok());
        assert!(opened(vec![create(8)]).is_ok());
        assert!(opened(Vec::new()).is_ok());
        for refused in [
            vec![create(8), create(7)],
            vec![create(7), create(7)],
            vec![create(9)],
            vec![create(7), create(8), create(8)],
        ] {
            assert_eq!(opened(refused), Err(MessageMismatch::Instructions));
        }
    }
}
