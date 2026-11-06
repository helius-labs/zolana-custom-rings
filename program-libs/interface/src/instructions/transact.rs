//! The compact `Transfer` and `AuthorityTransfer` data, read in place and expanded into
//! the SPP `TransactIxData` the SPP proof's external data hash covers.
//!
//! An SPP reader knows `TransactIxData`. A frame carries the same transaction, adds the ring proof and
//! leaves out what the shape and the ring account fix. `transact_ix_data` rebuilds SPP's exact fields,
//! so SPP verifies its own proof and external data hash with no knowledge of the frame. The ring
//! statement and the CPI data read one parse, a statement over bytes other than the settled ones would
//! prove nothing about them.
//!
//! Read after `docs/design/owner-rails.md`, `program-libs/interface/src/accounts/state.rs`. Read before
//! `program-libs/interface/src/proof/statement.rs`, `programs/custom-ring/src/instructions/transfer/processor.rs`.
//!
//! The sections in wire order, each with what it is to SPP.
//! 1. Byte 0, [`transact_flag`], one bit per optional section. SPP never sees it.
//! 2. Bytes 1 to 3, `FrameHeader`, SPP's shape index, the nullifier count `n` and the published slot count `m`, flags in their top bits. SPP's selector and vector lengths follow from them.
//! 3. Byte 4, the approval mask. A statement element, SPP never sees it.
//! 4. The ring proof. SPP never sees it.
//! 5. The revisions, tracking, then own and curator under their flags. SPP never sees them. Each names a root the program reads from the bound registry.
//! 6. `expiry_unix_ts`, `tx_viewing_u` and `salt`. SPP's fields, the expiry in four bytes and the key without its 0x04 tag.
//! 7. [`FrameExtensions`] under `EXTENSIONS`. SPP's `data_hash`, `ring_data_hash`, application messages and cached selector, then `approval_totals`, a statement element SPP never sees.
//! 8. `interface_transfers`, SPP's public legs as sent, then under `OWN_ROOT` the SPL withdrawal token owners the program checks for the policy's withdrawal hash.
//! 9. The exit bitmap over `m`.
//! 10. One [`RingOutput`] per slot, SPP's `utxo_hash`, `owner_tag` and `data`, then the slot's record. A non-exit slot carries a short tag and its record opens the ring's scheme 10 body. An exit carries the full tag, its record goes to the auditor message and SPP's scheme 3 body follows.
//! 11. [`Replies`] under `REPLY_METADATA`, appended to each scheme 10 body inside SPP's `data`.
//! 12. [`FramedSenderBundle`] on an anonymous frame, SPP's first message under scheme 9.
//! 13. The envelope and the recipient keys. With the exits' records, the auditor message, SPP's last message, with the auditor's `u` as its view tag.
//! 14. `private_tx_hash`. SPP's, the ring proof reopens it over the slots it opened.
//! 15. [`AnonymousProofData`] or [`InProofOwner`]. The BSB22 commitment and default owner tag of SPP's anonymous selector, and the in proof owner's key for the statement.
//! 16. `spp_proof`. SPP's, with `b` compressed, and the expansion decompresses it.
//! 17. The nullifiers and input trees. SPP's `inputs` and `tree_contexts`.
//!
//! What binds what. SPP's external data hash covers `TransactIxData` through `messages` and the settlement accounts, so every section from 6 to 13 it receives but the cached selector, and it binds bytes alone. The ring statement covers every record, the envelope, the recipient keys, the salt, the viewing key, the first nullifier and the published input count. SPP's proof holds an exit's tag to its owner. No proof constrains a non-exit slot's tag, a payload past a record, the sender bundle or a reply.

#[path = "transact/expansion.rs"]
mod expansion;

use solana_address::Address;
use spr_hasher::{primitives::solana_owner_identity, HasherError};
use spr_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            transact::{
                AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite,
                MAX_CACHE_WRITES,
            },
            validate_interface_transfers,
        },
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        CircuitId, InterfaceTransfer, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    N_PUBLIC_SLOTS,
};
use wincode::{containers, len::FixIntLen, Serialize};

use crate::{
    anonymous_exit::ANONYMOUS_PARTIES,
    audit_stream::{
        AuditStreamLayout, BundleLayout, MIN_REPLY_LEN, OUTPUT_RECORD_LEN,
        RECIPIENT_PAYLOAD_LENGTH_LEN,
    },
    bytes::Bytes,
    cosign::ApprovalMask,
    disclosure::AuditLayout,
    error::CustomRingError,
    key_catalog::{FrameKey, RecordPools, RingCircuit, TransferShape, TransferSpend},
    output::CONFIDENTIAL_DATA_FREE_BODY_LEN,
    statement::{
        AuditHead, ConfidentialSender, SignerSet, TransferFamily, TransferRoots, TransferStatement,
    },
    storage::Revision,
    stream::{framed_slot_tag, slot_tag, unframed_slot_tag, SLOT_TAG_LEN},
    CustomRingProof, InstructionTag, LiveRoots, PlainGroth16Proof, RingMode, RingPolicy, RootRead,
    TAGGED_X25519_KEY_LEN,
};

const ZERO_FIELD: [u8; 32] = [0; 32];
/// Key support reads the shape alone.
const NO_PROOF_DATA: AnonymousRingEddsaProofData = AnonymousRingEddsaProofData {
    bsb22_commitment: Bsb22Commitment {
        commitment: ZERO_FIELD,
        commitment_pok: ZERO_FIELD,
    },
    default_owner_tag: None,
};

/// The program rail the data serves, fixed by the instruction tag and the ring mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Confidential,
    Anonymous,
    /// `AuthorityTransfer` on a confidential ring.
    Delegate,
    /// `AuthorityTransfer` on an anonymous ring, the anonymous frame keeps victim and recipients hidden.
    AnonymousDelegate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailSigner {
    /// The confidential rail's owner signer run.
    Owners,
    /// The anonymous rail, the payer, the owner run, the co-signers and the funders sign.
    Payer,
    Delegate {
        delegate: Address,
        anonymous_ring: bool,
    },
}

impl RailSigner {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        match RingRail::of(tag, ring.mode()?)? {
            RingRail::Anonymous => Ok(Self::Payer),
            RingRail::Confidential => Ok(Self::Owners),
            rail @ (RingRail::Delegate | RingRail::AnonymousDelegate) => ring
                .delegate()
                .map(|delegate| Self::Delegate {
                    delegate: *delegate,
                    anonymous_ring: rail == RingRail::AnonymousDelegate,
                })
                .ok_or(CustomRingError::DelegateDisabled),
        }
    }

    pub const fn rail(self) -> RingRail {
        match self {
            Self::Owners => RingRail::Confidential,
            Self::Payer => RingRail::Anonymous,
            Self::Delegate {
                anonymous_ring: false,
                ..
            } => RingRail::Delegate,
            Self::Delegate {
                anonymous_ring: true,
                ..
            } => RingRail::AnonymousDelegate,
        }
    }
}

impl RingRail {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        RailSigner::new(tag, ring).map(RailSigner::rail)
    }

    pub fn of(tag: InstructionTag, mode: RingMode) -> Result<Self, CustomRingError> {
        use InstructionTag::{AuthorityTransfer, Transfer};
        match (tag, mode) {
            (Transfer, RingMode::Anonymous) => Ok(Self::Anonymous),
            (Transfer, RingMode::Confidential) => Ok(Self::Confidential),
            (AuthorityTransfer, RingMode::Anonymous) => Ok(Self::AnonymousDelegate),
            (AuthorityTransfer, RingMode::Confidential) => Ok(Self::Delegate),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    pub const fn spp_tag(self) -> u8 {
        match self {
            Self::Confidential | Self::Anonymous => RING_TRANSACT,
            Self::Delegate | Self::AnonymousDelegate => RING_AUTHORITY_TRANSACT,
        }
    }

    pub const fn is_delegate(self) -> bool {
        matches!(self, Self::Delegate | Self::AnonymousDelegate)
    }

    pub const fn anonymous_frame(self) -> bool {
        matches!(self, Self::Anonymous | Self::AnonymousDelegate)
    }

    /// Public owners settle on SPP's confidential rail, so no hidden sender proves its signature.
    const fn spp_rail(self, public_owners: bool) -> Self {
        match (self, public_owners) {
            (Self::Anonymous, true) => Self::Confidential,
            (rail, _) => rail,
        }
    }

    fn circuit(self, n_in: u8, n_out: u8, proof_data: AnonymousRingEddsaProofData) -> CircuitId {
        let slots = N_PUBLIC_SLOTS as u8;
        match self {
            Self::Confidential => CircuitId::ConfidentialRingEddsa(n_in, n_out, slots),
            Self::Anonymous => CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data),
            Self::Delegate | Self::AnonymousDelegate => {
                CircuitId::RingAuthority(n_in, n_out, slots)
            }
        }
    }

    /// The authority rail admits SPP's ring-authority widths alone.
    pub fn supports(self, shape: Shape) -> bool {
        match (
            u8::try_from(shape.n_inputs()),
            u8::try_from(shape.n_outputs()),
        ) {
            (Ok(n_in), Ok(n_out)) => self.circuit(n_in, n_out, NO_PROOF_DATA).is_supported(),
            _ => false,
        }
    }

    /// The key the header names, before the outputs are read.
    fn key_shape(self, header: &FrameHeader) -> Result<TransferShape, CustomRingError> {
        let supported = self
            .spp_rail(header.flags.public_owners)
            .supports(Shape::new(
                usize::from(header.n_in),
                usize::from(header.n_out),
            ));
        let (n_out, inputs) = (usize::from(header.n_out), usize::from(header.input_count));
        let key = FrameKey {
            rail: self,
            inputs,
            outputs: n_out,
            spends_default_ring: header.flags.entry,
            wide: header.flags.wide_owners,
        }
        .shape()
        .filter(|_| supported)
        .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if inputs == 0 || inputs > usize::from(header.n_in) {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(key)
    }
}

impl core::fmt::Display for RingRail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Confidential => "confidential",
            Self::Anonymous => "anonymous",
            Self::Delegate => "delegate",
            Self::AnonymousDelegate => "anonymous delegate",
        })
    }
}

/// The data of `Transfer` and `AuthorityTransfer`, every count ahead of the sections it sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingTransactData<'a> {
    pub rail: RingRail,
    /// SPP shape inputs.
    pub n_in: u8,
    /// SPP shape outputs, the key's `N`.
    pub n_out: u8,
    /// The ring's, verified ahead of the SPP call.
    pub proof: &'a CustomRingProof,
    pub tracking_revision: Revision,
    /// Present exactly on a ring with own records, off the delegate rails.
    pub own_revision: Option<Revision>,
    /// Present exactly on a policy ring, off the delegate rails.
    pub policy: Option<PolicyProof>,
    /// Token owners checked on chain in SPL withdrawal order, present with `own_revision`.
    pub spl_withdrawal_owners: &'a [[u8; 32]],
    /// The proof computes the mask, the program demands a co-signer per set bit.
    pub approval: ApprovalMask,
    /// The statement's `R == 0`, the frame spends no note.
    pub no_spend: bool,
    /// The anonymous rail with every live owner a published signer, SPP's confidential rail settles it.
    pub public_owners: bool,
    /// SPP's expiry, the expansion widens it.
    pub expiry_unix_ts: u32,
    /// SPP's `tx_viewing_pk` without its tag, the proof holds every published blinding to the secret the envelope seals.
    pub tx_viewing_u: &'a [u8; 32],
    /// Random per attempt, a resend under the same first nullifier reuses no keystream.
    pub salt: &'a [u8; 16],
    pub extensions: FrameExtensions<'a>,
    /// SPP's public legs, forwarded as sent.
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// Every recipient body carries a payload past its record, one width per frame.
    pub has_data: bool,
    /// The key with entry capacity, the one that also spends a default-ring note.
    pub entry: bool,
    /// The key with its full owner rows, a hidden owner count needs the frame to name the key.
    pub wide_owners: bool,
    /// The `m` published slots, slot `i` keeps its index in every derivation.
    pub outputs: Vec<RingOutput<'a>>,
    /// Set exactly under `REPLY_METADATA`.
    pub replies: Option<Replies<'a>>,
    /// Present exactly on an anonymous frame.
    pub sender: Option<FramedSenderBundle<'a>>,
    /// `envelope_ct`, the transmitted length is the stream layout's.
    pub envelope: &'a [u8],
    /// One sealed key per published slot, in slot order.
    pub recipient_keys: &'a [u8],
    /// SPP's, the proof reopens it over the slots it opened and ties both proofs to one transaction.
    pub private_tx_hash: &'a [u8; 32],
    /// Present exactly on the anonymous rail with a hidden sender.
    pub anonymous: Option<AnonymousProofData<'a>>,
    /// Set exactly on the in-proof owner rail, SPP's anonymous rail of a confidential ring.
    pub in_proof_owner: Option<InProofOwner<'a>>,
    /// SPP's with `b` compressed, `expand` decompresses it for SPP's verifier.
    pub spp_proof: &'a PlainGroth16Proof,
    /// One per published SPP input, including address and dummy slots.
    pub nullifiers: &'a [[u8; 32]],
    pub input_trees: InputTrees,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProof {
    /// Set exactly when a source names a curator registry.
    pub curator_revision: Option<Revision>,
}

/// One application message, forwarded ahead of the auditor's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppMessage<'a> {
    pub view_tag: &'a [u8; 32],
    pub data: &'a [u8],
}

/// SPP's optional fields a frame carries through.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameExtensions<'a> {
    /// The transaction's application digest, distinct from a note's `data_hash`.
    pub data_hash: Option<&'a [u8; 32]>,
    /// The transaction's ring digest, distinct from a note's `ring_data_hash`.
    pub ring_data_hash: Option<&'a [u8; 32]>,
    pub messages: Vec<AppMessage<'a>>,
    /// The cached selector, refused on the authority rails.
    pub cache: Option<CacheAccess>,
    /// Present only for a co-signer that reads exact totals, the opening stays off chain.
    pub approval_totals: Option<&'a [u8; 32]>,
}

/// The owner SPP's anonymous rail verifies and hides, the frame names its key and the statement binds its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InProofOwner<'a> {
    pub owner: &'a [u8; 32],
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
}

impl InProofOwner<'_> {
    /// Ring notes only, a default-ring input would publish the owner SPP hides.
    fn proof_data(&self) -> AnonymousRingEddsaProofData {
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: *self.commitment,
                commitment_pok: *self.commitment_pok,
            },
            default_owner_tag: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousProofData<'a> {
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
    /// The hidden owner's default-ring key.
    pub default_owner_tag: Option<&'a [u8; 32]>,
}

/// The tree contexts inputs spend from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputTrees {
    One(TreeContext),
    /// Bit `i` of `second_inputs` spends input `i` from `second`.
    Two {
        first: TreeContext,
        second: TreeContext,
        second_inputs: u64,
    },
}

impl InputTrees {
    fn tree_index(self, input: usize) -> u8 {
        match self {
            Self::One(_) => 0,
            Self::Two { second_inputs, .. } => ((second_inputs >> input) & 1) as u8,
        }
    }

    fn contexts(self) -> Vec<TreeContext> {
        match self {
            Self::One(context) => vec![context],
            Self::Two { first, second, .. } => vec![first, second],
        }
    }
}

/// The bytes a slot hands SPP outside the proof, the external data hash binds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotBody<'a> {
    /// The record then the payload, one stream under the slot's delivered secret.
    Recipient(&'a [u8]),
    /// Scheme 3 under its own owner tag, a default-ring wallet reads it.
    Exit(&'a [u8]),
}

/// A published output slot without its SPP framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingOutput<'a> {
    pub hash: &'a [u8; 32],
    /// SPP binds an exit's tag to its owner, any other is a slot tag.
    pub owner_tag: [u8; 32],
    pub body: SlotBody<'a>,
    /// A recipient body's leading bytes, an exit's own section of the auditor message.
    pub record: &'a [u8; OUTPUT_RECORD_LEN],
}

impl<'a> RingOutput<'a> {
    /// The frame's claim, the proof reads the slot's own ring id.
    pub const fn is_exit(&self) -> bool {
        matches!(self.body, SlotBody::Exit(_))
    }

    const fn bears_recipient_body(&self) -> bool {
        matches!(self.body, SlotBody::Recipient(_))
    }

    /// The bytes past the record, a payload or an exit's scheme 3 body.
    const fn extra_len(&self) -> usize {
        match self.body {
            SlotBody::Recipient(body) => body.len().saturating_sub(OUTPUT_RECORD_LEN),
            SlotBody::Exit(body) => body.len(),
        }
    }

    /// A frame with no data carries each body at its plain length.
    const fn has_plain_body(&self) -> bool {
        match self.body {
            SlotBody::Recipient(body) => body.len() == OUTPUT_RECORD_LEN,
            SlotBody::Exit(payload) => payload.len() == CONFIDENTIAL_DATA_FREE_BODY_LEN,
        }
    }

    fn record_leads_body(&self) -> bool {
        match self.body {
            SlotBody::Recipient(body) => body.first_chunk() == Some(self.record),
            SlotBody::Exit(_) => true,
        }
    }
}

/// Sender bundle, forwarded under its tag as the first SPP message, `m` fixes the length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramedSenderBundle<'a> {
    pub tag: &'a [u8; 32],
    pub body: &'a [u8],
}

/// Every reply of a frame, one length so a hidden dummy matches a recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replies<'a> {
    /// `reply_len`, at least [`MIN_REPLY_LEN`].
    len: u16,
    /// `len` bytes per non-exit slot, in slot order, SPP's external data hash binds them through each output.
    region: &'a [u8],
}

impl<'a> Replies<'a> {
    pub fn new(len: u16, region: &'a [u8]) -> Result<Self, CustomRingError> {
        let chunk_len = usize::from(len);
        if chunk_len < MIN_REPLY_LEN || !region.len().is_multiple_of(chunk_len) {
            return Err(CustomRingError::ReplyLength);
        }
        Ok(Self { len, region })
    }

    pub const fn byte_len(self) -> u16 {
        self.len
    }

    pub const fn region(self) -> &'a [u8] {
        self.region
    }

    fn checked(self, bodies: usize) -> Result<Self, CustomRingError> {
        match usize::from(self.len).checked_mul(bodies) == Some(self.region.len()) {
            true => Ok(self),
            false => Err(CustomRingError::ReplyLength),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedAuthorization<'a> {
    ConfidentialSigner,
    ConfidentialInProof(InProofOwner<'a>),
    AnonymousHidden(AnonymousProofData<'a>),
    AnonymousPublic,
    Delegate,
    AnonymousDelegate,
}

impl<'a> CheckedAuthorization<'a> {
    fn new(data: &RingTransactData<'a>) -> Result<Self, CustomRingError> {
        if data.anonymous.is_some() != (data.rail == RingRail::Anonymous && !data.public_owners)
            || (data.in_proof_owner.is_some() && data.rail != RingRail::Confidential)
        {
            return Err(CustomRingError::FlagNotAllowed);
        }
        match data.rail {
            RingRail::Confidential => Ok(match data.in_proof_owner {
                Some(owner) => Self::ConfidentialInProof(owner),
                None => Self::ConfidentialSigner,
            }),
            RingRail::Anonymous => match data.anonymous {
                Some(proof) => Ok(Self::AnonymousHidden(proof)),
                None => Ok(Self::AnonymousPublic),
            },
            RingRail::Delegate => Ok(Self::Delegate),
            RingRail::AnonymousDelegate => Ok(Self::AnonymousDelegate),
        }
    }
}

/// One public leg's committed accounts, the asset account then the user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement<'a> {
    pub asset_account: &'a [u8; 32],
    pub user_account: &'a [u8; 32],
}

/// The stream layout is always the one the data's own frame selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransact<'a> {
    data: RingTransactData<'a>,
    stream: AuditStreamLayout,
    authorization: CheckedAuthorization<'a>,
}

impl<'a> ParsedTransact<'a> {
    pub fn new(data: RingTransactData<'a>) -> Result<Self, CustomRingError> {
        // 1. The selected key fixes the stream capacity before any section length is accepted.
        let stream = data.audit_stream()?;
        // 2. The retained data agrees with the rail and stream, proof and account checks remain external.
        let authorization = data.validate_under(stream)?;
        Ok(Self {
            data,
            stream,
            authorization,
        })
    }

    pub const fn authorization(&self) -> CheckedAuthorization<'a> {
        self.authorization
    }

    pub const fn data(&self) -> &RingTransactData<'a> {
        &self.data
    }

    pub fn into_data(self) -> RingTransactData<'a> {
        self.data
    }

    pub const fn audit_stream(&self) -> AuditStreamLayout {
        self.stream
    }

    pub fn transfer_statement<'s>(
        &'s self,
        binding: TransferBinding<'s>,
    ) -> Result<TransferStatement<'s>, CustomRingError> {
        let data = &self.data;
        // 1. The accepted authorization selects the statement rail, incompatible raw proof fields cannot select another rail.
        let family = match self.authorization {
            CheckedAuthorization::ConfidentialSigner => TransferFamily::Confidential {
                sender: ConfidentialSender::Signer,
            },
            CheckedAuthorization::ConfidentialInProof(_) => TransferFamily::Confidential {
                sender: ConfidentialSender::InProof(binding.sender),
            },
            CheckedAuthorization::Delegate => TransferFamily::Confidential {
                sender: ConfidentialSender::Authority,
            },
            authorization => TransferFamily::Anonymous {
                party_identities: binding.party_identities,
                public_owners: matches!(authorization, CheckedAuthorization::AnonymousPublic),
                delegate: matches!(authorization, CheckedAuthorization::AnonymousDelegate),
            },
        };
        // 2. Ciphertexts, the first nullifier and the published count come from the same frame sent to SPP.
        // The caller supplies account identities, served roots and public leg totals after their program checks.
        Ok(TransferStatement {
            head: AuditHead {
                first_nullifier: data.first_nullifier()?,
                ring_id: binding.ring_id,
                tx_viewing_u: data.tx_viewing_u,
                auditor_pubkey: binding.auditor_pubkey,
                envelope: data.envelope,
                recipient_keys: data.recipient_keys,
                salt: data.salt,
                layout: data.audit_layout(),
            },
            family,
            approval_mask: data.approval,
            approval_totals: data.extensions.approval_totals.unwrap_or(&ZERO_FIELD),
            no_spend: data.no_spend,
            outputs: &data.outputs,
            output_capacity: self.stream.capacity,
            input_count: data.nullifiers.len(),
            private_tx_hash: data.private_tx_hash,
            signers: binding.signers,
            roots: binding.roots,
            public_assets: binding.public_assets,
            public_amounts: binding.public_amounts,
            public_gross: binding.public_gross,
            withdrawal_hash: binding.withdrawal_hash,
        })
    }
}

/// What the program supplies beside the data for the transfer statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferBinding<'a> {
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    /// The in-proof owner identity, otherwise zero.
    pub sender: &'a [u8; 32],
    /// Default on the authority rails and on an empty run.
    pub signers: SignerSet,
    /// Zero outside the anonymous family.
    pub party_identities: &'a [[u8; 32]; ANONYMOUS_PARTIES],
    pub roots: &'a TransferRoots,
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

impl<'a> RingTransactData<'a> {
    /// Every length fixed by the flags, the shape and the counts, trailing bytes refused.
    pub fn parse(data: &'a [u8], rail: RingRail) -> Result<ParsedTransact<'a>, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::RingTransactLength);
        // 1. The flags and the header admit the rail's sections and name the key, every later length follows from them.
        let flags = TransactFlags(bytes.byte()?);
        flags.check(rail)?;
        let header = FrameHeader::read(&mut bytes, rail)?;
        let input_count = header.input_count;
        let output_count = usize::from(header.output_count);
        // 2. The ring's own fields, ahead of everything SPP reads. A revision names a root, `roots` reads it.
        let approval = ApprovalMask::new(bytes.byte()?).ok_or(CustomRingError::FlagNotAllowed)?;
        let proof = bytes.pod()?;
        let tracking_revision = *bytes.pod()?;
        let own_revision = flags
            .reads_own_root()
            .then(|| bytes.pod().copied())
            .transpose()?;
        let policy = match flags.has(transact_flag::POLICY) {
            false => None,
            true => Some(PolicyProof {
                curator_revision: flags
                    .has(transact_flag::CURATOR)
                    .then(|| bytes.pod().copied())
                    .transpose()?,
            }),
        };
        // 3. SPP's head and public legs pass as sent, `check_extensions` refuses a field off the rail.
        let expiry_unix_ts = bytes.u32()?;
        let tx_viewing_u = bytes.array()?;
        let salt = bytes.array()?;
        let extensions = match flags.has(transact_flag::EXTENSIONS) {
            false => FrameExtensions::default(),
            true => FrameExtensions::read(&mut bytes, rail)?,
        };
        check_extensions(&extensions, rail)?;
        let shape = rail.key_shape(&header)?;
        let interface_transfers = bytes.interface_transfers()?;
        let spl_withdrawal_owners = match flags.reads_own_root() {
            true => bytes.fields(crate::spl_withdrawal_count(&interface_transfers))?,
            false => &[],
        };
        // 4. Every slot carries a record, the bitmap names the exits.
        let exits = bytes.bitmap(output_count)?;
        let stream = AuditStreamLayout {
            key: shape.audit_key(),
            inputs: usize::from(input_count),
            outputs: output_count,
            capacity: usize::from(shape.outputs),
        };
        // 5. Each slot's fields for SPP, then its record. A non-exit tag travels short and regains its
        // leading zeros. The bytes past the record carry a length under `has_data` and their plain
        // length otherwise.
        let mut outputs = Vec::with_capacity(output_count);
        for slot in 0..output_count {
            let exit = (exits >> slot) & 1 == 1;
            let extra = match (header.flags.has_data, exit) {
                (true, _) => usize::from(bytes.u16()?),
                (false, true) => CONFIDENTIAL_DATA_FREE_BODY_LEN,
                (false, false) => 0,
            };
            let hash = bytes.array()?;
            let owner_tag = match exit {
                true => *bytes.array()?,
                false => unframed_slot_tag(bytes.array()?),
            };
            outputs.push(match exit {
                true => RingOutput {
                    hash,
                    owner_tag,
                    record: bytes.array()?,
                    body: SlotBody::Exit(bytes.take(extra)?),
                },
                false => {
                    let body = bytes.take(OUTPUT_RECORD_LEN + extra)?;
                    RingOutput {
                        hash,
                        owner_tag,
                        record: body
                            .first_chunk()
                            .ok_or(CustomRingError::RingTransactLength)?,
                        body: SlotBody::Recipient(body),
                    }
                }
            });
        }
        // 6. One reply length per frame, a hidden dummy then matches a recipient.
        let replies = match flags.has(transact_flag::REPLY_METADATA) {
            false => None,
            true => {
                let len = bytes.u16()?;
                let bodies = outputs
                    .iter()
                    .filter(|output| output.bears_recipient_body())
                    .count();
                Some(Replies::new(len, bytes.take(usize::from(len) * bodies)?)?.checked(bodies)?)
            }
        };
        // 7. The bundle's length follows `m`, the frame spends no byte on it.
        let sender = match rail.anonymous_frame() {
            true => Some(FramedSenderBundle {
                tag: bytes.array()?,
                body: bytes.take(
                    BundleLayout {
                        outputs: output_count,
                    }
                    .byte_len(),
                )?,
            }),
            false => None,
        };
        // 8. The auditor's envelope and the recipient keys, their lengths follow `n` and `m`.
        let envelope = bytes.take(stream.envelope().len)?;
        let recipient_keys = bytes.take(stream.keys_len())?;
        // 9. SPP's proof data, nullifiers and trees. A byte past them refuses.
        let private_tx_hash = bytes.array()?;
        let anonymous = (rail == RingRail::Anonymous && !header.flags.public_owners)
            .then(|| {
                Ok::<_, CustomRingError>(AnonymousProofData {
                    commitment: bytes.array()?,
                    commitment_pok: bytes.array()?,
                    default_owner_tag: header
                        .flags
                        .default_owner_tag
                        .then(|| bytes.array())
                        .transpose()?,
                })
            })
            .transpose()?;
        let in_proof_owner = match flags.has(transact_flag::OWNER_IN_PROOF) {
            false => None,
            true => Some(InProofOwner {
                owner: bytes.array()?,
                commitment: bytes.array()?,
                commitment_pok: bytes.array()?,
            }),
        };
        let spp_proof = bytes.pod()?;
        let nullifiers = bytes.fields(usize::from(input_count))?;
        let input_trees = match flags.has(transact_flag::SECOND_TREE) {
            false => InputTrees::One(bytes.tree_context()?),
            true => {
                let second_inputs = bytes.bitmap(usize::from(input_count))?;
                InputTrees::Two {
                    first: bytes.tree_context()?,
                    second: bytes.tree_context()?,
                    second_inputs,
                }
            }
        };
        if !bytes.rest().is_empty() {
            return Err(CustomRingError::RingTransactLength);
        }
        let data = Self {
            rail,
            n_in: header.n_in,
            n_out: header.n_out,
            proof,
            tracking_revision,
            own_revision,
            policy,
            spl_withdrawal_owners,
            approval,
            no_spend: flags.has(transact_flag::NO_SPEND),
            public_owners: header.flags.public_owners,
            expiry_unix_ts,
            tx_viewing_u,
            salt,
            extensions,
            interface_transfers,
            has_data: header.flags.has_data,
            entry: header.flags.entry,
            wide_owners: header.flags.wide_owners,
            outputs,
            replies,
            sender,
            envelope,
            recipient_keys,
            private_tx_hash,
            anonymous,
            in_proof_owner,
            spp_proof,
            nullifiers,
            input_trees,
        };
        ParsedTransact::new(data)
    }

    /// The bytes `parse` reads back, refusing what it refuses.
    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        self.encode_under(self.rail.key_shape(&FrameHeader::of(self)?)?)
    }

    /// For catalog sizing, `parse` refuses a `shape` off the catalog.
    pub fn encode_under(&self, shape: TransferShape) -> Result<Vec<u8>, CustomRingError> {
        let flags = self.flags();
        let header = FrameHeader::of(self)?;
        let stream = self.stream_under(shape);
        self.validate_under(stream)?;
        let interface_transfers =
            <containers::Vec<InterfaceTransfer, FixIntLen<u8>> as Serialize>::serialize(
                &self.interface_transfers,
            )
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let mut out = Vec::with_capacity(self.frame_len(stream, interface_transfers.len())?);
        out.push(flags.0);
        out.extend(header.bytes()?);
        out.push(self.approval.bits());
        out.extend_from_slice(bytemuck::bytes_of(self.proof));
        out.extend_from_slice(&self.tracking_revision.0);
        if let Some(revision) = self.own_revision {
            out.extend_from_slice(&revision.0);
        }
        if let Some(revision) = self.policy.and_then(|policy| policy.curator_revision) {
            out.extend_from_slice(&revision.0);
        }
        out.extend_from_slice(&self.expiry_unix_ts.to_le_bytes());
        out.extend_from_slice(self.tx_viewing_u);
        out.extend_from_slice(self.salt);
        if !self.extensions.is_empty() {
            self.extensions.write(&mut out)?;
        }
        out.extend_from_slice(&interface_transfers);
        out.extend_from_slice(self.spl_withdrawal_owners.as_flattened());
        push_bitmap(&mut out, self.outputs.iter().map(RingOutput::is_exit));
        for output in &self.outputs {
            if self.has_data {
                let len = u16::try_from(output.extra_len())
                    .map_err(|_| CustomRingError::OutputBodyLength)?;
                out.extend_from_slice(&len.to_le_bytes());
            }
            out.extend_from_slice(output.hash);
            match output.body {
                SlotBody::Exit(body) => {
                    out.extend_from_slice(&output.owner_tag);
                    out.extend_from_slice(output.record);
                    out.extend_from_slice(body);
                }
                SlotBody::Recipient(body) => {
                    out.extend_from_slice(&framed_slot_tag(&output.owner_tag));
                    out.extend_from_slice(body);
                }
            }
        }
        if let Some(replies) = self.replies {
            out.extend_from_slice(&replies.len.to_le_bytes());
            out.extend_from_slice(replies.region);
        }
        if let Some(sender) = self.sender {
            out.extend_from_slice(sender.tag);
            out.extend_from_slice(sender.body);
        }
        out.extend_from_slice(self.envelope);
        out.extend_from_slice(self.recipient_keys);
        out.extend_from_slice(self.private_tx_hash);
        if let Some(anonymous) = &self.anonymous {
            out.extend_from_slice(anonymous.commitment);
            out.extend_from_slice(anonymous.commitment_pok);
            if let Some(tag) = anonymous.default_owner_tag {
                out.extend_from_slice(tag);
            }
        }
        if let Some(owner) = &self.in_proof_owner {
            out.extend_from_slice(owner.owner);
            out.extend_from_slice(owner.commitment);
            out.extend_from_slice(owner.commitment_pok);
        }
        out.extend_from_slice(bytemuck::bytes_of(self.spp_proof));
        out.extend_from_slice(self.nullifiers.as_flattened());
        match self.input_trees {
            InputTrees::One(context) => push_tree_context(&mut out, context)?,
            InputTrees::Two {
                first,
                second,
                second_inputs,
            } => {
                push_bitmap(
                    &mut out,
                    (0..self.nullifiers.len()).map(|input| (second_inputs >> input) & 1 == 1),
                );
                push_tree_context(&mut out, first)?;
                push_tree_context(&mut out, second)?;
            }
        }
        Ok(out)
    }

    fn validate_under(
        &self,
        stream: AuditStreamLayout,
    ) -> Result<CheckedAuthorization<'a>, CustomRingError> {
        // 1. Proof fields, policy sections and extensions must belong to the selected authorization rail.
        let authorization = CheckedAuthorization::new(self)?;
        let flags = self.flags();
        flags.check(self.rail)?;
        let header = FrameHeader::of(self)?;
        check_extensions(&self.extensions, self.rail)?;
        // 2. Published counts fit the stream, each required section has the length selected by its flags.
        // Replies contain one complete chunk per recipient body, nonexit tags retain their canonical leading zeros.
        stream.checked()?;
        self.check_payload_width()?;
        let anonymous_frame = self.rail.anonymous_frame();
        let owners_expected = match flags.reads_own_root() {
            true => crate::spl_withdrawal_count(&self.interface_transfers),
            false => 0,
        };
        if self.own_revision.is_some() != flags.reads_own_root()
            || self.spl_withdrawal_owners.len() != owners_expected
            || self.sender.is_some() != anonymous_frame
            || self
                .sender
                .is_some_and(|sender| sender.body.len() != self.bundle_layout().byte_len())
            || self.envelope.len() != stream.envelope().len
            || self.recipient_keys.len() != stream.keys_len()
            || !self.outputs.iter().all(|output| {
                output.record_leads_body()
                    && (self.has_data || output.has_plain_body())
                    && (output.is_exit() || slot_tag(output.owner_tag) == output.owner_tag)
            })
        {
            return Err(CustomRingError::RingTransactLength);
        }
        if let Some(replies) = self.replies {
            replies.checked(self.recipient_body_count())?;
        }
        // 3. The compact count fits its header and SPP shape, tree bits cannot select an unpublished input.
        header.bytes()?;
        if self.nullifiers.is_empty() || self.nullifiers.len() > usize::from(self.n_in) {
            return Err(CustomRingError::RingTransactLength);
        }
        if let InputTrees::Two { second_inputs, .. } = self.input_trees {
            if second_inputs
                .checked_shr(self.nullifiers.len() as u32)
                .unwrap_or(0)
                != 0
            {
                return Err(CustomRingError::InvalidInstructionData);
            }
        }
        // 4. Bodies and application messages fit their length prefixes, public legs keep SPP's count and nonzero amount rules under ring errors.
        // No check here proves a ciphertext opening, validates a root or verifies either proof.
        if self
            .outputs
            .iter()
            .any(|output| output.extra_len() > usize::from(u16::MAX))
        {
            return Err(CustomRingError::OutputBodyLength);
        }
        if self
            .extensions
            .messages
            .iter()
            .any(|message| message.data.len() > usize::from(u16::MAX))
        {
            return Err(CustomRingError::OutputBodyLength);
        }
        check_public_legs(&self.interface_transfers)?;
        Ok(authorization)
    }

    /// Under `has_data` every recipient payload has one width, a payload of its own width would mark its slot.
    fn check_payload_width(&self) -> Result<(), CustomRingError> {
        if !self.has_data {
            return Ok(());
        }
        let mut widths = self.outputs.iter().filter_map(|output| match output.body {
            SlotBody::Recipient(body) => Some(body.len()),
            SlotBody::Exit(_) => None,
        });
        if let Some(width) = widths.next() {
            if width < OUTPUT_RECORD_LEN + RECIPIENT_PAYLOAD_LENGTH_LEN
                || widths.any(|next| next != width)
            {
                return Err(CustomRingError::OutputBodyLength);
            }
        }
        Ok(())
    }

    fn frame_len(
        &self,
        stream: AuditStreamLayout,
        interface_transfers: usize,
    ) -> Result<usize, CustomRingError> {
        const FIELD: usize = 32;
        let revision = core::mem::size_of::<Revision>();
        let policy = self
            .policy
            .map_or(0, |policy| policy.curator_revision.map_or(0, |_| revision));
        let sender = self.sender.map_or(0, |sender| FIELD + sender.body.len());
        let replies = self.replies.map_or(0, |replies| 2 + replies.region.len());
        let anonymous = self.anonymous.map_or(0, |anonymous| {
            FIELD * (2 + usize::from(anonymous.default_owner_tag.is_some()))
        });
        let in_proof_owner = self.in_proof_owner.map_or(0, |_| 3 * FIELD);
        let inputs = self.nullifiers.len();
        let trees = match self.input_trees {
            InputTrees::One(context) => tree_context_len(context)?,
            InputTrees::Two { first, second, .. } => {
                inputs.div_ceil(8) + tree_context_len(first)? + tree_context_len(second)?
            }
        };
        let extensions = match self.extensions.is_empty() {
            true => 0,
            false => self.extensions.frame_len(),
        };
        let slots = self
            .outputs
            .iter()
            .map(|output| {
                let len_prefix = match self.has_data {
                    true => 2,
                    false => 0,
                };
                let tag = if output.is_exit() {
                    FIELD
                } else {
                    SLOT_TAG_LEN
                };
                len_prefix + FIELD + tag + OUTPUT_RECORD_LEN + output.extra_len()
            })
            .sum::<usize>();
        Ok(1 + 3
            + 1
            + core::mem::size_of::<CustomRingProof>()
            + revision
            + self.own_revision.map_or(0, |_| revision)
            + policy
            + FIELD * self.spl_withdrawal_owners.len()
            + 4
            + FIELD
            + 16
            + extensions
            + interface_transfers
            + self.outputs.len().div_ceil(8)
            + slots
            + replies
            + sender
            + stream.sealed_len()
            + FIELD
            + anonymous
            + in_proof_owner
            + core::mem::size_of::<PlainGroth16Proof>()
            + FIELD * inputs
            + trees)
    }

    /// Refuses a frame whose sections disagree with what the rail reads of the ring.
    pub fn roots(
        &self,
        ring: &RingPolicy,
        roots: &LiveRoots<'_>,
    ) -> Result<TransferRoots, CustomRingError> {
        // 1. The frame carries a section exactly where the rail reads that root, no bit the prover sets opens or skips a read.
        let read = RootRead::transfer(ring, self.rail.is_delegate());
        let policy = match (self.policy, read == RootRead::Policy) {
            (None, false) => None,
            (Some(_), false) => return Err(CustomRingError::UnexpectedPolicyProof),
            (None, true) => return Err(CustomRingError::MissingPolicyProof),
            (Some(proof), true) => Some(proof),
        };
        let curator_revision = match (
            policy.and_then(|proof| proof.curator_revision),
            ring.curator_registry(read),
        ) {
            (None, None) => None,
            (Some(revision), Some(_)) => Some(revision),
            _ => return Err(CustomRingError::FlagNotAllowed),
        };
        if self.own_revision.is_some() != (read != RootRead::None) {
            return Err(CustomRingError::FlagNotAllowed);
        }
        // 2. The delegate's proof clears the mask, a set bit has no proof behind it.
        if !self.approval.is_empty() && self.rail.is_delegate() {
            return Err(CustomRingError::UnexpectedApproval);
        }
        // 3. Each root comes from its bound registry at the named revision, a retired root fails here ahead of the proof.
        let mut bound = TransferRoots {
            tracking_root: roots.tracking(self.tracking_revision)?,
            ..TransferRoots::default()
        };
        if policy.is_some() {
            bound.policy_hash = *ring.policy_hash()?;
        }
        if let Some(revision) = self.own_revision {
            bound.own_root = roots.own(revision)?;
        }
        if let Some(revision) = curator_revision {
            bound.curator_root = roots.curator(revision)?;
        }
        Ok(bound)
    }

    pub fn transfer_circuit(&self, legs: usize) -> Result<RingCircuit, CustomRingError> {
        // The proof holds the live owners to the key's rows, the frame names only the key.
        RingCircuit::transfer(TransferSpend {
            rail: self.rail,
            inputs: self.nullifiers.len(),
            outputs: usize::from(self.n_out),
            spends_default_ring: self.entry,
            legs,
            owners: 0,
            pools: RecordPools::default(),
            wide: self.wide_owners,
        })
        .ok_or(CustomRingError::RingShapeUnkeyed)
    }

    /// The run SPP reads as owner signers, between the nullifier PDAs and the settlement groups.
    pub fn owner_signers<'s, T>(
        &self,
        spp: &'s [T],
        settlements: usize,
    ) -> Result<&'s [T], CustomRingError> {
        let trees = match self.input_trees {
            InputTrees::One(_) => 1,
            InputTrees::Two { .. } => 2,
        };
        let start = crate::RING_TRANSACT_ACCOUNT_PREFIX_LEN + trees + self.nullifiers.len();
        // The cached selector's accounts follow the settlement groups, a run read through them would
        // take a cache as an unsigned owner and every cached frame would refuse.
        let cache_accounts = self.extensions.cache.map_or(0, |access| {
            usize::from(access.read_bitmap != 0) + 2 * usize::from(access.writes_cache())
        });
        spp.len()
            .checked_sub(settlements + cache_accounts)
            .and_then(|end| spp.get(start..end))
            .ok_or(CustomRingError::InvalidSettlementAccounts)
    }

    /// The SPP selector of the data's shape and rail.
    pub fn circuit(&self) -> CircuitId {
        // 1. An in-proof owner settles on SPP's anonymous rail though its ring is confidential, a public-owner frame on the confidential rail though its ring is anonymous.
        let circuit = match &self.in_proof_owner {
            Some(owner) => RingRail::Anonymous.circuit(self.n_in, self.n_out, owner.proof_data()),
            None => {
                let proof_data =
                    self.anonymous
                        .map_or(NO_PROOF_DATA, |anonymous| AnonymousRingEddsaProofData {
                            bsb22_commitment: Bsb22Commitment {
                                commitment: *anonymous.commitment,
                                commitment_pok: *anonymous.commitment_pok,
                            },
                            default_owner_tag: anonymous.default_owner_tag.copied(),
                        });
                self.rail
                    .spp_rail(self.public_owners)
                    .circuit(self.n_in, self.n_out, proof_data)
            }
        };
        // 2. Cached access and a delegate's exit each pick SPP's variant of that rail.
        match (circuit, self.extensions.cache) {
            (CircuitId::ConfidentialRingEddsa(n_in, n_out, slots), Some(access)) => {
                CircuitId::ConfidentialRingEddsaCached(n_in, n_out, slots, access)
            }
            (CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data), Some(access)) => {
                CircuitId::AnonymousRingEddsaCached(n_in, n_out, slots, proof_data, access)
            }
            (CircuitId::RingAuthority(n_in, n_out, slots), None)
                if self.outputs.iter().any(RingOutput::is_exit) =>
            {
                CircuitId::RingAuthorityExit(n_in, n_out, slots)
            }
            (circuit, _) => circuit,
        }
    }

    pub fn first_nullifier(&self) -> Result<&'a [u8; 32], CustomRingError> {
        self.nullifiers
            .first()
            .ok_or(CustomRingError::RingTransactLength)
    }

    /// The in-proof owner's identity, `None` off that rail.
    pub fn in_proof_sender(&self) -> Result<Option<[u8; 32]>, HasherError> {
        self.in_proof_owner
            .map(|owner| solana_owner_identity(owner.owner))
            .transpose()
    }

    pub fn audit_layout(&self) -> AuditLayout {
        AuditLayout { entry: self.entry }
    }

    /// Every ciphertext length of the transfer, refusing a frame no key serves.
    pub fn audit_stream(&self) -> Result<AuditStreamLayout, CustomRingError> {
        let shape = self.rail.key_shape(&FrameHeader::of(self)?)?;
        Ok(self.stream_under(shape))
    }

    pub fn stream_under(&self, shape: TransferShape) -> AuditStreamLayout {
        AuditStreamLayout {
            key: shape.audit_key(),
            inputs: self.nullifiers.len(),
            outputs: self.outputs.len(),
            capacity: usize::from(shape.outputs),
        }
    }

    pub fn bundle_layout(&self) -> BundleLayout {
        BundleLayout {
            outputs: self.outputs.len(),
        }
    }

    fn recipient_body_count(&self) -> usize {
        self.outputs
            .iter()
            .filter(|output| output.bears_recipient_body())
            .count()
    }

    /// The reply of each slot in order, empty on an exit.
    pub fn slot_replies(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        let mut replies = self
            .replies
            .map(|replies| replies.region.chunks_exact(usize::from(replies.len)));
        self.outputs.iter().map(
            move |output| match (output.bears_recipient_body(), &mut replies) {
                (true, Some(replies)) => replies.next().unwrap_or_default(),
                _ => &[],
            },
        )
    }

    fn flags(&self) -> TransactFlags {
        let bits = [
            (self.policy.is_some(), transact_flag::POLICY),
            (
                self.policy
                    .is_some_and(|policy| policy.curator_revision.is_some()),
                transact_flag::CURATOR,
            ),
            (self.no_spend, transact_flag::NO_SPEND),
            (self.in_proof_owner.is_some(), transact_flag::OWNER_IN_PROOF),
            (self.own_revision.is_some(), transact_flag::OWN_ROOT),
            (
                matches!(self.input_trees, InputTrees::Two { .. }),
                transact_flag::SECOND_TREE,
            ),
            (self.replies.is_some(), transact_flag::REPLY_METADATA),
            (!self.extensions.is_empty(), transact_flag::EXTENSIONS),
        ];
        TransactFlags(
            bits.into_iter()
                .filter(|(set, _)| *set)
                .fold(0, |flags, (_, bit)| flags | bit),
        )
    }
}

impl<'a> FrameExtensions<'a> {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn read(bytes: &mut Bytes<'a>, rail: RingRail) -> Result<Self, CustomRingError> {
        let flags = bytes.byte()?;
        if flags & !extension_flag::KNOWN != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let has = |bit: u8| flags & bit != 0;
        let data_hash = has(extension_flag::DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let ring_data_hash = has(extension_flag::RING_DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let messages = match has(extension_flag::MESSAGES) {
            false => Vec::new(),
            true => {
                let count = usize::from(bytes.byte()?);
                check_message_count(count, rail)?;
                // The bump allocator keeps every growth step, so the list takes its exact size once.
                let mut messages = Vec::with_capacity(count);
                for _ in 0..count {
                    let view_tag = bytes.array()?;
                    let len = bytes.u16()?;
                    messages.push(AppMessage {
                        view_tag,
                        data: bytes.take(usize::from(len))?,
                    });
                }
                messages
            }
        };
        let cache = has(extension_flag::CACHE)
            .then(|| read_cache_access(bytes))
            .transpose()?;
        let approval_totals = has(extension_flag::APPROVAL_TOTALS)
            .then(|| bytes.array())
            .transpose()?;
        Ok(Self {
            data_hash,
            ring_data_hash,
            messages,
            cache,
            approval_totals,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), CustomRingError> {
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        out.push(
            flag(self.data_hash.is_some(), extension_flag::DATA_HASH)
                | flag(
                    self.ring_data_hash.is_some(),
                    extension_flag::RING_DATA_HASH,
                )
                | flag(!self.messages.is_empty(), extension_flag::MESSAGES)
                | flag(self.cache.is_some(), extension_flag::CACHE)
                | flag(
                    self.approval_totals.is_some(),
                    extension_flag::APPROVAL_TOTALS,
                ),
        );
        if let Some(hash) = self.data_hash {
            out.extend_from_slice(hash);
        }
        if let Some(hash) = self.ring_data_hash {
            out.extend_from_slice(hash);
        }
        if !self.messages.is_empty() {
            out.push(count_byte(self.messages.len())?);
            for message in &self.messages {
                let len = u16::try_from(message.data.len())
                    .map_err(|_| CustomRingError::OutputBodyLength)?;
                out.extend_from_slice(message.view_tag);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(message.data);
            }
        }
        if let Some(cache) = &self.cache {
            write_cache_access(cache, out);
        }
        if let Some(totals) = self.approval_totals {
            out.extend_from_slice(totals);
        }
        Ok(())
    }

    fn frame_len(&self) -> usize {
        const FIELD: usize = 32;
        1 + self.data_hash.map_or(0, |_| FIELD)
            + self.ring_data_hash.map_or(0, |_| FIELD)
            + self.approval_totals.map_or(0, |_| FIELD)
            + match self.messages.is_empty() {
                true => 0,
                false => {
                    1 + self
                        .messages
                        .iter()
                        .map(|message| FIELD + 2 + message.data.len())
                        .sum::<usize>()
                }
            }
            + self.cache.map_or(0, |_| CACHE_ACCESS_LEN)
    }
}

/// The byte leading [`FrameExtensions`], one bit per optional field in wire order.
pub mod extension_flag {
    pub const DATA_HASH: u8 = 1 << 0;
    pub const RING_DATA_HASH: u8 = 1 << 1;
    pub const MESSAGES: u8 = 1 << 2;
    pub const CACHE: u8 = 1 << 3;
    pub const APPROVAL_TOTALS: u8 = 1 << 4;
    pub const KNOWN: u8 = DATA_HASH | RING_DATA_HASH | MESSAGES | CACHE | APPROVAL_TOTALS;
}

const CACHE_ACCESS_LEN: usize = 8 + 2 * MAX_CACHE_WRITES;

fn read_cache_access(bytes: &mut Bytes<'_>) -> Result<CacheAccess, CustomRingError> {
    let read_bitmap = u64::from_le_bytes(*bytes.array()?);
    let mut write_slots = CacheAccess::NO_WRITES;
    for write in &mut write_slots {
        let [output, slot] = *bytes.array()?;
        *write = CacheWrite { output, slot };
    }
    Ok(CacheAccess {
        read_bitmap,
        write_slots,
    })
}

fn write_cache_access(cache: &CacheAccess, out: &mut Vec<u8>) {
    out.extend_from_slice(&cache.read_bitmap.to_le_bytes());
    for write in &cache.write_slots {
        out.extend_from_slice(&[write.output, write.slot]);
    }
}

/// Byte 0 of the compact data, one bit per optional section.
pub mod transact_flag {
    pub const BYTE: usize = 0;
    pub const POLICY: u8 = 1 << 0;
    pub const CURATOR: u8 = 1 << 1;
    pub const NO_SPEND: u8 = 1 << 2;
    /// The confidential rail's owner signs inside SPP's anonymous rail proof.
    pub const OWNER_IN_PROOF: u8 = 1 << 3;
    /// The own revision and the SPL withdrawal owners follow.
    pub const OWN_ROOT: u8 = 1 << 4;
    pub const SECOND_TREE: u8 = 1 << 5;
    /// Anonymous frame only, one reply per body-bearing slot.
    pub const REPLY_METADATA: u8 = 1 << 6;
    /// SPP's optional fields follow the salt.
    pub const EXTENSIONS: u8 = 1 << 7;
}

/// Byte 1, the index into `SPP_SUPPORTED_SHAPES` below these flags.
pub mod shape_flag {
    pub const BYTE: usize = 1;
    pub const DEFAULT_OWNER_TAG: u8 = 1 << 6;
    pub const PUBLIC_OWNERS: u8 = 1 << 7;
}

/// Byte 2, the published input count below these flags.
pub mod input_flag {
    pub const BYTE: usize = 2;
    /// One length per slot for the bytes past its record.
    pub const HAS_DATA: u8 = 1 << 6;
    pub const ENTRY: u8 = 1 << 7;
}

pub const OUTPUT_COUNT_BYTE: usize = 3;
/// Byte 3, the proof's key opens its full owner rows.
pub mod output_flag {
    pub const WIDE_OWNERS: u8 = 1 << 7;
}
pub const APPROVAL_BYTE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransactFlags(u8);

impl TransactFlags {
    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// A delegate frame carries no policy section, and a policy section sits on the own root.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        let foreign_owner =
            self.has(transact_flag::OWNER_IN_PROOF) && rail != RingRail::Confidential;
        let foreign_reply = self.has(transact_flag::REPLY_METADATA) && !rail.anonymous_frame();
        let delegate_policy = rail.is_delegate()
            && (self.has(transact_flag::POLICY) || self.has(transact_flag::OWN_ROOT));
        if foreign_owner || foreign_reply || delegate_policy {
            return Err(CustomRingError::FlagNotAllowed);
        }
        if (self.has(transact_flag::CURATOR) && !self.has(transact_flag::POLICY))
            || (self.has(transact_flag::POLICY) && !self.has(transact_flag::OWN_ROOT))
        {
            return Err(CustomRingError::FlagNotAllowed);
        }
        Ok(())
    }

    const fn reads_own_root(self) -> bool {
        self.has(transact_flag::OWN_ROOT)
    }
}

/// The runtime's ceiling on CPI instruction data, the expanded SPP call must fit it.
pub const MAX_CPI_DATA_LEN: usize = 10 * 1024;

/// SPP's `messages` vector has a `u8` length.
pub const MAX_SPP_MESSAGES: usize = u8::MAX as usize;

/// SPP also receives the auditor message and an anonymous frame's sender bundle as messages.
pub const fn max_application_messages(rail: RingRail) -> usize {
    MAX_SPP_MESSAGES - 1 - rail.anonymous_frame() as usize
}

/// Runs ahead of the message list's allocation, the SPP encoder never meets an excess.
fn check_message_count(count: usize, rail: RingRail) -> Result<(), CustomRingError> {
    match count <= max_application_messages(rail) {
        true => Ok(()),
        false => Err(CustomRingError::TooManyApplicationMessages),
    }
}

fn check_public_legs(transfers: &[InterfaceTransfer]) -> Result<(), CustomRingError> {
    validate_interface_transfers(transfers).map_err(|error| match error {
        ShieldedPoolError::TooManyInterfaceTransfers => CustomRingError::TooManyPublicLegs,
        ShieldedPoolError::ZeroInterfaceTransferAmount => CustomRingError::ZeroPublicLegAmount,
        _ => CustomRingError::InvalidInstructionData,
    })
}

/// The delegate's cached selector has no SPP rail, its entry would spend default-ring notes.
fn check_extensions(
    extensions: &FrameExtensions<'_>,
    rail: RingRail,
) -> Result<(), CustomRingError> {
    if rail.is_delegate() && extensions.cache.is_some() {
        return Err(CustomRingError::FlagNotAllowed);
    }
    check_message_count(extensions.messages.len(), rail)
}

/// Bytes 1 to 3 of the compact data, the SPP shape's index and the input count below their flags, then `m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    n_in: u8,
    n_out: u8,
    input_count: u8,
    output_count: u8,
    flags: FrameFlags,
}

impl FrameHeader {
    /// The shape index or the input count, bits 6 and 7 carry the flags.
    const LOW: u8 = 0b0011_1111;

    fn read(bytes: &mut Bytes<'_>, rail: RingRail) -> Result<Self, CustomRingError> {
        let [shape, inputs, output_count] = *bytes.array()?;
        let spp_shape = SPP_SUPPORTED_SHAPES
            .get(usize::from(shape & Self::LOW))
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        let flags = FrameFlags {
            default_owner_tag: shape & shape_flag::DEFAULT_OWNER_TAG != 0,
            public_owners: shape & shape_flag::PUBLIC_OWNERS != 0,
            has_data: inputs & input_flag::HAS_DATA != 0,
            entry: inputs & input_flag::ENTRY != 0,
            wide_owners: output_count & output_flag::WIDE_OWNERS != 0,
        };
        flags.check(rail)?;
        let header = Self {
            n_in: count_byte(spp_shape.n_inputs())?,
            n_out: count_byte(spp_shape.n_outputs())?,
            input_count: inputs & Self::LOW,
            output_count: output_count & !output_flag::WIDE_OWNERS,
            flags,
        };
        header.check_output_count()?;
        Ok(header)
    }

    fn of(data: &RingTransactData<'_>) -> Result<Self, CustomRingError> {
        let flags = FrameFlags::of(data);
        flags.check(data.rail)?;
        let header = Self {
            n_in: data.n_in,
            n_out: data.n_out,
            input_count: count_byte(data.nullifiers.len())?,
            output_count: count_byte(data.outputs.len())?,
            flags,
        };
        header.check_output_count()?;
        Ok(header)
    }

    const fn check_output_count(self) -> Result<(), CustomRingError> {
        match self.output_count >= 1 && self.output_count <= self.n_out {
            true => Ok(()),
            false => Err(CustomRingError::OutputCountOutOfRange),
        }
    }

    fn bytes(self) -> Result<[u8; 3], CustomRingError> {
        let shape = Shape::new(usize::from(self.n_in), usize::from(self.n_out));
        let index = SPP_SUPPORTED_SHAPES
            .iter()
            .position(|supported| *supported == shape)
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if self.input_count > Self::LOW {
            return Err(CustomRingError::RingTransactLength);
        }
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        let flags = self.flags;
        Ok([
            index as u8
                | flag(flags.default_owner_tag, shape_flag::DEFAULT_OWNER_TAG)
                | flag(flags.public_owners, shape_flag::PUBLIC_OWNERS),
            self.input_count
                | flag(flags.has_data, input_flag::HAS_DATA)
                | flag(flags.entry, input_flag::ENTRY),
            self.output_count | flag(flags.wide_owners, output_flag::WIDE_OWNERS),
        ])
    }
}

const _: () = assert!(
    SPP_SUPPORTED_SHAPES.len() <= FrameHeader::LOW as usize + 1
        && spr_interface::MAX_TRANSACT_INPUTS <= FrameHeader::LOW as usize
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameFlags {
    /// Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok.
    default_owner_tag: bool,
    /// Shape byte bit 7, the anonymous rail settling on SPP's confidential rail.
    public_owners: bool,
    /// Input byte bit 6.
    has_data: bool,
    /// Input byte bit 7.
    entry: bool,
    /// Output count byte bit 7.
    wide_owners: bool,
}

impl FrameFlags {
    fn of(data: &RingTransactData<'_>) -> Self {
        Self {
            default_owner_tag: data
                .anonymous
                .is_some_and(|anonymous| anonymous.default_owner_tag.is_some()),
            public_owners: data.public_owners,
            has_data: data.has_data,
            entry: data.entry,
            wide_owners: data.wide_owners,
        }
    }

    /// The anonymous rail alone takes public owners and a default owner tag, a hidden owner alone the tag, and the delegate spends no default-ring note.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        let off_anonymous =
            rail != RingRail::Anonymous && (self.default_owner_tag || self.public_owners);
        match off_anonymous
            || (self.public_owners && self.default_owner_tag)
            || (self.entry && rail.is_delegate())
        {
            true => Err(CustomRingError::FlagNotAllowed),
            false => Ok(()),
        }
    }
}

fn invalid<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidInstructionData
}

fn count_byte(count: usize) -> Result<u8, CustomRingError> {
    u8::try_from(count).map_err(|_| CustomRingError::RingTransactLength)
}

fn push_bitmap(out: &mut Vec<u8>, bits: impl ExactSizeIterator<Item = bool>) {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (index, _) in bits.enumerate().filter(|(_, set)| *set) {
        bytes[index / 8] |= 1 << (index % 8);
    }
    out.extend_from_slice(&bytes);
}

fn tree_context_len(context: TreeContext) -> Result<usize, CustomRingError> {
    let size = wincode::serialized_size(&context).map_err(invalid)?;
    usize::try_from(size).map_err(invalid)
}

fn push_tree_context(out: &mut Vec<u8>, context: TreeContext) -> Result<(), CustomRingError> {
    out.extend(
        <TreeContext as Serialize>::serialize(&context)
            .map_err(|_| CustomRingError::InvalidInstructionData)?,
    );
    Ok(())
}
