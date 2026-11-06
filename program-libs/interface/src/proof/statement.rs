//! The `HashChain4` public inputs of ring transfers and registry writes.
//!
//! An SPP proof binds SPP's own public values. A ring proof has one public input, the fold of a
//! statement the verifier rebuilds, so a prover picks no element the program derives. A statement
//! element enforces nothing alone, it fixes a value and a constraint or a program check gives it
//! meaning. `docs/design/proof-composition.md` names the enforcer of each.
//!
//! Each order here is the circuit's, a change on one side alone fails every proof. The Go twins are
//! `TransferCircuit.statement` in `prover/circuits/transfer/transfer.go`, `Envelope.Head` in
//! `prover/circuits/audit/audit.go`, and `statement` in each of `prover/circuits/registry/apply_records.go`,
//! `apply_enrollments.go` and `register_key.go`. `program-libs/interface/tests/statements.rs` and
//! `go_vectors.rs` pin them through `test-vectors/proof/ring-statements.json`.
//!
//! Read after `program-libs/interface/src/instructions/transact.rs`, `docs/design/proof-composition.md`.
//! Read before `prover/circuits/transfer/transfer.go`, `programs/custom-ring/src/instructions/transfer/verify.rs`.

use spr_hasher::{
    hash_chain::{create_hash_chain_4, create_hash_chain_4_from_slice},
    primitives::{hash_bytes, pack_be, right_align, solana_owner_identity},
    Hasher, HasherError, Poseidon,
};
use spr_interface::N_PUBLIC_SLOTS;

use crate::{
    anonymous_exit::ANONYMOUS_PARTIES,
    cosign::ApprovalMask,
    disclosure::{pack_disclosure, AuditLayout},
    domain,
    error::CustomRingError,
    key_catalog::{ApplyMode, RingCircuit},
    tagged_x25519,
    transact::RingOutput,
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

const ZERO_FIELD: [u8; 32] = [0; 32];

/// `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, envelope_digest, salt, layout]`.
pub const AUDIT_HEAD_ELEMENTS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditHead<'a> {
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub tx_viewing_u: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub envelope: &'a [u8],
    pub recipient_keys: &'a [u8],
    pub salt: &'a [u8; 16],
    pub layout: AuditLayout,
}

impl AuditHead<'_> {
    /// `statement` is the domain, so a proof of one kind cannot answer another.
    fn elements_under(
        &self,
        statement: u32,
    ) -> Result<[[u8; 32]; AUDIT_HEAD_ELEMENTS], HasherError> {
        let [tx0, tx1] = pack_be(&tagged_x25519(self.tx_viewing_u));
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        Ok([
            domain::field(statement),
            *self.first_nullifier,
            *self.ring_id,
            tx0,
            tx1,
            aud0,
            aud1,
            Poseidon::hashv(&[
                &ciphertext_digest(self.envelope)?,
                &ciphertext_digest(self.recipient_keys)?,
            ])?,
            right_align(self.salt),
            right_align(&[self.layout.value()]),
        ])
    }
}

/// One ring transfer's proof, mirror `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferStatement<'a> {
    pub head: AuditHead<'a>,
    pub family: TransferFamily<'a>,
    pub approval_mask: ApprovalMask,
    /// Zero unless the frame discloses totals to a co-signer.
    pub approval_totals: &'a [u8; 32],
    /// `R` is zero, no note is spent but address inputs still require SPP authorization.
    pub no_spend: bool,
    /// The `m` published slots.
    pub outputs: &'a [RingOutput<'a>],
    /// `N`, the key's output capacity.
    pub output_capacity: usize,
    /// `n`, the frame's nullifier count.
    pub input_count: usize,
    pub private_tx_hash: &'a [u8; 32],
    /// Default on the authority rails and on an empty run.
    pub signers: SignerSet,
    pub roots: &'a TransferRoots,
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// SPP's signed nets, a withdrawal is `q - |amount|`.
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Gross withdrawals per slot as right-aligned u128.
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

/// Zero where the frame reads none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferRoots {
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    pub curator_root: [u8; 32],
    pub tracking_root: [u8; 32],
}

/// Everything but the party cells, the public slots and the close.
const TRANSFER_FIXED_ELEMENTS: usize = AUDIT_HEAD_ELEMENTS + 3 + 3 + 2 + 2 + 1 + 2 + 4 + 1;

impl TransferStatement<'_> {
    pub const fn element_count(&self) -> usize {
        TRANSFER_FIXED_ELEMENTS + ANONYMOUS_PARTIES + 3 * N_PUBLIC_SLOTS + 1
    }

    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let capacity = self.output_capacity;
        let mut elements = Vec::with_capacity(self.element_count());
        // 1. The head ties the proof to SPP's first nullifier, the ring, the sealed key and the auditor stream.
        elements.extend(self.head.elements_under(domain::TRANSFER_STATEMENT)?);
        // 2. One key serves every rail. The circuit holds at most one bit set, and only the program's `delegate` bit parts the signer and delegate rails.
        elements.extend(self.family.rail_bits().map(bit));
        elements.extend([
            // 3. The proof holds these three to what it opened, the program acts on the mask and on the spend bit.
            right_align(&[self.approval_mask.bits()]),
            *self.approval_totals,
            bit(self.no_spend),
            // 4. One record ciphertext per published slot, zero filled to `N`, so the count alone carries `m`.
            count(self.outputs.len()),
            record_chain(self.outputs, capacity)?,
            // 5. The circuit holds every note below `n`. PrivateTxHash binds the note, output and address
            // chains SPP proved, and its blinding binds the head's first nullifier.
            count(self.input_count),
            *self.private_tx_hash,
            *self.family.sender(),
        ]);
        // 6. The circuit refuses a hidden owner equal to any party the program names.
        elements.extend(self.family.parties());
        elements.extend([
            // 7. SPP's owner run, the ring's policy hash, then each root the program read live, zero where the rail reads none.
            count(self.signers.count),
            self.signers.chain,
            self.roots.policy_hash,
            self.roots.own_root,
            self.roots.curator_root,
            self.roots.tracking_root,
        ]);
        // 8. SPP's public slots, then the legs the policy screens. The program folds both from settled legs, the circuit consumes them.
        for (slot, asset) in self.public_assets.iter().enumerate() {
            elements.extend([*asset, self.public_amounts[slot], self.public_gross[slot]]);
        }
        elements.push(*self.withdrawal_hash);
        // 9. The nonzero length counts itself and closes the chain, HashChain4 pads zeros.
        let length = (elements.len() + 1) as u64;
        elements.push(right_align(&length.to_be_bytes()));
        Ok(elements)
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFamily<'a> {
    /// The signer, in-proof and authority rails.
    Confidential { sender: ConfidentialSender<'a> },
    /// The anonymous rail, the head's layout picks the entry disclosure.
    Anonymous {
        /// `solana_owner_identity` of each co-signer in account order, zero past the last.
        party_identities: &'a [[u8; 32]; ANONYMOUS_PARTIES],
        /// No hidden sender exists, every live owner is a published signer.
        public_owners: bool,
        /// Set only under the authority tag.
        delegate: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidentialSender<'a> {
    Signer,
    InProof(&'a [u8; 32]),
    Authority,
}

impl TransferFamily<'_> {
    /// `in_proof`, `hidden`, `delegate`, a clear set is the signer rail.
    fn rail_bits(&self) -> [bool; 3] {
        match self {
            Self::Confidential { sender } => [
                matches!(sender, ConfidentialSender::InProof(_)),
                false,
                matches!(sender, ConfidentialSender::Authority),
            ],
            Self::Anonymous {
                public_owners,
                delegate,
                ..
            } => [false, !public_owners && !delegate, *delegate],
        }
    }

    fn sender(&self) -> &[u8; 32] {
        match self {
            Self::Confidential { sender } => sender.identity(),
            Self::Anonymous { .. } => &ZERO_FIELD,
        }
    }

    fn parties(&self) -> [[u8; 32]; ANONYMOUS_PARTIES] {
        match self {
            Self::Confidential { .. } => [ZERO_FIELD; ANONYMOUS_PARTIES],
            Self::Anonymous {
                party_identities, ..
            } => **party_identities,
        }
    }
}

impl ConfidentialSender<'_> {
    /// Zero on the signer and authority rails.
    pub fn identity(&self) -> &[u8; 32] {
        match self {
            Self::InProof(identity) => identity,
            Self::Signer | Self::Authority => &ZERO_FIELD,
        }
    }
}

/// SPP's owner signer run, deduplicated by first occurrence, the order `fill_owner_signer_hashes` reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignerSet {
    pub count: usize,
    /// Zero on an empty set, the one encoding every rail binds.
    pub chain: [u8; 32],
}

impl SignerSet {
    /// `slots` is the key's `S`, a run wider than it refused.
    pub fn new<'a>(
        owners: impl Iterator<Item = &'a [u8; 32]>,
        slots: usize,
    ) -> Result<Self, CustomRingError> {
        let mut unique: Vec<&[u8; 32]> = Vec::with_capacity(slots);
        for owner in owners {
            if !unique.contains(&owner) {
                unique.push(owner);
            }
        }
        if unique.len() > slots {
            return Err(CustomRingError::OwnerSignerCount);
        }
        if unique.is_empty() {
            return Ok(Self::default());
        }
        let mut identities = Vec::with_capacity(unique.len());
        for owner in &unique {
            identities.push(solana_owner_identity(owner)?);
        }
        Ok(Self {
            count: unique.len(),
            chain: zero_filled_chain(identities.iter(), slots)?,
        })
    }
}

/// Zero past the last cell, the chain width stays the key's.
fn zero_filled_chain<'a>(
    cells: impl Iterator<Item = &'a [u8; 32]>,
    width: usize,
) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4(cells.chain(core::iter::repeat(&ZERO_FIELD)).take(width))
}

/// `Poseidon(u32 len(ct), HashChain4(pack_left31(ct)))`, without the tag trailing zeros collide.
pub fn ciphertext_digest(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    let chain = create_hash_chain_4_from_slice(&pack_disclosure(ciphertext))?;
    Poseidon::hashv(&[
        &right_align(&(ciphertext.len() as u32).to_be_bytes()),
        &chain,
    ])
}

/// `HashChain4(hash_bytes(record_i))`, untagged since every record is one length.
pub fn record_chain(outputs: &[RingOutput<'_>], capacity: usize) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for output in outputs {
        hashes.push(hash_bytes(output.record)?);
    }
    zero_filled_chain(hashes.iter(), capacity)
}

/// An application of `count` writes, mirror `prover/circuits/registry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyRecordsStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    /// `chain_start` of the registry and revision.
    pub chain_start: [u8; 32],
    /// The chain past the last write.
    pub chain_end: [u8; 32],
    pub count: u64,
    /// Set exactly when a write tightens a policy field or changes an asset limit.
    pub restrictive: bool,
    /// `None` selects the public key, its statement ends at the restrictive bit.
    pub private: Option<PrivateWrites>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateWrites {
    /// The private key refuses zero, a batch without a private owner write is public.
    pub private_writes: u16,
    /// The pinned tracking registry's root at the instruction's revision, each selected owner's row opens under it.
    pub tracking_root: [u8; 32],
}

impl ApplyRecordsStatement {
    pub const fn mode(&self) -> ApplyMode {
        match self.private {
            Some(_) => ApplyMode::Private,
            None => ApplyMode::Public,
        }
    }

    pub const fn circuit(&self) -> RingCircuit {
        RingCircuit::apply_records(self.count, self.mode())
    }

    pub fn elements(&self) -> Vec<[u8; 32]> {
        let mut elements = Vec::with_capacity(11);
        // 1. CRAP binds the record transition, the exact write chain under the selected write count and the proven retirement class.
        elements.extend([
            domain::field(domain::APPLY_RECORDS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
            bit(self.restrictive),
        ]);
        // 2. A private key also binds the selected writes and the tracking root their rows open under.
        // The two families verify under distinct keys, so the shorter public statement needs no separate domain.
        if let Some(private) = &self.private {
            elements.extend([
                right_align(&private.private_writes.to_be_bytes()),
                private.tracking_root,
            ]);
        }
        elements
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// An application of `count` entries to the tracking tree, mirror
/// `prover/circuits/registry/apply_enrollments.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyEnrollmentsStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: [u8; 32],
    pub chain_end: [u8; 32],
    pub count: u64,
}

impl ApplyEnrollmentsStatement {
    /// `[CRTA, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`.
    pub fn elements(&self) -> [[u8; 32]; 8] {
        [
            domain::field(domain::APPLY_ENROLLMENTS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
        ]
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// The auditor envelope of an enrolled nullifier key, mirror
/// `prover/circuits/registry/register_key.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterKeyStatement<'a> {
    /// The tracking registry's, a proof for another ring fails.
    pub ring_id: &'a [u8; 32],
    /// The owner identity of the signing member.
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub list_tag: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
    pub ciphertext: &'a [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

impl RegisterKeyStatement<'_> {
    /// `[CRRG, ring_id, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`.
    pub fn elements(&self) -> Result<[[u8; 32]; 10], HasherError> {
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(domain::REGISTER_KEY),
            *self.ring_id,
            *self.member,
            *self.nullifier_pk,
            *self.list_tag,
            aud0,
            aud1,
            eph0,
            eph1,
            hash_bytes(self.ciphertext)?,
        ])
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }
}

fn bit(value: bool) -> [u8; 32] {
    right_align(&[u8::from(value)])
}

fn count(value: usize) -> [u8; 32] {
    right_align(&(value as u64).to_be_bytes())
}
