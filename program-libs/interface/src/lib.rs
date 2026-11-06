//! Account layouts, instruction data, errors and statements of the custom ring
//! program, shared by the program, the SDKs and the services.
//!
//! # Reading guide
//!
//! For a reader who knows SPP and has not seen a ring. SPP verifies one proof and settles notes. A ring
//! adds a second proof over the same transaction. The ring program rebuilds that proof's statement from
//! its accounts and the frame, then forwards SPP's own data under the ring PDA's signature. Paths sit
//! under `program-libs/interface/src/` unless they say otherwise.
//!
//! 1. `docs/spec.md`, `docs/design/proof-composition.md`. What a ring enforces, and the side enforcing each guarantee.
//! 2. `accounts/state.rs`. The ring account, its pinned table, and the registries a frame may read.
//! 3. `accounts/member_registry.rs`, `accounts/storage.rs`, `accounts/tracking.rs`, `proof/auditor_key.rs`. The policy and tracking trees, the root history, zero grace, the floor and the auditor key check.
//! 4. `instructions/transact.rs`. The frame, each section named against SPP's `TransactIxData`.
//! 5. `proof/statement.rs`, `proof/domain.rs`. The statement in element order, with its Go twins.
//! 6. `proof/audit_stream.rs`, `proof/disclosure.rs`, `codec/output.rs`, `codec/stream.rs`. What the auditor and a recipient read of each slot.
//! 7. `proof/key_catalog.rs`, `proof/ring_keys.rs`, `proof/verification.rs`. The key serving each frame.
//! 8. `instructions/merge.rs`, `instructions/withdrawals.rs`, `instructions/anonymous_exit.rs`, `instructions/cosign.rs`. The other paths.
//!
//! Beside the crate, `program-libs/policy/src/rule_table/mod.rs` holds the rule table,
//! `program-libs/member-registry/src/lib.rs` the trees, `programs/storage/src/lib.rs` the program
//! that keeps their roots, `programs/custom-ring/src/instructions/transfer/processor.rs` the transfer's
//! entry point and `prover/circuits/transfer/transfer.go` its circuit.

#[path = "instructions/anonymous_exit.rs"]
pub mod anonymous_exit;
#[path = "proof/audit_stream.rs"]
pub mod audit_stream;
#[path = "proof/auditor_key.rs"]
mod auditor_key;
#[path = "proof/blinding.rs"]
pub mod blinding;
#[path = "codec/bytes.rs"]
mod bytes;
#[path = "instructions/cosign.rs"]
pub mod cosign;
#[path = "proof/disclosure.rs"]
pub mod disclosure;
#[path = "proof/domain.rs"]
pub mod domain;
pub mod error;
#[path = "instructions/instruction.rs"]
pub mod instruction;
#[path = "proof/key_catalog.rs"]
pub mod key_catalog;
#[path = "accounts/member_registry.rs"]
pub mod member_registry;
#[path = "instructions/merge.rs"]
pub mod merge;
#[path = "codec/output.rs"]
pub mod output;
#[path = "accounts/owner_grant.rs"]
pub mod owner_grant;
#[path = "proof/ring_keys.rs"]
pub mod ring_keys;
#[path = "codec/spp.rs"]
pub mod spp;
#[path = "accounts/state.rs"]
pub mod state;
#[path = "proof/statement.rs"]
pub mod statement;
#[path = "accounts/storage.rs"]
pub mod storage;
#[path = "instructions/storage.rs"]
pub mod storage_instruction;
#[path = "codec/stream.rs"]
pub mod stream;
#[path = "accounts/tracking.rs"]
pub mod tracking;
pub use owner_grant::OwnerGrant;
#[path = "instructions/transact.rs"]
pub mod transact;
#[path = "proof/verification.rs"]
mod verification;
#[path = "instructions/withdrawals.rs"]
pub mod withdrawals;
pub use withdrawals::*;

// Keep the generated modules at their existing public paths.
#[cfg(feature = "verifying-keys")]
mod verifying_keys;
#[cfg(feature = "verifying-keys")]
pub use verifying_keys::*;

#[cfg(feature = "verifying-keys")]
pub fn proving_key_hashes() -> impl Iterator<Item = (&'static str, [u8; 32])> {
    PROVING_KEY_SHA256S.iter().copied()
}

pub use anonymous_exit::*;
pub use audit_stream::*;
pub use auditor_key::is_auditor_key;
pub use disclosure::*;
pub use error::CustomRingError;
pub use instruction::*;
pub use member_registry::*;
pub use merge::*;
pub use output::*;
pub use spp::*;
pub use state::*;
pub use statement::*;
pub use transact::*;
pub use verification::{RegisterKeyCheck, RingProof};

/// Not a deployable key, no keypair exists for it.
pub const STORAGE_PROGRAM_ID: solana_address::Address =
    solana_address::Address::new_from_array([0x53; 32]);

/// One-byte `0x04` scheme tag followed by a canonical X25519 u-coordinate.
pub use output::RECIPIENT_KEY_LEN as TAGGED_X25519_KEY_LEN;
pub const VIEWING_PUBKEY_TAG: u8 = 4;
/// AES-256-CTR ciphertext of `nullifier_secret || list_salt`, 32 bytes each with a zero lead.
pub const REGISTER_KEY_CIPHERTEXT_LEN: usize = 64;

pub fn tagged_x25519(u: &[u8; 32]) -> [u8; TAGGED_X25519_KEY_LEN] {
    let mut key = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
    key[1..].copy_from_slice(u);
    key
}

/// `0x04 || eph_u || envelope_ct || record_ct... || tail_ct...`, published under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorMessage<'a> {
    format: DisclosureFormat,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub envelope: &'a [u8],
    /// One record per published slot.
    pub records: &'a [u8],
    /// One tail per published slot, empty while `has_data` is clear.
    pub tails: &'a [u8],
}

impl<'a> AuditorMessage<'a> {
    /// `None` unless the key is tagged and every length is `layout`'s.
    pub fn parse(data: &'a [u8], layout: AuditStreamLayout) -> Option<Self> {
        layout.checked().ok()?;
        let (eph_pk, rest) = data.split_first_chunk::<TAGGED_X25519_KEY_LEN>()?;
        let (envelope, rest) = rest.split_at_checked(layout.envelope().len)?;
        let (records, tails) = rest.split_at_checked(layout.records_len())?;
        (eph_pk[0] == VIEWING_PUBKEY_TAG && tails.len() == layout.tails_len()).then_some(Self {
            format: layout.key.format,
            eph_pk,
            envelope,
            records,
            tails,
        })
    }

    pub fn record(&self, slot: usize) -> Option<&'a [u8]> {
        let length = self.format.record_len();
        let start = slot.checked_mul(length)?;
        self.records.get(start..start.checked_add(length)?)
    }

    pub fn tail(&self, slot: usize) -> Option<&'a [u8; DATA_TAIL_LEN]> {
        self.tails.as_chunks().0.get(slot)
    }

    /// `ciphertexts` is the envelope, the records and the tails in slot order.
    pub fn data<'c>(
        eph_u: &[u8; 32],
        ciphertexts: impl Iterator<Item = &'c [u8]> + Clone,
    ) -> Vec<u8> {
        let len = ciphertexts.clone().map(<[u8]>::len).sum::<usize>();
        let mut data = Vec::with_capacity(TAGGED_X25519_KEY_LEN + len);
        data.extend_from_slice(&tagged_x25519(eph_u));
        ciphertexts.for_each(|ciphertext| data.extend_from_slice(ciphertext));
        data
    }
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
