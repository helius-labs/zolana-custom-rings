//! Account layouts, instruction data, errors and statements of the custom ring
//! program, shared by the program, the SDKs and the services.

#[path = "instructions/anonymous_exit.rs"]
pub mod anonymous_exit;
#[path = "codec/anonymous_output.rs"]
pub mod anonymous_output;
#[path = "proof/blinding.rs"]
pub mod blinding;
#[path = "codec/bytes.rs"]
mod bytes;
#[path = "instructions/cosign.rs"]
pub mod cosign;
#[path = "instructions/deposit.rs"]
pub mod deposit;
#[path = "instructions/deposit_audit.rs"]
pub mod deposit_audit;
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
pub use anonymous_output::*;
pub use deposit::*;
pub use deposit_audit::*;
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
pub use verification::RingProof;

/// Not a deployable key, no keypair exists for it.
pub const STORAGE_PROGRAM_ID: solana_address::Address =
    solana_address::Address::new_from_array([0x53; 32]);

/// One-byte `0x04` scheme tag followed by a canonical X25519 u-coordinate.
pub use output::RECIPIENT_KEY_LEN as TAGGED_X25519_KEY_LEN;
pub const VIEWING_PUBKEY_TAG: u8 = 4;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
/// The auditor message before its disclosure fields.
pub const AUDITOR_MESSAGE_PREFIX_LEN: usize = TAGGED_X25519_KEY_LEN + AUDIT_CIPHERTEXT_LEN;

pub fn tagged_x25519(u: &[u8; 32]) -> [u8; TAGGED_X25519_KEY_LEN] {
    let mut key = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
    key[1..].copy_from_slice(u);
    key
}

/// `0x04 || eph_u || sealed || disclosure`, published under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorMessage<'a> {
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub sealed: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: &'a [[u8; 32]],
}

impl<'a> AuditorMessage<'a> {
    /// `None` unless the key is tagged and the disclosure has the field count of `layout`.
    pub fn parse(data: &'a [u8], layout: DisclosureLayout) -> Option<Self> {
        let (eph_pk, rest) = data.split_first_chunk::<TAGGED_X25519_KEY_LEN>()?;
        let (sealed, disclosure) = rest.split_first_chunk::<AUDIT_CIPHERTEXT_LEN>()?;
        if eph_pk[0] != VIEWING_PUBKEY_TAG || disclosure.len() != 32 * layout.field_count() {
            return None;
        }
        Some(Self {
            eph_pk,
            sealed,
            disclosure: disclosure.as_chunks::<32>().0,
        })
    }

    pub fn data(
        eph_u: &[u8; 32],
        sealed: &[u8; AUDIT_CIPHERTEXT_LEN],
        disclosure: &[[u8; 32]],
    ) -> Vec<u8> {
        [&tagged_x25519(eph_u)[..], sealed, disclosure.as_flattened()].concat()
    }
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
