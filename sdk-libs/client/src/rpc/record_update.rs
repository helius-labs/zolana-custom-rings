use custom_ring_interface::{
    domain, mint_policy_write, queue_chain,
    storage_instruction::{EscrowWriteData, StorageWriteData},
    CustomRingError, EscrowKey, QueueEntry, RecordWriteData, WriteRecordsIxData,
    AUDIT_CIPHERTEXT_LEN, GRACE_SLOTS,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::{Signer, SignerError};
use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use spr_indexer_api::{Base64String, Hash, RpcMethod, SerializablePubkey, SerializableSignature};
use spr_keypair::X25519Pubkey;
use thiserror::Error;
use zolana_ring_indexer::rpc::RingListWriteView;
use zolana_ring_policy::{registry_field, ring_id_field, ListId, ListSet, Member, MemberError};

use super::{GET_RECORD_UPDATE_STATUS, SUBMIT_RECORD_UPDATE};

/// Slots a graced update waits for more writes before it goes out short.
pub const BATCH_WINDOW_SLOTS: u64 = 40;
/// Outlives the batch window, a full grace wait and one more window for the pass that sends the batch.
pub const RECORD_UPDATE_SLOTS: u64 = 2 * BATCH_WINDOW_SLOTS + GRACE_SLOTS;

/// Authority lists that grant, never a restriction.
pub const ENROLMENT_LISTS: ListSet =
    ListSet::of(&[ListId::Allow, ListId::Reader, ListId::Approval]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RecordUpdateEntry {
    Write(RingListWriteView),
    /// The service checks `proof` against the escrow key before it queues the entry.
    Escrow(EscrowRegistration),
    /// The writer takes it only on the signature of `wallet`.
    WalletGrant(WalletGrant),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletGrant {
    pub wallet: Hash,
    pub reader: Hash,
    pub access: ReaderAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReaderAccess {
    Granted,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EscrowRegistration {
    pub member: Hash,
    pub nullifier_pk: Hash,
    /// Tagged X25519 ephemeral key, 33 bytes.
    pub eph_pk: Base64String,
    /// AES-256-CTR ciphertext of the nullifier secret, 32 bytes.
    pub ciphertext: Base64String,
    /// The register key `CustomRingProof`, 192 bytes.
    pub proof: Base64String,
}

/// The signed content, the request names the registry beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordUpdate {
    /// The writer refuses another cluster's genesis hash.
    pub genesis_hash: Hash,
    pub ring: SerializablePubkey,
    pub entries: Vec<RecordUpdateEntry>,
    pub valid_until_slot: u64,
    /// Record bits of the authority lists the update waits for, zero for none.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub awaited_lists: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitRecordUpdateRequest {
    /// A `StorageRegistry` account.
    pub registry: SerializablePubkey,
    pub update: RecordUpdate,
    pub signer: SerializablePubkey,
    /// Raw Ed25519 over the 32 bytes of [`RecordUpdateStatement::hash`].
    pub signature: SerializableSignature,
}

/// The statement hash, a resubmitted update keeps its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordUpdateId(pub Hash);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitRecordUpdateResponse {
    pub update_id: RecordUpdateId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRecordUpdateStatusRequest {
    pub update_id: RecordUpdateId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RecordUpdateStatus {
    /// Held until a config authority update sets every awaited list of the member.
    AwaitingAuthority,
    Queued,
    Submitted {
        signature: SerializableSignature,
    },
    /// `revision` is the registry revision the update produced.
    Applied {
        signature: SerializableSignature,
        revision: u64,
    },
    Refused {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordUpdateStatement {
    pub genesis_hash: [u8; 32],
    pub ring: Address,
    pub registry: Address,
    /// The queue chain of the entries from zero.
    pub entries_hash: [u8; 32],
    pub valid_until_slot: u64,
    pub awaited_lists: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordUpdateError {
    #[error(transparent)]
    Entry(#[from] CustomRingError),
    #[error("escrow ciphertext is not {AUDIT_CIPHERTEXT_LEN} bytes")]
    CiphertextLength,
    #[error("escrow ephemeral key is not a tagged X25519 key")]
    EphemeralKey,
    #[error("escrow member is not the owner identity of the signer")]
    EscrowOwner,
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error("record update signing failed")]
    Signing(#[source] SignerError),
    #[error("record update signature is invalid")]
    Signature,
}

pub mod method {
    use super::*;

    pub struct SubmitRecordUpdate;
    pub struct GetRecordUpdateStatus;

    impl RpcMethod for SubmitRecordUpdate {
        const NAME: &'static str = SUBMIT_RECORD_UPDATE;
        type Request = SubmitRecordUpdateRequest;
        type Response = SubmitRecordUpdateResponse;
    }

    impl RpcMethod for GetRecordUpdateStatus {
        const NAME: &'static str = GET_RECORD_UPDATE_STATUS;
        type Request = GetRecordUpdateStatusRequest;
        type Response = RecordUpdateStatus;
    }
}

impl RecordUpdateEntry {
    /// The leaf write the apply proof hashes for the entry.
    pub fn entry(&self) -> Result<QueueEntry, RecordUpdateError> {
        let record = match self {
            Self::Write(write) => list_write(write),
            Self::Escrow(registration) => {
                return Ok(QueueEntry::escrow(
                    registration.member.0,
                    &registration.key()?,
                )?);
            }
            Self::WalletGrant(grant) => grant.record()?,
        };
        Ok(StorageWriteData::Record(record).entry()?)
    }

    /// An escrow entry publishes `signer` as its owner.
    pub fn write(&self, signer: &Address) -> Result<StorageWriteData, RecordUpdateError> {
        Ok(match self {
            Self::Write(write) => StorageWriteData::Record(list_write(write)),
            Self::Escrow(registration) => StorageWriteData::Escrow(registration.write(signer)?),
            Self::WalletGrant(grant) => StorageWriteData::Record(grant.record()?),
        })
    }
}

impl EscrowRegistration {
    pub fn key(&self) -> Result<EscrowKey<'_>, RecordUpdateError> {
        Ok(EscrowKey {
            nullifier_pk: &self.nullifier_pk.0,
            ciphertext: self
                .ciphertext
                .0
                .as_slice()
                .try_into()
                .map_err(|_| RecordUpdateError::CiphertextLength)?,
        })
    }

    fn write(&self, owner: &Address) -> Result<EscrowWriteData, RecordUpdateError> {
        let eph_pk = <[u8; 33]>::try_from(self.eph_pk.0.as_slice())
            .ok()
            .and_then(|bytes| X25519Pubkey::from_bytes(bytes).ok())
            .ok_or(RecordUpdateError::EphemeralKey)?;
        let key = self.key()?;
        let write = EscrowWriteData {
            owner: *owner,
            nullifier_pk: *key.nullifier_pk,
            eph_u: eph_pk.u(),
            ciphertext: *key.ciphertext,
        };
        if write.member()? != self.member.0 {
            return Err(RecordUpdateError::EscrowOwner);
        }
        Ok(write)
    }
}

impl WalletGrant {
    fn record(&self) -> Result<RecordWriteData, RecordUpdateError> {
        let bit = ListId::Reader.record_bit();
        let value = match self.access {
            ReaderAccess::Granted => bit,
            ReaderAccess::Revoked => 0,
        };
        let member = Member::wallet_grant(
            &Member::from_bytes(self.wallet.0)?,
            &Member::from_bytes(self.reader.0)?,
        )?;
        Ok(RecordWriteData {
            member: *member.as_bytes(),
            lists: WriteRecordsIxData {
                mask: bit.to_le_bytes(),
                value: value.to_le_bytes(),
            },
            mint_policy: mint_policy_write(None),
        })
    }
}

impl RecordUpdate {
    pub fn statement(&self, registry: Address) -> Result<RecordUpdateStatement, RecordUpdateError> {
        let entries_hash = self.entries.iter().try_fold([0; 32], |chain, entry| {
            Ok::<_, RecordUpdateError>(
                queue_chain(&chain, &entry.entry()?).map_err(CustomRingError::from)?,
            )
        })?;
        Ok(RecordUpdateStatement {
            genesis_hash: self.genesis_hash.0,
            ring: self.ring.0,
            registry,
            entries_hash,
            valid_until_slot: self.valid_until_slot,
            awaited_lists: self.awaited_lists,
        })
    }

    /// The writer refuses a `signer` that does not hold every entry.
    pub fn sign<S: Signer + ?Sized>(
        self,
        registry: Address,
        signer: &S,
    ) -> Result<SubmitRecordUpdateRequest, RecordUpdateError> {
        let hash = self.statement(registry)?.hash()?;
        let signature = signer
            .try_sign_message(&hash)
            .map_err(RecordUpdateError::Signing)?;
        Ok(SubmitRecordUpdateRequest {
            registry: registry.into(),
            update: self,
            signer: signer.pubkey().into(),
            signature: signature.into(),
        })
    }
}

impl SubmitRecordUpdateRequest {
    pub fn statement(&self) -> Result<RecordUpdateStatement, RecordUpdateError> {
        self.update.statement(self.registry.0)
    }

    /// Signature only, the writer checks what `signer` may write.
    pub fn verify(&self) -> Result<RecordUpdateId, RecordUpdateError> {
        let id = self.statement()?.id()?;
        if !self.signature.0.verify(self.signer.0.as_ref(), &id.0 .0) {
            return Err(RecordUpdateError::Signature);
        }
        Ok(id)
    }
}

impl RecordUpdateStatement {
    /// Mirrored by `recordUpdateStatementHash` in `sdk-libs/ts/src/protocol/ring-rpc/record-update.ts`.
    ///   `Poseidon(CRRU, hash_bytes(genesis_hash), hash_bytes(ring), hash_bytes(registry), entries_hash, valid_until_slot[, awaited_lists])`
    pub fn hash(&self) -> Result<[u8; 32], CustomRingError> {
        let awaited = right_align(&self.awaited_lists.to_be_bytes());
        let elements: [&[u8]; 7] = [
            &domain::field(domain::RECORD_UPDATE),
            &hash_bytes(&self.genesis_hash)?,
            &ring_id_field(self.ring.as_array())?,
            &registry_field(self.registry.as_array())?,
            &self.entries_hash,
            &right_align(&self.valid_until_slot.to_be_bytes()),
            &awaited,
        ];
        // The width separates an enrolment's hash from a plain update's.
        let width = if self.awaited_lists == 0 { 6 } else { 7 };
        Ok(Poseidon::hashv(&elements[..width])?)
    }

    pub fn id(&self) -> Result<RecordUpdateId, CustomRingError> {
        Ok(RecordUpdateId(Hash(self.hash()?)))
    }
}

fn list_write(write: &RingListWriteView) -> RecordWriteData {
    RecordWriteData {
        member: write.member.0,
        lists: WriteRecordsIxData {
            mask: write.mask.to_le_bytes(),
            value: write.value.to_le_bytes(),
        },
        mint_policy: mint_policy_write(write.mint_policy),
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
