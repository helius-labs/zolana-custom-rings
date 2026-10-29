use custom_ring_interface::{
    domain, mint_policy_write, queue_chain, storage_instruction::StorageWriteData, CustomRingError,
    EscrowKey, QueueEntry, WriteRecordsIxData, AUDIT_CIPHERTEXT_LEN,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::{primitives::right_align, Hasher, Poseidon};
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};
use thiserror::Error;
use zolana_ring_indexer::rpc::RingListWriteView;
use zolana_ring_policy::{registry_field, ring_id_field, ListId, Member, MemberError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RecordUpdateEntry {
    Write(RingListWriteView),
    /// The service checks `proof` against the escrow key before it queues the entry.
    Escrow(EscrowRegistration),
    WalletGrant(WalletGrantWrite),
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

/// The `Reader` list of `Member::wallet_grant(wallet, reader)`, set when `granted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletGrantWrite {
    pub wallet: Hash,
    pub reader: Hash,
    pub granted: bool,
}

/// The signed content, the request names the registry beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordUpdate {
    pub ring: SerializablePubkey,
    pub entries: Vec<RecordUpdateEntry>,
    pub valid_until_slot: u64,
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
    pub ring: Address,
    pub registry: Address,
    /// The queue chain of the entries from zero.
    pub entries_hash: [u8; 32],
    pub valid_until_slot: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordUpdateError {
    #[error(transparent)]
    Entry(#[from] CustomRingError),
    #[error("escrow ciphertext is not {AUDIT_CIPHERTEXT_LEN} bytes")]
    CiphertextLength,
    #[error(transparent)]
    Member(#[from] MemberError),
}

impl RecordUpdateEntry {
    /// The leaf write the apply proof hashes for the entry.
    pub fn entry(&self) -> Result<QueueEntry, RecordUpdateError> {
        Ok(self.write()?.entry()?)
    }

    pub fn write(&self) -> Result<StorageWriteData, RecordUpdateError> {
        match self {
            Self::Write(write) => Ok(StorageWriteData {
                member: write.member.0,
                lists: WriteRecordsIxData {
                    mask: write.mask.to_le_bytes(),
                    value: write.value.to_le_bytes(),
                },
                mint_policy: mint_policy_write(write.mint_policy),
                escrow_key: [0; 32],
            }),
            Self::Escrow(registration) => {
                let ciphertext =
                    <&[u8; AUDIT_CIPHERTEXT_LEN]>::try_from(registration.ciphertext.0.as_slice())
                        .map_err(|_| RecordUpdateError::CiphertextLength)?;
                let key = EscrowKey {
                    nullifier_pk: &registration.nullifier_pk.0,
                    ciphertext,
                };
                Ok(StorageWriteData {
                    member: registration.member.0,
                    lists: WriteRecordsIxData::default(),
                    mint_policy: mint_policy_write(None),
                    escrow_key: key.hash().map_err(CustomRingError::from)?,
                })
            }
            Self::WalletGrant(grant) => {
                let member = Member::wallet_grant(
                    &Member::from_bytes(grant.wallet.0)?,
                    &Member::from_bytes(grant.reader.0)?,
                )?;
                let reader = ListId::Reader.record_bit();
                let value = if grant.granted { reader } else { 0 };
                Ok(StorageWriteData {
                    member: *member.as_bytes(),
                    lists: WriteRecordsIxData {
                        mask: reader.to_le_bytes(),
                        value: value.to_le_bytes(),
                    },
                    mint_policy: mint_policy_write(None),
                    escrow_key: [0; 32],
                })
            }
        }
    }
}

impl SubmitRecordUpdateRequest {
    pub fn statement(&self) -> Result<RecordUpdateStatement, RecordUpdateError> {
        let entries_hash = self
            .update
            .entries
            .iter()
            .try_fold([0; 32], |chain, entry| {
                Ok::<_, RecordUpdateError>(
                    queue_chain(&chain, &entry.entry()?).map_err(CustomRingError::from)?,
                )
            })?;
        Ok(RecordUpdateStatement {
            ring: self.update.ring.0,
            registry: self.registry.0,
            entries_hash,
            valid_until_slot: self.update.valid_until_slot,
        })
    }
}

impl RecordUpdateStatement {
    /// `Poseidon(CRRU, hash_bytes(ring), hash_bytes(registry), entries_hash, valid_until_slot)`.
    pub fn hash(&self) -> Result<[u8; 32], CustomRingError> {
        Ok(Poseidon::hashv(&[
            &domain::field(domain::RECORD_UPDATE),
            &ring_id_field(self.ring.as_array())?,
            &registry_field(self.registry.as_array())?,
            &self.entries_hash,
            &right_align(&self.valid_until_slot.to_be_bytes()),
        ])?)
    }

    pub fn id(&self) -> Result<RecordUpdateId, CustomRingError> {
        Ok(RecordUpdateId(Hash(self.hash()?)))
    }
}
