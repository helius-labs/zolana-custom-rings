//! Escrows a member's nullifier key to the ring auditor, the proof covers the encryption alone.

use custom_ring_interface::{
    key_catalog::RingCircuit, tag, CustomRingError, CustomRingProof, RegisterKeyIxData,
    RegisterKeyStatement, RingMode,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::AsyncRpc;
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_indexer_api::Hash;
use spr_keypair::{NullifierKey, ShieldedAddress, ShieldedKeypair, X25519Pubkey};
use zeroize::Zeroizing;
use zolana_ring_client::AsyncRingIndexer;
use zolana_ring_client::{rpc::EscrowRegistration, NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_policy::Member;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    records::{MemberRead, MemberWrite, OwnerRead, RecordReads},
    request::KeyRegister,
    submission::BoundRoot,
    CustomRing, CustomRingConfig, RingError,
};

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowedRecipients<'a> {
    pub ring: CustomRing,
    pub recipients: &'a [ShieldedAddress],
}

impl EscrowedRecipients<'_> {
    /// Under key escrow the first recipient without an escrowed nullifier key is refused.
    pub async fn check(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<(), RingError> {
        if self.ring.require_config(rpc).await?.mode != RingMode::ConfidentialEscrow {
            return Ok(());
        }
        let owners = self
            .recipients
            .iter()
            .map(|recipient| recipient.signing_pubkey.owner_proof_input_hash())
            .collect::<Result<Vec<_>, _>>()?;
        let reads = RecordReads {
            root: BoundRoot::newest(self.ring, rpc).await?,
            members: &owners,
        }
        .read(rpc)
        .await?;
        for ((recipient, owner), read) in self.recipients.iter().zip(owners).zip(&reads) {
            OwnerRead { owner, read }.escrowed(&recipient.nullifier_pubkey)?;
        }
        Ok(())
    }
}

/// Hands out the nullifier secret in `seal`, one call before the prover request is sent.
pub trait KeyEscrowAuthority: Send + Sync {
    fn nullifier_pubkey(&self) -> Result<[u8; 32], RingError>;

    fn seal(&self, auditor: &X25519Pubkey) -> Result<SealedEscrow, RingError>;
}

/// Dropped once the prover request is sent.
pub struct SealedEscrow {
    pub envelope: NullifierKeyEnvelope,
    pub nullifier_secret: Zeroizing<[u8; 32]>,
}

impl KeyEscrowAuthority for NullifierKey {
    fn nullifier_pubkey(&self) -> Result<[u8; 32], RingError> {
        Ok(self.pubkey()?)
    }

    fn seal(&self, auditor: &X25519Pubkey) -> Result<SealedEscrow, RingError> {
        Ok(SealedEscrow {
            envelope: NullifierKeyEnvelope::new(self, auditor)?,
            nullifier_secret: Zeroizing::new(right_align(&self.secret())),
        })
    }
}

impl KeyEscrowAuthority for ShieldedKeypair {
    fn nullifier_pubkey(&self) -> Result<[u8; 32], RingError> {
        self.nullifier_key.nullifier_pubkey()
    }

    fn seal(&self, auditor: &X25519Pubkey) -> Result<SealedEscrow, RingError> {
        self.nullifier_key.seal(auditor)
    }
}

#[must_use]
pub struct RegisterKey<'a> {
    pub ring: CustomRing,
    /// Its signing key signs the instruction, its nullifier key is the one escrowed.
    pub member: ShieldedAddress,
    /// Pays the insert fee the config charges a member.
    pub payer: Address,
    pub authority: &'a dyn KeyEscrowAuthority,
}

#[must_use]
pub struct ProvenKeyRegistration {
    pub instruction: Instruction,
}

impl RegisterKey<'_> {
    /// Refuses a member whose record already escrows a key, a second key never replaces it.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenKeyRegistration, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        let escrow = EscrowProof {
            config: &config,
            member: &self.member,
            authority: self.authority,
        };
        let nullifier_pk = escrow.nullifier_pk()?;
        let signer = self.member.solana_address()?;
        let identity = solana_owner_identity(signer.as_array())?;
        let registry = self.ring.require_registry(client.zolana()).await?;
        self.ring
            .require_queue(client.zolana())
            .await?
            .admit_member_write(&registry)?;
        let read = MemberRead {
            root: BoundRoot::current(self.ring, &registry),
            member: identity,
        }
        .read(client.zolana())
        .await?;
        if read
            .record()
            .is_some_and(|record| record.escrow_key != [0; 32])
        {
            return Err(RingError::KeyAlreadyRegistered {
                member: Member::from_bytes(identity)?,
            });
        }
        let ProvenEscrow { proof, sealed, .. } = escrow.prove(client).await?;
        let write = MemberWrite {
            ring: self.ring,
            config: &config,
            member: signer,
            payer: self.payer,
        };
        let mut data = vec![tag::REGISTER_KEY];
        data.extend_from_slice(bytemuck::bytes_of(&RegisterKeyIxData {
            proof,
            nullifier_pk,
            eph_u: sealed.eph_pk.u(),
            ciphertext: sealed.ciphertext,
            max_fee: write.max_fee(),
        }));
        Ok(ProvenKeyRegistration {
            instruction: Instruction {
                program_id: self.ring.program_id(),
                accounts: write.metas(),
                data,
            },
        })
    }
}

/// The writer refuses a second escrow key for one member.
#[must_use]
pub struct KeyRegistration<'a> {
    pub ring: CustomRing,
    /// Its signing key signs the update, its nullifier key is the one escrowed.
    pub member: ShieldedAddress,
    pub authority: &'a dyn KeyEscrowAuthority,
}

impl KeyRegistration<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<EscrowRegistration, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        let ProvenEscrow {
            proof,
            identity,
            nullifier_pk,
            sealed,
        } = EscrowProof {
            config: &config,
            member: &self.member,
            authority: self.authority,
        }
        .prove(client)
        .await?;
        Ok(EscrowRegistration {
            member: Hash(identity),
            nullifier_pk: Hash(nullifier_pk),
            eph_pk: sealed.eph_pk.as_bytes().to_vec().into(),
            ciphertext: sealed.ciphertext.to_vec().into(),
            proof: bytemuck::bytes_of(&proof).to_vec().into(),
        })
    }
}

struct EscrowProof<'a> {
    config: &'a CustomRingConfig,
    member: &'a ShieldedAddress,
    authority: &'a dyn KeyEscrowAuthority,
}

struct ProvenEscrow {
    proof: CustomRingProof,
    identity: [u8; 32],
    nullifier_pk: [u8; 32],
    sealed: SealedNullifierKey,
}

impl EscrowProof<'_> {
    /// Refuses before any proof an anonymous ring or an authority holding another nullifier key.
    fn nullifier_pk(&self) -> Result<[u8; 32], RingError> {
        if self.config.mode == RingMode::Anonymous {
            return Err(CustomRingError::AnonymousRingRefused.into());
        }
        let nullifier_pk = self.authority.nullifier_pubkey()?;
        if nullifier_pk != self.member.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        Ok(nullifier_pk)
    }

    async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenEscrow, RingError> {
        let nullifier_pk = self.nullifier_pk()?;
        let identity = solana_owner_identity(self.member.solana_address()?.as_array())?;
        let auditor_pk = self.config.auditor_pubkey;
        let SealedEscrow {
            envelope,
            nullifier_secret,
        } = self.authority.seal(&auditor_pk)?;
        let eph_u = envelope.sealed.eph_pk.u();
        let public_input_hash = RegisterKeyStatement {
            member: &identity,
            nullifier_pk: &nullifier_pk,
            auditor_pubkey: auditor_pk.as_bytes(),
            eph_u: &eph_u,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()?;
        let body = KeyRegister {
            public_input_hash,
            member: identity,
            nullifier_secret,
            eph_sk: envelope.ephemeral_sk.clone(),
            auditor_pk,
        };
        let proof = RingRequest::new(RingCircuit::RegisterKey, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(ProvenEscrow {
            proof: to_instruction_proof(proof)?,
            identity,
            nullifier_pk,
            sealed: envelope.sealed,
        })
    }
}
