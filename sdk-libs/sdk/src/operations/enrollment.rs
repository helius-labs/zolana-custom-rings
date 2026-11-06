//! Storage `Enroll` writes the owner's tracking authorization, an apply moves it into the tracking tree.
//!
//! A first enrollment proves `RegisterKey`, the ciphertext opens to the nullifier secret and list salt
//! under the registry's auditor key, and fixes the key, list tag and seal for good. It grants nothing
//! until `ApplyEnrollments` inserts its row in a tracking root. A rotation carries no proof and writes
//! only the viewing key on the authorization, the owner's signature alone authorizes it, and it leaves
//! no tracking work.
//!
//! A signed attempt is recorded before its broadcast and reconciled by signature and by the
//! authorization account. A first enrollment lands once, the program refuses a second key.
//!
//! Read after `sdk-libs/client/src/rpc/relay_enroll.rs` and
//! `programs/storage/src/instructions/enroll.rs`.
//! Read before `services/ring-rpc/src/operations/relay.rs`.

use std::error::Error as StdError;

use async_trait::async_trait;
use custom_ring_interface::{
    domain,
    key_catalog::RingCircuit,
    storage_instruction::{tag, EnrollIxData, EnrollRequest, OwnerGrantIxData},
    tracking::TrackingAuthorization,
    ReaderKeyBytes, RegisterKeyStatement, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use spr_client::{
    compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig, RpcSendTransactionConfig,
};
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_keypair::{NullifierKey, X25519Pubkey};
use wincode::{SchemaRead, SchemaWrite};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{
        PrepareRelayRequest, ProofInputBytes, RelayEnrollInputs, RelayIntent, RelayQuote,
        ENROLL_COMPUTE_UNITS,
    },
    NullifierKeyEnvelope,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::SignatureHistory;
use crate::{
    prover::{to_instruction_proof, RingRequest},
    relay_message::{ExpectedEnroll, ExpectedMessage},
    request::KeyRegister,
    storage::storage_ix,
    submission::{check_transaction_size, outcome, transaction_error, Outcome},
    CustomRing, MessageMismatch, PreparedRelay, RingError,
};

#[cfg(test)]
#[path = "../tests/operations/enrollment.rs"]
mod tests;

/// The owner signs, a wallet with its key and a PDA through its program's `invoke_signed`.
#[must_use]
pub struct Enroll<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub owner: Address,
    pub nullifier_key: &'a NullifierKey,
    /// The key senders read from the authorization, a rotation moves only it.
    pub viewing_pubkey: X25519Pubkey,
    /// `ListSaltHolder::list_salt` of the ring.
    pub list_salt: [u8; 32],
}

/// The program signs through CPI for a PDA.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOwnerGrant {
    pub payer: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    pub grant: Address,
    pub reader: ReaderKeyBytes,
    pub active: bool,
}

/// An owner with no SOL, the relay pays and the owner signs the digest here and the message after.
#[must_use]
pub struct EnrollRelay<'a> {
    pub inputs: RelayEnrollInputs,
    pub owner: &'a dyn Signer,
}

/// A first enrollment holds the proof, a rotation none.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct EnrollInstruction {
    pub payer: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    /// `EnrollRequest::encode`, the tag excluded.
    pub request: Vec<u8>,
}

#[async_trait]
pub trait EnrollmentJournal: Send + Sync {
    /// Returns once `attempt` survives a restart, the broadcast follows only `Ok`.
    async fn record(
        &self,
        attempt: &EnrollmentAttempt,
    ) -> Result<(), Box<dyn StdError + Send + Sync>>;
}

#[must_use]
#[derive(Clone, Debug, PartialEq, SchemaWrite, SchemaRead)]
pub struct EnrollmentAttempt {
    pub instruction: EnrollInstruction,
    pub transaction: VersionedTransaction,
    pub last_valid_block_height: u64,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    Landed {
        slot: u64,
    },
    Failed(TransactionError),
    /// The attempt shows no landing and the authorization already holds its key and viewing key.
    Reserved,
    /// The attempt can still land.
    Pending,
    /// No landing and no matching authorization past the blockhash, the same request may go again.
    Expired,
}

impl Enroll<'_> {
    /// `payer` is the quoted fee payer.
    pub async fn prepare_relay<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        quote: RelayQuote,
        owner: &dyn Signer,
    ) -> Result<PreparedRelay, RingError> {
        if self.payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer: self.payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let instruction = self.prove(client).await?;
        EnrollRelay {
            inputs: RelayEnrollInputs {
                ring_program_id: self.ring.program_id(),
                owner: self.owner,
                tracking_registry: instruction.tracking_registry,
                instruction_data: instruction.instruction().data,
            },
            owner,
        }
        .prepare(quote)
    }

    /// The program refuses a second key for one owner, a present authorization takes a rotation.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<EnrollInstruction, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        let tracking_registry = config.account().tracking;
        // 1. A present authorization fixed key, tag and seal, a rotation repeats them unproven.
        let (authorization, _) =
            TrackingAuthorization::find_address(&tracking_registry, &self.owner);
        let enrolled = client
            .get_account(authorization)
            .await?
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data));
        let viewing_u = self.viewing_pubkey.u();
        if let Some(enrolled) = enrolled {
            if enrolled.nullifier_pk != self.nullifier_key.pubkey()? {
                return Err(RingError::AlreadyEnrolled { owner: self.owner });
            }
            return Ok(EnrollInstruction {
                payer: self.payer,
                owner: self.owner,
                tracking_registry,
                request: rotation_request(&enrolled, viewing_u),
            });
        }
        // 2. RegisterKey proves the ciphertext opens to the nullifier secret and list salt under
        //    the auditor key the registry pins, so the auditor recovers both from the account.
        let ring_id = self.ring.ring_id()?;
        let auditor_pk = config.auditor_pubkey;
        let key = self.nullifier_key;
        let envelope = NullifierKeyEnvelope::new(key, &self.list_salt, &auditor_pk)?;
        let nullifier_pk = key.pubkey()?;
        let list_tag = domain::list_tag(&self.list_salt)?;
        let member = solana_owner_identity(self.owner.as_array())?;
        let eph_u = envelope.sealed.eph_pk.u();
        let public_input_hash = RegisterKeyStatement {
            ring_id: &ring_id,
            member: &member,
            nullifier_pk: &nullifier_pk,
            list_tag: &list_tag,
            auditor_pubkey: auditor_pk.as_bytes(),
            eph_u: &eph_u,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()?;
        let body = KeyRegister {
            public_input_hash,
            ring_id,
            member,
            nullifier_secret: Zeroizing::new(right_align(&key.secret())),
            list_salt: self.list_salt,
            eph_sk: envelope.ephemeral_sk.clone(),
            auditor_pk,
        };
        let proof = RingRequest::new(RingCircuit::RegisterKey, &body)?
            .prove(client, public_input_hash)
            .await?;
        let ix = EnrollIxData {
            nullifier_pk,
            list_tag,
            viewing_u,
            eph_u,
            ciphertext: envelope.sealed.ciphertext,
        };
        Ok(EnrollInstruction {
            payer: self.payer,
            owner: self.owner,
            tracking_registry,
            request: EnrollRequest {
                ix: &ix,
                proof: Some(&to_instruction_proof(proof)?),
            }
            .encode(),
        })
    }
}

impl EnrollInstruction {
    pub fn authorization(&self) -> Address {
        TrackingAuthorization::find_address(&self.tracking_registry, &self.owner).0
    }

    /// The fields and the proof, a rotation holds none.
    pub fn parsed(&self) -> Result<EnrollRequest<'_>, RingError> {
        Ok(EnrollRequest::parse(&self.request)?)
    }

    /// For a PDA owner its program passes it to `invoke_signed`.
    pub fn instruction(&self) -> Instruction {
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new(self.tracking_registry, false),
                AccountMeta::new(self.authorization(), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::ENROLL][..], &self.request].concat(),
        )
    }

    /// `Ok` means recorded and broadcast or in doubt, a preflight refusal returns its error.
    pub async fn submit<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        signers: &[&(dyn Signer + Sync)],
        journal: &dyn EnrollmentJournal,
    ) -> Result<EnrollmentAttempt, RingError> {
        // 1. The payer heads the message, the owner signs beside it unless it is the payer.
        let instruction = self.instruction();
        let budget = ComputeBudgetConfig::new(ENROLL_COMPUTE_UNITS);
        check_transaction_size(&self.payer, &instruction, budget)?;
        let (blockhash, last_valid_block_height) = client.get_latest_blockhash().await?;
        let message = compile_message(&self.payer, &[instruction], blockhash, budget)?;
        let transaction = {
            let all: Vec<&dyn Signer> = signers
                .iter()
                .map(|signer| *signer as &dyn Signer)
                .collect();
            sign_transaction(message, &all)?
        };
        let attempt = EnrollmentAttempt {
            instruction: self.clone(),
            transaction,
            last_valid_block_height,
        };
        // 2. The attempt is durable before any byte leaves, a crash after the send still reconciles.
        journal
            .record(&attempt)
            .await
            .map_err(RingError::AttemptNotRecorded)?;
        // 3. Only a preflight refusal proves the bytes did not land, any other error stays in doubt.
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(solana_commitment_config::CommitmentLevel::Confirmed),
            ..RpcSendTransactionConfig::default()
        };
        match client
            .send_transaction_with_config(&attempt.transaction, config)
            .await
            .err()
            .and_then(transaction_error)
        {
            Some(refused) => Err(RingError::EnrollmentRefused(refused)),
            None => Ok(attempt),
        }
    }
}

/// The authorization's final key, tag and seal under a new viewing key, unproven.
pub(crate) fn rotation_request(enrolled: &TrackingAuthorization, viewing_u: [u8; 32]) -> Vec<u8> {
    let ix = EnrollIxData {
        nullifier_pk: enrolled.nullifier_pk,
        list_tag: enrolled.list_tag,
        viewing_u,
        eph_u: enrolled.eph_u,
        ciphertext: enrolled.ciphertext,
    };
    EnrollRequest {
        ix: &ix,
        proof: None,
    }
    .encode()
}

impl EnrollRelay<'_> {
    /// A PDA holds no key to sign here, its program enrolls through CPI.
    pub fn prepare(self, quote: RelayQuote) -> Result<PreparedRelay, RingError> {
        if self.owner.try_pubkey()? != self.inputs.owner {
            return Err(MessageMismatch::Signer.into());
        }
        let owner_signature = self
            .owner
            .try_sign_message(&self.inputs.request_digest())?
            .into();
        let expected = ExpectedEnroll {
            fee_payer: quote.fee_payer.0,
            inputs: self.inputs.clone(),
        };
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: self.inputs.ring_program_id.into(),
            quote,
            intent: RelayIntent::Enroll {
                proof_inputs: ProofInputBytes::new(Zeroizing::new(self.inputs.encode()?)),
                owner_signature,
            },
            co_signers: Vec::new(),
        })
        .expecting(ExpectedMessage::Enroll(expected)))
    }
}

impl EnrollmentAttempt {
    pub fn signature(&self) -> Signature {
        self.transaction.signatures[0]
    }

    pub fn encode(&self) -> Result<Vec<u8>, RingError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        wincode::deserialize_exact(bytes).map_err(|_| RingError::AttemptUnreadable)
    }

    /// An RPC failure is an error, never an expiry.
    pub async fn reconcile<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<EnrollmentOutcome, RingError> {
        // 1. The attempt's own status decides first.
        let observed = outcome(
            client.zolana(),
            self.signature(),
            self.last_valid_block_height,
        )
        .await?;
        if let Outcome::Confirmed { slot } = observed {
            return Ok(EnrollmentOutcome::Landed { slot });
        }
        // 2. An authorization already holding the attempt's key and viewing key needs no resend,
        //    some `Enroll` wrote it, ours or another.
        let data = self.instruction.parsed()?.ix;
        let held = client
            .get_account(self.instruction.authorization())
            .await?
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
            .is_some_and(|held| {
                held.nullifier_pk == data.nullifier_pk && held.viewing_u == data.viewing_u
            });
        if held {
            return Ok(EnrollmentOutcome::Reserved);
        }
        Ok(match observed {
            Outcome::Unknown => EnrollmentOutcome::Pending,
            Outcome::Failed(TransactionError::BlockhashNotFound) => EnrollmentOutcome::Expired,
            Outcome::Failed(error) | Outcome::Stale(error) => EnrollmentOutcome::Failed(error),
            Outcome::Confirmed { slot } => EnrollmentOutcome::Landed { slot },
        })
    }

    pub async fn resubmit<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
        signers: &[&(dyn Signer + Sync)],
        journal: &dyn EnrollmentJournal,
    ) -> Result<EnrollmentAttempt, RingError> {
        match self.reconcile(client).await? {
            EnrollmentOutcome::Expired => self.instruction.submit(client, signers, journal).await,
            settled => Err(RingError::AttemptNotExpired(settled)),
        }
    }
}

impl WriteOwnerGrant {
    pub fn instruction(self) -> Instruction {
        let data = OwnerGrantIxData {
            reader: self.reader,
            active: u8::from(self.active),
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new_readonly(self.tracking_registry, false),
                AccountMeta::new(self.grant, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::OWNER_GRANT][..], bytemuck::bytes_of(&data)].concat(),
        )
    }
}
