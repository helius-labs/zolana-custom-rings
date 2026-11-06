use std::{collections::HashSet, future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{storage_instruction, tracking::TrackingAuthorization};
use custom_ring_sdk::{FitError, FitSigners, RingError, SealRow, TransactionFit};
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use sea_orm::{
    sqlx::error::{Error as SqlxError, ErrorKind},
    DatabaseConnection, DbErr, RuntimeErr, TransactionTrait,
};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions},
    state::{Account, Mint},
};
use spr_client::{compile_message, ComputeBudgetConfig};
use spr_instruction::instruction::CreateAssociatedTokenAccount;
use spr_interface::{SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_PROGRAM_ID};
use thiserror::Error;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayEnrollInputs, RelayId,
    RelayIntent, RelayMergeInputs, RelayProofInputs, RelayProofInputsError, RelayQuote, RelayRail,
    RelayStatus, RelayStep, SubmitRelayRequest, TokenAccountSetupError, ENROLL_COMPUTE_UNITS,
};
use zolana_ring_transaction::ClassifiedInput;

use crate::{
    cosign::{
        CoSignDecision, CoSignFlows, CoSignPolicy, CoSignRefusal, CoSignRequest, CoSignSettlement,
        RefusingCoSigner,
    },
    database::Store,
    error::{redacted, RingRpcError},
    landing::{Attempt, ChainOutcome, ChainSubmit, Landing, LatestBlockhash, Simulation},
    merge_inputs::{HoldInputs, MergeInputs},
    relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
    relay_reservations::{
        Admission, Admit, AttemptEnd, Bind, Claim, ClaimCleanup, Fund, FundOutcome, Lease,
        RelayBudget, RelayReservations, Release, Reservation, SpendCheck,
    },
    relay_submit::{presigned_transaction, CollectedSignature},
    relays::{
        Awaiting, Closing, Committed, PendingCoSign, RelayEvent, RelayRecord, RelayRevision,
        RelayRow, RelayState, RelayStore, SignerAdmission, Transition, TransitionError,
    },
    transfer_debits::deposit_flows,
};

/// Longest quote window, one blockhash lifetime.
pub const QUOTE_SLOTS: u64 = 150;
pub const RELAY_TRACK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PROOFS: usize = 4;
const EXPIRED: &str = "the relay message expired before it landed";

const MANAGED_MERGE_DOMAIN: &[u8] = b"zolana/ring-rpc-managed-merge";
/// One blockhash lifetime for the wallet to sign the stored message.
pub const ABANDONED_AFTER_SLOTS: u64 = QUOTE_SLOTS;
const SWEEP_PAGE: u64 = 16;
const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
const ATTEMPT_KEY_DOMAIN: &[u8] = b"zolana/ring-rpc-attempt";
const DELEGATE_KEY_DOMAIN: &[u8] = b"zolana/ring-rpc-attempt-delegate";

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("the ring is not relayed here")]
    RingNotServed,
    #[error("the quote names another fee payer")]
    QuoteFeePayer,
    #[error("the quote expired")]
    QuoteExpired,
    #[error("the quote outlasts the relay window")]
    QuoteWindow,
    #[error("the proof inputs are invalid because {0}")]
    ProofInputs(#[from] RelayProofInputsError),
    #[error("the proof inputs name another ring")]
    RingMismatch,
    #[error("the proof inputs name another rail")]
    RailMismatch,
    #[error("the owner signature does not sign the proof inputs")]
    OwnerSignature,
    #[error("the transfer is refused because {0}")]
    Proof(String),
    #[error("the co-signer refused the transfer")]
    CoSignRefused,
    #[error("the relay is unknown")]
    UnknownRelay,
    #[error("the relay message awaits no signature from the signer")]
    UnexpectedSigner,
    #[error("the signature does not sign the relay message")]
    SignerSignature,
    #[error("the cluster refused the transaction because {reason}")]
    SendRefused { reason: String },
    #[error(transparent)]
    TokenAccountSetup(#[from] TokenAccountSetupError),
    #[error("the depositor is the relay fee payer")]
    DepositorIsFeePayer,
    #[error("the enrollment is no tag 6 of a ring's tracking registry under its own owner")]
    InvalidEnrollment,
    #[error("the relay budget has no room for the request")]
    Budget,
    #[error("the signer holds its whole share of the relay budget")]
    SignerBudget,
    #[error("the enrollment request does not carry the owner's signature")]
    EnrollmentSignature,
    #[error("the request does not carry the ring delegate's signature")]
    DelegateSignature,
    #[error("the relay spent the allowance the request holds")]
    Allowance,
    #[error("an earlier relay of the request can still land")]
    LiveAttempt,
    #[error("the request does not carry the depositor's signature")]
    DepositorSignature,
    #[error("the relay budget is unset, the operator funds no enrollment or token account")]
    BudgetUnset,
    /// One code per row, a client reads the row from the code alone.
    #[error("the sealed auditor stream does not open under the key the records select, seal under the {row:?} row and sign again")]
    Reseal { row: SealRow },
    #[error(
        "the owner already holds a tracking authorization, only a rotation goes without a proof"
    )]
    AlreadyEnrolled,
    #[error("the RegisterKey proof does not verify for the enrolled key")]
    RegisterKeyProof,
    #[error("the chain simulation refuses the enrollment before any signature because {reason}")]
    EnrollmentRefused { reason: String },
    #[error("the message does not fit one v1 transaction because {reason}")]
    Oversized { reason: String },
}

pub enum RelayPayload {
    Transfer(RelayProofInputs),
    /// A transfer frame of only dummies on the deposit rail.
    Deposit(RelayProofInputs),
    Merge(RelayMergeInputs),
    Enroll(RelayEnrollInputs),
}

/// Admits a ring only while its config names an auditor key the service holds.
#[async_trait]
pub trait ServedRings: Send + Sync {
    async fn check(&self, ring: Address) -> Result<(), RingRpcError>;

    /// The tracking registry the ring pins, the relay pays for no other enrollment.
    async fn tracking_registry(&self, ring: Address) -> Result<Address, RingRpcError>;

    async fn delegate(&self, ring: Address) -> Result<Option<Address>, RingRpcError>;
}

struct NoRings;

#[must_use]
pub struct RelayParts {
    pub store: Store,
    pub prover: Arc<dyn RelayProver>,
    /// The SPP payer every relayed message names.
    pub fee_payer: Keypair,
    pub chain: Arc<dyn ChainSubmit>,
}

/// One stored record per `relayId`.
pub struct Relay {
    store: Store,
    prover: Arc<dyn RelayProver>,
    fee_payer: Keypair,
    chain: Arc<dyn ChainSubmit>,
    rings: Arc<dyn ServedRings>,
    co_signer: Arc<dyn CoSignPolicy>,
    proofs: Semaphore,
    budget: RelayBudget,
}

/// Every signature except the fee payer's is collected.
#[must_use]
pub(crate) struct HeldMerge {
    pub ring: Address,
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
    pub nullifiers: Vec<[u8; 32]>,
}

#[must_use]
struct PrepareCheck<'a> {
    request: &'a PrepareRelayRequest,
    payload: &'a RelayPayload,
    fee_payer: Address,
    slot: u64,
}

struct Checked {
    owner_signature: Option<[u8; 64]>,
    signer: Option<Address>,
    setup: Vec<CreateAssociatedTokenAccount>,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationAfterWrite {
    Keep,
    Free(Signature),
}

enum WriteError {
    /// The commit was never sent.
    Uncommitted(DbErr),
    /// The write may have committed unless the store refused it.
    Committing(DbErr),
}

enum UnstoredWrite<'a> {
    /// Another record holds the relay id.
    Existing,
    Failed(&'a WriteError),
}

#[must_use]
struct FailedWrite<'a> {
    write: UnstoredWrite<'a>,
    co_signature: Option<Signature>,
    stored: Result<Option<&'a RelayState>, &'a DbErr>,
}

#[must_use]
enum Applied {
    /// The caller wrote the next revision.
    Written(RelayRow),
    /// Another writer moved the relay first, the row is the stored one.
    Overtaken(RelayRow),
    Unchanged(RelayRow),
}

impl RelayError {
    pub const fn code(&self) -> i32 {
        match self {
            Self::RingNotServed => -32100,
            Self::QuoteFeePayer => -32101,
            Self::QuoteExpired => -32102,
            Self::QuoteWindow => -32103,
            Self::ProofInputs(_) => -32104,
            Self::RingMismatch => -32105,
            Self::RailMismatch => -32106,
            Self::OwnerSignature => -32107,
            Self::Proof(_) => -32108,
            Self::CoSignRefused => -32109,
            Self::UnknownRelay => -32110,
            Self::UnexpectedSigner => -32111,
            Self::SignerSignature => -32112,
            Self::SendRefused { .. } => -32113,
            Self::TokenAccountSetup(_) => -32200,
            Self::DepositorIsFeePayer => -32201,
            Self::InvalidEnrollment => -32202,
            Self::Budget => -32203,
            Self::SignerBudget => -32204,
            Self::EnrollmentSignature => -32205,
            Self::DelegateSignature => -32206,
            Self::Allowance => -32207,
            Self::LiveAttempt => -32208,
            Self::DepositorSignature => -32209,
            Self::BudgetUnset => -32210,
            Self::Reseal {
                row: SealRow::Narrow,
            } => -32211,
            Self::Reseal { row: SealRow::Wide } => -32212,
            Self::AlreadyEnrolled => -32213,
            Self::RegisterKeyProof => -32214,
            Self::EnrollmentRefused { .. } => -32215,
            Self::Oversized { .. } => -32216,
        }
    }

    /// A refused transfer is the caller's, an unreachable chain or prover is the service's.
    pub(crate) fn proof(error: RingError) -> RingRpcError {
        match error {
            RingError::Client(error) => RingRpcError::Upstream(error),
            RingError::Indexer(refused) => RingRpcError::Refused(refused),
            RingError::ResealRequired { row } => Self::Reseal { row }.into(),
            oversized @ (RingError::TransferTooWide { .. }
            | RingError::TransactionTooLarge { .. }
            | RingError::TooManyAddresses { .. }) => Self::Oversized {
                reason: oversized.to_string(),
            }
            .into(),
            refused => Self::Proof(refused.to_string()).into(),
        }
    }
}

impl From<&RelayError> for ErrorObjectOwned {
    fn from(error: &RelayError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

#[async_trait]
impl ServedRings for NoRings {
    async fn delegate(&self, _ring: Address) -> Result<Option<Address>, RingRpcError> {
        Ok(None)
    }

    async fn check(&self, _ring: Address) -> Result<(), RingRpcError> {
        Err(RelayError::RingNotServed.into())
    }

    async fn tracking_registry(&self, _ring: Address) -> Result<Address, RingRpcError> {
        Err(RelayError::RingNotServed.into())
    }
}

impl Relay {
    pub fn new(parts: RelayParts) -> Self {
        Self {
            store: parts.store,
            prover: parts.prover,
            fee_payer: parts.fee_payer,
            chain: parts.chain,
            rings: Arc::new(NoRings),
            co_signer: Arc::new(RefusingCoSigner),
            proofs: Semaphore::new(MAX_CONCURRENT_PROOFS),
            budget: RelayBudget::default(),
        }
    }

    /// Without it the relay funds no enrollment and no token account.
    #[must_use = "use the updated relay"]
    pub const fn with_budget(mut self, budget: RelayBudget) -> Self {
        self.budget = budget;
        self
    }

    #[must_use = "use the updated relay"]
    pub fn with_co_signer(mut self, co_signer: Arc<dyn CoSignPolicy>) -> Self {
        self.co_signer = co_signer;
        self
    }

    /// Without it the relay refuses every ring.
    #[must_use = "use the updated relay"]
    pub fn with_rings(mut self, rings: Arc<dyn ServedRings>) -> Self {
        self.rings = rings;
        self
    }

    pub fn fee_payer(&self) -> Address {
        self.fee_payer.pubkey()
    }

    fn parties(&self, named: &[spr_indexer_api::SerializablePubkey]) -> RelayParties {
        RelayParties {
            fee_payer: self.fee_payer(),
            co_signers: match named {
                [] => self.co_signer.signer().into_iter().collect(),
                named => named.iter().map(|signer| signer.0).collect(),
            },
        }
    }

    pub async fn quote(&self, request: &GetRelayQuoteRequest) -> Result<RelayQuote, RingRpcError> {
        self.rings.check(request.ring.0).await?;
        Ok(RelayQuote {
            fee_payer: self.fee_payer().into(),
            valid_until_slot: self.chain.slot().await? + QUOTE_SLOTS,
        })
    }

    /// A repeated request returns the stored relay, it proves nothing again.
    pub async fn prepare(&self, request: &PrepareRelayRequest) -> Result<RelayStep, RingRpcError> {
        let relay_id = request
            .relay_id()
            .map_err(|_| RingRpcError::StateUnavailable)?;
        if let Some(step) = self.stored(&relay_id).await? {
            return Ok(step);
        }
        let ring = request.ring.0;
        self.rings.check(ring).await?;
        let payload = RelayPayload::decode(&request.intent).map_err(RelayError::from)?;
        if let RelayPayload::Enroll(enrollment) = &payload {
            // Every enrollment spends the operator's lamports, a disabled budget refuses before the
            // admission and the proof check.
            self.require_budget()?;
            if enrollment.tracking_registry != self.rings.tracking_registry(ring).await? {
                return Err(RelayError::InvalidEnrollment.into());
            }
        }
        if let RelayPayload::Transfer(RelayProofInputs {
            rail: RelayRail::Delegate { delegate, .. },
            ..
        }) = &payload
        {
            if self.rings.delegate(ring).await? != Some(*delegate) {
                return Err(RelayError::DelegateSignature.into());
            }
        }
        let parties = self.parties(&request.co_signers);
        let Checked {
            owner_signature,
            signer,
            setup,
        } = PrepareCheck {
            request,
            payload: &payload,
            fee_payer: parties.fee_payer,
            slot: self.chain.slot().await?,
        }
        .check()?;
        // 1. Only a verified signature reaches the store, a stranger leaves no row and no lease.
        let claim = match signer {
            Some(signer) => Some(
                self.admit(Admit {
                    key: attempt_key(request)?,
                    relay_id: &relay_id,
                    signer,
                    slot: self.chain.slot().await?,
                })
                .await?,
            ),
            None => None,
        };
        let lease = claim.as_ref().map(|claim| claim.lease);
        let staged = async {
            let proven = match &payload {
                // The wallet proved its seal, the relay only pays.
                RelayPayload::Enroll(enrollment) => {
                    self.prover.check_enrollment(enrollment).await?;
                    let proven = enrollment_step(enrollment, parties.fee_payer);
                    self.preflight(&proven).await?;
                    proven
                }
                _ => {
                    let _proof = self
                        .proofs
                        .try_acquire()
                        .map_err(|_| RingRpcError::RelayProverBusy)?;
                    self.prover
                        .prove(RelayProofRequest {
                            ring,
                            parties: parties.clone(),
                            payload: &payload,
                            owner_signature,
                        })
                        .await?
                }
            };
            self.stage(ProvenStep {
                relay_id,
                payload,
                setup,
                proven,
                parties,
                lease,
            })
            .await
        };
        self.under_lease(lease, staged).await
    }

    /// One caller holds the lease, a concurrent duplicate proves and pays for nothing.
    async fn admit(&self, admit: Admit<'_>) -> Result<Claim, RingRpcError> {
        let Admit {
            key,
            relay_id,
            signer,
            slot,
        } = admit;
        for _ in 0..2 {
            let admission = self
                .reservations()
                .admit(Admit {
                    key,
                    relay_id,
                    signer,
                    slot,
                })
                .await?;
            match admission {
                Admission::Claimed(claim) => return Ok(*claim),
                Admission::Busy => return Err(RingRpcError::RelayProverBusy),
                // A bound message may still land, the retry refuses until settlement or proven expiry
                // frees the key.
                Admission::Bound(held) => self.settle_earlier_attempt(&held).await?,
            }
        }
        Err(RingRpcError::RelayProverBusy)
    }

    /// Ok only once the message cannot land and its row is settled or left to the sweep.
    async fn settle_earlier_attempt(&self, held: &Reservation) -> Result<(), RingRpcError> {
        let row = self.row(&held.relay_id).await?;
        let RelayRow { record, .. } = self.advance(&held.relay_id, row).await?;
        match record.state {
            RelayState::AwaitingSignature(_) | RelayState::Sent(_) => {
                Err(RelayError::LiveAttempt.into())
            }
            RelayState::Confirmed { .. } => self.release_landed(held, &record.message).await,
            RelayState::Failed { .. } => self.release(held).await,
        }
    }

    /// A failure yields at once, a lost yield only delays a retry until the lease lapses.
    async fn under_lease<T>(
        &self,
        lease: Option<Lease>,
        work: impl Future<Output = Result<T, RingRpcError>>,
    ) -> Result<T, RingRpcError> {
        let result = work.await;
        if result.is_err() {
            if let Some(lease) = lease {
                if let Err(error) = self.reservations().yield_lease(&lease).await {
                    warn!("relay lease did not yield {}", redacted(&error));
                }
            }
        }
        result
    }

    /// A held reservation resumes the same request, its nonce already passed.
    pub(crate) async fn holds(&self, relay_id: &RelayId) -> Result<bool, RingRpcError> {
        Ok(self.reservations().by_relay(relay_id).await?.is_some())
    }

    fn require_budget(&self) -> Result<(), RelayError> {
        match self.budget.is_set() {
            true => Ok(()),
            false => Err(RelayError::BudgetUnset),
        }
    }

    async fn fund(&self, fund: Fund) -> Result<Reservation, RingRpcError> {
        self.require_budget()?;
        match self.reservations().fund(fund).await? {
            FundOutcome::Held(held) => Ok(*held),
            FundOutcome::OverTotal => Err(RelayError::Budget.into()),
            FundOutcome::OverSigner => Err(RelayError::SignerBudget.into()),
            FundOutcome::LeaseLost => Err(RingRpcError::RelayProverBusy),
        }
    }

    fn reservations(&self) -> RelayReservations<'_, DatabaseConnection> {
        RelayReservations::new(self.store.connection())
    }

    pub(crate) async fn stored(
        &self,
        relay_id: &RelayId,
    ) -> Result<Option<RelayStep>, RingRpcError> {
        Ok(self
            .relays()
            .get(relay_id)
            .await?
            .map(|row| step(relay_id.clone(), &row.record)))
    }

    /// The source signs nothing, the delegate signs the returned message.
    pub(crate) async fn prepare_delegated(
        &self,
        relay_id: RelayId,
        seal: DelegateSeal<'_>,
    ) -> Result<RelayStep, RingRpcError> {
        let ring = seal.ring;
        let delegate = seal.delegate;
        let allowed = seal.allowed;
        self.rings.check(ring).await?;
        let parties = self.parties(&[]);
        let claim = self
            .admit(Admit {
                key: delegate_key(&relay_id),
                relay_id: &relay_id,
                signer: delegate,
                slot: self.chain.slot().await?,
            })
            .await?;
        let lease = claim.lease;
        let staged = async {
            let (payload, proven) = {
                let _proof = self
                    .proofs
                    .try_acquire()
                    .map_err(|_| RingRpcError::RelayProverBusy)?;
                let sealed = self.prover.seal_delegate(seal, parties.clone()).await?;
                // Sealed inputs answer to the resolved openings before proving, compact padding
                // publishes no position.
                allowed.check_inputs(
                    sealed
                        .inputs
                        .iter()
                        .filter(|input| !input.is_compact())
                        .map(|input| (input.input_class(), &input.nullifier)),
                )?;
                let payload = RelayPayload::Transfer(sealed);
                let proven = self
                    .prover
                    .prove(RelayProofRequest {
                        ring,
                        parties: parties.clone(),
                        payload: &payload,
                        owner_signature: None,
                    })
                    .await?;
                (payload, proven)
            };
            self.stage(ProvenStep {
                relay_id,
                payload,
                setup: Vec::new(),
                proven,
                parties,
                lease: Some(lease),
            })
            .await
        };
        self.under_lease(Some(lease), staged).await
    }

    /// A relay awaiting no signer is co-signed before the record lands.
    async fn stage(&self, proven: ProvenStep) -> Result<RelayStep, RingRpcError> {
        let ProvenStep {
            relay_id,
            payload,
            setup,
            proven,
            parties,
            lease,
        } = proven;
        // 1. Every lamport the message can cost is held before the send, landed rent stays charged.
        let MissingSetup {
            mut instructions,
            rent: setup_rent,
        } = self.missing_setup(&setup).await?;
        let landing_rent = match self.created_rent(&payload).await? {
            Some(created) => Some(setup_rent.saturating_add(created)),
            None => (setup_rent > 0).then_some(setup_rent),
        }
        .map(|rent| rent.saturating_add(proven.tree_fees));
        self.reserve(RelaySpend {
            proven: &proven,
            lease,
            setup: &instructions,
            landing_rent,
        })
        .await?;
        // 2. The message compiles under a fresh blockhash, its fit was checked with the same setup.
        let fee_payer = self.fee_payer();
        let LatestBlockhash {
            blockhash,
            last_valid_block_height,
        } = self.chain.latest_blockhash().await?;
        instructions.push(proven.instruction.clone());
        let message = compile_message(&fee_payer, &instructions, blockhash, proven.budget)?;
        let awaiting = CoSignStep {
            payload: &payload,
            proven,
            named: &parties.co_signers,
        }
        .plan(self.co_signer.as_ref())?;
        // The decoded secrets zeroize before the store and send awaits.
        drop(payload);
        let record = RelayRecord {
            state: self.open(&message, awaiting).await?,
            message,
            last_valid_block_height,
        };
        // 3. The record and the row's binding commit before any send, the sweep and a retry read the live
        // message from here on.
        let stored = self
            .store_attempt(StagedAttempt {
                lease,
                relay_id: &relay_id,
                record: &record,
                slot: self.chain.slot().await?,
            })
            .await;
        let write = match &stored {
            Ok(AttemptWrite::Stored) => None,
            Ok(AttemptWrite::Existing | AttemptWrite::Refused(_)) => Some(UnstoredWrite::Existing),
            Err(error) => Some(UnstoredWrite::Failed(error)),
        };
        // A kept reservation resumes on a retry, the sweep releases it otherwise.
        if let Some(write) = write {
            let read = self.relays().get(&relay_id).await;
            self.free_unless_stored(FailedWrite {
                write,
                co_signature: record.state.co_signature(),
                stored: stored_state(&read),
            })
            .await?;
            if let AttemptWrite::Refused(refused) = stored? {
                return Err(refused);
            }
            return Ok(step(
                relay_id,
                &read?.ok_or(RingRpcError::StateUnavailable)?.record,
            ));
        }
        // 4. A crash past the commit leaves `Sent` for the tracker, the same signature resends.
        let row = RelayRow {
            revision: RelayRevision::FIRST,
            record,
        };
        let row = self.first_send(&relay_id, row).await?;
        self.release_failed(&relay_id, &row.record.state).await?;
        Ok(step(relay_id, &row.record))
    }

    /// The record and the row's binding commit together, a lost lease stores no message.
    async fn store_attempt(&self, staged: StagedAttempt<'_>) -> Result<AttemptWrite, WriteError> {
        let StagedAttempt {
            lease,
            relay_id,
            record,
            slot,
        } = staged;
        let Some(lease) = lease else {
            return Ok(
                match self
                    .relays()
                    .insert(relay_id, record)
                    .await
                    .map_err(WriteError::Committing)?
                {
                    true => AttemptWrite::Stored,
                    false => AttemptWrite::Existing,
                },
            );
        };
        let transaction = self
            .store
            .connection()
            .begin()
            .await
            .map_err(WriteError::Uncommitted)?;
        let staged = async {
            if !RelayStore::new(&transaction)
                .insert(relay_id, record)
                .await?
            {
                return Ok(AttemptWrite::Existing);
            }
            let bound = RelayReservations::new(&transaction)
                .bind(Bind {
                    lease,
                    relay_id,
                    fee: message_fee(&record.message),
                    slot,
                })
                .await?;
            Ok(match bound {
                SpendCheck::Accepted => AttemptWrite::Stored,
                SpendCheck::OverAllowance => AttemptWrite::Refused(RelayError::Allowance.into()),
                SpendCheck::LeaseLost => AttemptWrite::Refused(RingRpcError::RelayProverBusy),
            })
        }
        .await
        .map_err(WriteError::Uncommitted)?;
        match staged {
            AttemptWrite::Stored => transaction.commit().await.map_err(WriteError::Committing)?,
            _ => transaction
                .rollback()
                .await
                .map_err(WriteError::Uncommitted)?,
        }
        Ok(staged)
    }

    /// A message past one transaction with its setup refuses ahead of any charge.
    async fn reserve(&self, spend: RelaySpend<'_>) -> Result<(), RingRpcError> {
        let RelaySpend {
            proven,
            lease,
            setup,
            landing_rent,
        } = spend;
        let fee_payer = self.fee_payer();
        TransactionFit::of(
            &proven.instruction,
            FitSigners::new(fee_payer).with_setup(setup),
            proven.budget,
        )
        .map(drop)
        .map_err(refused_fit)?;
        let Some(landing_rent) = landing_rent else {
            return Ok(());
        };
        let fee = message_fee_of(&proven.instruction, fee_payer);
        self.fund(Fund {
            lease: lease.ok_or(RelayError::OwnerSignature)?,
            lamports: landing_rent.saturating_add(fee),
            fee_allowance: fee,
            landing_rent,
            budget: self.budget,
        })
        .await?;
        Ok(())
    }

    /// SPP verifies the creation proof only on chain, a simulation refuses a bad one before any
    /// signature or charge.
    async fn preflight(&self, proven: &ProvenRelay) -> Result<(), RingRpcError> {
        let LatestBlockhash { blockhash, .. } = self.chain.latest_blockhash().await?;
        let message = compile_message(
            &self.fee_payer(),
            core::slice::from_ref(&proven.instruction),
            blockhash,
            proven.budget,
        )?;
        match self.chain.simulate(&message).await? {
            Simulation::Passed => Ok(()),
            Simulation::Refused { reason } => Err(RelayError::EnrollmentRefused { reason }.into()),
        }
    }

    /// Only a missing account takes a create, the row reserves its rent alone.
    async fn missing_setup(
        &self,
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<MissingSetup, RingRpcError> {
        let mut instructions = Vec::new();
        let mut rent = 0u64;
        for create in setup {
            if self.chain.account_data(create.address()).await?.is_some() {
                continue;
            }
            instructions.push(create.instruction());
            let data_len = match create.token_program.to_bytes() {
                SPL_TOKEN_PROGRAM_ID => SPL_TOKEN_ACCOUNT_LEN,
                _ => token_2022_account_len(
                    &self
                        .chain
                        .account_data(create.mint)
                        .await?
                        .ok_or(RingRpcError::StateUnavailable)?,
                )?,
            };
            rent = rent.saturating_add(self.chain.rent_exempt_lamports(data_len).await?);
        }
        Ok(MissingSetup { instructions, rent })
    }

    /// Every enrollment holds its fee, only a first one reserves rent, no instruction closes the
    /// account.
    async fn created_rent(&self, payload: &RelayPayload) -> Result<Option<u64>, RingRpcError> {
        let RelayPayload::Enroll(enrollment) = payload else {
            return Ok(None);
        };
        let (authorization, _) =
            TrackingAuthorization::find_address(&enrollment.tracking_registry, &enrollment.owner);
        // The same read as the proof check, an account with no data still takes the create.
        let enrolled = self
            .chain
            .account_data(authorization)
            .await?
            .is_some_and(|data| !data.is_empty());
        Ok(Some(match enrolled {
            true => 0,
            false => {
                self.chain
                    .rent_exempt_lamports(TrackingAuthorization::SIZE)
                    .await?
            }
        }))
    }

    /// Ends a row whose attempt can no longer land, a selection a retry or another closer overtook
    /// changes nothing.
    async fn release(&self, held: &Reservation) -> Result<(), RingRpcError> {
        let slot = self.chain.slot().await?;
        let Some(claim) = self
            .reservations()
            .claim_cleanup(ClaimCleanup {
                held,
                slot,
                abandoned_before: slot.saturating_sub(ABANDONED_AFTER_SLOTS),
            })
            .await?
        else {
            return Ok(());
        };
        let Claim { lease, held } = claim;
        // The charge returns, every fee the chain took stays in the total.
        let released = async {
            Ok(self
                .reservations()
                .release(Release {
                    key: &lease.key,
                    relay_id: &held.relay_id,
                    end: AttemptEnd::Unlanded,
                })
                .await?)
        };
        self.under_lease(Some(lease), released).await
    }

    /// Only the message fee and the landing rent stay spent.
    async fn release_landed(
        &self,
        held: &Reservation,
        message: &VersionedMessage,
    ) -> Result<(), RingRpcError> {
        let lamports = held.landing_rent.saturating_add(message_fee(message));
        Ok(self
            .reservations()
            .release(Release {
                key: &held.key,
                relay_id: &held.relay_id,
                end: AttemptEnd::Landed { lamports },
            })
            .await?)
    }

    /// Past the window nothing of a live relay is left, a wallet that never signed let the blockhash lapse.
    pub async fn sweep_abandoned(&self) -> Result<(), RingRpcError> {
        let slot = self.chain.slot().await?;
        let before = slot.saturating_sub(ABANDONED_AFTER_SLOTS);
        let abandoned = self
            .reservations()
            .abandoned(before, slot, SWEEP_PAGE)
            .await?;
        for held in abandoned {
            if let Err(error) = self.sweep_row(&held).await {
                warn!("relay reservation did not sweep {}", redacted(&error));
            }
        }
        Ok(())
    }

    async fn sweep_row(&self, held: &Reservation) -> Result<(), RingRpcError> {
        // 1. The relay advances first, a release acts only on the stored final state.
        let record = match self.relays().get(&held.relay_id).await? {
            None => None,
            Some(row) => Some(self.advance(&held.relay_id, row).await?.record),
        };
        // 2. A release waits on a final state, and the cleanup claim already excludes another closer.
        match record {
            Some(RelayRecord {
                state: RelayState::Confirmed { .. },
                message,
                ..
            }) => self.release_landed(held, &message).await,
            None
            | Some(RelayRecord {
                state: RelayState::Failed { .. },
                ..
            }) => self.release(held).await,
            Some(_) => Ok(()),
        }
    }

    pub(crate) async fn send_merge(&self, merge: HeldMerge) -> Result<RelayId, RingRpcError> {
        let relay_id = RelayId(
            <[u8; 32]>::from(
                Sha256::new()
                    .chain_update(MANAGED_MERGE_DOMAIN)
                    .chain_update(merge.message.serialize())
                    .finalize(),
            )
            .into(),
        );
        // A merge awaits no wallet signer and demands no co-signer.
        let closing = Closing {
            co_signature: None,
            fee_payer: self.fee_payer_signs(&merge.message),
        };
        let unsigned = Awaiting {
            signatures: Vec::new(),
            awaiting: Vec::new(),
            co_sign: None,
        };
        let record = RelayRecord {
            state: RelayState::open(unsigned, Some(closing))?,
            message: merge.message,
            last_valid_block_height: merge.last_valid_block_height,
        };
        let hold = HoldInputs {
            ring: &merge.ring,
            relay_id: &relay_id,
            nullifiers: &merge.nullifiers,
        };
        match self.store_merge(&record, hold).await {
            Ok(true) => {}
            // The stored relay keeps the co-signer reservation.
            Ok(false) => return Ok(relay_id),
            Err(error) => {
                let stored = self.relays().get(&relay_id).await;
                self.free_unless_stored(FailedWrite {
                    write: UnstoredWrite::Failed(&error),
                    co_signature: record.state.co_signature(),
                    stored: stored_state(&stored),
                })
                .await?;
                return Err(error.into());
            }
        }
        let row = RelayRow {
            revision: RelayRevision::FIRST,
            record,
        };
        self.first_send(&relay_id, row).await?;
        Ok(relay_id)
    }

    /// `false` when the relay is stored already.
    async fn store_merge(
        &self,
        record: &RelayRecord,
        hold: HoldInputs<'_>,
    ) -> Result<bool, WriteError> {
        let transaction = self
            .store
            .connection()
            .begin()
            .await
            .map_err(WriteError::Uncommitted)?;
        let staged = async {
            if !RelayStore::new(&transaction)
                .insert(hold.relay_id, record)
                .await?
            {
                return Ok(false);
            }
            MergeInputs { conn: &transaction }.hold(hold).await?;
            Ok(true)
        }
        .await
        .map_err(WriteError::Uncommitted)?;
        if staged {
            transaction.commit().await.map_err(WriteError::Committing)?;
        }
        Ok(staged)
    }

    pub(crate) fn merge_inputs(&self) -> MergeInputs<'_, DatabaseConnection> {
        MergeInputs {
            conn: self.store.connection(),
        }
    }

    /// Each submission applies to the newest revision, only the writer of `Sent` makes the first send.
    pub async fn submit(&self, request: &SubmitRelayRequest) -> Result<RelayStatus, RingRpcError> {
        let relay_id = &request.relay_id;
        let signature = CollectedSignature {
            signer: request.signer.0,
            signature: request.signature.0,
        };
        let mut row = self.row(relay_id).await?;
        // 1. Each round reads one revision, a relay moves once per signer and once to its end.
        while let RelayState::AwaitingSignature(awaiting) = &row.record.state {
            let last = match awaiting.admit(signature.signer)? {
                SignerAdmission::Collected => break,
                SignerAdmission::Awaited { last } => last,
            };
            if !signature
                .signature
                .verify(signature.signer.as_ref(), &row.record.message.serialize())
            {
                return Err(RelayError::SignerSignature.into());
            }
            // 2. The last signature closes the relay, the co-signer reserves its allowance before the write.
            let closing = match last {
                true => Some(
                    self.closing(&row.record.message, awaiting.co_sign.as_ref())
                        .await?,
                ),
                false => None,
            };
            let event = RelayEvent::Signed {
                signature,
                closing: closing.map(Box::new),
            };
            row = match self.transition(relay_id, row, event).await? {
                Applied::Written(written) => {
                    row = self.first_send(relay_id, written).await?;
                    break;
                }
                Applied::Overtaken(newer) => newer,
                Applied::Unchanged(same) => {
                    row = same;
                    break;
                }
            };
        }
        // 3. A stored failure frees the allowance an overtaken round decided again.
        let row = self.advance(relay_id, row).await?;
        self.release_failed(relay_id, &row.record.state).await?;
        Ok(relay_status(&row.record.state))
    }

    pub async fn status(
        &self,
        request: &GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingRpcError> {
        let row = self.row(&request.relay_id).await?;
        let row = self.advance(&request.relay_id, row).await?;
        self.release_failed(&request.relay_id, &row.record.state)
            .await?;
        Ok(relay_status(&row.record.state))
    }

    /// A failed release stays for the next sweep.
    async fn release_failed(
        &self,
        relay_id: &RelayId,
        state: &RelayState,
    ) -> Result<(), RingRpcError> {
        if matches!(state, RelayState::Failed { .. }) {
            if let Some(held) = self.reservations().by_relay(relay_id).await? {
                if let Err(error) = self.release(&held).await {
                    warn!("relay reservation did not release {}", redacted(&error));
                }
            }
        }
        Ok(())
    }

    /// A restart resumes every relay it left pending.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        loop {
            if let Err(error) = self.track().await {
                warn!("relay tracking failed {}", redacted(&error));
            }
            if let Err(error) = self.sweep_abandoned().await {
                warn!("relay sweep failed {}", redacted(&error));
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// One pass over the pending relays.
    pub async fn track(&self) -> Result<(), RingRpcError> {
        for relay_id in self.relays().pending().await? {
            let tracked = async {
                let row = self.row(&relay_id).await?;
                let row = self.advance(&relay_id, row).await?;
                self.resend(&row.record).await?;
                self.release_failed(&relay_id, &row.record.state).await
            }
            .await;
            if let Err(error) = tracked {
                warn!("relay {} did not advance {}", relay_id.0, redacted(&error));
            }
        }
        Ok(())
    }

    fn relays(&self) -> RelayStore<'_, DatabaseConnection> {
        RelayStore::new(self.store.connection())
    }

    async fn row(&self, relay_id: &RelayId) -> Result<RelayRow, RingRpcError> {
        self.relays()
            .get(relay_id)
            .await?
            .ok_or_else(|| RelayError::UnknownRelay.into())
    }

    /// A relay awaiting no wallet signer closes before it is stored.
    async fn open(
        &self,
        message: &VersionedMessage,
        awaiting: Awaiting,
    ) -> Result<RelayState, RingRpcError> {
        let closing = match awaiting.awaiting.is_empty() {
            true => Some(self.closing(message, awaiting.co_sign.as_ref()).await?),
            false => None,
        };
        Ok(RelayState::open(awaiting, closing)?)
    }

    /// The fee payer signs only after the co-sign decision, every later send repeats both signatures.
    async fn closing(
        &self,
        message: &VersionedMessage,
        co_sign: Option<&PendingCoSign>,
    ) -> Result<Closing, RingRpcError> {
        let co_signature = match co_sign {
            Some(pending) => Some(self.co_sign(message, pending).await?),
            None => None,
        };
        Ok(Closing {
            co_signature,
            fee_payer: self.fee_payer_signs(message),
        })
    }

    /// A refusal stores nothing, a repeat of a held decision reserves nothing more.
    async fn co_sign(
        &self,
        message: &VersionedMessage,
        pending: &PendingCoSign,
    ) -> Result<CollectedSignature, RingRpcError> {
        let request = CoSignRequest {
            ring: pending.ring,
            message: message.clone(),
            flows: pending.flows.clone(),
        };
        match self.co_signer.decide(&request).await? {
            CoSignDecision::Signed(signature) => Ok(CollectedSignature {
                signer: pending.signer,
                signature,
            }),
            CoSignDecision::Refused(
                CoSignRefusal::Disabled | CoSignRefusal::OverLimit | CoSignRefusal::NotApproved,
            ) => Err(RelayError::CoSignRefused.into()),
        }
    }

    fn fee_payer_signs(&self, message: &VersionedMessage) -> CollectedSignature {
        CollectedSignature {
            signer: self.fee_payer(),
            signature: self.fee_payer.sign_message(&message.serialize()),
        }
    }

    async fn first_send(
        &self,
        relay_id: &RelayId,
        row: RelayRow,
    ) -> Result<RelayRow, RingRpcError> {
        match self.resend(&row.record).await {
            Ok(()) => Ok(row),
            Err(RingRpcError::Relay(RelayError::SendRefused { .. })) => {
                self.advance(relay_id, row).await
            }
            Err(error) => Err(error),
        }
    }

    /// A refusal leaves the relay open, an earlier send can still land.
    async fn resend(&self, record: &RelayRecord) -> Result<(), RingRpcError> {
        match &record.state {
            RelayState::Sent(sent) => {
                let transaction = presigned_transaction(&record.message, &sent.signatures)?;
                self.chain.send(&transaction).await
            }
            _ => Ok(()),
        }
    }

    /// The chain decides the next event of a sent relay, the block height alone expires an unsigned one.
    async fn advance(&self, relay_id: &RelayId, row: RelayRow) -> Result<RelayRow, RingRpcError> {
        let last_valid_block_height = row.record.last_valid_block_height;
        let event = match &row.record.state {
            RelayState::AwaitingSignature(_)
                if self.chain.block_height().await? > last_valid_block_height =>
            {
                RelayEvent::Dropped {
                    reason: EXPIRED.to_owned(),
                }
            }
            RelayState::Sent(sent) => {
                let attempt = Attempt {
                    signature: sent.signature,
                    last_valid_block_height,
                };
                match attempt.landing(self.chain.as_ref()).await? {
                    Landing::Pending => return Ok(row),
                    Landing::Landed(outcome) => landed(outcome),
                    Landing::Expired => RelayEvent::Dropped {
                        reason: EXPIRED.to_owned(),
                    },
                }
            }
            // A failed settlement retries here, freeing twice frees nothing more.
            RelayState::Failed { co_signature, .. } => {
                self.settle(*co_signature, CoSignSettlement::Failed).await?;
                return Ok(row);
            }
            RelayState::AwaitingSignature(_) | RelayState::Confirmed { .. } => return Ok(row),
        };
        Ok(self.transition(relay_id, row, event).await?.row())
    }

    /// Commits over the revision `row` was read at, only the winning writer settles what the new state
    /// ends.
    async fn transition(
        &self,
        relay_id: &RelayId,
        row: RelayRow,
        event: RelayEvent,
    ) -> Result<Applied, RingRpcError> {
        // 1. A failure the chain charged commits its fee with the failure, a crash cannot count it twice.
        let landed_fee =
            matches!(event, RelayEvent::Reverted { .. }).then(|| message_fee(&row.record.message));
        let next = match row.record.state.apply(event)? {
            Transition::Unchanged => return Ok(Applied::Unchanged(row)),
            Transition::Next(next) => next,
        };
        // 2. A lost closing write frees its co-sign unless the stored relay holds the same co-signature.
        let reserved = match row.record.state {
            RelayState::AwaitingSignature(_) => next.co_signature(),
            _ => None,
        };
        // 3. Confirmed usage settles before the write, a crash between them settles again from `Sent`.
        if let RelayState::Confirmed { co_signature, .. } = &next {
            self.settle(*co_signature, CoSignSettlement::Confirmed)
                .await?;
        }
        let record = RelayRecord {
            state: next,
            ..row.record
        };
        let written = self
            .commit(CommitRelay {
                relay_id,
                expected: row.revision,
                record: &record,
                landed_fee,
            })
            .await;
        let revision = match written {
            Ok(Committed::Written(revision)) => revision,
            Ok(Committed::Stale) => {
                let stored = self.relays().get(relay_id).await;
                self.free_unless_stored(FailedWrite {
                    write: UnstoredWrite::Existing,
                    co_signature: reserved,
                    stored: stored_state(&stored),
                })
                .await?;
                let newer = stored?.ok_or(RelayError::UnknownRelay)?;
                return Ok(Applied::Overtaken(newer));
            }
            Err(error) => {
                let stored = self.relays().get(relay_id).await;
                self.free_unless_stored(FailedWrite {
                    write: UnstoredWrite::Failed(&error),
                    co_signature: reserved,
                    stored: stored_state(&stored),
                })
                .await?;
                return Err(error.into());
            }
        };
        // 4. The landed message keeps its fee and setup rent, a failed one frees its allowance.
        match &record.state {
            RelayState::Confirmed { .. } => {
                if let Some(held) = self.reservations().by_relay(relay_id).await? {
                    self.release_landed(&held, &record.message).await?;
                }
            }
            RelayState::Failed { co_signature, .. } => {
                self.settle(*co_signature, CoSignSettlement::Failed).await?;
            }
            RelayState::AwaitingSignature(_) | RelayState::Sent(_) => {}
        }
        Ok(Applied::Written(RelayRow { revision, record }))
    }

    /// A stale revision writes nothing, and a charged failure takes its fee only with the winning write.
    async fn commit(&self, commit: CommitRelay<'_>) -> Result<Committed, WriteError> {
        let CommitRelay {
            relay_id,
            expected,
            record,
            landed_fee,
        } = commit;
        let Some(fee) = landed_fee else {
            return self
                .relays()
                .commit(relay_id, expected, record)
                .await
                .map_err(WriteError::Committing);
        };
        let transaction = self
            .store
            .connection()
            .begin()
            .await
            .map_err(WriteError::Uncommitted)?;
        let staged = async {
            let committed = RelayStore::new(&transaction)
                .commit(relay_id, expected, record)
                .await?;
            if let Committed::Written(_) = committed {
                RelayReservations::new(&transaction)
                    .charge_landed(relay_id, fee)
                    .await?;
            }
            Ok::<_, DbErr>(committed)
        }
        .await
        .map_err(WriteError::Uncommitted)?;
        match staged {
            Committed::Written(_) => transaction.commit().await.map_err(WriteError::Committing)?,
            Committed::Stale => transaction
                .rollback()
                .await
                .map_err(WriteError::Uncommitted)?,
        }
        Ok(staged)
    }

    async fn free_unless_stored(&self, failed: FailedWrite<'_>) -> Result<(), RingRpcError> {
        match failed.reservation() {
            ReservationAfterWrite::Free(co_signature) => {
                self.co_signer
                    .settle(CoSignSettlement::Failed(co_signature))
                    .await
            }
            ReservationAfterWrite::Keep => Ok(()),
        }
    }

    async fn settle(
        &self,
        co_signature: Option<Signature>,
        settlement: fn(Signature) -> CoSignSettlement,
    ) -> Result<(), RingRpcError> {
        match co_signature {
            Some(signature) => self.co_signer.settle(settlement(signature)).await,
            None => Ok(()),
        }
    }
}

struct ProvenStep {
    relay_id: RelayId,
    payload: RelayPayload,
    setup: Vec<CreateAssociatedTokenAccount>,
    proven: ProvenRelay,
    parties: RelayParties,
    /// Held when a wallet party's signature was verified, that party answers for the reservation.
    lease: Option<Lease>,
}

struct RelaySpend<'a> {
    proven: &'a ProvenRelay,
    lease: Option<Lease>,
    setup: &'a [Instruction],
    /// `None` holds nothing, `Some(0)` still holds its fee, `Some` counts the tree fees.
    landing_rent: Option<u64>,
}

struct StagedAttempt<'a> {
    lease: Option<Lease>,
    relay_id: &'a RelayId,
    record: &'a RelayRecord,
    slot: u64,
}

enum AttemptWrite {
    Stored,
    /// Another record holds the relay id.
    Existing,
    Refused(RingRpcError),
}

struct MissingSetup {
    instructions: Vec<Instruction>,
    rent: u64,
}

struct CoSignStep<'a> {
    payload: &'a RelayPayload,
    proven: ProvenRelay,
    /// The prover names none outside it.
    named: &'a [Address],
}

#[must_use]
struct CommitRelay<'a> {
    relay_id: &'a RelayId,
    expected: RelayRevision,
    record: &'a RelayRecord,
    /// The fee of a message that landed and failed.
    landed_fee: Option<u64>,
}

impl CoSignStep<'_> {
    /// The service signs its own place in the run, each other approver signs the message.
    fn plan(self, co_signer: &dyn CoSignPolicy) -> Result<Awaiting, RingRpcError> {
        let Self {
            payload,
            proven,
            named,
        } = self;
        if !proven
            .co_signers
            .iter()
            .all(|signer| named.contains(signer))
        {
            return Err(RelayError::CoSignRefused.into());
        }
        let own = co_signer
            .signer()
            .filter(|signer| proven.co_signers.contains(signer));
        let co_sign = own
            .map(|signer| {
                Ok::<_, RingRpcError>(PendingCoSign {
                    signer,
                    ring: payload.ring_program_id(),
                    flows: payload.flows()?,
                })
            })
            .transpose()?;
        let others = proven
            .co_signers
            .into_iter()
            .filter(|signer| Some(*signer) != own);
        Ok(Awaiting {
            signatures: Vec::new(),
            awaiting: proven.signers.into_iter().chain(others).collect(),
            co_sign,
        })
    }
}

impl FailedWrite<'_> {
    /// An unknown commit outcome or an unreadable store keeps the reservation, a stored relay can still land.
    fn reservation(self) -> ReservationAfterWrite {
        let Some(co_signature) = self.co_signature else {
            return ReservationAfterWrite::Keep;
        };
        if let UnstoredWrite::Failed(WriteError::Committing(error)) = self.write {
            if !refused(error) {
                return ReservationAfterWrite::Keep;
            }
        }
        match self.stored {
            Ok(Some(state)) if state.co_signature() == Some(co_signature) => {
                ReservationAfterWrite::Keep
            }
            Ok(_) => ReservationAfterWrite::Free(co_signature),
            Err(_) => ReservationAfterWrite::Keep,
        }
    }
}

impl Applied {
    fn row(self) -> RelayRow {
        match self {
            Self::Written(row) | Self::Overtaken(row) | Self::Unchanged(row) => row,
        }
    }
}

impl From<TransitionError> for RingRpcError {
    fn from(error: TransitionError) -> Self {
        match error {
            TransitionError::UnexpectedSigner => RelayError::UnexpectedSigner.into(),
            TransitionError::Closing | TransitionError::Unsent => Self::StateUnavailable,
        }
    }
}

impl From<WriteError> for RingRpcError {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Uncommitted(error) | WriteError::Committing(error) => error.into(),
        }
    }
}

impl PrepareCheck<'_> {
    fn check(self) -> Result<Checked, RingRpcError> {
        let Self {
            request,
            payload,
            fee_payer,
            slot,
        } = self;
        let quote = &request.quote;
        if quote.fee_payer.0 != fee_payer {
            return Err(RelayError::QuoteFeePayer.into());
        }
        if quote.valid_until_slot < slot {
            return Err(RelayError::QuoteExpired.into());
        }
        if quote.valid_until_slot > slot.saturating_add(QUOTE_SLOTS) {
            return Err(RelayError::QuoteWindow.into());
        }
        if payload.ring_program_id() != request.ring.0 {
            return Err(RelayError::RingMismatch.into());
        }
        let unsigned = Checked {
            owner_signature: None,
            signer: None,
            setup: Vec::new(),
        };
        let proof_inputs = match payload {
            RelayPayload::Transfer(proof_inputs) => proof_inputs,
            RelayPayload::Deposit(deposit) => {
                if !matches!(deposit.rail, RelayRail::Deposit { .. }) {
                    return Err(RelayError::RailMismatch.into());
                }
                // One funder signs every leg, the request digest spends the relay's proving.
                let mut funders = deposit.deposit_funders();
                let depositor = funders.next().ok_or(RelayError::DepositorSignature)?;
                if funders.any(|funder| funder != depositor) {
                    return Err(RelayError::DepositorSignature.into());
                }
                if depositor == fee_payer {
                    return Err(RelayError::DepositorIsFeePayer.into());
                }
                let RelayIntent::Deposit {
                    proof_inputs,
                    depositor_signature,
                } = &request.intent
                else {
                    return Err(RelayError::DepositorSignature.into());
                };
                if !depositor_signature
                    .0
                    .verify(depositor.as_ref(), &proof_inputs.deposit_request_digest())
                {
                    return Err(RelayError::DepositorSignature.into());
                }
                return Ok(Checked {
                    signer: Some(depositor),
                    ..unsigned
                });
            }
            RelayPayload::Merge(merge) => {
                let RelayIntent::Merge {
                    proof_inputs,
                    owner_signature,
                } = &request.intent
                else {
                    return Err(RelayError::OwnerSignature.into());
                };
                if !merge.sender.signing_pubkey.verify_message(
                    &proof_inputs.merge_request_digest(),
                    &<[u8; 64]>::from(owner_signature.0),
                ) {
                    return Err(RelayError::OwnerSignature.into());
                }
                return Ok(Checked {
                    signer: merge
                        .sender
                        .signing_pubkey
                        .as_ed25519()
                        .ok()
                        .map(Address::new_from_array),
                    ..unsigned
                });
            }
            RelayPayload::Enroll(enrollment) => {
                check_enrollment(enrollment, fee_payer)?;
                let RelayIntent::Enroll {
                    owner_signature, ..
                } = &request.intent
                else {
                    return Err(RelayError::EnrollmentSignature.into());
                };
                if !owner_signature
                    .0
                    .verify(enrollment.owner.as_ref(), &enrollment.request_digest())
                {
                    return Err(RelayError::EnrollmentSignature.into());
                }
                return Ok(Checked {
                    signer: Some(enrollment.owner),
                    ..unsigned
                });
            }
        };
        if proof_inputs.rail.operation() != request.intent.operation() {
            return Err(RelayError::RailMismatch.into());
        }
        let setup = proof_inputs
            .token_account_setup(fee_payer, request.intent.token_account_setup())
            .map_err(RelayError::from)?;
        let signature = match &request.intent {
            RelayIntent::Anonymous {
                owner_signature, ..
            }
            | RelayIntent::Confidential {
                owner_signature, ..
            } => Some(<[u8; 64]>::from(owner_signature.0)),
            RelayIntent::Delegate { .. } => None,
            RelayIntent::Deposit { .. }
            | RelayIntent::Merge { .. }
            | RelayIntent::Enroll { .. } => return Ok(Checked { setup, ..unsigned }),
        };
        let digest = proof_inputs
            .spp_proof_inputs(fee_payer)
            .message_hash()
            .map_err(RelayProofInputsError::from)
            .map_err(RelayError::from)?;
        let Some(signature) = signature else {
            let (
                RelayRail::Delegate { delegate, .. },
                RelayIntent::Delegate {
                    delegate_signature, ..
                },
            ) = (&proof_inputs.rail, &request.intent)
            else {
                return Err(RelayError::DelegateSignature.into());
            };
            if !delegate_signature.0.verify(delegate.as_ref(), &digest) {
                return Err(RelayError::DelegateSignature.into());
            }
            return Ok(Checked {
                signer: Some(*delegate),
                setup,
                ..unsigned
            });
        };
        match proof_inputs
            .sender
            .signing_pubkey
            .verify_message(&digest, &signature)
        {
            true => Ok(Checked {
                owner_signature: Some(signature),
                signer: proof_inputs
                    .sender
                    .signing_pubkey
                    .as_ed25519()
                    .ok()
                    .map(Address::new_from_array),
                setup,
            }),
            false => Err(RelayError::OwnerSignature.into()),
        }
    }
}

impl RelayPayload {
    fn decode(intent: &RelayIntent) -> Result<Self, RelayProofInputsError> {
        let bytes = intent.proof_inputs().as_bytes();
        Ok(match intent {
            RelayIntent::Deposit { .. } => Self::Deposit(RelayProofInputs::decode(bytes)?),
            RelayIntent::Merge { .. } => Self::Merge(RelayMergeInputs::decode(bytes)?),
            RelayIntent::Enroll { .. } => Self::Enroll(RelayEnrollInputs::decode(bytes)?),
            RelayIntent::Anonymous { .. }
            | RelayIntent::Confidential { .. }
            | RelayIntent::Delegate { .. } => Self::Transfer(RelayProofInputs::decode(bytes)?),
        })
    }

    pub fn ring_program_id(&self) -> Address {
        match self {
            Self::Transfer(inputs) => inputs.ring_program_id,
            Self::Deposit(inputs) => inputs.ring_program_id,
            Self::Merge(inputs) => inputs.ring_program_id,
            Self::Enroll(inputs) => inputs.ring_program_id,
        }
    }

    /// A transfer's debits come from the frame the co-signer signs.
    fn flows(&self) -> Result<CoSignFlows, RelayError> {
        Ok(match self {
            Self::Transfer(_) => CoSignFlows::Frame,
            Self::Deposit(inputs) => CoSignFlows::Published(
                deposit_flows(
                    inputs.ring_program_id,
                    &inputs.external_data.interface_transfers,
                )
                .map_err(|error| RelayError::Proof(error.to_string()))?,
            ),
            Self::Merge(_) | Self::Enroll(_) => CoSignFlows::Published(Vec::new()),
        })
    }
}

/// Modelled at the base fee, the relay sets no priority fee.
fn signature_fees(signatures: usize) -> u64 {
    u64::try_from(signatures)
        .unwrap_or(u64::MAX)
        .saturating_mul(LAMPORTS_PER_SIGNATURE)
}

fn message_fee(message: &VersionedMessage) -> u64 {
    signature_fees(usize::from(message.header().num_required_signatures))
}

/// The fee of a message holding `instruction`, the compiler counts the fee payer and each other signer once.
fn message_fee_of(instruction: &Instruction, fee_payer: Address) -> u64 {
    let signers: HashSet<Address> = instruction
        .accounts
        .iter()
        .filter(|account| account.is_signer)
        .map(|account| account.pubkey)
        .chain([fee_payer])
        .collect();
    signature_fees(signers.len())
}

/// The size the associated token program allocates for a mint, its required extensions included.
fn token_2022_account_len(mint: &[u8]) -> Result<usize, RingRpcError> {
    let mint =
        StateWithExtensions::<Mint>::unpack(mint).map_err(|_| RingRpcError::StateUnavailable)?;
    let mint_extensions = mint
        .get_extension_types()
        .map_err(|_| RingRpcError::StateUnavailable)?;
    let mut extensions = ExtensionType::get_required_init_account_extensions(&mint_extensions);
    extensions.push(ExtensionType::ImmutableOwner);
    ExtensionType::try_calculate_account_len::<Account>(&extensions)
        .map_err(|_| RingRpcError::StateUnavailable)
}

/// Every part of the request but the quote, a fresh quote still finds the row its old message holds.
fn attempt_key(request: &PrepareRelayRequest) -> Result<[u8; 32], RingRpcError> {
    let unquoted = serde_json::to_vec(&(&request.ring, &request.intent, &request.co_signers))
        .map(Zeroizing::new)
        .map_err(|_| RingRpcError::StateUnavailable)?;
    Ok(Sha256::new()
        .chain_update(ATTEMPT_KEY_DOMAIN)
        .chain_update(&*unquoted)
        .finalize()
        .into())
}

/// The delegate signed a nonce and a timestamp, its relay id already names one signed request.
fn delegate_key(relay_id: &RelayId) -> [u8; 32] {
    Sha256::new()
        .chain_update(DELEGATE_KEY_DOMAIN)
        .chain_update(relay_id.0 .0)
        .finalize()
        .into()
}

/// The relay pays for no owner's account but the owner's own, and for no other storage instruction.
fn check_enrollment(enrollment: &RelayEnrollInputs, fee_payer: Address) -> Result<(), RelayError> {
    let refused = enrollment.owner == fee_payer
        || enrollment.instruction_data.first() != Some(&storage_instruction::tag::ENROLL)
        || enrollment.instruction_data.len() > solana_message::v1::MAX_TRANSACTION_SIZE;
    match refused {
        true => Err(RelayError::InvalidEnrollment),
        false => Ok(()),
    }
}

fn enrollment_step(enrollment: &RelayEnrollInputs, fee_payer: Address) -> ProvenRelay {
    ProvenRelay {
        instruction: enrollment.instruction(fee_payer),
        budget: ComputeBudgetConfig::new(ENROLL_COMPUTE_UNITS),
        co_signers: Vec::new(),
        signers: vec![enrollment.owner],
        tree_fees: 0,
    }
}

fn refused_fit(error: FitError) -> RingRpcError {
    RelayError::proof(error.into())
}

/// A constraint violation or a failed pool acquire proves the store never committed the write.
fn refused(error: &DbErr) -> bool {
    match error {
        DbErr::ConnectionAcquire(_) => true,
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(error)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(error))) => matches!(
            error.kind(),
            ErrorKind::UniqueViolation
                | ErrorKind::ForeignKeyViolation
                | ErrorKind::NotNullViolation
                | ErrorKind::CheckViolation
        ),
        _ => false,
    }
}

fn landed(outcome: ChainOutcome) -> RelayEvent {
    match outcome {
        ChainOutcome::Confirmed { slot } => RelayEvent::Landed { slot },
        ChainOutcome::Failed { reason } => RelayEvent::Reverted { reason },
    }
}

fn stored_state(read: &Result<Option<RelayRow>, DbErr>) -> Result<Option<&RelayState>, &DbErr> {
    read.as_ref()
        .map(|row| row.as_ref().map(|row| &row.record.state))
}

fn step(relay_id: RelayId, record: &RelayRecord) -> RelayStep {
    match record.state {
        RelayState::AwaitingSignature(_) => RelayStep::SignMessage {
            relay_id,
            message: record.message.serialize().into(),
        },
        _ => RelayStep::Submitted { relay_id },
    }
}

fn relay_status(state: &RelayState) -> RelayStatus {
    match state {
        RelayState::AwaitingSignature(_) => RelayStatus::AwaitingSignature,
        RelayState::Sent(sent) => RelayStatus::Sent {
            signature: sent.signature.into(),
        },
        RelayState::Confirmed {
            signature, slot, ..
        } => RelayStatus::Confirmed {
            signature: (*signature).into(),
            slot: *slot,
        },
        RelayState::Failed { reason, .. } => RelayStatus::Failed {
            reason: reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use solana_instruction::AccountMeta;

    use super::*;

    #[test]
    fn a_reseal_refusal_names_its_row_in_its_code() {
        let code = |row| match RelayError::proof(RingError::ResealRequired { row }) {
            RingRpcError::Relay(refused) => ErrorObjectOwned::from(&refused).code(),
            other => panic!("a relay refusal, not {other}"),
        };
        assert_eq!(code(SealRow::Narrow), -32211);
        assert_eq!(code(SealRow::Wide), -32212);
        let other = RelayError::proof(RingError::RelayAuditorMessage);
        assert!(matches!(other, RingRpcError::Relay(RelayError::Proof(_))));
    }

    #[test]
    fn enrollment_refusal_codes_are_stable() {
        let refused = RelayError::EnrollmentRefused {
            reason: String::new(),
        };
        assert_eq!(
            [
                RelayError::AlreadyEnrolled.code(),
                RelayError::RegisterKeyProof.code(),
                refused.code(),
            ],
            [-32213, -32214, -32215]
        );
    }

    #[test]
    fn an_in_doubt_commit_keeps_the_reservation_with_no_stored_relay() {
        let lost = WriteError::Committing(DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(
            std::io::ErrorKind::ConnectionReset.into(),
        ))));

        let reservation = FailedWrite {
            write: UnstoredWrite::Failed(&lost),
            co_signature: Some(Signature::from([1; 64])),
            stored: Ok(None),
        }
        .reservation();

        assert_eq!(reservation, ReservationAfterWrite::Keep);
    }

    /// The payer heads SPP's list and a co-owner can repeat, each still signs once.
    #[test]
    fn the_message_fee_matches_the_compiled_message() {
        let fee_payer = Address::new_from_array([1; 32]);
        let owner = Address::new_from_array([2; 32]);
        let instruction = Instruction {
            program_id: Address::new_from_array([3; 32]),
            accounts: vec![
                AccountMeta::new(fee_payer, true),
                AccountMeta::new_readonly(owner, true),
                AccountMeta::new_readonly(owner, true),
                AccountMeta::new_readonly(Address::new_from_array([4; 32]), false),
            ],
            data: vec![custom_ring_interface::tag::TRANSFER],
        };
        let budget = ComputeBudgetConfig::new(200_000);
        let compiled = compile_message(
            &fee_payer,
            core::slice::from_ref(&instruction),
            Default::default(),
            budget,
        )
        .expect("compiled");

        assert_eq!(
            message_fee_of(&instruction, fee_payer),
            2 * LAMPORTS_PER_SIGNATURE
        );
        assert_eq!(
            message_fee_of(&instruction, fee_payer),
            message_fee(&compiled)
        );
    }

    #[test]
    fn an_oversized_frame_refuses_under_its_own_code() {
        let oversized = RelayError::proof(RingError::TransactionTooLarge {
            bytes: 4_097,
            limit: 4_096,
        });
        let RingRpcError::Relay(refused) = oversized else {
            panic!("a relay refusal");
        };
        assert_eq!(ErrorObjectOwned::from(&refused).code(), -32216);
    }
}
