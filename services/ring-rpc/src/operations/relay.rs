use std::{sync::Arc, time::Duration};

use custom_ring_sdk::{RingError, SenderOutflow};
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use sea_orm::{DatabaseConnection, TransactionTrait};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::compile_message;
use spr_keypair::PublicKey;
use spr_transaction::{instructions::transact::SettlementTransfer, SOL_MINT};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayDepositInputs, RelayId,
    RelayIntent, RelayMergeInputs, RelayProofInputs, RelayProofInputsError, RelayQuote,
    RelayStatus, RelayStep, SubmitRelayRequest, TokenAccountSetupError,
};
use zolana_ring_policy::Member;

use crate::{
    cosign::{
        AssetFlow, CoSignDecision, CoSignPolicy, CoSignRefusal, CoSignRequest, CoSignSettlement,
        RefusingCoSigner,
    },
    database::Store,
    error::{redacted, RingRpcError},
    landing::{Attempt, ChainOutcome, ChainSubmit, Landing, LatestBlockhash},
    merge_inputs::{HoldInputs, MergeInputs},
    relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
    relay_submit::{presigned_transaction, CollectedSignature},
    relays::{RelayRecord, RelayState, RelayStore},
};

/// Longest quote window, one blockhash lifetime.
pub const QUOTE_SLOTS: u64 = 150;
pub const RELAY_TRACK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PROOFS: usize = 4;
const EXPIRED: &str = "the relay message expired before it landed";
const MANAGED_MERGE_DOMAIN: &[u8] = b"zolana/ring-rpc-managed-merge/v1";

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
}

pub enum RelayPayload {
    Transfer(RelayProofInputs),
    Deposit(RelayDepositInputs),
    Merge(RelayMergeInputs),
}

pub enum ServedRings {
    One(Address),
    Any,
}

#[must_use]
pub struct RelayParts {
    pub store: Store,
    pub prover: Arc<dyn RelayProver>,
    /// The SPP payer every relayed message names.
    pub fee_payer: Keypair,
    pub chain: Arc<dyn ChainSubmit>,
    pub rings: ServedRings,
}

/// One stored record per `relayId`.
pub struct Relay {
    store: Store,
    prover: Arc<dyn RelayProver>,
    fee_payer: Keypair,
    chain: Arc<dyn ChainSubmit>,
    rings: ServedRings,
    co_signer: Arc<dyn CoSignPolicy>,
    proofs: Semaphore,
    /// Every record write after the proofs, one relay state at a time.
    transitions: Mutex<()>,
}

/// Every signature except the fee payer's is collected.
#[must_use]
pub(crate) struct HeldMerge {
    pub ring: Address,
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
    pub co_signature: Option<CollectedSignature>,
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
    setup: Vec<Instruction>,
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
        }
    }

    /// A refused transfer is the caller's, an unreachable chain or prover is the service's.
    pub(crate) fn proof(error: RingError) -> RingRpcError {
        match error {
            RingError::Client(error) => RingRpcError::Upstream(error),
            RingError::Indexer(refused) => RingRpcError::Refused(refused),
            refused => Self::Proof(refused.to_string()).into(),
        }
    }
}

impl From<&RelayError> for ErrorObjectOwned {
    fn from(error: &RelayError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

impl ServedRings {
    fn check(&self, ring: Address) -> Result<(), RelayError> {
        match self {
            Self::One(served) if *served != ring => Err(RelayError::RingNotServed),
            Self::One(_) | Self::Any => Ok(()),
        }
    }
}

impl Relay {
    pub fn new(parts: RelayParts) -> Self {
        Self {
            store: parts.store,
            prover: parts.prover,
            fee_payer: parts.fee_payer,
            chain: parts.chain,
            rings: parts.rings,
            co_signer: Arc::new(RefusingCoSigner),
            proofs: Semaphore::new(MAX_CONCURRENT_PROOFS),
            transitions: Mutex::new(()),
        }
    }

    #[must_use = "use the updated relay"]
    pub fn with_co_signer(mut self, co_signer: Arc<dyn CoSignPolicy>) -> Self {
        self.co_signer = co_signer;
        self
    }

    pub fn fee_payer(&self) -> Address {
        self.fee_payer.pubkey()
    }

    fn parties(&self) -> RelayParties {
        RelayParties {
            fee_payer: self.fee_payer(),
            co_signer: self.co_signer.signer(),
        }
    }

    pub async fn quote(&self, request: &GetRelayQuoteRequest) -> Result<RelayQuote, RingRpcError> {
        self.rings.check(request.ring.0)?;
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
        self.rings.check(ring)?;
        let payload = RelayPayload::decode(&request.intent).map_err(RelayError::from)?;
        let parties = self.parties();
        let Checked {
            owner_signature,
            setup,
        } = PrepareCheck {
            request,
            payload: &payload,
            fee_payer: parties.fee_payer,
            slot: self.chain.slot().await?,
        }
        .check()?;
        let proven = {
            let _proof = self.proofs.try_acquire().map_err(|_| RingRpcError::Busy)?;
            self.prover
                .prove(RelayProofRequest {
                    ring,
                    parties,
                    payload: &payload,
                    owner_signature,
                })
                .await?
        };
        self.stage(ProvenStep {
            relay_id,
            payload,
            setup,
            proven,
        })
        .await
    }

    pub(crate) async fn stored(
        &self,
        relay_id: &RelayId,
    ) -> Result<Option<RelayStep>, RingRpcError> {
        Ok(self
            .relays()
            .get(relay_id)
            .await?
            .map(|record| step(relay_id.clone(), &record)))
    }

    /// The source signs nothing, the delegate signs the returned message.
    pub(crate) async fn prepare_delegated(
        &self,
        relay_id: RelayId,
        seal: DelegateSeal<'_>,
    ) -> Result<RelayStep, RingRpcError> {
        let ring = seal.ring;
        self.rings.check(ring)?;
        let parties = self.parties();
        let (payload, proven) = {
            let _proof = self.proofs.try_acquire().map_err(|_| RingRpcError::Busy)?;
            let payload = RelayPayload::Transfer(self.prover.seal_delegate(seal, parties).await?);
            let proven = self
                .prover
                .prove(RelayProofRequest {
                    ring,
                    parties,
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
        })
        .await
    }

    /// The co-signer signs before the record lands, a lost insert frees its reservation.
    async fn stage(&self, proven: ProvenStep) -> Result<RelayStep, RingRpcError> {
        let ProvenStep {
            relay_id,
            payload,
            mut setup,
            proven,
        } = proven;
        let fee_payer = self.fee_payer();
        let LatestBlockhash {
            blockhash,
            last_valid_block_height,
        } = self.chain.latest_blockhash().await?;
        setup.push(proven.instruction.clone());
        let message = compile_message(&fee_payer, &setup, blockhash, proven.budget)?;
        let co_signed = CoSignStep {
            message: &message,
            payload: &payload,
            proven,
        }
        .decide(self.co_signer.as_ref())
        .await?;
        // The decoded secrets zeroize before the store and send awaits.
        drop(payload);
        let mut record = RelayRecord {
            message,
            signatures: co_signed.signature.into_iter().collect(),
            co_signature: co_signed.signature.map(|collected| collected.signature),
            state: RelayState::AwaitingSignature,
            awaiting: co_signed.signers,
            last_valid_block_height,
        };
        self.sign_when_complete(&mut record);
        let _transition = self.transitions.lock().await;
        let inserted = self.relays().insert(&relay_id, &record).await;
        if !matches!(inserted, Ok(true)) {
            self.settle(record.co_signature, CoSignSettlement::Failed)
                .await?;
            inserted?;
            let stored = self.relays().get(&relay_id).await?;
            return Ok(step(
                relay_id,
                &stored.ok_or(RingRpcError::StateUnavailable)?,
            ));
        }
        self.first_send(&relay_id, &mut record).await?;
        Ok(step(relay_id, &record))
    }

    /// The record and its held inputs commit together before the send.
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
        let mut record = RelayRecord {
            message: merge.message,
            signatures: merge.co_signature.into_iter().collect(),
            awaiting: Vec::new(),
            co_signature: merge.co_signature.map(|collected| collected.signature),
            last_valid_block_height: merge.last_valid_block_height,
            state: RelayState::AwaitingSignature,
        };
        self.sign_when_complete(&mut record);
        let _transition = self.transitions.lock().await;
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
                self.settle(record.co_signature, CoSignSettlement::Failed)
                    .await?;
                return Err(error);
            }
        }
        self.first_send(&relay_id, &mut record).await?;
        Ok(relay_id)
    }

    /// `false` when the relay is stored already.
    async fn store_merge(
        &self,
        record: &RelayRecord,
        hold: HoldInputs<'_>,
    ) -> Result<bool, RingRpcError> {
        let transaction = self.store.connection().begin().await?;
        if !RelayStore::new(&transaction)
            .insert(hold.relay_id, record)
            .await?
        {
            return Ok(false);
        }
        MergeInputs { conn: &transaction }.hold(hold).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) fn merge_inputs(&self) -> MergeInputs<'_, DatabaseConnection> {
        MergeInputs {
            conn: self.store.connection(),
        }
    }

    /// A signature already collected leaves the relay as it is.
    pub async fn submit(&self, request: &SubmitRelayRequest) -> Result<RelayStatus, RingRpcError> {
        let _transition = self.transitions.lock().await;
        let mut record = self.record(&request.relay_id).await?;
        let (signer, signature) = (request.signer.0, request.signature.0);
        if record.state == RelayState::AwaitingSignature
            && !record
                .signatures
                .iter()
                .any(|collected| collected.signer == signer)
        {
            let index = record
                .awaiting
                .iter()
                .position(|awaited| *awaited == signer)
                .ok_or(RelayError::UnexpectedSigner)?;
            if !signature.verify(signer.as_ref(), &record.message.serialize()) {
                return Err(RelayError::SignerSignature.into());
            }
            record.awaiting.remove(index);
            record
                .signatures
                .push(CollectedSignature { signer, signature });
            self.sign_when_complete(&mut record);
            self.relays().update(&request.relay_id, &record).await?;
            self.first_send(&request.relay_id, &mut record).await?;
        }
        self.advance(&request.relay_id, &mut record).await?;
        Ok(relay_status(&record.state))
    }

    pub async fn status(
        &self,
        request: &GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingRpcError> {
        let _transition = self.transitions.lock().await;
        let mut record = self.record(&request.relay_id).await?;
        self.advance(&request.relay_id, &mut record).await?;
        Ok(relay_status(&record.state))
    }

    /// A restart resumes every relay it left pending.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        loop {
            if let Err(error) = self.track().await {
                warn!("relay tracking failed {}", redacted(&error));
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub(crate) async fn track(&self) -> Result<(), RingRpcError> {
        for relay_id in self.relays().pending().await? {
            let _transition = self.transitions.lock().await;
            let tracked = async {
                let mut record = self.record(&relay_id).await?;
                self.advance(&relay_id, &mut record).await?;
                self.resend(&record).await
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

    async fn record(&self, relay_id: &RelayId) -> Result<RelayRecord, RingRpcError> {
        self.relays()
            .get(relay_id)
            .await?
            .ok_or_else(|| RelayError::UnknownRelay.into())
    }

    /// Fixes the relay's one signature, every later send repeats it.
    fn sign_when_complete(&self, record: &mut RelayRecord) {
        if record.state != RelayState::AwaitingSignature || !record.awaiting.is_empty() {
            return;
        }
        let signature = self.fee_payer.sign_message(&record.message.serialize());
        record.signatures.push(CollectedSignature {
            signer: self.fee_payer(),
            signature,
        });
        record.state = RelayState::Sent {
            signature: signature.into(),
        };
    }

    /// A refused preflight forwards nothing and ends the relay.
    async fn first_send(
        &self,
        relay_id: &RelayId,
        record: &mut RelayRecord,
    ) -> Result<(), RingRpcError> {
        if !matches!(record.state, RelayState::Sent { .. }) {
            return Ok(());
        }
        let transaction = presigned_transaction(&record.message, &record.signatures)?;
        match self.chain.send(&transaction).await {
            Err(RingRpcError::Relay(RelayError::SendRefused { reason })) => {
                record.state = RelayState::Failed { reason };
                self.close(relay_id, record).await
            }
            sent => sent,
        }
    }

    /// A refusal leaves the relay open, an earlier send can still land.
    async fn resend(&self, record: &RelayRecord) -> Result<(), RingRpcError> {
        match record.state {
            RelayState::Sent { .. } => {
                let transaction = presigned_transaction(&record.message, &record.signatures)?;
                self.chain.send(&transaction).await
            }
            _ => Ok(()),
        }
    }

    async fn advance(
        &self,
        relay_id: &RelayId,
        record: &mut RelayRecord,
    ) -> Result<(), RingRpcError> {
        let last_valid_block_height = record.last_valid_block_height;
        record.state = match record.state.clone() {
            RelayState::AwaitingSignature
                if self.chain.block_height().await? > last_valid_block_height =>
            {
                RelayState::Failed {
                    reason: EXPIRED.to_owned(),
                }
            }
            RelayState::Sent { signature } => {
                let attempt = Attempt {
                    signature: signature.0,
                    last_valid_block_height,
                };
                match attempt.landing(self.chain.as_ref()).await? {
                    Landing::Pending => return Ok(()),
                    Landing::Landed(ChainOutcome::Confirmed { slot }) => {
                        RelayState::Confirmed { signature, slot }
                    }
                    Landing::Landed(ChainOutcome::Failed { reason }) => {
                        RelayState::Failed { reason }
                    }
                    Landing::Expired => RelayState::Failed {
                        reason: EXPIRED.to_owned(),
                    },
                }
            }
            RelayState::AwaitingSignature
            | RelayState::Confirmed { .. }
            | RelayState::Failed { .. } => return Ok(()),
        };
        self.close(relay_id, record).await
    }

    /// Settles the co-signer for the final state before the store keeps it.
    async fn close(&self, relay_id: &RelayId, record: &RelayRecord) -> Result<(), RingRpcError> {
        let settlement = match record.state {
            RelayState::Confirmed { .. } => CoSignSettlement::Confirmed,
            _ => CoSignSettlement::Failed,
        };
        self.settle(record.co_signature, settlement).await?;
        Ok(self.relays().update(relay_id, record).await?)
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
    setup: Vec<Instruction>,
    proven: ProvenRelay,
}

struct CoSignStep<'a> {
    message: &'a VersionedMessage,
    payload: &'a RelayPayload,
    proven: ProvenRelay,
}

struct CoSigned {
    signature: Option<CollectedSignature>,
    signers: Vec<Address>,
}

impl CoSignStep<'_> {
    async fn decide(self, co_signer: &dyn CoSignPolicy) -> Result<CoSigned, RingRpcError> {
        let Self {
            message,
            payload,
            proven,
        } = self;
        let Some(named) = proven.co_signer else {
            return Ok(CoSigned {
                signature: None,
                signers: proven.signers,
            });
        };
        let signer = co_signer
            .signer_named(named)
            .ok_or(RelayError::CoSignRefused)?;
        let sender = payload.sender()?;
        let request = CoSignRequest {
            ring: payload.ring_program_id(),
            message: message.clone(),
            sender,
            demand: proven.co_sign_demand,
            flows: payload.flows(sender)?,
        };
        match co_signer.decide(&request).await? {
            CoSignDecision::Signed(signature) => Ok(CoSigned {
                signature: Some(CollectedSignature { signer, signature }),
                signers: proven.signers,
            }),
            CoSignDecision::Refused(CoSignRefusal::Disabled | CoSignRefusal::OverLimit) => {
                Err(RelayError::CoSignRefused.into())
            }
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
            setup: Vec::new(),
        };
        let proof_inputs = match payload {
            RelayPayload::Transfer(proof_inputs) => proof_inputs,
            RelayPayload::Deposit(deposit) if deposit.depositor == fee_payer => {
                return Err(RelayError::DepositorIsFeePayer.into())
            }
            RelayPayload::Deposit(_) | RelayPayload::Merge(_) => return Ok(unsigned),
        };
        if proof_inputs.rail.operation() != request.intent.operation() {
            return Err(RelayError::RailMismatch.into());
        }
        let setup = proof_inputs
            .token_account_setup(fee_payer, request.intent.token_account_setup())
            .map_err(RelayError::from)?
            .iter()
            .map(|create| create.instruction())
            .collect();
        let signature = match &request.intent {
            RelayIntent::Anonymous {
                owner_signature, ..
            }
            | RelayIntent::Confidential {
                owner_signature, ..
            } => <[u8; 64]>::from(owner_signature.0),
            RelayIntent::Delegate { .. }
            | RelayIntent::Deposit { .. }
            | RelayIntent::Merge { .. } => return Ok(Checked { setup, ..unsigned }),
        };
        let digest = proof_inputs
            .spp_proof_inputs(fee_payer)
            .message_hash()
            .map_err(RelayProofInputsError::from)
            .map_err(RelayError::from)?;
        match proof_inputs
            .sender
            .signing_pubkey
            .verify_message(&digest, &signature)
        {
            true => Ok(Checked {
                owner_signature: Some(signature),
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
            RelayIntent::Deposit { .. } => Self::Deposit(RelayDepositInputs::decode(bytes)?),
            RelayIntent::Merge { .. } => Self::Merge(RelayMergeInputs::decode(bytes)?),
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
        }
    }

    /// The deposit's recipient, the spender otherwise.
    fn sender(&self) -> Result<Member, RelayError> {
        let owner: &PublicKey = match self {
            Self::Transfer(inputs) => &inputs.sender.signing_pubkey,
            Self::Deposit(inputs) => &inputs.recipient.signing_pubkey,
            Self::Merge(inputs) => &inputs.sender.signing_pubkey,
        };
        let owner_hash = owner
            .owner_proof_input_hash()
            .map_err(RelayProofInputsError::from)?;
        Member::from_bytes(owner_hash).map_err(|error| RelayError::Proof(error.to_string()))
    }

    fn flows(&self, sender: Member) -> Result<Vec<AssetFlow>, RingRpcError> {
        Ok(match self {
            Self::Transfer(proof_inputs) => asset_flows(proof_inputs, sender)?,
            Self::Deposit(inputs) => vec![AssetFlow {
                asset: inputs.asset.mint(),
                transferred: 0,
                deposited: inputs.amount,
                withdrawn: 0,
            }],
            Self::Merge(_) => Vec::new(),
        })
    }
}

fn step(relay_id: RelayId, record: &RelayRecord) -> RelayStep {
    match record.state {
        RelayState::AwaitingSignature => RelayStep::SignMessage {
            relay_id,
            message: record.message.serialize().into(),
        },
        _ => RelayStep::Submitted { relay_id },
    }
}

fn relay_status(state: &RelayState) -> RelayStatus {
    match state {
        RelayState::AwaitingSignature => RelayStatus::AwaitingSignature,
        RelayState::Sent { signature } => RelayStatus::Sent {
            signature: signature.clone(),
        },
        RelayState::Confirmed { signature, slot } => RelayStatus::Confirmed {
            signature: signature.clone(),
            slot: *slot,
        },
        RelayState::Failed { reason } => RelayStatus::Failed {
            reason: reason.clone(),
        },
    }
}

/// One flow per asset.
fn asset_flows(
    proof_inputs: &RelayProofInputs,
    sender: Member,
) -> Result<Vec<AssetFlow>, RingRpcError> {
    let mut flows: Vec<AssetFlow> = Vec::new();
    let rule = SenderOutflow {
        sender,
        ring: proof_inputs.ring_program_id,
    };
    for output in &proof_inputs.outputs {
        if rule.counts(output).map_err(RelayError::proof)? {
            let flow = flow(&mut flows, output.asset.asset);
            flow.transferred = flow.transferred.saturating_add(output.amount);
        }
    }
    for transfer in &proof_inputs.external_data.interface_transfers {
        let asset = match transfer {
            SettlementTransfer::Spl { mint, .. } => *mint,
            SettlementTransfer::Sol { .. } => SOL_MINT,
        };
        let flow = flow(&mut flows, asset);
        let total = match transfer.is_deposit() {
            true => &mut flow.deposited,
            false => &mut flow.withdrawn,
        };
        *total = total.saturating_add(transfer.amount());
    }
    Ok(flows)
}

fn flow(flows: &mut Vec<AssetFlow>, asset: Address) -> &mut AssetFlow {
    let index = match flows.iter().position(|flow| flow.asset == asset) {
        Some(index) => index,
        None => {
            flows.push(AssetFlow {
                asset,
                transferred: 0,
                deposited: 0,
                withdrawn: 0,
            });
            flows.len() - 1
        }
    };
    &mut flows[index]
}
