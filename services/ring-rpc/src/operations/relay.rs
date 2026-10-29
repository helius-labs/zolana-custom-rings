use std::{sync::Arc, time::Duration};

use custom_ring_sdk::RingError;
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use spr_client::compile_message;
use spr_transaction::{instructions::transact::SettlementTransfer, SOL_MINT};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayId, RelayIntent,
    RelayProofInputs, RelayProofInputsError, RelayQuote, RelayStatus, RelayStep,
    SubmitRelayRequest,
};
use zolana_ring_policy::Member;

use crate::{
    cosign::{
        AssetFlow, CoSignDecision, CoSignRefusal, CoSignRequest, CoSignSettlement, CoSignPolicy,
        RefusingCoSigner,
    },
    database::Store,
    error::{redacted, RingRpcError},
    relay_chain::{ChainOutcome, RelayChain},
    relay_prover::{ProvenRelay, RelayProofRequest, RelayProver},
    relay_submit::{CollectedSignature, RelaySubmit, RelayTransaction},
    relays::{RelayRecord, RelayState, RelayStore},
};

/// Longest quote window, one blockhash lifetime.
pub const QUOTE_SLOTS: u64 = 150;
pub const RELAY_TRACK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PROOFS: usize = 4;
const EXPIRED: &str = "the relay message expired before it landed";

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
}

pub enum ServedRings {
    One(Address),
    Any,
}

#[must_use]
pub struct RelayParts {
    pub store: Store,
    pub prover: Arc<dyn RelayProver>,
    pub submit: Arc<dyn RelaySubmit>,
    pub chain: Arc<dyn RelayChain>,
    pub rings: ServedRings,
}

/// One stored record per `relayId`.
pub struct Relay {
    store: Store,
    prover: Arc<dyn RelayProver>,
    submit: Arc<dyn RelaySubmit>,
    chain: Arc<dyn RelayChain>,
    rings: ServedRings,
    co_signer: Arc<dyn CoSignPolicy>,
    proofs: Semaphore,
    /// Every record write after the proofs, one relay state at a time.
    transitions: Mutex<()>,
}

#[must_use]
struct PrepareCheck<'a> {
    request: &'a PrepareRelayRequest,
    proof_inputs: &'a RelayProofInputs,
    fee_payer: Address,
    slot: u64,
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
            submit: parts.submit,
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
        self.submit.fee_payer()
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
        if let Some(record) = self.relays().get(&relay_id).await? {
            return Ok(step(relay_id, &record));
        }
        let ring = request.ring.0;
        self.rings.check(ring)?;
        let proof_inputs = RelayProofInputs::decode(&proof_input_bytes(&request.intent).0)
            .map_err(RelayError::from)?;
        let fee_payer = self.fee_payer();
        let owner_signature = PrepareCheck {
            request,
            proof_inputs: &proof_inputs,
            fee_payer,
            slot: self.chain.slot().await?,
        }
        .check()?;
        let proven = {
            let _proof = self.proofs.try_acquire().map_err(|_| RingRpcError::Busy)?;
            self.prover
                .prove(RelayProofRequest {
                    ring,
                    fee_payer,
                    proof_inputs: &proof_inputs,
                    owner_signature,
                })
                .await?
        };
        let (blockhash, last_valid_block_height) = self.chain.latest_blockhash().await?;
        let message = compile_message(
            &fee_payer,
            core::slice::from_ref(&proven.instruction),
            blockhash,
            proven.budget,
        )?;
        let co_signed = CoSignStep {
            message: &message,
            proof_inputs: &proof_inputs,
            proven,
        }
        .decide(self.co_signer.as_ref())
        .await?;
        let mut record = RelayRecord {
            message,
            signatures: co_signed.signature.into_iter().collect(),
            co_signature: co_signed.signature.map(|collected| collected.signature),
            state: match co_signed.signers.is_empty() {
                true => RelayState::Signed,
                false => RelayState::AwaitingSignature,
            },
            awaiting: co_signed.signers,
            last_valid_block_height,
        };
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
        if record.state == RelayState::Signed {
            self.send(&relay_id, &mut record).await?;
        }
        Ok(step(relay_id, &record))
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
            if record.awaiting.is_empty() {
                record.state = RelayState::Signed;
            }
            self.relays().update(&request.relay_id, &record).await?;
        }
        self.advance(&request.relay_id, &mut record).await?;
        relay_status(&record.state)
    }

    pub async fn status(
        &self,
        request: &GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingRpcError> {
        let _transition = self.transitions.lock().await;
        let mut record = self.record(&request.relay_id).await?;
        self.advance(&request.relay_id, &mut record).await?;
        relay_status(&record.state)
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

    async fn track(&self) -> Result<(), RingRpcError> {
        for relay_id in self.relays().pending().await? {
            let _transition = self.transitions.lock().await;
            let advanced = match self.record(&relay_id).await {
                Ok(mut record) => self.advance(&relay_id, &mut record).await,
                Err(error) => Err(error),
            };
            if let Err(error) = advanced {
                warn!("relay {} did not advance {}", relay_id.0, redacted(&error));
            }
        }
        Ok(())
    }

    fn relays(&self) -> RelayStore<'_> {
        RelayStore::new(self.store.connection())
    }

    async fn record(&self, relay_id: &RelayId) -> Result<RelayRecord, RingRpcError> {
        self.relays()
            .get(relay_id)
            .await?
            .ok_or_else(|| RelayError::UnknownRelay.into())
    }

    async fn send(&self, relay_id: &RelayId, record: &mut RelayRecord) -> Result<(), RingRpcError> {
        let transaction = RelayTransaction {
            message: record.message.clone(),
            signatures: record.signatures.clone(),
        };
        match self.submit.submit(transaction).await {
            Ok(signature) => {
                record.state = RelayState::Sent {
                    signature: signature.into(),
                };
                Ok(self.relays().update(relay_id, record).await?)
            }
            Err(RingRpcError::Relay(RelayError::SendRefused { reason })) => {
                record.state = RelayState::Failed { reason };
                self.close(relay_id, record).await
            }
            Err(error) => Err(error),
        }
    }

    /// Past its last valid block height a relay that has not landed fails.
    async fn advance(
        &self,
        relay_id: &RelayId,
        record: &mut RelayRecord,
    ) -> Result<(), RingRpcError> {
        let last_valid_block_height = record.last_valid_block_height;
        let expired = || async {
            Ok::<_, RingRpcError>(self.chain.block_height().await? > last_valid_block_height)
        };
        match record.state.clone() {
            RelayState::AwaitingSignature if expired().await? => {
                record.state = RelayState::Failed {
                    reason: EXPIRED.to_owned(),
                };
                self.close(relay_id, record).await
            }
            // A resend lands as already processed or fails its preflight past expiry.
            RelayState::Signed => self.send(relay_id, record).await,
            RelayState::Sent { signature } => {
                let outcome = match self.chain.outcome(signature.0).await? {
                    Some(outcome) => outcome,
                    // The transaction can land between the first lookup and the expiry check.
                    None if expired().await? => {
                        self.chain.outcome(signature.0).await?.unwrap_or_else(|| {
                            ChainOutcome::Failed {
                                reason: EXPIRED.to_owned(),
                            }
                        })
                    }
                    None => return Ok(()),
                };
                record.state = match outcome {
                    ChainOutcome::Confirmed { slot } => RelayState::Confirmed { signature, slot },
                    ChainOutcome::Failed { reason } => RelayState::Failed { reason },
                };
                self.close(relay_id, record).await
            }
            RelayState::AwaitingSignature
            | RelayState::Confirmed { .. }
            | RelayState::Failed { .. } => Ok(()),
        }
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

struct CoSignStep<'a> {
    message: &'a VersionedMessage,
    proof_inputs: &'a RelayProofInputs,
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
            proof_inputs,
            proven,
        } = self;
        let Some(co_signer_address) = proven.co_signer else {
            return Ok(CoSigned {
                signature: None,
                signers: proven.signers,
            });
        };
        let sender = proof_inputs
            .sender
            .signing_pubkey
            .owner_proof_input_hash()
            .map_err(RelayProofInputsError::from)
            .map_err(RelayError::from)?;
        let request = CoSignRequest {
            ring: proof_inputs.ring_program_id,
            message: message.clone(),
            sender: Member::from_bytes(sender)
                .map_err(|error| RelayError::Proof(error.to_string()))?,
            demand: proven.co_sign_demand,
            flows: asset_flows(proof_inputs),
        };
        match co_signer.decide(&request).await? {
            CoSignDecision::Signed(signature) => Ok(CoSigned {
                signature: Some(CollectedSignature {
                    signer: co_signer_address,
                    signature,
                }),
                signers: proven.signers,
            }),
            CoSignDecision::Refused(CoSignRefusal::Disabled | CoSignRefusal::OverLimit) => {
                Err(RelayError::CoSignRefused.into())
            }
        }
    }
}

impl PrepareCheck<'_> {
    fn check(self) -> Result<Option<[u8; 64]>, RingRpcError> {
        let Self {
            request,
            proof_inputs,
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
        if proof_inputs.ring_program_id != request.ring.0 {
            return Err(RelayError::RingMismatch.into());
        }
        if proof_inputs.rail.operation() != Some(request.intent.operation()) {
            return Err(RelayError::RailMismatch.into());
        }
        let signature = match &request.intent {
            RelayIntent::Anonymous {
                owner_signature, ..
            }
            | RelayIntent::Confidential {
                owner_signature, ..
            } => <[u8; 64]>::from(owner_signature.0),
            RelayIntent::Delegate { .. } | RelayIntent::Deposit { .. } => return Ok(None),
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
            true => Ok(Some(signature)),
            false => Err(RelayError::OwnerSignature.into()),
        }
    }
}

fn proof_input_bytes(intent: &RelayIntent) -> &spr_indexer_api::Base64String {
    match intent {
        RelayIntent::Anonymous { proof_inputs, .. }
        | RelayIntent::Confidential { proof_inputs, .. }
        | RelayIntent::Delegate { proof_inputs }
        | RelayIntent::Deposit { proof_inputs } => proof_inputs,
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

/// `Signed` is unreachable after `advance`.
fn relay_status(state: &RelayState) -> Result<RelayStatus, RingRpcError> {
    Ok(match state {
        RelayState::AwaitingSignature => RelayStatus::AwaitingSignature,
        RelayState::Signed => return Err(RingRpcError::StateUnavailable),
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
    })
}

/// One flow per asset, a payment to another owner counts as transferred.
fn asset_flows(proof_inputs: &RelayProofInputs) -> Vec<AssetFlow> {
    let mut flows: Vec<AssetFlow> = Vec::new();
    let sender = &proof_inputs.sender.signing_pubkey;
    for output in &proof_inputs.outputs {
        if output
            .owner_address
            .is_some_and(|owner| owner.signing_pubkey != *sender)
        {
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
    flows
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
