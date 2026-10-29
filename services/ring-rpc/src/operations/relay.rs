use std::{sync::Arc, time::Duration};

use custom_ring_sdk::{RingError, SenderOutflow};
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use solana_signature::Signature;
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
    relay_chain::{ChainOutcome, RelayChain},
    relay_prover::{DelegateSeal, ProvenRelay, RelayProofRequest, RelayProver},
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

    pub(crate) fn co_signer(&self) -> Option<Address> {
        self.co_signer.signer()
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
        let fee_payer = self.fee_payer();
        let Checked {
            owner_signature,
            setup,
        } = PrepareCheck {
            request,
            payload: &payload,
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
                    payload: &payload,
                    owner_signature,
                    co_signer: self.co_signer(),
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
        let fee_payer = self.fee_payer();
        let (payload, proven) = {
            let _proof = self.proofs.try_acquire().map_err(|_| RingRpcError::Busy)?;
            let payload = RelayPayload::Transfer(
                self.prover
                    .seal_delegate(DelegateSeal { fee_payer, ..seal })
                    .await?,
            );
            let proven = self
                .prover
                .prove(RelayProofRequest {
                    ring,
                    fee_payer,
                    payload: &payload,
                    owner_signature: None,
                    co_signer: self.co_signer(),
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
        let (blockhash, last_valid_block_height) = self.chain.latest_blockhash().await?;
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
        let Some(co_signer_address) = proven.co_signer else {
            return Ok(CoSigned {
                signature: None,
                signers: proven.signers,
            });
        };
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
