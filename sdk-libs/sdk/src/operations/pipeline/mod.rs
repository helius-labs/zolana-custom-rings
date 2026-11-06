//! One transfer pipeline for every rail, a rail only stages the transfer and seals its outputs.

mod anonymous;
mod audit;
mod compact;
mod delegate;
mod owner;
mod plan;
mod policy;
mod pool_subjects;
mod proof;
mod public_owners;
mod relay;
mod relayed;
mod selection;
mod spp;
#[cfg(test)]
#[path = "../../tests/operations/pipeline.rs"]
mod tests;

use custom_ring_interface::{
    cosign::{ApprovalMask, CoSignDemand, CoSignOperation},
    key_catalog::{RecordPools, RingCircuit, RowAuthorization, TransferAddresses, TransferSpend},
    AnonymousParties, CheckedAuthorization, CustomRingError, CustomRingProof, DisclosureFormat,
    FramedSenderBundle, InputTrees, InstructionTag, LiveSlot, ParsedTransact, PlainGroth16Proof,
    PolicyProof, PublicLeg, PublicSlots, RingPolicy, RingRail, RootRead, Settlement,
    SignerDataCounts, SignerSet, TransferBinding, ANONYMOUS_PARTIES, AUDIT_RECORD_LEN,
    TRANSFER_OUTPUT_CAPACITIES,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{AsyncRpc, ClientError, OwnerAuthorization, ProofAuthority, Shape, TransferInput};
use spr_event::is_confidential_encrypted_output;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::transact::CacheAccess;
use spr_interface::{instruction::TreeContext, N_PUBLIC_SLOTS};
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_program::instruction::TransactInterfaceTransferAccounts;
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, SettlementTransfer, SppProofInputs, SppProofOutputUtxo,
    },
    utxo::SppProofInputUtxo,
    ShieldedKeys, TransactionError,
};
use zolana_ring_client::{rpc::SubjectListSalt, AsyncRingIndexer};
use zolana_ring_keys::RingKeys;
use zolana_ring_policy::{ApprovalTotals, Member, OwnerDebit};
use zolana_ring_transaction::{published_outputs, PublishedSlot, RingDelivery, RingOutputRail};
use zolana_ring_transaction::{random_field_element, ClassifiedInput};

pub use self::{
    anonymous::{
        Anonymous, AnonymousMove, AnonymousPayment, AnonymousTransfer, ApplicationData, CachedNote,
        CoOwner, EntrySpend, NoteData, ReadCache, RingPayment,
    },
    delegate::{
        DelegateCandidates, DelegateFunding, DelegateMove, DelegateOutput, DelegatePayment,
        DelegateSource, DelegateTransfer, DelegateTransferInput, DelegateWithdrawal, Delegated,
    },
    owner::{CustomRingTransfer, CustomRingTransferInput, Owner},
    plan::SealRow,
    public_owners::{PublicOwnerTransfer, PublicOwners},
    relay::UnsignedRelay,
    relayed::{Relayed, RelayedTransfer, RelayedTransferInput},
};

pub(crate) use self::{
    anonymous::HiddenOwner,
    delegate::{delegate_rail, same_owner},
    pool_subjects::KnownSalts,
};

use self::{
    anonymous::AnonymousSpend,
    audit::{AuditSeal, PresealedAudit, SealedAudit},
    compact::{
        OwnedAppMessage, OwnedExtensions, OwnedInProofOwner, OwnedOutput, OwnedSenderBundle,
        TransactAccounts, TransactParts,
    },
    plan::{PlannedTransfer, TransferPlanner},
    policy::{owner_rows, PolicyInputs, PolicyRead},
    spp::{Spp, SppRail, SppWitness},
};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    heap::boxed,
    limits::Outflows,
    projection::retry_projection_lag,
    relay_message::ApprovalOpening,
    submission::{check_transaction_size, send_budget, BoundPolicy, BoundState},
    trees::{spend_trees, SpendTrees},
    CustomRing, CustomRingConfig, RingError,
};

mod sealed {
    pub trait Sealed {}
}

pub trait RingSender: ShieldedKeys + RingKeys + Send + Sync {}

impl<T: ShieldedKeys + RingKeys + Send + Sync + ?Sized> RingSender for T {}

/// Who authorizes the spends, the owner, the hidden owner or the delegate.
pub trait Rail: sealed::Sealed + Send + Sync {
    #[doc(hidden)]
    fn kind(&self) -> RailKind<'_>;
}

#[doc(hidden)]
pub enum RailKind<'a> {
    Owner(&'a Owner<'a>),
    Anonymous(&'a Anonymous<'a>),
    Delegated(&'a Delegated<'a>),
    Relayed(&'a Relayed<'a>),
    PublicOwners(&'a PublicOwners<'a>),
}

#[must_use = "prove or discard the transfer explicitly"]
pub struct RingTransfer<R: Rail> {
    ring: CustomRing,
    rail: R,
    co_signers: Vec<Address>,
    priority_fee: Option<u64>,
    list_salts: Vec<SubjectListSalt>,
    approval: ApprovalDisclosure,
    /// `None` seals ahead of the relay's reads under the row the public counts select.
    seal_row: Option<SealRow>,
}

/// A frame that discloses its totals carries a digest a named co-signer opens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApprovalDisclosure {
    #[default]
    None,
    Totals,
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    ring: CustomRing,
    config: Box<RingPolicy>,
    parts: TransactParts,
    accounts: TransactAccounts,
    bound: BoundState,
    pub tx_viewing_key: ViewingKey,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    pub co_signers: Vec<Address>,
    pub co_sign_demand: CoSignDemand,
    /// For a co-signer that reads exact totals, never the transaction secret.
    pub approval_opening: Option<ApprovalOpening>,
    /// Per owner and asset, a composed payment can charge an owner whose funds return to it.
    pub charged_outflows: Vec<OwnerDebit>,
}

/// A transfer past its outputs' sealing, ready for its statements.
pub(crate) struct Staged<'a> {
    pub proof_inputs: SppProofInputs,
    pub rail: RingOutputRail,
    pub sender: ShieldedAddress,
    pub authority: TransferAuthority,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub spend: Spend<'a>,
    /// Set when the wallet sealed the auditor message the owner signed over.
    pub presealed: Option<PresealedAudit>,
    /// Every enrolled subject a salted list reads.
    pub list_salts: Vec<SubjectListSalt>,
}

pub(crate) enum Spend<'a> {
    Owner,
    /// The confidential rail's owner signs inside the SPP proof, no owner signs the transaction.
    InProofOwner(OwnerAuthorization<'a>),
    Anonymous(Box<AnonymousSpend<'a>>),
    /// An anonymous ring's frame with no hidden sender, its owners are the published signers.
    PublicOwners,
    Delegate {
        delegate: Address,
        rail: RingRail,
    },
}

impl Spend<'_> {
    fn rail(&self) -> RingRail {
        match self {
            Self::Owner | Self::InProofOwner(_) => RingRail::Confidential,
            Self::Anonymous(_) | Self::PublicOwners => RingRail::Anonymous,
            Self::Delegate { rail, .. } => *rail,
        }
    }

    /// The delegate signs alone, its empty run takes no address.
    const fn row_authorization(&self) -> RowAuthorization {
        match self {
            Self::Owner | Self::PublicOwners | Self::Delegate { .. } => RowAuthorization::Run,
            Self::InProofOwner(_) => RowAuthorization::InProof,
            Self::Anonymous(_) => RowAuthorization::Hidden,
        }
    }

    fn spp_rail(&self) -> SppRail<'_> {
        match self {
            Self::Owner | Self::PublicOwners => SppRail::OwnerSigners,
            Self::InProofOwner(owner) => SppRail::Anonymous(*owner),
            Self::Anonymous(anonymous) => SppRail::Anonymous(anonymous.signer),
            Self::Delegate { .. } => SppRail::Delegate,
        }
    }

    fn in_proof_owner(&self) -> Result<Option<[u8; 32]>, RingError> {
        match self {
            Self::InProofOwner(owner) => Ok(Some(owner.public_key().as_ed25519()?)),
            Self::Owner | Self::Anonymous(_) | Self::PublicOwners | Self::Delegate { .. } => {
                Ok(None)
            }
        }
    }
}

/// One public co-owner's nullifier key, one prover holds every owner's secret.
pub(crate) struct CoOwnerKey {
    pub owner: Address,
    /// `owner_proof_input_hash`, the field a proof input carries.
    pub owner_pk_hash: [u8; 32],
    pub key: NullifierKey,
}

impl CoOwnerKey {
    fn of(co_owner: &CoOwner<'_>) -> Result<Self, RingError> {
        Ok(Self {
            owner: co_owner.owner,
            owner_pk_hash: spr_hasher::primitives::solana_owner_identity(
                co_owner.owner.as_array(),
            )?,
            key: co_owner.nullifier_key.clone(),
        })
    }
}

/// `owner` is `None` only when every input is padding.
pub(crate) struct TransferAuthority {
    pub owner: Option<NullifierKey>,
    pub co_owners: Vec<CoOwnerKey>,
}

impl ProofAuthority for TransferAuthority {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        let zero_key = NullifierKey::from_secret([0; 31]);
        for input in inputs {
            if input.nullifier_secret.is_some() {
                continue;
            }
            let owner_pk_hash = input.owner_pk_hash.to_bytes_be();
            let co_owner = self
                .co_owners
                .iter()
                .find(|co_owner| trailing_eq(&co_owner.owner_pk_hash, &owner_pk_hash));
            let zero_nullifier = zero_key.nullifier(&input.utxo.hash()?, &input.utxo.blinding)?;
            // One owner holds keyed and zero-key notes, each input's own nullifier picks its secret.
            let key = match trailing_eq(&zero_nullifier, &input.nullifier.to_bytes_be()) {
                true => Some(&zero_key),
                false => co_owner
                    .map(|co_owner| &co_owner.key)
                    .or(self.owner.as_ref()),
            };
            if let Some(key) = key {
                key.complete_inputs(core::slice::from_mut(input))?;
            }
        }
        Ok(())
    }
}

/// A big endian integer drops its leading zeros.
fn trailing_eq(field: &[u8; 32], integer: &[u8]) -> bool {
    field
        .iter()
        .rev()
        .zip(integer.iter().rev().chain(core::iter::repeat(&0)))
        .all(|(left, right)| left == right)
}

impl<R: Rail> RingTransfer<R> {
    pub fn ring(&self) -> CustomRing {
        self.ring
    }

    /// A salted list refuses an enrolled owner with no salt.
    #[must_use = "use the updated transfer"]
    pub fn with_list_salt(mut self, owner: Member, list_salt: [u8; 32]) -> Self {
        self.list_salts.push(SubjectListSalt {
            member: *owner.as_bytes(),
            list_salt,
        });
        self
    }

    /// Read in call order while a demanded class stays uncovered.
    #[must_use = "use the updated transfer"]
    pub fn with_co_signer(mut self, signer: Address) -> Self {
        self.co_signers.push(signer);
        self
    }

    /// Lamports the v1 header carries, the size check measures the header it adds.
    #[must_use = "use the updated transfer"]
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    /// The frame carries a digest of its totals, the opening reads as `approval_opening`.
    #[must_use = "use the updated transfer"]
    pub const fn with_exact_approval(mut self) -> Self {
        self.approval = ApprovalDisclosure::Totals;
        self
    }

    /// The row a relay's `ResealRequired` names, the owner then signs the new seal.
    #[must_use = "use the updated transfer"]
    pub const fn with_seal_row(mut self, row: SealRow) -> Self {
        self.seal_row = Some(row);
        self
    }

    pub async fn prove<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        retry_projection_lag(|| async {
            let assembled = boxed(|| self.assemble(client)).await?;
            boxed(|| assembled.prove(client)).await
        })
        .await
    }

    /// Every chain value is read once.
    pub(crate) async fn assemble<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let framed = boxed(|| self.frame(client)).await?;
        boxed(|| framed.witness(client)).await
    }

    /// The refusals of an assembly without its SPP witness, anchor path or signature.
    async fn measure<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<(), RingError> {
        boxed(|| self.frame(client)).await.map(drop)
    }

    async fn frame<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<Unwitnessed<'_>, RingError> {
        let prepared = boxed(|| self.prepare(client.zolana())).await?;
        let policy = boxed(|| prepared.read_policy(client.zolana())).await?;
        let sealed = prepared.seal(policy)?;
        boxed(|| sealed.frame(client)).await
    }

    /// Reads accounts only, no Merkle path and no record.
    async fn seal_unread<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
    ) -> Result<Sealed<'_, PlannedTransfer>, RingError> {
        let prepared = boxed(|| self.prepare(client)).await?;
        let planner = prepared.planner()?;
        // A direct submission reads before it plans. The relay reads after the seal and keeps
        // it only where the read's key opens the same stream, so the seal takes the key the
        // public counts select and a later read never widens it in silence.
        let plan = match self.seal_row {
            Some(row) => planner.plan_at(row)?,
            None => planner.plan(RecordPools::default())?,
        };
        prepared.seal(plan)
    }

    async fn prepare<C: AsyncRpc + ?Sized>(&self, client: &C) -> Result<Prepared<'_>, RingError> {
        let config = self.ring.require_config(client).await?;
        self.ring.require_active(client).await?;
        let mut staged = match self.rail.kind() {
            RailKind::Owner(owner) => boxed(|| owner.stage(self.ring, client, &config)).await?,
            RailKind::Anonymous(rail) => boxed(|| rail.stage(self.ring, client, &config)).await?,
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
            RailKind::Relayed(relayed) => {
                boxed(|| relayed.stage(self.ring, client, &config)).await?
            }
            RailKind::PublicOwners(public) => boxed(|| public.stage(self.ring, &config)).await?,
        };
        check_ring_output_markers(&staged.proof_inputs)?;
        staged.list_salts.extend_from_slice(&self.list_salts);
        let approval_blinder = match (self.rail.kind(), self.approval) {
            (RailKind::Relayed(relayed), _) => relayed.approval_blinder(),
            (RailKind::Delegated(_), _) | (_, ApprovalDisclosure::None) => None,
            (_, ApprovalDisclosure::Totals) => Some(random_field_element()),
        };
        boxed(|| {
            Pipeline {
                ring: self.ring,
                config,
                staged,
                co_signers: self.co_signers.clone(),
                priority_fee: self.priority_fee,
                approval_blinder,
            }
            .prepare(client)
        })
        .await
    }
}

struct Pipeline<'a> {
    ring: CustomRing,
    config: CustomRingConfig,
    staged: Staged<'a>,
    co_signers: Vec<Address>,
    priority_fee: Option<u64>,
    approval_blinder: Option<[u8; 32]>,
}

struct Frame {
    ring: CustomRing,
    ring_id: [u8; 32],
    proof_inputs: SppProofInputs,
    rail: RingOutputRail,
    sealed: SealedAudit,
    published_inputs: usize,
    policy: PolicyInputs,
    sender_pk_hash: [u8; 32],
    public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
    public_gross: [[u8; 32]; N_PUBLIC_SLOTS],
    parts: TransactParts,
    accounts: TransactAccounts,
    co_sign_demand: CoSignDemand,
    approval_opening: Option<ApprovalOpening>,
}

struct Unwitnessed<'a> {
    frame: Frame,
    config: CustomRingConfig,
    authority: TransferAuthority,
    spend: Spend<'a>,
    trees: SpendTrees,
    priority_fee: Option<u64>,
}

/// A transfer whose external data is final.
struct Sealed<'a, P = PolicyInputs> {
    pipeline: Pipeline<'a>,
    sealed: SealedAudit,
    trees: SpendTrees,
    preview: Preview,
    published_inputs: usize,
    policy: P,
}

trait Planned {
    fn plan(&self) -> PlannedTransfer;
}

impl Planned for PlannedTransfer {
    fn plan(&self) -> PlannedTransfer {
        *self
    }
}

impl Planned for PolicyInputs {
    fn plan(&self) -> PlannedTransfer {
        self.plan
    }
}

/// Staged and checked, the key it plans decides every stream counter.
struct Prepared<'a> {
    pipeline: Pipeline<'a>,
    trees: SpendTrees,
    preview: Preview,
    published_inputs: usize,
}

#[derive(Clone)]
struct Preview {
    rail: RingRail,
    in_proof_owner: Option<[u8; 32]>,
    public_owners: bool,
    n_in: u8,
    n_out: u8,
    trees: usize,
    expiry_unix_ts: u32,
    /// Past the sender bundle and ahead of the auditor's message.
    app_messages: Vec<OwnedAppMessage>,
    discloses_approval: bool,
    signer_data_counts: Option<SignerDataCounts>,
}

impl Preview {
    /// `key` sets the header's wide flag, every stream counter follows it.
    fn parts(
        &self,
        inputs: &SppProofInputs,
        rail: &RingOutputRail,
        sender: &ShieldedAddress,
        key: TransferKey,
    ) -> Result<TransactParts, RingError> {
        Ok(preview_parts(PreviewParts {
            preview: self,
            wide_owners: key.wide,
            inputs,
            published: &rail.published_slots(inputs, sender)?,
            sender_bundle: rail.published_sender(inputs, &sender.viewing_pubkey)?,
            tx_viewing_u: rail.tx_viewing_key().pubkey().u(),
            format: rail.format(),
        }))
    }
}

/// A transfer whose compact data is final but for its proofs.
pub(crate) struct Assembled {
    frame: Frame,
    config: Box<RingPolicy>,
    auditor: X25519Pubkey,
    spp: Spp,
    /// Hashed as the program rebuilds it.
    public_input_hash: [u8; 32],
    /// Zero off the anonymous frame.
    party_identities: [[u8; 32]; ANONYMOUS_PARTIES],
    /// The statement's sender identity, zero where the rail names none.
    sender: [u8; 32],
    bound: BoundState,
}

impl<'a> Pipeline<'a> {
    async fn prepare<R: AsyncRpc + ?Sized>(self, client: &R) -> Result<Prepared<'a>, RingError> {
        let Staged {
            mut proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed,
            list_salts,
        } = self.staged;
        let program = self.ring.program_id();
        let ring_rail = spend.rail();
        if rail.format() == DisclosureFormat::SingleAssetPayout && !matches!(spend, Spend::Owner) {
            return Err(RingError::ShapeUnkeyed { rail: ring_rail });
        }
        rail.check_format(&proof_inputs)?;
        // The compact data carries a u32 expiry, an unbounded one keeps its farthest value.
        let expiry_unix_ts =
            u32::try_from(proof_inputs.external_data.expiry_unix_ts).unwrap_or(u32::MAX);
        proof_inputs.external_data.expiry_unix_ts = u64::from(expiry_unix_ts);
        check_distinct(&proof_inputs.input_utxos)?;
        if ring_rail.is_delegate()
            && proof_inputs
                .external_data
                .interface_transfers
                .iter()
                .any(|transfer| transfer.is_deposit())
        {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }
        if matches!(spend, Spend::InProofOwner(_)) {
            if let Some(index) = default_ring_input(&proof_inputs.input_utxos) {
                return Err(RingError::InProofDefaultRingInput { index });
            }
        }
        check_membership(
            program,
            &proof_inputs.input_utxos,
            &proof_inputs.output_utxos,
        )?;
        let trees = spend_trees(
            client,
            &proof_inputs.input_utxos,
            proof_inputs.output_tree_id,
        )
        .await?;
        let shape = proof_inputs.check_shape()?;
        let n_in = shape_byte(shape.n_inputs(), ring_rail)?;
        let n_out = shape_byte(shape.n_outputs(), ring_rail)?;
        let published_inputs = proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .count();
        let preview = Preview {
            rail: ring_rail,
            in_proof_owner: spend.in_proof_owner()?,
            public_owners: matches!(spend, Spend::PublicOwners),
            n_in,
            n_out,
            trees: trees.inputs.len(),
            expiry_unix_ts,
            app_messages: proof_inputs
                .external_data
                .messages
                .iter()
                .skip(usize::from(ring_rail.anonymous_frame()))
                .map(|message| OwnedAppMessage {
                    view_tag: message.view_tag,
                    data: message.data.clone(),
                })
                .collect(),
            discloses_approval: self.approval_blinder.is_some(),
            signer_data_counts: signer_data_counts(&owner_signers, &proof_inputs.output_utxos)?,
        };

        Ok(Prepared {
            pipeline: Pipeline {
                priority_fee: self.priority_fee,
                approval_blinder: self.approval_blinder,
                ring: self.ring,
                config: self.config,
                co_signers: self.co_signers,
                staged: Staged {
                    proof_inputs,
                    rail,
                    sender,
                    authority,
                    owner_signers,
                    interface_transfer_accounts,
                    spend,
                    presealed,
                    list_salts,
                },
            },
            trees,
            preview,
            published_inputs,
        })
    }
}

impl<'a> Prepared<'a> {
    async fn read_policy<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        let staged = &self.pipeline.staged;
        let proof_inputs = &staged.proof_inputs;
        let public = public_slots(&proof_inputs.external_data.interface_transfers)?;
        let salts = KnownSalts::new(staged.list_salts.clone());
        let planner = self.planner()?;
        // A relayed frame arrives sealed, a read keeps it only under the row its owner sealed.
        let sealed = staged
            .presealed
            .as_ref()
            .map(|presealed| planner.plan_at(presealed.row))
            .transpose()?;
        PolicyRead {
            token_owner_hint: match &staged.spend {
                Spend::Anonymous(a) => a.token_owner,
                _ => None,
            },
            config: &self.pipeline.config,
            inputs: proof_inputs,
            public: &public,
            salts: &salts,
            planner,
            sealed,
        }
        .read(client)
        .await
    }

    fn planner(&self) -> Result<TransferPlanner<'_>, RingError> {
        let staged = &self.pipeline.staged;
        let proof_inputs = &staged.proof_inputs;
        let rail = self.preview.rail;
        // The program names the key from the legs its read screens, a ring reading no root
        // screens none and a deposit never counts.
        let legs = match RootRead::transfer(self.pipeline.config.account(), rail.is_delegate()) {
            RootRead::None => 0,
            RootRead::Own | RootRead::Policy => proof_inputs
                .external_data
                .interface_transfers
                .iter()
                .filter(|leg| !leg.is_deposit())
                .count(),
        };
        Ok(TransferPlanner {
            subjects: TransferSpend {
                format: staged.rail.format(),
                rail,
                inputs: self.published_inputs,
                outputs: usize::from(self.preview.n_out),
                spends_default_ring: spends_default_ring(&proof_inputs.input_utxos),
                legs,
                owners: owner_rows(rail, proof_inputs)?.len(),
                pools: RecordPools::default(),
                wide: false,
            },
            preview: &self.preview,
            inputs: proof_inputs,
            rail: &staged.rail,
            sender: &staged.sender,
            // A disclosed opening spans every slot of the key like a data tail, a key of another
            // output count would leave the opening's rows short of the digest it proves.
            spans_capacity: proof_inputs.output_utxos.iter().any(carries_data)
                || self.pipeline.approval_blinder.is_some(),
        })
    }

    /// The external data is final after the seal, the owner signs its message hash.
    fn seal<P: Planned>(self, policy: P) -> Result<Sealed<'a, P>, RingError> {
        let plan = policy.plan();
        let Prepared {
            pipeline,
            trees,
            preview,
            published_inputs,
        } = self;
        let Pipeline {
            ring,
            config,
            staged,
            co_signers,
            priority_fee,
            approval_blinder,
        } = pipeline;
        let Staged {
            mut proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed,
            list_salts,
        } = staged;
        let ring_rail = preview.rail;
        let auditor = config.auditor_pubkey;

        // The auditor message precedes every hash over the external data.
        let layout = plan.stream;
        let flags = preview
            .parts(&proof_inputs, &rail, &sender, plan.key)?
            .data()?
            .audit_layout();
        let sealed = match presealed {
            Some(presealed) => {
                let opened = presealed.open(layout, flags, &auditor)?;
                // The program expands the frame's viewing key, another costs a proof and fails the hash.
                if opened.eph_u != rail.tx_viewing_key().pubkey().u() {
                    return Err(RingError::RelayAuditorMessage);
                }
                opened
            }
            None => AuditSeal {
                rail: &rail,
                layout,
                flags,
                inputs: &proof_inputs,
                auditor: &auditor,
            }
            .seal()?,
        };
        proof_inputs
            .external_data
            .messages
            .push(sealed.message(&auditor));
        proof_inputs.external_data.instruction_discriminator = ring_rail.spp_tag();

        Ok(Sealed {
            pipeline: Pipeline {
                priority_fee,
                approval_blinder,
                ring,
                config,
                co_signers,
                staged: Staged {
                    proof_inputs,
                    rail,
                    sender,
                    authority,
                    owner_signers,
                    interface_transfer_accounts,
                    spend,
                    presealed: None,
                    list_salts,
                },
            },
            sealed,
            trees,
            preview,
            published_inputs,
            policy,
        })
    }
}

impl<'a> Sealed<'a> {
    async fn frame<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<Unwitnessed<'a>, RingError> {
        let Sealed {
            pipeline:
                Pipeline {
                    ring,
                    config: ring_config,
                    staged,
                    co_signers: supplied_co_signers,
                    priority_fee,
                    approval_blinder,
                },
            sealed,
            trees,
            preview,
            published_inputs,
            policy,
        } = self;
        let Staged {
            proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed: _,
            list_salts: _,
        } = staged;
        let config = &ring_config;
        let ring_rail = preview.rail;
        let ring_id = ring.ring_id()?;
        let public = public_slots(&proof_inputs.external_data.interface_transfers)?;
        let public_assets = public.asset_fields()?;
        let public_amount_fields = public.amount_fields()?;
        let public_gross = public.gross_fields();
        let sender_pk_hash = sender.signing_pubkey.owner_proof_input_hash()?;
        let delegate = match spend {
            Spend::Delegate { delegate, .. } => Some(delegate),
            Spend::Owner | Spend::InProofOwner(_) | Spend::Anonymous(_) | Spend::PublicOwners => {
                None
            }
        };
        let transfers = &proof_inputs.external_data.interface_transfers;
        let spends_note = proof_inputs
            .input_utxos
            .iter()
            .any(ClassifiedInput::is_note);
        let demand = match ring_rail.is_delegate() {
            true => CoSignDemand::NONE,
            false => CoSignOperation {
                spends_note,
                public_legs: public.classes(),
                approval: policy.approval,
            }
            .demand(),
        };
        let co_signers = CoSignerChoice {
            ring,
            config,
            demand,
            supplied: supplied_co_signers,
        }
        .resolve(client.zolana())
        .await?;
        let in_proof_owner = preview.in_proof_owner.map(Address::new_from_array);
        if co_signers.iter().any(|co_signer| {
            owner_signers.contains(co_signer) || in_proof_owner == Some(*co_signer)
        }) {
            return Err(CustomRingError::CoSignerIsOwner.into());
        }
        let anonymous = match &spend {
            Spend::Anonymous(anonymous) => Some(anonymous),
            Spend::Owner
            | Spend::InProofOwner(_)
            | Spend::PublicOwners
            | Spend::Delegate { .. } => None,
        };
        if let Some(anonymous) = anonymous {
            HiddenOwner::of(&anonymous.signer.public_key())?
                .check_signers(co_signers.iter().copied())?;
        }
        let authorization = spend.row_authorization();
        check_owner_capacity(&OwnerCapacity {
            rows: owner_signers.len() + authorization.unsigned_rows(),
            authorization,
            n_inputs: published_inputs,
            co_signers: co_signers.len(),
            legs: transfers.len(),
        })?;
        let accounts = TransactAccounts {
            payer: proof_inputs.payer,
            input_trees: trees.inputs.clone(),
            output_tree: trees.output,
            owner_signers,
            interface_transfer_accounts,
            read_cache: proof_inputs.cache_accounts.read,
            co_signers,
            delegate,
        };
        let mut parts = preview.parts(&proof_inputs, &rail, &sender, policy.plan.key)?;
        parts.seal_audit(sealed.envelope.clone(), &sealed.records, &sealed.tails);
        parts.approval = policy.approval;
        let approval_opening = match approval_blinder {
            Some(blinder) => {
                let totals = approval_totals_of(&proof_inputs, policy.plan.stream.capacity)?;
                parts.extensions.approval_totals = Some(totals.commitment(&blinder)?);
                Some(ApprovalOpening::of(&totals, &blinder))
            }
            None => None,
        };
        parts.tracking_revision = policy.tracking.revision;
        parts.own_revision = policy.own.map(|own| own.revision);
        parts.policy = (policy.read == RootRead::Policy).then(|| PolicyProof {
            curator_revision: policy.curator.map(|curator| curator.revision),
        });
        parts.spl_withdrawal_owners = policy.spl_withdrawal_owners.clone();
        if anonymous.is_some() {
            // SPP publishes the hidden owner's key exactly when it spends its own default-ring note.
            let hidden_default = proof_inputs.input_utxos.iter().any(|input| {
                audit::is_default_ring(input) && input.utxo.owner == sender.signing_pubkey
            });
            parts.anonymous = Some(compact::OwnedAnonymousProofData {
                commitment: [0; 32],
                commitment_pok: [0; 32],
                default_owner_tag: hidden_default
                    .then(|| sender.signing_pubkey.as_ed25519())
                    .transpose()?,
            });
        }
        let settlements: Vec<_> = transfers
            .iter()
            .map(|transfer| transfer.settlement_accounts())
            .collect();
        let settlement_views: Vec<Settlement<'_>> = settlements
            .iter()
            .map(|[asset_account, user_account]| Settlement {
                asset_account,
                user_account,
            })
            .collect();
        if parts
            .data()?
            .external_data_hash(config.account(), &settlement_views)?
            != proof_inputs.external_data.hash()?
        {
            return Err(RingError::ExternalDataMismatch);
        }
        let unwitnessed = Unwitnessed {
            frame: Frame {
                ring,
                ring_id,
                proof_inputs,
                rail,
                sealed,
                published_inputs,
                policy,
                sender_pk_hash,
                public_assets,
                public_amount_fields,
                public_gross,
                parts,
                accounts,
                co_sign_demand: demand,
                approval_opening,
            },
            config: ring_config,
            authority,
            spend,
            trees,
            priority_fee,
        };
        unwitnessed.check_size()?;
        Ok(unwitnessed)
    }
}

impl Unwitnessed<'_> {
    fn check_size(&self) -> Result<(), RingError> {
        let proof_inputs = &self.frame.proof_inputs;
        let budget = send_budget(
            match self.spend.rail().is_delegate() {
                true => InstructionTag::AuthorityTransfer,
                false => InstructionTag::Transfer,
            },
            self.priority_fee,
        );
        match check_transaction_size(&proof_inputs.payer, &self.instruction()?, budget) {
            Err(RingError::TransactionTooLarge { bytes, limit }) => {
                let shape = proof_inputs.check_shape()?;
                Err(RingError::TransferTooWide {
                    inputs: shape.n_inputs(),
                    outputs: shape.n_outputs(),
                    bytes,
                    limit,
                })
            }
            checked => checked,
        }
    }

    /// Sized as the proven instruction, the witness and the proofs fill fields of fixed width.
    fn instruction(&self) -> Result<Instruction, RingError> {
        let frame = &self.frame;
        frame
            .accounts
            .instruction(frame.ring, self.config.account(), &frame.parts)
    }

    async fn witness<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let Self {
            mut frame,
            config,
            authority,
            spend,
            trees,
            ..
        } = self;
        let ring = frame.ring;
        let exit_destination = match &spend {
            Spend::Anonymous(anonymous) => anonymous.exit_destination,
            Spend::Owner
            | Spend::InProofOwner(_)
            | Spend::PublicOwners
            | Spend::Delegate { .. } => None,
        };
        let party_identities = match frame.parts.rail.anonymous_frame() {
            true => AnonymousParties {
                payer: frame.proof_inputs.payer.as_array(),
                co_signers: &frame.accounts.co_signers,
                funders: &frame.accounts.deposit_funders(&frame.parts),
                exit_destination: exit_destination.as_ref().map(Address::as_array),
            }
            .identities()?,
            false => [[0; 32]; ANONYMOUS_PARTIES],
        };
        let spp = SppWitness {
            ring: ring.program_id(),
            rail: match spend.spp_rail() {
                SppRail::Delegate if frame.parts.outputs.iter().any(OwnedOutput::is_exit) => {
                    SppRail::DelegateExit
                }
                rail => rail,
            },
            owner_signers: &frame.accounts.owner_signers,
            inputs: &frame.proof_inputs,
            trees: &trees,
            authority: &authority,
        }
        .build(client)
        .await?;
        let private_tx_hash = spp.private_tx_hash();
        frame.parts.private_tx_hash = private_tx_hash;
        let auditor = config.auditor_pubkey;
        let parsed = ParsedTransact::new(frame.parts.data()?)?;
        // Only the in-proof owner is named, the signer set carries the signer rail's owners.
        let sender = match parsed.authorization() {
            CheckedAuthorization::ConfidentialInProof(_) => frame.sender_pk_hash,
            CheckedAuthorization::ConfidentialSigner
            | CheckedAuthorization::AnonymousHidden(_)
            | CheckedAuthorization::AnonymousPublic
            | CheckedAuthorization::Delegate
            | CheckedAuthorization::AnonymousDelegate => [0; 32],
        };
        let signers = SignerSet::new(
            frame.accounts.owner_signers.iter().map(Address::as_array),
            parsed.audit_stream().key.signer_slots(),
        )?;
        let public_input_hash = parsed
            .transfer_statement(TransferBinding {
                ring_id: &frame.ring_id,
                auditor_pubkey: auditor.as_bytes(),
                sender: &sender,
                signers,
                party_identities: &party_identities,
                roots: &frame.policy.roots(),
                public_assets: &frame.public_assets,
                public_amounts: &frame.public_amount_fields,
                public_gross: &frame.public_gross,
                withdrawal_hash: &frame.policy.withdrawal_hash()?,
            })?
            .hash()?;
        let bound = BoundState {
            roots: frame
                .policy
                .own
                .into_iter()
                .chain(frame.policy.curator)
                .chain([frame.policy.tracking])
                .collect(),
            policy: frame.policy.screened().then_some(BoundPolicy {
                ring,
                hash: frame.policy.policy_hash,
            }),
        };
        Ok(Assembled {
            frame,
            config: Box::new(*config.account()),
            auditor,
            spp,
            public_input_hash,
            party_identities,
            sender,
            bound,
        })
    }
}

#[cfg(test)]
impl Assembled {
    pub(crate) fn proof_inputs(&self) -> &SppProofInputs {
        &self.frame.proof_inputs
    }

    pub(crate) fn parts(&self) -> &TransactParts {
        &self.frame.parts
    }

    pub(crate) fn accounts(&self) -> &TransactAccounts {
        &self.frame.accounts
    }

    pub(crate) fn co_sign_demand(&self) -> CoSignDemand {
        self.frame.co_sign_demand
    }
}

impl Assembled {
    async fn prove<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        let (proven_spp, proof) = {
            let request = self.request()?;
            // Neither proof is an input to the other.
            futures::try_join!(
                boxed(|| self.spp.prove(client, self.frame.published_inputs)),
                boxed(|| request.prove(client)),
            )?
        };
        let Frame {
            ring,
            proof_inputs,
            rail,
            mut parts,
            accounts,
            co_sign_demand,
            approval_opening,
            policy,
            ..
        } = self.frame;
        parts.proof = proof;
        parts.spp_proof = proven_spp.proof;
        parts.nullifiers = proven_spp.nullifiers;
        parts.input_trees = proven_spp.input_trees;
        let commitment = proven_spp.commitment;
        if let Some(anonymous) = parts.anonymous.as_mut() {
            let commitment = commitment.ok_or(RingError::IncompleteProofSet)?;
            *anonymous = compact::OwnedAnonymousProofData {
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
                default_owner_tag: proven_spp.default_owner_tag,
            };
        }
        if let Some(owner) = parts.in_proof_owner.as_mut() {
            let commitment = commitment.ok_or(RingError::IncompleteProofSet)?;
            owner.commitment = commitment.commitment;
            owner.commitment_pok = commitment.commitment_pok;
        }
        let co_signers = accounts.co_signers.clone();
        Ok(ProvenRingTransfer {
            ring,
            config: self.config,
            bound: self.bound,
            parts,
            accounts,
            tx_viewing_key: rail.tx_viewing_key().clone(),
            outputs: proof_inputs.output_utxos,
            co_signers,
            co_sign_demand,
            approval_opening,
            charged_outflows: policy.charged_outflows,
        })
    }
}

impl ProvenRingTransfer {
    pub(crate) fn bound(&self) -> BoundState {
        self.bound.clone()
    }

    pub fn instruction(&self) -> Result<Instruction, RingError> {
        self.accounts
            .instruction(self.ring, &self.config, &self.parts)
    }

    /// The owners who sign the transaction in public, none on the anonymous and in-proof owner rails.
    pub fn owner_signers(&self) -> &[Address] {
        &self.accounts.owner_signers
    }

    /// Every tree SPP charges a fee to, see [`crate::written_tree_fees`].
    pub fn written_trees(&self) -> impl Iterator<Item = Address> + '_ {
        self.accounts
            .input_trees
            .iter()
            .copied()
            .chain([self.accounts.output_tree])
    }

    /// The keys that sign for a deposit leg, in leg order, the payer among them where it funds one.
    pub fn deposit_funders(&self) -> Vec<Address> {
        self.accounts
            .deposit_funders(&self.parts)
            .into_iter()
            .map(Address::new_from_array)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferKey {
    pub circuit: RingCircuit,
    pub wide: bool,
}

/// `None` when the catalog keys no transfer of `spend`.
pub fn transfer_key(spend: TransferSpend) -> Option<TransferKey> {
    let spend = spend.fitted();
    RingCircuit::transfer(spend).map(|circuit| TransferKey {
        circuit,
        wide: spend.wide,
    })
}

/// Whether `rail` keys a transfer of `shape` publishing every input, none a default-ring UTXO.
pub fn shape_keyed(rail: RingRail, shape: Shape) -> bool {
    keyed(rail, shape, false)
}

/// Whether an anonymous key serves a default-ring spend of `shape`.
pub fn entry_shape_keyed(shape: Shape) -> bool {
    keyed(RingRail::Anonymous, shape, true)
}

fn keyed(rail: RingRail, shape: Shape, spends_default_ring: bool) -> bool {
    rail.supports(shape)
        && transfer_key(TransferSpend {
            format: rail.disclosure_format(shape),
            rail,
            inputs: shape.n_inputs(),
            outputs: shape.n_outputs(),
            spends_default_ring,
            legs: 0,
            owners: 0,
            pools: RecordPools::default(),
            wide: false,
        })
        .is_some()
}

/// The compact data before any proof, sized and hashed as the proven one.
struct PreviewParts<'a> {
    preview: &'a Preview,
    wide_owners: bool,
    inputs: &'a SppProofInputs,
    published: &'a [PublishedSlot<'a>],
    sender_bundle: Option<FramedSenderBundle<'a>>,
    tx_viewing_u: [u8; 32],
    format: DisclosureFormat,
}

const UNSEALED_RECORD: [u8; AUDIT_RECORD_LEN] = [0; AUDIT_RECORD_LEN];

fn preview_parts(parts: PreviewParts<'_>) -> TransactParts {
    let preview = parts.preview;
    let external = &parts.inputs.external_data;
    let nullifiers = parts
        .inputs
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .map(SppProofInputUtxo::nullifier)
        .collect();
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    TransactParts {
        rail: preview.rail,
        n_in: preview.n_in,
        n_out: preview.n_out,
        proof: zeroed_proof(),
        tracking_revision: Default::default(),
        own_revision: None,
        policy: None,
        spl_withdrawal_owners: Vec::new(),
        approval: ApprovalMask::default(),
        // `R == 0`, an address spends no note and still needs SPP's authorization.
        no_spend: !parts
            .inputs
            .input_utxos
            .iter()
            .any(ClassifiedInput::is_note),
        public_owners: preview.public_owners,
        expiry_unix_ts: preview.expiry_unix_ts,
        tx_viewing_u: parts.tx_viewing_u,
        salt: external.salt,
        extensions: OwnedExtensions {
            format: parts.format,
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            messages: preview.app_messages.clone(),
            cache: cache_access(parts.inputs),
            // Sized here, `frame` writes the digest of the totals.
            approval_totals: preview.discloses_approval.then_some([0; 32]),
            signer_data_counts: preview.signer_data_counts,
        },
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        has_data: parts.inputs.output_utxos.iter().any(carries_data),
        entry: spends_default_ring(&parts.inputs.input_utxos),
        wide_owners: parts.wide_owners,
        outputs: parts
            .published
            .iter()
            .map(|slot| {
                OwnedOutput::of(slot.wire(&UNSEALED_RECORD[..parts.format.record_len()], None))
            })
            .collect(),
        replies: owned_replies(parts.published),
        sender: parts.sender_bundle.map(OwnedSenderBundle::of),
        envelope: Vec::new(),
        private_tx_hash: [0; 32],
        anonymous: None,
        in_proof_owner: preview.in_proof_owner.map(|owner| OwnedInProofOwner {
            owner,
            commitment: [0; 32],
            commitment_pok: [0; 32],
        }),
        spp_proof: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
        nullifiers,
        input_trees: match preview.trees {
            1 => InputTrees::One(context),
            _ => InputTrees::Two {
                first: context,
                second: context,
                second_inputs: 0,
            },
        },
    }
}

/// The cached selector of the slots a rail marked. Reads alone, a cached write refuses at staging.
fn cache_access(inputs: &SppProofInputs) -> Option<CacheAccess> {
    let read_bitmap = inputs
        .input_utxos
        .iter()
        .filter_map(|input| input.cache_slot)
        .fold(0u64, |bits, slot| bits | 1 << slot);
    (read_bitmap != 0).then_some(CacheAccess {
        read_bitmap,
        write_slots: CacheAccess::NO_WRITES,
    })
}

/// A key without data capacity holds every slot's data hashes to zero.
fn carries_data(output: &SppProofOutputUtxo) -> bool {
    !output.is_dummy()
        && [output.data_hash, output.ring_data_hash]
            .iter()
            .flatten()
            .any(|hash| *hash != [0; 32])
}

/// The frame's counts over the owner signer run, absent at zero since one statement value keeps one encoding.
/// SPP takes one owner signature for all its data-bearing slots, the circuit proves these counts so a
/// signer's check can notice a slot the sender left out of its terms. A wrong value fails the proof.
fn signer_data_counts(
    owner_signers: &[Address],
    outputs: &[SppProofOutputUtxo],
) -> Result<Option<SignerDataCounts>, RingError> {
    let run = owner_signers
        .iter()
        .map(|signer| Ok(solana_owner_identity(signer.as_array())?))
        .collect::<Result<Vec<_>, RingError>>()?;
    let slots = published_outputs(outputs)
        .iter()
        .filter(|output| !output.is_dummy())
        .filter_map(|output| Some((output.owner_address?, output.data_hash.unwrap_or_default())))
        .map(|(owner, data_hash)| Ok((owner.signing_pubkey.owner_proof_input_hash()?, data_hash)))
        .collect::<Result<Vec<_>, RingError>>()?;
    let counts = SignerDataCounts::of_run(
        &run,
        slots.iter().map(|(owner_identity, data_hash)| LiveSlot {
            owner_identity,
            data_hash,
        }),
    )?;
    Ok((counts != SignerDataCounts::default()).then_some(counts))
}

/// One length per frame, `None` without reply metadata.
fn owned_replies(published: &[PublishedSlot<'_>]) -> Option<(u16, Vec<u8>)> {
    let len = published.iter().map(|slot| slot.reply.len()).max()?;
    let region = published
        .iter()
        .flat_map(|slot| slot.reply)
        .copied()
        .collect();
    u16::try_from(len)
        .ok()
        .filter(|len| *len != 0)
        .map(|len| (len, region))
}

fn zeroed_proof() -> CustomRingProof {
    bytemuck::Zeroable::zeroed()
}

fn spends_default_ring(inputs: &[SppProofInputUtxo]) -> bool {
    default_ring_input(inputs).is_some()
}

/// SPP's anonymous rail publishes the hidden owner of a default-ring input.
fn default_ring_input(inputs: &[SppProofInputUtxo]) -> Option<usize> {
    inputs.iter().position(audit::is_default_ring)
}

struct DeliveredRail {
    outputs: usize,
    rail: RingRail,
}

impl DeliveredRail {
    fn delivery(self) -> Result<RingDelivery, RingError> {
        match TRANSFER_OUTPUT_CAPACITIES.contains(&self.outputs) {
            true => Ok(RingDelivery::Delivered),
            false => Err(RingError::ShapeUnkeyed { rail: self.rail }),
        }
    }
}

pub(crate) struct OwnerCapacity {
    pub rows: usize,
    pub authorization: RowAuthorization,
    pub n_inputs: usize,
    pub co_signers: usize,
    pub legs: usize,
}

pub(crate) fn check_owner_capacity(capacity: &OwnerCapacity) -> Result<(), RingError> {
    let limit = TransferAddresses {
        n_inputs: capacity.n_inputs,
        co_signers: capacity.co_signers,
        legs: capacity.legs,
    }
    .owner_rows(capacity.authorization);
    match capacity.rows > limit {
        true => Err(RingError::TooManyOwnerSigners {
            owners: capacity.rows,
            limit,
        }),
        false => Ok(()),
    }
}

fn shape_byte(count: usize, rail: RingRail) -> Result<u8, RingError> {
    u8::try_from(count).map_err(|_| RingError::ShapeUnkeyed { rail })
}

/// Each real input spends once, a repeated nullifier fails on chain after proving.
fn check_distinct(inputs: &[SppProofInputUtxo]) -> Result<(), RingError> {
    let real: Vec<_> = inputs.iter().filter(|input| !input.is_dummy()).collect();
    match real.iter().enumerate().find(|(index, input)| {
        real[..*index]
            .iter()
            .any(|earlier| earlier.nullifier == input.nullifier)
    }) {
        Some((_, input)) => Err(RingError::DuplicateInput {
            nullifier: input.nullifier,
        }),
        None => Ok(()),
    }
}

/// Every ring field names the transfer's ring, only a ring note carries ring data.
pub(crate) fn check_membership(
    program: Address,
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), RingError> {
    let slots = inputs
        .iter()
        .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
        .chain(
            outputs
                .iter()
                .map(|output| (output.ring_program_id, output.ring_data_hash)),
        );
    for (ring, data) in slots {
        match ring {
            Some(ring) if ring != program => return Err(RingError::ForeignRing(ring)),
            None if data.is_some() => return Err(RingError::RingDataOutsideRing),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn transaction_key(
    sender: &dyn RingSender,
    first_nullifier: [u8; 32],
) -> Result<ViewingKey, RingError> {
    let keys = sender.transaction_keys(&[spr_transaction::TransactionKeyRequest {
        viewing_pubkey: sender.address()?.viewing_pubkey,
        first_nullifier,
    }])?;
    Ok(zolana_ring_client::exactly_one(keys)?)
}

pub(crate) fn public_leg(transfer: &SettlementTransfer) -> PublicLeg {
    PublicLeg {
        transfer: transfer.interface_transfer(),
        mint: match transfer {
            SettlementTransfer::Spl { mint, .. } => Some(mint.to_bytes()),
            SettlementTransfer::Sol { .. } => None,
        },
    }
}

/// `capacity` is the selected key's `N`, the circuit commits every slot of it.
pub(crate) fn approval_totals_of(
    inputs: &SppProofInputs,
    capacity: usize,
) -> Result<ApprovalTotals, RingError> {
    read_outflows(inputs, |outflows| outflows.approval_totals(capacity))
}

pub(crate) fn charged_outflows_of(inputs: &SppProofInputs) -> Result<Vec<OwnerDebit>, RingError> {
    read_outflows(inputs, |outflows| outflows.flows())
}

/// The wallet and the relay read one layout, rows are the inputs' owners whatever their padding.
fn read_outflows<T>(
    inputs: &SppProofInputs,
    read: impl FnOnce(&Outflows<'_>) -> Result<T, RingError>,
) -> Result<T, RingError> {
    let public = public_slots(&inputs.external_data.interface_transfers)?;
    let senders = inputs
        .input_utxos
        .iter()
        .filter(|input| input.is_note())
        .map(|input| Ok(input.utxo.owner.owner_proof_input_hash()?))
        .collect::<Result<Vec<_>, RingError>>()?;
    read(&Outflows {
        senders: &senders,
        inputs: &inputs.input_utxos,
        outputs: &inputs.output_utxos,
        public_assets: &public.asset_fields()?,
        public_gross: &public.gross(),
    })
}

pub(crate) fn public_slots(transfers: &[SettlementTransfer]) -> Result<PublicSlots, RingError> {
    PublicSlots::fold(transfers.iter().map(|transfer| Ok(public_leg(transfer))))
}

/// A default-ring exit publishes its actual owner, the ring circuit burns an unmarked one.
fn check_ring_output_markers(inputs: &SppProofInputs) -> Result<(), RingError> {
    let external = &inputs.external_data;
    for (index, output) in inputs.output_utxos.iter().enumerate() {
        let Some(owner) = &output.owner_address else {
            continue;
        };
        let marked = external
            .outputs
            .get(index)
            .and_then(|slot| slot.data.as_deref())
            .is_some_and(is_confidential_encrypted_output);
        match (output.ring_program_id.is_some(), marked) {
            (true, false) => {}
            (false, true) => {
                let tag = external
                    .resolved_owner_tags
                    .get(index)
                    .ok_or(TransactionError::OwnerTagMismatch { slot_index: index })?;
                if solana_owner_identity(tag)? != owner.signing_pubkey.owner_proof_input_hash()? {
                    return Err(TransactionError::OwnerTagMismatch { slot_index: index }.into());
                }
            }
            _ => return Err(RingError::RingOutputMarkerMismatch { index }),
        }
    }
    Ok(())
}

/// The shape SPP's own finalization pads to.
pub(crate) fn canonical_shape(
    transaction: &ConfidentialTransaction,
    sender: &ShieldedAddress,
) -> Result<Shape, RingError> {
    let finalized = transaction.clone().finalize(sender)?;
    Ok(Shape::new(
        finalized.input_utxos().len(),
        finalized.output_utxos().len(),
    ))
}

/// The blinding seed is fixed once padded, the rail's goes in first.
pub(crate) fn pad_under_rail(
    transaction: ConfidentialTransaction,
    rail: &RingOutputRail,
    shape: Shape,
    sender: &ShieldedAddress,
) -> Result<ConfidentialTransaction, RingError> {
    let mut transaction = transaction.with_blinding_seed(rail.blinding_seed()?)?;
    transaction.pad_utxos(shape, sender)?;
    Ok(transaction)
}
