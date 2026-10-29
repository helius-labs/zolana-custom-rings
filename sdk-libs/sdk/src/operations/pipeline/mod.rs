//! One transfer pipeline for every rail, a rail only stages the transfer and seals its outputs.

mod anonymous;
mod audit;
mod compact;
mod delegate;
mod owner;
mod policy;
mod relay;
mod relayed;
mod selection;
mod spp;
#[cfg(test)]
#[path = "../../tests/operations/pipeline.rs"]
mod tests;
mod withdrawals;

use custom_ring_interface::{
    compute_unit_limit, cosign::CoSignDemand, stream::SenderCommitment, AuditBinding,
    CustomRingError, CustomRingProof, InputTrees, InstructionTag, ParsedTransact,
    PlainGroth16Proof, PublicLeg, PublicSlots, RingMode, RingProgramConfig, RingRail, SenderBundle,
    Settlement, CONFIDENTIAL_RING_MAX_INPUTS, DELIVERED_AUDIT_CAPACITIES,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{
    AsyncRpc, ClientError, ComputeBudgetConfig, ProofAuthority, Shape, TransferInput,
};
use spr_event::is_confidential_encrypted_output;
use spr_hasher::primitives::solana_owner_identity;
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
use zolana_ring_client::ViewingHistory;
use zolana_ring_keys::RingKeys;
use zolana_ring_transaction::{PublishedSlot, RingDelivery, RingOutputRail};

pub use self::{
    anonymous::{
        Anonymous, AnonymousMove, AnonymousPayment, AnonymousTransfer, EntrySpend, RingPayment,
    },
    delegate::{
        DelegateMove, DelegateOutput, DelegatePayment, DelegateTransfer, DelegateTransferInput,
        Delegated,
    },
    owner::{CustomRingTransfer, CustomRingTransferInput, Owner},
    relayed::{Relayed, RelayedTransfer, RelayedTransferInput},
};

pub(crate) use self::anonymous::HiddenOwner;

use self::{
    anonymous::{AnonymousKey, AnonymousSpend},
    audit::{AnonymousStatement, AuditProving, AuditSeal, PresealedAudit, SealedAudit},
    compact::{OwnedOutput, OwnedPolicyProof, OwnedSenderBundle, TransactAccounts, TransactParts},
    policy::{PolicyInputs, PolicyProving, PolicyRead},
    spp::{Spp, SppWitness},
};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    heap::boxed,
    projection::retry_projection_lag,
    submission::{check_transaction_size, BoundPolicy, BoundState},
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
}

#[must_use = "prove or discard the transfer explicitly"]
pub struct RingTransfer<R: Rail> {
    ring: CustomRing,
    rail: R,
    co_signer: Option<Address>,
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    ring: CustomRing,
    config: Box<RingProgramConfig>,
    parts: TransactParts,
    accounts: TransactAccounts,
    bound: BoundState,
    pub tx_viewing_key: ViewingKey,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The supplied co-signer when the ring demands one, it signs the transaction.
    pub co_signer: Option<Address>,
    pub co_sign_demand: CoSignDemand,
    /// The anonymous sender's viewing history past the transfer's tags.
    pub viewing_history: Option<ViewingHistory>,
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
}

pub(crate) enum Spend<'a> {
    Owner,
    Anonymous(Box<AnonymousSpend<'a>>),
    Delegate { delegate: Address },
}

impl Spend<'_> {
    fn rail(&self) -> RingRail {
        match self {
            Self::Owner => RingRail::Confidential,
            Self::Anonymous(_) => RingRail::Anonymous,
            Self::Delegate { .. } => RingRail::Delegate,
        }
    }
}

/// `None` only when every input is padding.
pub(crate) struct TransferAuthority {
    pub owner: Option<NullifierKey>,
}

impl ProofAuthority for TransferAuthority {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        match &self.owner {
            Some(owner) => owner.complete_inputs(inputs),
            None => Ok(()),
        }
    }
}

impl<R: Rail> RingTransfer<R> {
    pub fn ring(&self) -> CustomRing {
        self.ring
    }

    /// Read only when the ring demands a co-signer, its record must cover the demand.
    #[must_use = "use the updated transfer"]
    pub fn with_co_signer(mut self, signer: Address) -> Self {
        self.co_signer = Some(signer);
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
        let sealed = boxed(|| self.seal(client.zolana())).await?;
        boxed(|| sealed.frame(client)).await
    }

    /// Reads accounts only, no Merkle path and no record.
    async fn seal<C: AsyncRpc + ?Sized>(&self, client: &C) -> Result<Sealed<'_>, RingError> {
        let config = self.ring.require_config(client).await?;
        self.ring.require_active(client).await?;
        let staged = match self.rail.kind() {
            RailKind::Owner(owner) => boxed(|| owner.stage(self.ring, client, &config)).await?,
            RailKind::Anonymous(rail) => boxed(|| rail.stage(self.ring, client, &config)).await?,
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
            RailKind::Relayed(relayed) => {
                boxed(|| relayed.stage(self.ring, client, &config)).await?
            }
        };
        check_ring_output_markers(&staged.proof_inputs)?;
        boxed(|| {
            Pipeline {
                ring: self.ring,
                config,
                staged,
                co_signer: self.co_signer,
            }
            .seal(client)
        })
        .await
    }
}

struct Pipeline<'a> {
    ring: CustomRing,
    config: CustomRingConfig,
    staged: Staged<'a>,
    co_signer: Option<Address>,
}

struct Frame {
    ring: CustomRing,
    ring_id: [u8; 32],
    proof_inputs: SppProofInputs,
    rail: RingOutputRail,
    sender: ShieldedAddress,
    sealed: SealedAudit,
    published_inputs: usize,
    policy: Option<PolicyInputs>,
    withdrawal_exemption: Option<withdrawals::Exemption>,
    private_tx_blinding: [u8; 32],
    sender_pk_hash: [u8; 32],
    public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
    parts: TransactParts,
    accounts: TransactAccounts,
    co_signer: Option<Address>,
    co_sign_demand: CoSignDemand,
}

struct Unwitnessed<'a> {
    frame: Frame,
    config: CustomRingConfig,
    authority: TransferAuthority,
    spend: Spend<'a>,
    trees: SpendTrees,
}

/// A transfer whose external data is final, before any record read.
struct Sealed<'a> {
    pipeline: Pipeline<'a>,
    sealed: SealedAudit,
    trees: SpendTrees,
    preview: Preview,
    published_inputs: usize,
}

#[derive(Clone, Copy)]
struct Preview {
    rail: RingRail,
    key_escrow: bool,
    n_in: u8,
    n_out: u8,
    trees: usize,
    expiry_unix_ts: u32,
}

impl Preview {
    fn parts(
        self,
        inputs: &SppProofInputs,
        rail: &RingOutputRail,
        sender: &ShieldedAddress,
    ) -> Result<TransactParts, RingError> {
        Ok(preview_parts(PreviewParts {
            rail: self.rail,
            key_escrow: self.key_escrow,
            n_in: self.n_in,
            n_out: self.n_out,
            inputs,
            published: &rail.published_slots(inputs, sender)?,
            sender: rail.published_sender(inputs)?,
            trees: self.trees,
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_u: rail.tx_viewing_key().pubkey().u(),
        }))
    }
}

/// A transfer whose compact data is final but for its proofs.
pub(crate) struct Assembled {
    frame: Frame,
    config: Box<RingProgramConfig>,
    auditor: X25519Pubkey,
    spp: Spp,
    audit_public_input_hash: [u8; 32],
    anonymous: Option<AnonymousStatement>,
    policy_sender: [u8; 32],
    bound: BoundState,
    viewing_history: Option<ViewingHistory>,
}

impl<'a> Pipeline<'a> {
    /// The external data is final after the seal, the owner signs its message hash.
    async fn seal<R: AsyncRpc + ?Sized>(self, client: &R) -> Result<Sealed<'a>, RingError> {
        let Staged {
            mut proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed,
        } = self.staged;
        let config = &self.config;
        let program = self.ring.program_id();
        let ring_rail = spend.rail();
        // The compact data carries a u32 expiry, an unbounded one keeps its farthest value.
        let expiry_unix_ts =
            u32::try_from(proof_inputs.external_data.expiry_unix_ts).unwrap_or(u32::MAX);
        proof_inputs.external_data.expiry_unix_ts = u64::from(expiry_unix_ts);
        check_distinct(&proof_inputs.input_utxos)?;
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
        let auditor = config.auditor_pubkey;
        let preview = Preview {
            rail: ring_rail,
            key_escrow: config.mode == RingMode::ConfidentialEscrow,
            n_in,
            n_out,
            trees: trees.inputs.len(),
            expiry_unix_ts,
        };

        // The auditor message precedes every hash over the external data.
        let unsealed = preview.parts(&proof_inputs, &rail, &sender)?;
        let (layout, flags) = (
            unsealed.data().disclosure_layout()?,
            unsealed.data().audit_layout(),
        );
        let sealed = match presealed {
            Some(presealed) => presealed.open(layout, flags, &auditor)?,
            None => AuditSeal {
                rail: &rail,
                layout,
                flags,
                published: &rail.published_slots(&proof_inputs, &sender)?,
                inputs: &proof_inputs,
                sender: &sender,
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
                ring: self.ring,
                config: self.config,
                co_signer: self.co_signer,
                staged: Staged {
                    proof_inputs,
                    rail,
                    sender,
                    authority,
                    owner_signers,
                    interface_transfer_accounts,
                    spend,
                    presealed: None,
                },
            },
            sealed,
            trees,
            preview,
            published_inputs,
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
                    co_signer: supplied_co_signer,
                },
            sealed,
            trees,
            preview,
            published_inputs,
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
        } = staged;
        let config = &ring_config;
        let ring_rail = preview.rail;
        let (n_in, n_out) = (preview.n_in, preview.n_out);
        let ring_id = ring.ring_id()?;
        let public = public_slots(&proof_inputs.external_data.interface_transfers)?;
        let public_assets = public.asset_fields()?;
        let public_amounts = public.amounts();
        let public_amount_fields = public.amount_fields()?;
        let private_tx_blinding = proof_inputs.private_tx_blinding()?;
        let sender_pk_hash = sender.signing_pubkey.owner_proof_input_hash()?;
        let policy = match config.has_policy {
            true => Some(
                PolicyRead {
                    token_owner_hint: match &spend {
                        Spend::Anonymous(a) => a.token_owner,
                        _ => None,
                    },
                    ring,
                    config,
                    rail: ring_rail,
                    inputs: &proof_inputs,
                    n_in,
                    n_out,
                    sender: sender_pk_hash,
                    public_assets: &public_assets,
                    public_amounts: &public_amounts,
                }
                .read(client.zolana())
                .await?,
            ),
            false => None,
        };
        let approval_required = policy
            .as_ref()
            .is_some_and(|policy| policy.approval_required);
        let transfers = &proof_inputs.external_data.interface_transfers;
        let legs: Vec<_> = transfers.iter().map(public_leg).collect();
        let demand = CoSignDemand::transact(approval_required, &legs);
        let withdrawal_exemption = withdrawals::Exemption::read(
            ring,
            config,
            &demand,
            policy.as_ref().map(|policy| policy.own),
            client.zolana(),
        )
        .await?;
        let demand = match withdrawal_exemption {
            Some(_) => demand.exempt_withdrawals(),
            None => demand,
        };
        let co_signer = CoSignerChoice {
            ring,
            config,
            demand: &demand,
            supplied: supplied_co_signer,
        }
        .resolve(client.zolana())
        .await?;
        if co_signer.is_some_and(|co_signer| owner_signers.contains(&co_signer)) {
            return Err(CustomRingError::CoSignerIsOwner.into());
        }
        let delegate = match spend {
            Spend::Delegate { delegate } => Some(delegate),
            Spend::Owner | Spend::Anonymous(_) => None,
        };
        if co_signer.is_some() && co_signer == delegate {
            return Err(CustomRingError::CoSignerIsDelegate.into());
        }
        let anonymous = match &spend {
            Spend::Anonymous(anonymous) => Some(anonymous),
            Spend::Owner | Spend::Delegate { .. } => None,
        };
        let sender_commitment = match (anonymous.is_some(), &policy) {
            (true, Some(_)) => Some(
                SenderCommitment {
                    sender_pk_hash,
                    private_tx_blinding,
                }
                .derive()?,
            ),
            _ => None,
        };
        let accounts = TransactAccounts {
            payer: proof_inputs.payer,
            input_trees: trees.inputs.clone(),
            output_tree: trees.output,
            owner_signers,
            interface_transfer_accounts,
            policy: (config.has_policy || withdrawal_exemption.is_some())
                .then(|| ring.policy_pda()),
            co_signer,
            delegate,
        };
        let mut parts = preview.parts(&proof_inputs, &rail, &sender)?;
        parts.eph_u = sealed.eph_u;
        parts.sealed = sealed.sealed;
        parts.disclosure = sealed.fields.clone();
        parts.approval_required = approval_required;
        parts.withdrawal_exemption = withdrawal_exemption.as_ref().map(|exemption| {
            custom_ring_interface::WithdrawalExemptionProof {
                proof: zeroed_proof(),
                own_revision: exemption.root.revision,
            }
        });
        parts.policy = policy.as_ref().map(|policy| OwnedPolicyProof {
            spl_withdrawal_owners: policy.spl_withdrawal_owners.clone(),
            proof: zeroed_proof(),
            own_revision: policy.own.revision,
            curator_revision: policy.curator.map(|curator| curator.revision),
            sender_commitment,
            recipients: match ring_rail.publishes_recipients() {
                true => policy.recipients.clone(),
                false => Vec::new(),
            },
        });
        if anonymous.is_some() {
            parts.anonymous = Some(compact::OwnedAnonymousProofData {
                commitment: [0; 32],
                commitment_pok: [0; 32],
                // SPP publishes the hidden owner's key exactly when it spends a default-ring note.
                default_owner_tag: parts
                    .full_openings
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
            .data()
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
                sender,
                sealed,
                published_inputs,
                policy,
                withdrawal_exemption,
                private_tx_blinding,
                sender_pk_hash,
                public_assets,
                public_amount_fields,
                parts,
                accounts,
                co_signer,
                co_sign_demand: demand,
            },
            config: ring_config,
            authority,
            spend,
            trees,
        };
        check_transaction_size(
            &unwitnessed.frame.proof_inputs.payer,
            &unwitnessed.instruction()?,
            ComputeBudgetConfig::new(compute_unit_limit(match ring_rail {
                RingRail::Delegate => InstructionTag::DelegateTransact,
                RingRail::Confidential | RingRail::Anonymous => InstructionTag::Transact,
            })),
        )?;
        Ok(unwitnessed)
    }
}

impl Unwitnessed<'_> {
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
        } = self;
        let ring = frame.ring;
        let ring_rail = spend.rail();
        let anonymous = match &spend {
            Spend::Anonymous(anonymous) => Some(anonymous),
            Spend::Owner | Spend::Delegate { .. } => None,
        };
        let party_identities = anonymous
            .map(|anonymous| anonymous.party_identities(frame.co_signer))
            .transpose()?;
        let hidden = anonymous.map(|anonymous| anonymous.hidden());
        let spp = SppWitness {
            ring: ring.program_id(),
            rail: ring_rail,
            inputs: &frame.proof_inputs,
            trees: &trees,
            authority: &authority,
            hidden,
        }
        .build(client)
        .await?;
        let private_tx_hash = spp.private_tx_hash();
        frame.parts.private_tx_hash = private_tx_hash;
        let auditor = config.auditor_pubkey;
        let audit_public_input_hash = ParsedTransact::new(frame.parts.data())?
            .audit_statement(AuditBinding {
                party_identities: &party_identities.unwrap_or_default(),
                ring_id: &frame.ring_id,
                auditor_pubkey: auditor.as_bytes(),
                key_escrow: frame.parts.key_escrow,
            })?
            .hash()?;
        let sender_commitment = frame
            .parts
            .policy
            .as_ref()
            .and_then(|policy| policy.sender_commitment);
        let statement = party_identities.map(|party_identities| AnonymousStatement {
            party_identities,
            private_tx_hash,
            private_tx_blinding: frame.private_tx_blinding,
            sender_commitment: sender_commitment.unwrap_or_default(),
        });
        let viewing_history = anonymous.and_then(|anonymous| anonymous.history.clone());
        let bound = BoundState {
            roots: frame
                .policy
                .iter()
                .flat_map(|policy| {
                    core::iter::once(policy.own).chain(policy.curator)
                })
                .chain(
                    frame
                        .withdrawal_exemption
                        .iter()
                        .map(|exemption| exemption.root),
                )
                .collect(),
            policy: frame.policy.as_ref().map(|policy| BoundPolicy {
                ring,
                hash: policy.policy_hash,
            }),
            queue: None,
        };
        let policy_sender = match (ring_rail, sender_commitment) {
            (RingRail::Delegate, _) => [0; 32],
            (_, Some(commitment)) => commitment,
            (_, None) => frame.sender_pk_hash,
        };
        Ok(Assembled {
            frame,
            config: Box::new(*config.account()),
            auditor,
            spp,
            audit_public_input_hash,
            anonymous: statement,
            policy_sender,
            bound,
            viewing_history,
        })
    }
}

impl Assembled {
    pub(crate) fn audit(&self) -> Result<AuditProving<'_>, RingError> {
        let frame = &self.frame;
        Ok(AuditProving {
            rail: &frame.rail,
            sealed: &frame.sealed,
            published: frame
                .rail
                .published_slots(&frame.proof_inputs, &frame.sender)?,
            inputs: &frame.proof_inputs,
            n_out: frame.parts.n_out,
            sender: &frame.sender,
            auditor: &self.auditor,
            ring_id: frame.ring_id,
            public_input_hash: self.audit_public_input_hash,
            anonymous: self.anonymous.as_ref(),
        })
    }

    fn policy_proving(&self) -> PolicyProving<'_> {
        let frame = &self.frame;
        PolicyProving {
            ring_id: frame.ring_id,
            rail: frame.parts.rail,
            inputs: &frame.proof_inputs,
            private_tx_hash: frame.parts.private_tx_hash,
            private_tx_blinding: frame.private_tx_blinding,
            sender: self.policy_sender,
            sender_pk_hash: frame.sender_pk_hash,
            public_assets: frame.public_assets,
            public_amount_fields: frame.public_amount_fields,
        }
    }

    /// `None` on a ring without a policy.
    #[cfg(test)]
    pub(crate) fn policy_request(&self) -> Result<Option<policy::PolicyRequest<'_>>, RingError> {
        self.frame
            .policy
            .as_ref()
            .map(|policy| policy.request(&self.policy_proving()))
            .transpose()
    }

    async fn prove<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        let audit = self.audit()?;
        let frame = &self.frame;
        let policy_proving = self.policy_proving();
        let policy_proof = async {
            match &frame.policy {
                Some(policy) => Ok(Some(policy.prove(client, &policy_proving).await?)),
                None => Ok::<_, RingError>(None),
            }
        };
        let withdrawal_proof = async {
            match &frame.withdrawal_exemption {
                Some(exemption) => Ok(Some(exemption.prove(client).await?)),
                None => Ok::<_, RingError>(None),
            }
        };
        // No proof is an input to another, every request goes out at once.
        let (proven_spp, audit_proof, policy_proof, withdrawal_proof) = futures::try_join!(
            boxed(|| self.spp.prove(client, frame.published_inputs)),
            boxed(|| audit.prove(client)),
            boxed(|| policy_proof),
            boxed(|| withdrawal_proof),
        )?;
        let Frame {
            ring,
            proof_inputs,
            rail,
            mut parts,
            accounts,
            co_signer,
            co_sign_demand,
            ..
        } = self.frame;
        parts.audit_proof = audit_proof;
        if let (Some(owned), Some(proof)) = (parts.policy.as_mut(), policy_proof) {
            owned.proof = proof;
        }
        if let (Some(owned), Some(proof)) = (parts.withdrawal_exemption.as_mut(), withdrawal_proof)
        {
            owned.proof = proof;
        }
        parts.spp_proof = proven_spp.proof;
        parts.nullifiers = proven_spp.nullifiers;
        parts.input_trees = proven_spp.input_trees;
        if parts.anonymous.is_some() {
            parts.anonymous = proven_spp.anonymous;
        }
        Ok(ProvenRingTransfer {
            ring,
            config: self.config,
            bound: self.bound,
            parts,
            accounts,
            tx_viewing_key: rail.tx_viewing_key().clone(),
            outputs: proof_inputs.output_utxos,
            co_signer,
            co_sign_demand,
            viewing_history: self.viewing_history,
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

    /// The owners who sign the transaction in public, none on the anonymous rail.
    pub fn owner_signers(&self) -> &[Address] {
        &self.accounts.owner_signers
    }
}

/// Whether `rail` keys a transfer of `shape` publishing every input, none a default-ring UTXO.
pub fn shape_keyed(rail: RingRail, shape: Shape) -> bool {
    let capacity = DELIVERED_AUDIT_CAPACITIES.contains(&shape.n_outputs());
    match rail {
        RingRail::Confidential => {
            capacity && shape.is_supported() && shape.n_inputs() <= CONFIDENTIAL_RING_MAX_INPUTS
        }
        RingRail::Delegate => capacity && shape.is_ring_authority(),
        RingRail::Anonymous => AnonymousKey::Commitment.serves(shape),
    }
}

/// The compact data before any proof, sized and hashed as the proven one.
struct PreviewParts<'a> {
    rail: RingRail,
    key_escrow: bool,
    n_in: u8,
    n_out: u8,
    inputs: &'a SppProofInputs,
    published: &'a [PublishedSlot<'a>],
    sender: Option<SenderBundle<'a>>,
    trees: usize,
    expiry_unix_ts: u32,
    tx_viewing_u: [u8; 32],
}

fn preview_parts(preview: PreviewParts<'_>) -> TransactParts {
    let external = &preview.inputs.external_data;
    let nullifiers = preview
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
        audit_proof: zeroed_proof(),
        policy: None,
        withdrawal_exemption: None,
        approval_required: false,
        expiry_unix_ts: preview.expiry_unix_ts,
        tx_viewing_u: preview.tx_viewing_u,
        salt: external.salt,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        key_escrow: preview.key_escrow,
        full_openings: preview.rail == RingRail::Anonymous
            && spends_default_ring(&preview.inputs.input_utxos),
        outputs: preview
            .published
            .iter()
            .map(|slot| OwnedOutput::of(slot.wire))
            .collect(),
        sender: preview.sender.map(OwnedSenderBundle::of),
        eph_u: [0; 32],
        sealed: [0; 32],
        disclosure: Vec::new(),
        private_tx_hash: [0; 32],
        anonymous: None,
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

fn zeroed_proof() -> CustomRingProof {
    bytemuck::Zeroable::zeroed()
}

fn spends_default_ring(inputs: &[SppProofInputUtxo]) -> bool {
    inputs
        .iter()
        .any(|input| !input.is_dummy() && input.utxo.ring_program_id.is_none())
}

fn delivered(outputs: usize, rail: RingRail) -> Result<RingDelivery, RingError> {
    match DELIVERED_AUDIT_CAPACITIES.contains(&outputs) {
        true => Ok(RingDelivery::Delivered),
        false => Err(RingError::ShapeUnkeyed { rail }),
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
