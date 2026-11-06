//! The record opens the merged note for its auditor.

use custom_ring_interface::{
    key_catalog::RingCircuit, AuditRecord, CustomRingMergeIxData, InstructionTag, MergePublicInput,
    OpeningRecord, RecordKind, RingMode, SealedMergeRecord, OPENING_RECORD_LEN,
    TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;
use spr_client::{AsyncRpc, AsyncWitnessReader, ComputeBudgetConfig, MergeProver, ProofCompressed};
use spr_hasher::primitives::{hash_bytes, pack_be, right_align, solana_owner_identity};
use spr_indexer_api::SerializablePubkey;
use spr_interface::{
    instruction::instruction_data::{
        merge_ring::MergeRingAuthority,
        merge_transact::{
            MergeOutputEncryption, MergeProof, MergeTransactIxData, MERGE_SUPPORTED_INPUT_COUNTS,
        },
    },
    tree_slot::tree_id_field,
    ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress};
use spr_program::instruction::MergeRing;
use spr_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::SppProofInputUtxo,
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayMergeInputs, RelayQuote},
    MergeRecordSeal,
};
use zolana_ring_keys::{MergeSeedHolder, MergeSeedRequest};

use crate::client::{RingClient, RingIndexerBackend};
use crate::relay_message::MessageMismatch;
use crate::{
    pipeline::HiddenOwner,
    prover::{to_instruction_proof, RingRequest},
    records::TrackingMemberRead,
    request::{self, MergeRequest, TrackingOpeningRequest},
    submission::{check_transaction_size, send_budget, BoundRoot},
    tree_id, CustomRing, CustomRingConfig, PreparedRelay, RingError,
};

pub use spr_transaction::instructions::merge::MERGE_DEFAULT_INPUT_COUNT;
/// The widest SPP circuit, [`FittedMerge`] finds what one transaction carries.
pub const MAX_RING_MERGE_INPUTS: usize = MERGE_SUPPORTED_INPUT_COUNTS[2];

#[must_use]
#[derive(Clone)]
pub struct CustomRingMerge {
    ring: CustomRing,
    inner: MergeTransaction,
    first_nullifier: [u8; 32],
}

/// The longest prefix of `inputs` whose merge fits one transaction, compact padding publishes nothing.
#[must_use]
pub struct FittedMerge<'a, K: ?Sized> {
    pub ring: CustomRing,
    pub inputs: Vec<WalletUtxo>,
    pub output_tree_id: u16,
    pub keys: &'a K,
    pub proof_input: &'a MergeProofInput,
    pub payer: Address,
}

impl<K: ShieldedKeys + MergeSeedHolder + ?Sized> FittedMerge<'_, K> {
    /// The size refusal of the shortest mergeable prefix when none fits.
    pub async fn prepare(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedCustomRingMerge, RingError> {
        let config = self.ring.require_config(rpc).await?;
        let budget = send_budget(InstructionTag::Merge, None);
        let site = MergeSite {
            ring: self.ring,
            input: self.proof_input,
            payer: self.payer,
            config: &config,
        };
        // 1. Every input is validated, a note past the fitted prefix refuses as one inside it would.
        let whole = CustomRingMerge::new(self.ring, self.inputs.clone(), None)?;
        // 2. The first input's key picks the rail, a zero-key owner adds its signature and account.
        let first = self.inputs.first().ok_or(TransactionError::NoInputs)?;
        let zero_key = first.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY;
        let owner = match zero_key {
            true => Some(public_owner(&first.utxo.owner)?),
            false => None,
        };
        // 3. Only the published nullifiers and the owner account change the size, fitted before the
        // holder derives a secret. A remote holder answers once for the chosen prefix.
        let mut count = self.inputs.len();
        while count > MIN_MERGE_INPUTS {
            let nullifiers = self.inputs[..count]
                .iter()
                .map(|input| input.nullifier)
                .collect();
            match site.check_size(MergeLayout::unsealed(owner, nullifiers), budget) {
                Ok(()) => break,
                Err(RingError::TransactionTooLarge { .. } | RingError::TooManyAddresses { .. }) => {
                    count -= 1
                }
                Err(refusal) => return Err(refusal),
            }
        }
        let merge = match count == self.inputs.len() {
            true => whole,
            false => {
                let mut inputs = self.inputs;
                inputs.truncate(count);
                CustomRingMerge::new(self.ring, inputs, None)?
            }
        }
        .with_output_tree_id(self.output_tree_id);
        let prepared = match zero_key {
            true => merge.encrypt_zero_key(
                self.keys,
                &ShieldedAddress {
                    nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
                    ..self.keys.address()?
                },
            )?,
            false => merge.encrypt(self.keys)?,
        };
        // 4. One exact check of the sealed bytes, it also refuses the shortest prefix when none fits.
        site.check_size(prepared.layout()?, budget)?;
        Ok(prepared)
    }
}

const MIN_MERGE_INPUTS: usize = 2;

impl CustomRingMerge {
    pub fn new(
        ring: CustomRing,
        inputs: Vec<WalletUtxo>,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        let first_nullifier = inputs.first().ok_or(TransactionError::NoInputs)?.nullifier;
        let inner =
            MergeTransaction::new_with_ring(inputs, ring.program_id(), output_ring_data_hash)?;
        Ok(Self {
            ring,
            inner,
            first_nullifier,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_unix_ts);
        self
    }

    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.inner = self.inner.with_output_tree_id(tree_id);
        self
    }

    /// The key's secret seeds every derivation.
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        keys: &K,
    ) -> Result<PreparedCustomRingMerge, TransactionError> {
        Ok(PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.encrypt(keys)?,
            priority_fee: None,
        })
    }

    /// The owner signs the merge in public, nothing selects a zero-key merge.
    pub fn encrypt_zero_key<H: MergeSeedHolder + ?Sized>(
        self,
        holder: &H,
        owner: &ShieldedAddress,
    ) -> Result<PreparedCustomRingMerge, RingError> {
        if owner.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY {
            return Err(RingError::MergeOwnerKey);
        }
        let seed = zolana_ring_client::exactly_one(holder.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: owner.viewing_pubkey,
            ring_program_id: self.ring.program_id(),
            first_nullifier: self.first_nullifier,
        }])?)?;
        Ok(PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.encrypt_zero_key(owner, seed)?,
            priority_fee: None,
        })
    }
}

/// Compact-padded to its circuit width.
#[must_use]
#[derive(Clone)]
pub struct PreparedCustomRingMerge {
    pub(crate) ring: CustomRing,
    pub(crate) inner: MergeProofInputs,
    pub(crate) priority_fee: Option<u64>,
}

#[derive(Clone)]
pub struct MergeProofInput {
    pub nullifier_key: NullifierKey,
    pub input_tree: Address,
    pub output_tree: Address,
}

pub struct ProvenCustomRingMerge {
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    tracking_registry: Address,
    /// Signs a zero-key merge.
    owner: Option<Address>,
    /// `None` under a zero key, the program reads no tracking root.
    bound: Option<BoundRoot>,
    pub data: CustomRingMergeIxData,
    pub output_hash: [u8; 32],
    pub input_count: usize,
    pub merged_amount: u64,
}

impl PreparedCustomRingMerge {
    /// Lamports the v1 header carries, the size check measures the header it adds.
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    pub const fn ring(&self) -> CustomRing {
        self.ring
    }

    /// Compact padding publishes no nullifier.
    pub fn published_inputs(&self) -> usize {
        self.inputs()
            .iter()
            .filter(|input| !input.is_compact())
            .count()
    }

    pub fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inner.input_utxos
    }

    pub const fn output(&self) -> &SppProofOutputUtxo {
        &self.inner.output_utxo
    }

    /// The zero-key owner signs in public, a keyed owner stays hidden on an anonymous ring.
    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
        config: &CustomRingConfig,
    ) -> Result<(), RingError> {
        if config.mode != RingMode::Anonymous || self.signing_owner()?.is_some() {
            return Ok(());
        }
        self.hidden_owner()?.check_signers(signers)
    }

    /// `Some` exactly on the zero-key rail.
    pub(crate) fn signing_owner(&self) -> Result<Option<Address>, RingError> {
        match self.inner.merge_seed {
            Some(_) => public_owner(&self.inner.signing_pubkey).map(Some),
            None => Ok(None),
        }
    }

    /// A keyed merge proves the nullifier secret and no EdDSA signature, a PDA owner qualifies.
    fn hidden_owner(&self) -> Result<HiddenOwner, RingError> {
        public_owner(&self.inner.signing_pubkey).map(HiddenOwner)
    }

    fn check_width(&self) -> Result<(), RingError> {
        let width = self.inner.input_utxos.len();
        match MERGE_SUPPORTED_INPUT_COUNTS.contains(&width) {
            true => Ok(()),
            false => Err(RingError::MergeTooWide { width }),
        }
    }

    /// The instruction under zeroed proofs, the size of the proven one.
    pub(crate) fn preview_instruction(
        &self,
        input: &MergeProofInput,
        payer: Address,
        config: &CustomRingConfig,
    ) -> Result<Instruction, RingError> {
        MergeSite {
            ring: self.ring,
            input,
            payer,
            config,
        }
        .instruction(self.layout()?)
    }

    fn layout(&self) -> Result<MergeLayout, RingError> {
        let inner = &self.inner;
        Ok(MergeLayout {
            owner: self.signing_owner()?,
            nullifiers: inner
                .input_utxos
                .iter()
                .filter(|input| !input.is_compact())
                .map(|input| input.nullifier)
                .collect(),
            expiry_unix_ts: inner.expiry_unix_ts,
            output_ring_data_hash: inner.output_utxo.ring_data_hash.unwrap_or_default(),
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: inner.output_ciphertext_salt,
                ciphertext: inner.output_ciphertext,
            },
        })
    }

    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        mut self,
        input: MergeProofInput,
        payer: Address,
        client: &RingClient<R, I>,
    ) -> Result<ProvenCustomRingMerge, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        self.ring.require_active(client.zolana()).await?;
        let owner = self.signing_owner()?;
        // A keyed owner stays apart from the payer.
        if owner.is_none() {
            self.hidden_owner()?.check_signers([payer])?;
        }
        self.check_width()?;
        check_transaction_size(
            &payer,
            &self.preview_instruction(&input, payer, &config)?,
            send_budget(InstructionTag::Merge, self.priority_fee),
        )?;
        let owner_pk_hash = self.inner.signing_pubkey.owner_proof_input_hash()?;
        let tracking = match owner {
            Some(_) => None,
            None => {
                let root = BoundRoot::tracking(config.account(), client.zolana()).await?;
                let opening = TrackingMemberRead {
                    root,
                    member: owner_pk_hash,
                }
                .read(client.zolana())
                .await?;
                Some((root, opening))
            }
        };
        let input_tree_id = tree_id(client.zolana(), input.input_tree).await?;
        if self
            .inner
            .input_utxos
            .iter()
            .any(|utxo| !utxo.is_dummy() && utxo.tree_id != input_tree_id)
        {
            return Err(RingError::InputTreeMismatch);
        }
        self.inner.output_tree_id = tree_id(client.zolana(), input.output_tree).await?;
        let commitments = self.inner.input_utxo_hashes()?;
        let witnesses = AsyncWitnessReader::input_witnesses(
            client.indexer(),
            &commitments,
            &self.inner.dummy_nullifiers(),
            None,
        )
        .await?;
        let result = MergeProver {
            transaction: self.inner.clone(),
            nullifier_key: input.nullifier_key.clone(),
            proofs: witnesses.spend_proofs,
            dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
            cache: None,
        }
        .build()?;
        let proof = client.prover().prove_merge_ring(&result.inputs).await?;
        let data =
            result.ring_instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?);
        let inner = &self.inner;
        let output = &inner.output_utxo;
        let mint = output.asset.asset.to_bytes();
        let owner_key = request::owner_key(&inner.signing_pubkey)?;
        let seed = inner.seed(&input.nullifier_key)?;
        let sealed = MergeRecordSeal {
            record: OpeningRecord {
                record: AuditRecord {
                    kind: RecordKind::Ring,
                    amount: output.amount,
                    owner_key,
                    mint,
                    nullifier_pk: inner
                        .output_utxo
                        .owner_address
                        .map(|owner| owner.nullifier_pubkey)
                        .unwrap_or_default(),
                },
                secret: *seed.as_bytes(),
            },
        }
        .seal(&config.auditor_pubkey)?;
        let first_nullifier = *data
            .merge
            .nullifiers
            .first()
            .ok_or(TransactionError::NoInputs)?;
        let ring_id = self.ring.ring_id()?;
        let payer_identity = solana_owner_identity(payer.as_array())?;
        let tracking_root = tracking.as_ref().map_or([0; 32], |(root, _)| root.root);
        let published_owner = match owner {
            Some(_) => owner_pk_hash,
            None => [0; 32],
        };
        let auditor = config.auditor_pubkey;
        let public_input_hash = MergePublicInput {
            output_utxo_hash: &data.merge.output_utxo_hash,
            first_nullifier: &first_nullifier,
            ring_id: &ring_id,
            auditor_pk: auditor.as_bytes(),
            eph_pk: sealed.eph_pk.as_bytes(),
            ciphertext: &sealed.ciphertext,
            payer: &payer_identity,
            published_owner: &published_owner,
            tracking_root: &tracking_root,
        }
        .hash()?;
        let body = MergeRequest {
            public_input_hash,
            output_utxo_hash: data.merge.output_utxo_hash,
            first_nullifier,
            ring_program_id: ring_id,
            auditor_pk: auditor,
            payer: payer_identity,
            tracking_root,
            eph_sk: sealed.ephemeral_sk,
            owner_key,
            owner_pk_hash,
            mint_chunks: pack_be::<32, 2>(&mint),
            asset: hash_bytes(&mint)?,
            amount: right_align(&output.amount.to_be_bytes()),
            nullifier_pk: output
                .owner_address
                .map(|owner| owner.nullifier_pubkey)
                .unwrap_or_default(),
            seed: Zeroizing::new(*seed.as_bytes()),
            output_tree_id: tree_id_field(inner.output_tree_id),
            output_ring_data_hash: output.ring_data_hash.unwrap_or_default(),
            tracking: tracking
                .as_ref()
                .map(|(_, opening)| TrackingOpeningRequest::from(opening)),
        };
        let proof = RingRequest::new(RingCircuit::Merge, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(ProvenCustomRingMerge {
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            ring: self.ring,
            tracking_registry: config.account().tracking,
            owner,
            bound: tracking.as_ref().map(|(root, _)| *root),
            data: CustomRingMergeIxData {
                tracking_revision: tracking
                    .as_ref()
                    .map_or_else(Default::default, |(root, _)| root.revision),
                output_ring_data_hash: data.output_ring_data_hash,
                authority: data.authority,
                sealed: SealedMergeRecord {
                    proof: to_instruction_proof(proof)?,
                    eph_pk: *sealed.eph_pk.as_bytes(),
                    ciphertext: sealed.ciphertext,
                },
                merge: data.merge,
            },
            output_hash: inner.output_hash()?,
            input_count: inner
                .input_utxos
                .iter()
                .filter(|utxo| !utxo.is_dummy())
                .count(),
            merged_amount: output.amount,
        })
    }
}

#[derive(Clone, Copy)]
struct MergeSite<'a> {
    ring: CustomRing,
    input: &'a MergeProofInput,
    payer: Address,
    config: &'a CustomRingConfig,
}

/// Every proof, hash and record beside these fields is fixed width.
struct MergeLayout {
    /// Signs a zero-key merge.
    owner: Option<Address>,
    nullifiers: Vec<[u8; 32]>,
    expiry_unix_ts: u64,
    output_ring_data_hash: [u8; 32],
    output_encryption: MergeOutputEncryption,
}

impl MergeLayout {
    /// Sealed fields at their fixed width, values arbitrary.
    fn unsealed(owner: Option<Address>, nullifiers: Vec<[u8; 32]>) -> Self {
        Self {
            owner,
            nullifiers,
            expiry_unix_ts: u64::MAX,
            output_ring_data_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: Default::default(),
                ciphertext: Default::default(),
            },
        }
    }
}

impl MergeSite<'_> {
    /// Zeroed proofs, hashes and record keep the proven instruction's size.
    fn instruction(self, layout: MergeLayout) -> Result<Instruction, RingError> {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: self.input.input_tree,
            output_tree: self.input.output_tree,
            payer: self.payer,
            tracking_registry: self.config.account().tracking,
            owner: layout.owner,
            data: CustomRingMergeIxData {
                tracking_revision: Default::default(),
                output_ring_data_hash: layout.output_ring_data_hash,
                authority: authority_of(layout.owner),
                sealed: SealedMergeRecord {
                    proof: bytemuck::Zeroable::zeroed(),
                    eph_pk: [0; TAGGED_X25519_KEY_LEN],
                    ciphertext: [0; OPENING_RECORD_LEN],
                },
                merge: MergeTransactIxData {
                    expiry_unix_ts: layout.expiry_unix_ts,
                    proof: MergeProof::zeroed(),
                    output_utxo_hash: [0; 32],
                    output_encryption: layout.output_encryption,
                    private_tx_hash: [0; 32],
                    nullifiers: layout.nullifiers,
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                    cache_slot: None,
                },
            },
        }
        .instruction()
    }

    fn check_size(self, layout: MergeLayout, budget: ComputeBudgetConfig) -> Result<(), RingError> {
        check_transaction_size(&self.payer, &self.instruction(layout)?, budget)
    }
}

/// Either key class, a PDA owner authorizes through CPI.
fn public_owner(key: &PublicKey) -> Result<Address, RingError> {
    Ok(Address::new_from_array(request::owner_key(key)?))
}

const fn authority_of(owner: Option<Address>) -> MergeRingAuthority {
    match owner {
        Some(_) => MergeRingAuthority::OwnerSigned,
        None => MergeRingAuthority::Ring,
    }
}

impl ProvenCustomRingMerge {
    /// Every tree SPP charges a fee to, see [`crate::written_tree_fees`].
    pub fn written_trees(&self) -> [Address; 2] {
        [self.input_tree, self.output_tree]
    }

    /// `Some` on a zero-key merge.
    pub fn owner_signer(&self) -> Option<Address> {
        self.owner
    }

    pub(crate) fn bound_root(&self) -> Option<BoundRoot> {
        self.bound
    }

    pub fn instruction(&self, payer: Address) -> Result<Instruction, RingError> {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            payer,
            tracking_registry: self.tracking_registry,
            owner: self.owner,
            data: self.data.clone(),
        }
        .instruction()
    }
}

#[must_use]
pub struct RingMergeOperation {
    pub(crate) prepared: PreparedCustomRingMerge,
    pub(crate) input: MergeProofInput,
}

impl RingMergeOperation {
    pub fn new(prepared: PreparedCustomRingMerge, input: MergeProofInput) -> Self {
        Self { prepared, input }
    }
}

/// `[ring, tracking registry]` ahead of SPP's `merge_ring` list.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub tracking_registry: Address,
    /// Signs a zero-key merge.
    pub owner: Option<Address>,
    pub data: CustomRingMergeIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut data = vec![custom_ring_interface::tag::MERGE];
        data.extend(self.data.serialize()?);
        let mut instruction = MergeRing {
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            payer: self.payer,
            owner: self.owner,
            data: self.data.merge,
            output_ring_data_hash: self.data.output_ring_data_hash,
            cache: None,
        }
        .instruction();
        instruction.data = data;
        let prefix = [
            AccountMeta::new_readonly(self.ring.policy_pda(), false),
            AccountMeta::new_readonly(self.tracking_registry, false),
        ];
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}

#[must_use]
pub struct MergeRelay<'a> {
    pub ring: CustomRing,
    /// Owns every input.
    pub sender: ShieldedAddress,
    /// Signs the request, the relay proves nothing for a stranger.
    pub owner: &'a dyn Signer,
    pub nullifier_key: NullifierKey,
    pub inputs: Vec<WalletUtxo>,
}

impl MergeRelay<'_> {
    /// Ring RPC derives the merged note from the nullifier key, no signed message follows.
    pub fn prepare(self, quote: RelayQuote) -> Result<PreparedRelay, RingError> {
        let ring = self.ring.program_id();
        if self.owner.try_pubkey()?.to_bytes() != self.sender.signing_pubkey.as_ed25519()? {
            return Err(MessageMismatch::Signer.into());
        }
        let proof_inputs = RelayMergeInputs {
            ring_program_id: ring,
            sender: self.sender,
            nullifier_key: self.nullifier_key,
            inputs: self.inputs,
        }
        .encode()?;
        let proof_inputs = ProofInputBytes::new(proof_inputs);
        let owner_signature = self
            .owner
            .try_sign_message(&proof_inputs.merge_request_digest())?
            .into();
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(ring),
            quote,
            intent: RelayIntent::Merge {
                proof_inputs,
                owner_signature,
            },
            co_signers: Vec::new(),
        }))
    }
}
