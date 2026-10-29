//! The custom-ring binding of SPP's owner-preserving merge.

use custom_ring_interface::{
    cosign::CoSignDemand, key_catalog::RingCircuit, merge_disclosure_field_count,
    CustomRingMergeIxData, MergeDisclosure, MergePublicInput, RingMode, AUDIT_CIPHERTEXT_LEN,
    MERGE_WIDTHS, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::{AsyncRpc, AsyncWitnessReader, ClientError, MergeProver, ProofCompressed};
use spr_hasher::primitives::{pack_be, right_align};
use spr_indexer_api::SerializablePubkey;
use spr_interface::{
    instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof, MergeTransactIxData,
    },
    instruction::tag::RING_MERGE_TRANSACT,
    tree_slot::tree_id_field,
};
use spr_keypair::{NullifierKey, ShieldedAddress, X25519Pubkey};
use spr_program::instruction::MergeRing;
use spr_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::{ProofInputUtxo, SppProofInputUtxo},
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayMergeInputs, RelayQuote},
    MergeDisclosureEncryption, MergeOpening,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    pipeline::HiddenOwner,
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{EscrowOpening, EscrowRead},
    request::{MergeRequest, MergeSlot},
    submission::BoundRoot,
    tree_id, CustomRing, CustomRingConfig, PreparedRelay, RingError,
};

pub use spr_transaction::instructions::merge::MERGE_DEFAULT_INPUT_COUNT;
/// The most real inputs a ring merge forwards beside its disclosure in one v1 transaction.
pub const MAX_RING_MERGE_INPUTS: usize = MERGE_WIDTHS[MERGE_WIDTHS.len() - 1];

#[must_use]
#[derive(Clone)]
pub struct CustomRingMerge {
    ring: CustomRing,
    inner: MergeTransaction,
}

impl CustomRingMerge {
    pub fn new(
        ring: CustomRing,
        inputs: Vec<WalletUtxo>,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        if inputs.len() > MAX_RING_MERGE_INPUTS {
            return Err(TransactionError::TooManyInputs {
                got: inputs.len(),
                max: MAX_RING_MERGE_INPUTS,
            });
        }
        let inner =
            MergeTransaction::new_with_ring(inputs, ring.program_id(), output_ring_data_hash)?;
        Ok(Self { ring, inner })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_unix_ts);
        self
    }

    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.inner = self.inner.with_output_tree_id(tree_id);
        self
    }

    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        keys: &K,
    ) -> Result<PreparedCustomRingMerge, TransactionError> {
        Ok(PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.encrypt(keys)?,
        })
    }
}

/// Compact-padded to its circuit width.
#[must_use]
#[derive(Clone)]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: MergeProofInputs,
}

#[derive(Clone)]
pub struct MergeProofInput {
    pub nullifier_key: NullifierKey,
    pub input_tree: Address,
    pub output_tree: Address,
    /// Read only when a record covers transfers.
    pub co_signer: Option<Address>,
}

pub struct ProvenCustomRingMerge {
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    mode: RingMode,
    co_signer: Option<Address>,
    /// `Some` on a key escrow ring, its merge proves the owner's escrow record under the root.
    bound: Option<BoundRoot>,
    pub data: CustomRingMergeIxData,
    pub output_hash: [u8; 32],
    pub input_count: usize,
    pub merged_amount: u64,
}

impl PreparedCustomRingMerge {
    pub const fn ring(&self) -> CustomRing {
        self.ring
    }

    pub fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inner.input_utxos
    }

    pub const fn output(&self) -> &SppProofOutputUtxo {
        &self.inner.output_utxo
    }

    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
        config: &CustomRingConfig,
    ) -> Result<(), RingError> {
        if config.mode != RingMode::Anonymous {
            return Ok(());
        }
        HiddenOwner::of(&self.inner.signing_pubkey)?.check_signers(signers)
    }

    fn merge_width(&self) -> Result<usize, RingError> {
        let width = self.inner.input_utxos.len();
        match MERGE_WIDTHS.contains(&width) {
            true => Ok(width),
            false => Err(RingError::MergeTooWide { width }),
        }
    }

    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        mut self,
        input: MergeProofInput,
        payer: Address,
        client: &RingClient<R, I>,
    ) -> Result<ProvenCustomRingMerge, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        self.ring.require_active(client.zolana()).await?;
        let co_signer = CoSignerChoice {
            ring: self.ring,
            config: &config,
            demand: &merge_demand(),
            supplied: input.co_signer,
        }
        .resolve(client.zolana())
        .await?;
        // The merge circuit separates the owner from the payer and co-signer on every ring.
        HiddenOwner::of(&self.inner.signing_pubkey)?
            .check_signers(core::iter::once(payer).chain(co_signer))?;
        self.merge_width()?;
        // A key escrow merge reads the owner's escrow record under the newest root before any proof.
        let escrow = match config.mode {
            RingMode::ConfidentialEscrow => {
                let owner = self.inner.signing_pubkey.owner_proof_input_hash()?;
                let nullifier_pk = input.nullifier_key.pubkey()?;
                let ring = self.ring;
                Some(
                    retry_projection_lag(|| async move {
                        let root = BoundRoot::newest(ring, client.zolana()).await?;
                        let record = EscrowRead {
                            root,
                            owner,
                            nullifier_pk,
                        }
                        .read(client.zolana())
                        .await?;
                        Ok(MergeEscrow { root, record })
                    })
                    .await?,
                )
            }
            _ => None,
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
        let disclosure = MergeDisclosureProof {
            party_identities: custom_ring_interface::AnonymousParties {
                payer: payer.as_array(),
                cosigner: co_signer.as_ref().map(Address::as_array),
                exit_destination: None,
            }
            .identities()?,
            ring: self.ring,
            auditor: config.auditor_pubkey,
            merge: &self.inner,
            nullifier_key: &input.nullifier_key,
            spp: &data.merge,
        };
        let bound = escrow.as_ref().map(|escrow| escrow.root);
        let disclosure = disclosure.prove(client, escrow.as_ref()).await?;
        let inner = self.inner;
        Ok(ProvenCustomRingMerge {
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            ring: self.ring,
            mode: config.mode,
            co_signer,
            bound,
            data: CustomRingMergeIxData {
                own_revision: bound.map_or_else(Default::default, |bound| bound.revision),
                output_ring_data_hash: data.output_ring_data_hash,
                disclosure,
                merge: data.merge,
            },
            output_hash: inner.output_hash()?,
            input_count: inner
                .input_utxos
                .iter()
                .filter(|utxo| !utxo.is_dummy())
                .count(),
            merged_amount: inner.output_utxo.amount,
        })
    }
}

impl ProvenCustomRingMerge {
    /// `Some` when a record covers transfers, it signs the transaction.
    pub fn co_signer(&self) -> Option<Address> {
        self.co_signer
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
            co_signer: self.co_signer,
            mode: self.mode,
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

    /// The instruction under zeroed proofs, the size of the proven one.
    pub(crate) fn preview_instruction(
        &self,
        payer: Address,
        config: &CustomRingConfig,
    ) -> Result<Instruction, RingError> {
        let merge = &self.prepared;
        let disclosure = MergeDisclosure {
            proof: bytemuck::Zeroable::zeroed(),
            eph_pk: [0; TAGGED_X25519_KEY_LEN],
            ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
            fields: vec![[0; 32]; merge_disclosure_field_count(merge.merge_width()?)],
        };
        CustomRingMergeInstruction {
            ring: merge.ring,
            input_tree: self.input.input_tree,
            output_tree: self.input.output_tree,
            payer,
            co_signer: CoSignerChoice {
                ring: merge.ring,
                config,
                demand: &merge_demand(),
                supplied: self.input.co_signer,
            }
            .unchecked()?
            .map(|(_, signer)| signer),
            mode: config.mode,
            data: CustomRingMergeIxData {
                own_revision: Default::default(),
                output_ring_data_hash: merge.inner.output_utxo.ring_data_hash.unwrap_or_default(),
                disclosure,
                merge: MergeTransactIxData {
                    expiry_unix_ts: merge.inner.expiry_unix_ts,
                    proof: MergeProof::zeroed(),
                    output_utxo_hash: [0; 32],
                    output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                        salt: merge.inner.output_ciphertext_salt,
                        ciphertext: merge.inner.output_ciphertext,
                    },
                    private_tx_hash: [0; 32],
                    nullifiers: merge
                        .inner
                        .input_utxos
                        .iter()
                        .filter(|input| !input.is_compact())
                        .map(|input| input.nullifier)
                        .collect(),
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                    cache_slot: None,
                },
            },
        }
        .instruction()
    }
}

/// `[config, policy?, co-signer record and signer?]` ahead of SPP's merge list.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub co_signer: Option<Address>,
    /// A key escrow merge binds the policy's own root at `own_revision`.
    pub mode: RingMode,
    pub data: CustomRingMergeIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut data = vec![RING_MERGE_TRANSACT];
        data.extend(
            self.data
                .serialize()
                .map_err(|_| custom_ring_interface::CustomRingError::InvalidInstructionData)?,
        );
        let mut instruction = MergeRing {
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            payer: self.payer,
            data: self.data.merge,
            output_ring_data_hash: self.data.output_ring_data_hash,
            cache: None,
        }
        .instruction();
        instruction.data = data;
        let mut prefix = vec![AccountMeta::new_readonly(self.ring.config_pda(), false)];
        if self.mode == RingMode::ConfidentialEscrow {
            prefix.push(AccountMeta::new_readonly(self.ring.policy_pda(), false));
        }
        prefix.extend(
            self.co_signer
                .into_iter()
                .flat_map(|co_signer| self.ring.co_signer_metas(co_signer)),
        );
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}

#[must_use]
pub struct MergeRelay {
    pub ring: CustomRing,
    /// Owns every input.
    pub sender: ShieldedAddress,
    pub nullifier_key: NullifierKey,
    pub inputs: Vec<WalletUtxo>,
}

impl MergeRelay {
    /// Ring RPC derives the merged note from the nullifier key, no wallet signature follows.
    pub fn prepare(self, quote: RelayQuote) -> Result<PreparedRelay, RingError> {
        let ring = self.ring.program_id();
        let proof_inputs = RelayMergeInputs {
            ring_program_id: ring,
            sender: self.sender,
            nullifier_key: self.nullifier_key,
            inputs: self.inputs,
        }
        .encode()?;
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(ring),
            quote,
            intent: RelayIntent::Merge {
                proof_inputs: ProofInputBytes::new(proof_inputs),
            },
        }))
    }
}

/// The auditor's opening of a merge, proven against the SPP merge it precedes.
#[must_use]
struct MergeDisclosureProof<'a> {
    party_identities: [[u8; 32]; 3],
    ring: CustomRing,
    auditor: X25519Pubkey,
    merge: &'a MergeProofInputs,
    nullifier_key: &'a NullifierKey,
    spp: &'a MergeTransactIxData,
}

struct MergeEscrow {
    root: BoundRoot,
    record: EscrowOpening,
}

impl MergeDisclosureProof<'_> {
    async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        escrow: Option<&MergeEscrow>,
    ) -> Result<MergeDisclosure, RingError> {
        let root = escrow.map(|escrow| escrow.root.root);
        let merge = self.merge;
        let width =
            u8::try_from(merge.input_utxos.len()).map_err(|_| ClientError::UnsupportedShape {
                n_in: merge.input_utxos.len(),
                n_out: 1,
            })?;
        let owner_key = merge.signing_pubkey.as_ed25519()?;
        let output = &merge.output_utxo;
        let opening = MergeOpening {
            owner_key,
            nullifier_pk: self.nullifier_key.pubkey()?,
            mint: *output.asset.asset.as_array(),
            amount: output.amount,
            output_blinding: output.blinding,
            input_commitments: merge
                .input_utxos
                .iter()
                .map(|input| match input.is_dummy() {
                    true => [0; 32],
                    false => input.utxo_hash,
                })
                .collect(),
        };
        let sealed =
            MergeDisclosureEncryption::new(&opening, merge.output_ciphertext_salt, &self.auditor)?;
        let first_nullifier = *self.spp.nullifiers.first().ok_or(ClientError::NoInputs)?;
        let ring_program_id = self.ring.ring_id()?;
        let public_input_hash = MergePublicInput {
            party_identities: &self.party_identities,
            private_tx_hash: &self.spp.private_tx_hash,
            output_utxo_hash: &self.spp.output_utxo_hash,
            first_nullifier: &first_nullifier,
            ring_id: &ring_program_id,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: sealed.eph_pk.as_bytes(),
            ciphertext: &sealed.ciphertext,
            salt: &merge.output_ciphertext_salt,
            fields: &sealed.fields,
            member_registry_root: root.as_ref(),
        }
        .hash()?;
        let inputs = merge
            .input_utxos
            .iter()
            .map(|input| {
                let utxo = ProofInputUtxo::try_from(input)?;
                Ok(MergeSlot {
                    domain: utxo.domain,
                    tree_id: utxo.tree_id,
                    amount: utxo.amount,
                    blinding: utxo.blinding,
                    ring_data_hash: utxo.ring_data_hash,
                })
            })
            .collect::<Result<_, TransactionError>>()?;
        let body = MergeRequest {
            party_identities: self.party_identities,
            public_input_hash,
            private_tx_hash: self.spp.private_tx_hash,
            output_utxo_hash: self.spp.output_utxo_hash,
            first_nullifier,
            ring_program_id,
            auditor_pk: self.auditor,
            salt: right_align(&merge.output_ciphertext_salt),
            eph_sk: sealed.ephemeral_sk,
            disclosure_key: sealed.disclosure_key,
            owner_key,
            nullifier_secret: Zeroizing::new(right_align(&self.nullifier_key.secret())),
            mint_chunks: pack_be::<32, 2>(output.asset.asset.as_array()),
            inputs,
            output_tree_id: tree_id_field(merge.output_tree_id),
            output_ring_data_hash: output.ring_data_hash.unwrap_or_default(),
            key_escrow: root.is_some(),
            member_registry_root: root.unwrap_or_default(),
            ct_hash: escrow.map_or([0; 32], |escrow| escrow.record.ct_hash),
            member: escrow.map(|escrow| escrow.record.opening.clone()),
        };
        let proof = RingRequest::new(RingCircuit::Merge { width }, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(MergeDisclosure {
            proof: to_instruction_proof(proof)?,
            eph_pk: *sealed.eph_pk.as_bytes(),
            ciphertext: sealed.ciphertext,
            fields: sealed.fields,
        })
    }
}

/// A merge is a transfer, no public leg adds a class.
fn merge_demand() -> CoSignDemand {
    CoSignDemand::transact(false, &[])
}
