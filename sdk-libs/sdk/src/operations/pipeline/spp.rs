//! The SPP half of a ring transfer, its witness complete or prepared for the indexed prover.

use custom_ring_interface::{InputTrees, PlainGroth16Proof};
use solana_address::Address;
use spr_client::{
    attach_input_proofs,
    prover::{
        indexed::{IndexedTransferPreparation, IndexedTransferRail, PreparedIndexedTransfer},
        transact::{AnonymousEddsaTransferInputs, AnonymousRingEddsaProver},
    },
    AsyncRpc, AsyncWitnessReader, ClientError, OwnerAuthorization, ProofAuthority, ProofCompressed,
    RingAuthorityProver, RingTransferProver, TransferInputs,
};
use spr_interface::instruction::{
    instruction_data::transact::Bsb22Commitment, CircuitId, TreeContext,
};
use spr_transaction::instructions::transact::SppProofInputs;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{trees::SpendTrees, RingError};

/// The SPP circuit a ring transfer proves on, with the owner that signs inside the proof.
#[derive(Clone, Copy)]
pub(super) enum SppRail<'a> {
    /// The confidential rail, every input owner signs the transaction.
    OwnerSigners,
    /// SPP's anonymous rail, the hidden owner of the anonymous ring or the in-proof owner of a confidential one.
    Anonymous(OwnerAuthorization<'a>),
    Delegate,
}

pub(super) struct ProvenSpp {
    pub proof: PlainGroth16Proof,
    /// The BSB22 commitment of the rails whose owner signs inside the proof.
    pub commitment: Option<Bsb22Commitment>,
    pub default_owner_tag: Option<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    pub input_trees: InputTrees,
}

struct RawSpp {
    proof: ProofCompressed,
    nullifiers: Vec<[u8; 32]>,
    tree_indexes: Vec<u8>,
    tree_contexts: Vec<TreeContext>,
    default_owner_tag: Option<[u8; 32]>,
}

pub(super) enum Spp {
    Complete(Box<CompleteSpp>),
    Indexed(Box<PreparedIndexedTransfer>),
}

pub(super) struct CompleteSpp {
    inputs: SppInputs,
    nullifiers: Vec<[u8; 32]>,
    input_tree_indexes: Vec<u8>,
    tree_contexts: Vec<TreeContext>,
    private_tx_hash: [u8; 32],
}

enum SppInputs {
    Ring(TransferInputs),
    Authority(TransferInputs),
    Anonymous {
        inputs: Box<AnonymousEddsaTransferInputs>,
        default_owner_tag: Option<[u8; 32]>,
    },
}

pub(super) struct SppWitness<'a> {
    pub ring: Address,
    pub rail: SppRail<'a>,
    pub inputs: &'a SppProofInputs,
    pub trees: &'a SpendTrees,
    pub authority: &'a dyn ProofAuthority,
}

impl SppWitness<'_> {
    pub async fn build<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<Spp, RingError> {
        let inputs = self.inputs;
        let allow_dummy_inputs = self.trees.allow_dummy_inputs;
        if client.indexed_prover().is_some() {
            let rail = match self.rail {
                SppRail::Anonymous(owner) => IndexedTransferRail::AnonymousRingEddsa {
                    ring: self.ring,
                    owner,
                },
                SppRail::Delegate => IndexedTransferRail::RingAuthority(self.ring),
                SppRail::OwnerSigners => IndexedTransferRail::Ring(self.ring),
            };
            let prepared = IndexedTransferPreparation {
                transaction: inputs.clone(),
                rail,
            }
            .prepare_with_dummy_policy(self.authority, allow_dummy_inputs)?;
            return Ok(Spp::Indexed(Box::new(prepared)));
        }
        let commitments = inputs.input_utxo_hashes()?;
        let witnesses = AsyncWitnessReader::input_witnesses(
            client.indexer(),
            &commitments,
            &inputs.dummy_nullifiers(),
            None,
        )
        .await?;
        let spends = attach_input_proofs(
            inputs.input_utxos.clone(),
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let shape = inputs.check_shape()?;
        let mut complete = match self.rail {
            SppRail::Anonymous(owner) => {
                let result = AnonymousRingEddsaProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    // The hidden owner signs inside the proof, every public signer slot is zero.
                    signer_pk_hashes: vec![[0; 32]; shape.signer_width()],
                    allow_dummy_inputs,
                    owner,
                    ring_program_id: Some(self.ring),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: SppInputs::Anonymous {
                        inputs: Box::new(result.inputs),
                        default_owner_tag: result.default_owner_tag,
                    },
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
            SppRail::OwnerSigners => {
                let result = RingTransferProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    signer_pk_hashes: inputs.signer_pk_hashes(shape.signer_width())?,
                    allow_dummy_inputs,
                    ring_program_id: Some(self.ring),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: SppInputs::Ring(result.inputs),
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
            SppRail::Delegate => {
                let result = RingAuthorityProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    payer: inputs.payer,
                    allow_dummy_inputs,
                    ring_program_id: Some(self.ring),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: SppInputs::Authority(result.inputs),
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
        };
        let transfer = match &mut complete.inputs {
            SppInputs::Ring(inputs) | SppInputs::Authority(inputs) => inputs,
            SppInputs::Anonymous { inputs, .. } => &mut inputs.transfer,
        };
        self.authority.complete_inputs(&mut transfer.inputs)?;
        Ok(Spp::Complete(Box::new(complete)))
    }
}

impl Spp {
    pub fn private_tx_hash(&self) -> [u8; 32] {
        match self {
            Self::Complete(complete) => complete.private_tx_hash,
            Self::Indexed(prepared) => prepared.private_tx_hash(),
        }
    }

    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        published_inputs: usize,
    ) -> Result<ProvenSpp, RingError> {
        let raw = match self {
            Self::Indexed(prepared) => {
                let prover = client
                    .indexed_prover()
                    .ok_or(ClientError::InvalidIndexedRequest)?;
                let proven = prover.prove_indexed(prepared.as_ref()).await?;
                RawSpp {
                    default_owner_tag: match proven.data.circuit {
                        CircuitId::AnonymousRingEddsa(.., data) => data.default_owner_tag,
                        _ => None,
                    },
                    nullifiers: proven
                        .data
                        .inputs
                        .iter()
                        .map(|input| input.nullifier_hash)
                        .collect(),
                    tree_indexes: proven
                        .data
                        .inputs
                        .iter()
                        .map(|input| input.tree_index)
                        .collect(),
                    tree_contexts: proven.data.tree_contexts,
                    proof: proven.proof,
                }
            }
            Self::Complete(complete) => {
                let (proof, default_owner_tag) = match &complete.inputs {
                    SppInputs::Ring(inputs) => {
                        (client.prover().prove_transfer_ring(inputs).await?, None)
                    }
                    SppInputs::Authority(inputs) => {
                        (client.prover().prove_ring_authority(inputs).await?, None)
                    }
                    SppInputs::Anonymous {
                        inputs,
                        default_owner_tag,
                    } => (
                        client.prove_request(inputs.as_ref()).await?,
                        *default_owner_tag,
                    ),
                };
                RawSpp {
                    proof: ProofCompressed::try_from(proof)?,
                    nullifiers: complete.nullifiers.clone(),
                    tree_indexes: complete.input_tree_indexes.clone(),
                    tree_contexts: complete.tree_contexts.clone(),
                    default_owner_tag,
                }
            }
        };
        let RawSpp {
            proof,
            nullifiers,
            tree_indexes: indexes,
            tree_contexts: contexts,
            default_owner_tag,
        } = raw;
        // SPP publishes the nullifier of every input slot but compact padding.
        let nullifiers: Vec<[u8; 32]> = nullifiers.into_iter().take(published_inputs).collect();
        let indexes: Vec<u8> = indexes.into_iter().take(published_inputs).collect();
        if nullifiers.len() != published_inputs {
            return Err(RingError::IncompleteProofSet);
        }
        let input_trees = match contexts.as_slice() {
            [one] => InputTrees::One(*one),
            [first, second] => InputTrees::Two {
                first: *first,
                second: *second,
                second_inputs: indexes
                    .iter()
                    .enumerate()
                    .filter(|(_, index)| **index == 1)
                    .fold(0, |bits, (input, _)| bits | 1 << input),
            },
            _ => return Err(RingError::IncompleteProofSet),
        };
        Ok(ProvenSpp {
            proof: PlainGroth16Proof {
                proof_a: proof.a,
                proof_b: proof.compressed_b()?,
                proof_c: proof.c,
            },
            commitment: proof.commitment.as_ref().map(|commitment| Bsb22Commitment {
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            }),
            default_owner_tag,
            nullifiers,
            input_trees,
        })
    }
}
