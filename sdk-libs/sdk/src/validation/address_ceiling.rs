//! The address ceiling of one compiled transaction, merging first takes several transactions and loses atomicity, so only a caller chooses it.

use bytemuck::Zeroable;
use custom_ring_interface::{
    max_application_messages, CustomRingError, InstructionTag, RingMode, RingPolicy, RingRail,
    RingTransactData, MAX_CPI_DATA_LEN,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::v1;
use spr_client::{
    compile_message, transaction_size, ClientError, ComputeBudgetConfig, TransactionSize,
};
use spr_interface::{instruction::TransactProof, pda, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::PublicKey;
use spr_transaction::utxo::SppProofInputUtxo;
use thiserror::Error;

use crate::RingError;

#[cfg(test)]
#[path = "../tests/validation/address_ceiling.rs"]
mod tests;

/// The one acceptance rule of a final transaction.
///
/// Each figure comes from the message the compiler builds, so the payer, owners, co-signers,
/// delegate, deposit authorities, cache writers and setup signers count once however many metas
/// name them. A role count would double a signer two roles share and miss one only setup adds.
pub struct TransactionFit<'a> {
    instruction: &'a Instruction,
    payer: Address,
    setup: &'a [Instruction],
    budget: ComputeBudgetConfig,
}

/// The message around the operation, setup compiles ahead of it in one transaction.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct FitSigners<'a> {
    payer: Address,
    setup: &'a [Instruction],
}

/// What the transaction costs against each ceiling, setup included.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    pub signatures: usize,
    pub bytes: usize,
    pub addresses: usize,
    /// The data SPP receives on the transfer tags, `None` on any other tag.
    pub cpi_bytes: Option<usize>,
    pub setup: SetupEffect,
}

/// What setup adds to the transaction it shares with the operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetupEffect {
    pub instructions: usize,
    pub signatures: usize,
    pub bytes: usize,
    pub addresses: usize,
}

#[derive(Debug, Error)]
pub enum FitError {
    #[error("the transaction needs {signatures} signatures, a v1 transaction carries {limit}")]
    Signatures { signatures: usize, limit: usize },
    #[error("the transaction takes {bytes} bytes, a v1 transaction carries {limit}")]
    Bytes { bytes: usize, limit: usize },
    #[error("the transaction names {addresses} addresses, a v1 transaction carries {limit}")]
    Addresses { addresses: usize, limit: usize },
    #[error("the transaction holds {instructions} instructions, a v1 transaction carries {limit}")]
    Instructions { instructions: usize, limit: usize },
    #[error("the transfer hands SPP {bytes} bytes of data, one CPI carries {limit}")]
    CpiBytes { bytes: usize, limit: usize },
    #[error("the transfer frame parses under neither rail of its tag")]
    UnparsedFrame,
    #[error("the frame carries more application messages than SPP takes beside its own, {limit} on its rail")]
    ApplicationMessages { limit: usize },
    #[error(transparent)]
    Program(#[from] CustomRingError),
    #[error(transparent)]
    Compile(#[from] ClientError),
}

impl<'a> FitSigners<'a> {
    pub const fn new(payer: Address) -> Self {
        Self { payer, setup: &[] }
    }

    /// The setup the final message carries, its signers and addresses join the count.
    pub const fn with_setup(mut self, setup: &'a [Instruction]) -> Self {
        self.setup = setup;
        self
    }
}

impl<'a> TransactionFit<'a> {
    /// Refuses an operation past any ceiling of one v1 transaction.
    pub fn of(
        instruction: &'a Instruction,
        signers: FitSigners<'a>,
        budget: ComputeBudgetConfig,
    ) -> Result<Fit, FitError> {
        let cpi_bytes = spp_cpi_bytes(instruction)?;
        Self::new(instruction, signers, budget).accept(cpi_bytes)
    }

    const fn new(
        instruction: &'a Instruction,
        signers: FitSigners<'a>,
        budget: ComputeBudgetConfig,
    ) -> Self {
        Self {
            instruction,
            payer: signers.payer,
            setup: signers.setup,
            budget,
        }
    }

    /// The compiled message clears every message ceiling, or no transaction can execute it.
    fn accept(&self, cpi_bytes: Option<usize>) -> Result<Fit, FitError> {
        let compiled = self.compiled()?;
        compiled.check()?;
        Ok(Fit {
            signatures: compiled.signatures,
            bytes: compiled.bytes,
            addresses: compiled.addresses,
            cpi_bytes,
            setup: self.setup_effect(compiled)?,
        })
    }

    fn compiled(&self) -> Result<Compiled, ClientError> {
        let instructions: Vec<Instruction> = self
            .setup
            .iter()
            .chain(core::iter::once(self.instruction))
            .cloned()
            .collect();
        Compiled::of(&self.payer, &instructions, self.budget)
    }

    fn setup_effect(&self, with: Compiled) -> Result<SetupEffect, ClientError> {
        if self.setup.is_empty() {
            return Ok(SetupEffect::default());
        }
        let alone = Compiled::of(
            &self.payer,
            core::slice::from_ref(self.instruction),
            self.budget,
        )?;
        Ok(SetupEffect {
            instructions: self.setup.len(),
            signatures: with.signatures.saturating_sub(alone.signatures),
            bytes: with.bytes.saturating_sub(alone.bytes),
            addresses: with.addresses.saturating_sub(alone.addresses),
        })
    }
}

/// One compiled message's figures.
#[derive(Clone, Copy, Debug)]
struct Compiled {
    signatures: usize,
    bytes: usize,
    addresses: usize,
    instructions: usize,
}

impl Compiled {
    fn of(
        payer: &Address,
        instructions: &[Instruction],
        budget: ComputeBudgetConfig,
    ) -> Result<Self, ClientError> {
        let size = transaction_size(payer, instructions, budget)?;
        // The blockhash is fixed width, the header it leaves is the sent one's.
        let message = compile_message(payer, instructions, Default::default(), budget)?;
        Ok(Self {
            signatures: usize::from(message.header().num_required_signatures),
            bytes: size.bytes,
            addresses: size.addresses,
            instructions: instructions.len(),
        })
    }

    /// Signatures lead, merging first cannot relieve them.
    fn check(self) -> Result<(), FitError> {
        if self.signatures > usize::from(v1::MAX_SIGNATURES) {
            return Err(FitError::Signatures {
                signatures: self.signatures,
                limit: usize::from(v1::MAX_SIGNATURES),
            });
        }
        if self.instructions > usize::from(v1::MAX_INSTRUCTIONS) {
            return Err(FitError::Instructions {
                instructions: self.instructions,
                limit: usize::from(v1::MAX_INSTRUCTIONS),
            });
        }
        if self.bytes > v1::MAX_TRANSACTION_SIZE {
            return Err(FitError::Bytes {
                bytes: self.bytes,
                limit: v1::MAX_TRANSACTION_SIZE,
            });
        }
        if self.addresses > usize::from(v1::MAX_ADDRESSES) {
            return Err(FitError::Addresses {
                addresses: self.addresses,
                limit: usize::from(v1::MAX_ADDRESSES),
            });
        }
        Ok(())
    }
}

/// The exact data the program forwards to SPP, `None` off the transfer tags, refused past the CPI limit.
///
/// A frame inside one transaction can still pass the limit, because the expansion widens outputs
/// and messages. The ring's mode decides the rail and the compact frame does not name it,
/// so the strict parser reads the frame under both rails of its tag and the longer expansion
/// counts. The zeroed policy and proof change no length, the policy reaches the expansion only as
/// a view tag of fixed width and the proof fields are fixed width.
fn spp_cpi_bytes(instruction: &Instruction) -> Result<Option<usize>, FitError> {
    let Some((tag, frame)) = instruction.data.split_first() else {
        return Ok(None);
    };
    let tag = match InstructionTag::try_from(*tag) {
        Ok(tag @ (InstructionTag::Transfer | InstructionTag::AuthorityTransfer)) => tag,
        _ => return Ok(None),
    };
    let ring = RingPolicy::zeroed();
    let expansion = |rail| -> Result<usize, CustomRingError> {
        let parsed = RingTransactData::parse(frame, rail)?;
        let data = parsed
            .data()
            .spp_instruction_data_under(&ring, TransactProof::zeroed())?;
        Ok(data.len())
    };
    // The frame parses under one rail of its tag. A rail refusing its message count names the
    // limit, any other refusal leaves the frame unparsed.
    let mut bytes = None;
    let mut refusal = FitError::UnparsedFrame;
    for mode in [RingMode::Confidential, RingMode::Anonymous] {
        let rail = RingRail::of(tag, mode)?;
        match expansion(rail) {
            Ok(len) => bytes = bytes.max(Some(len)),
            Err(CustomRingError::TooManyApplicationMessages) => {
                refusal = FitError::ApplicationMessages {
                    limit: max_application_messages(rail),
                }
            }
            Err(_) => {}
        }
    }
    let bytes = bytes.ok_or(refusal)?;
    if bytes > MAX_CPI_DATA_LEN {
        return Err(FitError::CpiBytes {
            bytes,
            limit: MAX_CPI_DATA_LEN,
        });
    }
    Ok(Some(bytes))
}

impl From<FitError> for RingError {
    /// Selection and merge narrowing read the two named refusals.
    fn from(error: FitError) -> Self {
        match error {
            FitError::Bytes { bytes, limit } => Self::TransactionTooLarge { bytes, limit },
            FitError::Addresses { addresses, limit } => Self::TooManyAddresses { addresses, limit },
            error => Self::AddressCeiling(error.into()),
        }
    }
}

/// One real input of the transaction, as SPP merge groups it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentInput {
    pub owner: PublicKey,
    pub asset: Address,
    pub nullifier_pubkey: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_program_id: Option<Address>,
    pub tree_id: u16,
    pub nullifier_pda: Address,
}

impl SpentInput {
    /// `tree` holds the input.
    pub fn of(input: &SppProofInputUtxo, tree: &Address) -> Self {
        Self {
            owner: input.utxo.owner,
            asset: input.utxo.asset.asset,
            nullifier_pubkey: input.nullifier_pubkey,
            data_hash: input.data_hash,
            ring_program_id: input.utxo.ring_program_id,
            tree_id: input.tree_id,
            nullifier_pda: pda::nullifier_pda(tree, &input.nullifier()).0,
        }
    }

    /// SPP merge refuses a note with a data hash.
    fn carries_data(&self) -> bool {
        self.data_hash.is_some_and(|hash| hash != [0; 32])
    }

    fn merges_with(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.asset == other.asset
            && self.nullifier_pubkey == other.nullifier_pubkey
            && self.ring_program_id == other.ring_program_id
            && self.tree_id == other.tree_id
    }
}

#[must_use]
pub struct AddressCeiling<'a> {
    pub payer: Address,
    pub instruction: &'a Instruction,
    pub budget: ComputeBudgetConfig,
    pub inputs: &'a [SpentInput],
    pub merge_capacity: MergeCapacity,
}

/// [`crate::FittedMerge`]'s published inputs per kind of merge, a zero-key merge adds its signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeCapacity {
    pub keyed: usize,
    pub zero_key: usize,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeilingDecision {
    Inline(TransactionSize),
    MergeFirst {
        /// The fewest merges that bring the compiled count under the ceiling.
        groups: Vec<MergeGroup>,
        /// With one nullifier PDA left per merged note.
        addresses: usize,
    },
}

/// One executable merge, one transaction carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeGroup {
    pub owner: PublicKey,
    pub asset: Address,
    pub nullifier_pubkey: [u8; 32],
    pub ring_program_id: Option<Address>,
    pub tree_id: u16,
    /// Positions in [`AddressCeiling::inputs`].
    pub inputs: Vec<usize>,
}

#[derive(Debug, Error)]
pub enum AddressCeilingError {
    #[error("{compiled} addresses pass the limit of {limit}, merging every valid group reaches {after_merging} and {data_notes} data notes cannot merge")]
    Unsupported {
        compiled: usize,
        limit: usize,
        after_merging: usize,
        data_notes: usize,
    },
    #[error(transparent)]
    Fit(#[from] FitError),
}

impl AddressCeiling<'_> {
    pub fn decide(self) -> Result<CeilingDecision, AddressCeilingError> {
        let limit = usize::from(v1::MAX_ADDRESSES);
        let signers = FitSigners::new(self.payer);
        match TransactionFit::of(self.instruction, signers, self.budget) {
            Ok(fit) => {
                return Ok(CeilingDecision::Inline(TransactionSize {
                    bytes: fit.bytes,
                    addresses: fit.addresses,
                }));
            }
            // Only the address count leaves a route, merging first narrows the spend.
            Err(FitError::Addresses { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        let compiled = self.compiled(&[]).map_err(FitError::from)?;
        let mut merged_away = Vec::new();
        let mut chosen = Vec::new();
        let mut after_merging = compiled.addresses;
        for group in self.groups() {
            // The merged note's own nullifier PDA replaces one of the group's.
            merged_away.extend(
                group.inputs[1..]
                    .iter()
                    .map(|position| self.inputs[*position].nullifier_pda),
            );
            chosen.push(group);
            after_merging = self
                .compiled(&merged_away)
                .map_err(FitError::from)?
                .addresses;
            if after_merging <= limit {
                return Ok(CeilingDecision::MergeFirst {
                    groups: chosen,
                    addresses: after_merging,
                });
            }
        }
        Err(AddressCeilingError::Unsupported {
            compiled: compiled.addresses,
            limit,
            after_merging,
            data_notes: self
                .inputs
                .iter()
                .filter(|input| input.carries_data())
                .count(),
        })
    }

    fn compiled(&self, merged_away: &[Address]) -> Result<TransactionSize, ClientError> {
        let mut instruction = self.instruction.clone();
        instruction
            .accounts
            .retain(|account| !merged_away.contains(&account.pubkey));
        transaction_size(
            &self.payer,
            core::slice::from_ref(&instruction),
            self.budget,
        )
    }

    /// Widest first, a run of one consolidates nothing.
    fn groups(&self) -> Vec<MergeGroup> {
        let mut groups: Vec<MergeGroup> = Vec::new();
        for (position, input) in self.inputs.iter().enumerate() {
            if input.carries_data() {
                continue;
            }
            let held = groups
                .iter_mut()
                .find(|group| input.merges_with(&self.inputs[group.inputs[0]]));
            match held {
                Some(group) => group.inputs.push(position),
                None => groups.push(MergeGroup {
                    owner: input.owner,
                    asset: input.asset,
                    nullifier_pubkey: input.nullifier_pubkey,
                    ring_program_id: input.ring_program_id,
                    tree_id: input.tree_id,
                    inputs: vec![position],
                }),
            }
        }
        let mut merges: Vec<MergeGroup> = groups
            .iter()
            .flat_map(|group| {
                group
                    .inputs
                    .chunks(self.capacity_of(group).max(1))
                    .filter(|run| run.len() > 1)
                    .map(|run| MergeGroup {
                        inputs: run.to_vec(),
                        ..group.clone()
                    })
            })
            .collect();
        merges.sort_by_key(|merge| core::cmp::Reverse(merge.inputs.len()));
        merges
    }

    fn capacity_of(&self, group: &MergeGroup) -> usize {
        match group.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY {
            true => self.merge_capacity.zero_key,
            false => self.merge_capacity.keyed,
        }
    }
}
