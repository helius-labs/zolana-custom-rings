use solana_address::Address;
use spr_event::MessageData;
use spr_instruction::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use spr_interface::{instruction::instruction_data::transact::TransactOutput, pda, MAX_OUTPUTS};
use spr_keypair::{
    constants::BLINDING_LEN, viewing_key::ViewTag, KeypairError, NullifierKey, ShieldedAddress,
    ViewingKey, X25519Keypair, X25519Pubkey, SHIELDED_ADDRESS_LEN,
};
use spr_transaction::{
    instructions::transact::{CacheAccounts, ExternalData, SettlementTransfer, SppProofInputs},
    utxo::SppProofInputUtxo,
    Data, Mint, SppProofOutputUtxo, TransactionError, Utxo,
};
use thiserror::Error;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_transaction::{AnonymousPlan, TaggedPayment};

use super::RelayOperation;

pub struct RelayProofInputs {
    pub rail: RelayRail,
    pub ring_program_id: Address,
    /// Owns every real input.
    pub sender: ShieldedAddress,
    pub nullifier_key: NullifierKey,
    pub tx_viewing_key: ViewingKey,
    /// Ephemeral secret of the auditor message in `external_data`.
    pub audit_ephemeral_key: Zeroizing<[u8; 32]>,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    /// One per interface transfer, each a withdrawal.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
}

pub enum RelayRail {
    Anonymous {
        plan: Box<AnonymousPlan>,
        exit_token_owner: Option<Address>,
    },
    Confidential,
    Delegate {
        delegate: Address,
    },
    Deposit,
    Merge,
}

#[derive(Debug, Error)]
pub enum RelayProofInputsError {
    #[error("relay proof inputs do not decode")]
    Decode(#[from] wincode::ReadError),
    #[error("relay proof inputs do not encode")]
    Encode(#[from] wincode::WriteError),
    #[error("input {index} is not an uncached spend of the sender")]
    Input { index: usize },
    #[error("output {index} names a cache slot")]
    CachedOutput { index: usize },
    #[error("interface transfer {index} is not a withdrawal with matching accounts")]
    Settlement { index: usize },
    #[error("nullifier key does not match the sender")]
    NullifierKey,
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}

impl RelayRail {
    /// `None` for a merge, no relay intent names one.
    pub const fn operation(&self) -> Option<RelayOperation> {
        match self {
            Self::Anonymous { .. } => Some(RelayOperation::Anonymous),
            Self::Confidential => Some(RelayOperation::Confidential),
            Self::Delegate { .. } => Some(RelayOperation::Delegate),
            Self::Deposit => Some(RelayOperation::Deposit),
            Self::Merge => None,
        }
    }
}

impl RelayProofInputs {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelayProofInputsError> {
        let wire = ProofInputsWire::of(self)?;
        Ok(Zeroizing::new(wincode::serialize(&wire)?))
    }

    /// Derives each input hash and nullifier again from its opening and the nullifier key.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        let wire: ProofInputsWire = wincode::deserialize_exact(bytes)?;
        wire.proof_inputs()
    }

    /// The owner signs their `message_hash`, the same under any `payer`.
    pub fn spp_proof_inputs(&self, payer: Address) -> SppProofInputs {
        SppProofInputs {
            input_utxos: self.inputs.clone(),
            output_utxos: self.outputs.clone(),
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data: self.external_data.clone(),
            payer,
            cache_accounts: CacheAccounts::default(),
        }
    }
}

#[derive(SchemaWrite, SchemaRead)]
struct ProofInputsWire {
    rail: RailWire,
    ring_program_id: Address,
    sender: [u8; SHIELDED_ADDRESS_LEN],
    nullifier_secret: [u8; BLINDING_LEN],
    tx_viewing_secret: [u8; 32],
    audit_ephemeral_key: [u8; 32],
    #[wincode(with = "containers::Vec<InputWire, FixIntLen<u8>>")]
    inputs: Vec<InputWire>,
    #[wincode(with = "containers::Vec<OutputWire, FixIntLen<u8>>")]
    outputs: Vec<OutputWire>,
    external_data: ExternalDataWire,
    blinding_seed: [u8; 32],
    output_tree_id: u16,
}

impl Drop for ProofInputsWire {
    fn drop(&mut self) {
        self.nullifier_secret.zeroize();
        self.tx_viewing_secret.zeroize();
        self.audit_ephemeral_key.zeroize();
    }
}

#[derive(SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u8")]
enum RailWire {
    Anonymous {
        plan: Box<PlanWire>,
        exit_token_owner: Option<Address>,
    },
    Confidential,
    Delegate {
        delegate: Address,
    },
    Deposit,
    Merge,
}

#[derive(SchemaWrite, SchemaRead)]
struct PlanWire {
    sender_tag: ViewTag,
    #[wincode(with = "containers::Vec<PaymentWire, FixIntLen<u8>>")]
    payments: Vec<PaymentWire>,
    dummy_tags: [ViewTag; MAX_OUTPUTS],
}

#[derive(SchemaWrite, SchemaRead)]
struct PaymentWire {
    recipient: [u8; 33],
    tag: ViewTag,
}

#[derive(SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u8")]
enum InputWire {
    Spend {
        asset: Address,
        asset_id: u64,
        amount: u64,
        blinding: [u8; 32],
        ring_program_id: Option<Address>,
        data: Data,
        data_hash: Option<[u8; 32]>,
        ring_data_hash: Option<[u8; 32]>,
        tree_id: u16,
        leaf_index: u64,
    },
    Dummy {
        blinding: [u8; 32],
        tree_id: u16,
    },
    Compact {
        tree_id: u16,
    },
}

#[derive(SchemaWrite, SchemaRead)]
struct OutputWire {
    asset: Address,
    asset_id: u64,
    amount: u64,
    blinding: [u8; 32],
    ring_program_id: Option<Address>,
    ring_data_hash: Option<[u8; 32]>,
    data_hash: Option<[u8; 32]>,
    owner_address: Option<[u8; SHIELDED_ADDRESS_LEN]>,
    owner_tag: Option<[u8; 32]>,
    data: Data,
    compact: bool,
}

#[derive(SchemaWrite, SchemaRead)]
struct ExternalDataWire {
    instruction_discriminator: u8,
    expiry_unix_ts: u64,
    #[wincode(with = "containers::Vec<WithdrawalWire, FixIntLen<u8>>")]
    withdrawals: Vec<WithdrawalWire>,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
    tx_viewing_pk: [u8; 33],
    salt: [u8; 16],
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    outputs: Vec<TransactOutput>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    resolved_owner_tags: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    messages: Vec<MessageData>,
}

#[derive(SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u8")]
enum WithdrawalWire {
    Sol {
        amount: u64,
        recipient: Address,
    },
    Spl {
        mint: Address,
        amount: u64,
        user_token_account: Address,
        token_program: Address,
    },
}

impl ProofInputsWire {
    fn of(inputs: &RelayProofInputs) -> Result<Self, RelayProofInputsError> {
        check_nullifier_key(&inputs.sender, &inputs.nullifier_key)?;
        let external = &inputs.external_data;
        Ok(Self {
            rail: RailWire::of(&inputs.rail),
            ring_program_id: inputs.ring_program_id,
            sender: inputs.sender.to_bytes(),
            nullifier_secret: *inputs.nullifier_key.secret(),
            tx_viewing_secret: *inputs.tx_viewing_key.secret_bytes(),
            audit_ephemeral_key: *inputs.audit_ephemeral_key,
            inputs: inputs
                .inputs
                .iter()
                .enumerate()
                .map(|(index, input)| {
                    InputWire::of(input, &inputs.sender)
                        .ok_or(RelayProofInputsError::Input { index })
                })
                .collect::<Result<_, _>>()?,
            outputs: inputs
                .outputs
                .iter()
                .enumerate()
                .map(|(index, output)| OutputWire::of(output, index))
                .collect::<Result<_, _>>()?,
            external_data: ExternalDataWire {
                instruction_discriminator: external.instruction_discriminator,
                expiry_unix_ts: external.expiry_unix_ts,
                withdrawals: withdrawals(
                    &external.interface_transfers,
                    &inputs.interface_transfer_accounts,
                )?,
                data_hash: external.data_hash,
                ring_data_hash: external.ring_data_hash,
                tx_viewing_pk: external.tx_viewing_pk,
                salt: external.salt,
                outputs: external.outputs.clone(),
                resolved_owner_tags: external.resolved_owner_tags.clone(),
                messages: external.messages.clone(),
            },
            blinding_seed: inputs.blinding_seed,
            output_tree_id: inputs.output_tree_id,
        })
    }

    fn proof_inputs(&self) -> Result<RelayProofInputs, RelayProofInputsError> {
        let sender = ShieldedAddress::from_bytes(&self.sender)?;
        let nullifier_key = NullifierKey::from_secret(self.nullifier_secret);
        check_nullifier_key(&sender, &nullifier_key)?;
        let external = &self.external_data;
        let (interface_transfers, interface_transfer_accounts) = external
            .withdrawals
            .iter()
            .map(WithdrawalWire::legs)
            .unzip();
        Ok(RelayProofInputs {
            rail: self.rail.rail()?,
            ring_program_id: self.ring_program_id,
            inputs: self
                .inputs
                .iter()
                .map(|input| input.input(&sender, &nullifier_key))
                .collect::<Result<_, _>>()?,
            outputs: self
                .outputs
                .iter()
                .map(OutputWire::output)
                .collect::<Result<_, _>>()?,
            sender,
            nullifier_key,
            tx_viewing_key: ViewingKey::from_secret_key(X25519Keypair::from_bytes(
                &self.tx_viewing_secret,
            )),
            audit_ephemeral_key: Zeroizing::new(self.audit_ephemeral_key),
            external_data: ExternalData {
                instruction_discriminator: external.instruction_discriminator,
                expiry_unix_ts: external.expiry_unix_ts,
                interface_transfers,
                data_hash: external.data_hash,
                ring_data_hash: external.ring_data_hash,
                tx_viewing_pk: external.tx_viewing_pk,
                salt: external.salt,
                outputs: external.outputs.clone(),
                resolved_owner_tags: external.resolved_owner_tags.clone(),
                messages: external.messages.clone(),
            },
            interface_transfer_accounts,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
        })
    }
}

impl RailWire {
    fn of(rail: &RelayRail) -> Self {
        match rail {
            RelayRail::Anonymous {
                plan,
                exit_token_owner,
            } => Self::Anonymous {
                plan: Box::new(PlanWire {
                    sender_tag: *plan.sender_tag(),
                    payments: plan
                        .payments()
                        .iter()
                        .map(|payment| PaymentWire {
                            recipient: *payment.recipient.as_bytes(),
                            tag: payment.tag,
                        })
                        .collect(),
                    dummy_tags: *plan.dummy_tags(),
                }),
                exit_token_owner: *exit_token_owner,
            },
            RelayRail::Confidential => Self::Confidential,
            RelayRail::Delegate { delegate } => Self::Delegate {
                delegate: *delegate,
            },
            RelayRail::Deposit => Self::Deposit,
            RelayRail::Merge => Self::Merge,
        }
    }

    fn rail(&self) -> Result<RelayRail, RelayProofInputsError> {
        Ok(match self {
            Self::Anonymous {
                plan,
                exit_token_owner,
            } => RelayRail::Anonymous {
                plan: Box::new(AnonymousPlan::from_tags(
                    plan.sender_tag,
                    plan.payments
                        .iter()
                        .map(|payment| {
                            Ok(TaggedPayment {
                                recipient: X25519Pubkey::from_bytes(payment.recipient)?,
                                tag: payment.tag,
                            })
                        })
                        .collect::<Result<_, KeypairError>>()?,
                    plan.dummy_tags,
                )),
                exit_token_owner: *exit_token_owner,
            },
            Self::Confidential => RelayRail::Confidential,
            Self::Delegate { delegate } => RelayRail::Delegate {
                delegate: *delegate,
            },
            Self::Deposit => RelayRail::Deposit,
            Self::Merge => RelayRail::Merge,
        })
    }
}

impl InputWire {
    fn of(input: &SppProofInputUtxo, sender: &ShieldedAddress) -> Option<Self> {
        if input.is_address() || input.cache_slot.is_some() {
            return None;
        }
        let tree_id = input.tree_id;
        if input.is_compact() {
            return Some(Self::Compact { tree_id });
        }
        if input.is_dummy() {
            return Some(Self::Dummy {
                blinding: input.utxo.blinding,
                tree_id,
            });
        }
        if input.utxo.owner != sender.signing_pubkey
            || input.nullifier_pubkey != sender.nullifier_pubkey
        {
            return None;
        }
        let utxo = &input.utxo;
        Some(Self::Spend {
            asset: utxo.asset.asset,
            asset_id: utxo.asset.asset_id,
            amount: utxo.amount,
            blinding: utxo.blinding,
            ring_program_id: utxo.ring_program_id,
            data: utxo.data.clone(),
            data_hash: input.data_hash,
            ring_data_hash: input.ring_data_hash,
            tree_id,
            leaf_index: input.leaf_index,
        })
    }

    fn input(
        &self,
        sender: &ShieldedAddress,
        nullifier_key: &NullifierKey,
    ) -> Result<SppProofInputUtxo, RelayProofInputsError> {
        Ok(match self {
            Self::Compact { tree_id } => SppProofInputUtxo::compact(*tree_id)?,
            Self::Dummy { blinding, tree_id } => {
                SppProofInputUtxo::dummy_with_blinding(*blinding, *tree_id)?
            }
            Self::Spend {
                asset,
                asset_id,
                amount,
                blinding,
                ring_program_id,
                data,
                data_hash,
                ring_data_hash,
                tree_id,
                leaf_index,
            } => {
                let utxo = Utxo {
                    owner: sender.signing_pubkey,
                    asset: Mint::new(*asset, *asset_id),
                    amount: *amount,
                    blinding: *blinding,
                    ring_program_id: *ring_program_id,
                    data: data.clone(),
                };
                let utxo_hash = utxo.hash(
                    &sender.nullifier_pubkey,
                    &data_hash.unwrap_or_default(),
                    &ring_data_hash.unwrap_or_default(),
                    *tree_id,
                )?;
                SppProofInputUtxo {
                    address: false,
                    nullifier: nullifier_key.nullifier(&utxo_hash, blinding)?,
                    utxo,
                    nullifier_pubkey: sender.nullifier_pubkey,
                    utxo_hash,
                    data_hash: *data_hash,
                    ring_data_hash: *ring_data_hash,
                    tree_id: *tree_id,
                    leaf_index: *leaf_index,
                    cache_slot: None,
                    compact: false,
                }
            }
        })
    }
}

impl OutputWire {
    fn of(output: &SppProofOutputUtxo, index: usize) -> Result<Self, RelayProofInputsError> {
        if output.cache_slot.is_some() {
            return Err(RelayProofInputsError::CachedOutput { index });
        }
        Ok(Self {
            asset: output.asset.asset,
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            ring_data_hash: output.ring_data_hash,
            data_hash: output.data_hash,
            owner_address: output.owner_address.as_ref().map(ShieldedAddress::to_bytes),
            owner_tag: output.owner_tag,
            data: output.data.clone(),
            compact: output.compact,
        })
    }

    fn output(&self) -> Result<SppProofOutputUtxo, RelayProofInputsError> {
        Ok(SppProofOutputUtxo {
            asset: Mint::new(self.asset, self.asset_id),
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            ring_data_hash: self.ring_data_hash,
            data_hash: self.data_hash,
            owner_address: self
                .owner_address
                .as_ref()
                .map(ShieldedAddress::from_bytes)
                .transpose()?,
            owner_tag: self.owner_tag,
            data: self.data.clone(),
            cache_slot: None,
            compact: self.compact,
        })
    }
}

impl WithdrawalWire {
    fn legs(&self) -> (SettlementTransfer, TransactInterfaceTransferAccounts) {
        match *self {
            Self::Sol { amount, recipient } => (
                SettlementTransfer::Sol {
                    is_deposit: false,
                    amount,
                    user_sol_account: recipient,
                },
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
            ),
            Self::Spl {
                mint,
                amount,
                user_token_account,
                token_program,
            } => (
                SettlementTransfer::Spl {
                    mint,
                    is_deposit: false,
                    amount,
                    user_spl_token: user_token_account,
                },
                TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account,
                    token_program,
                }),
            ),
        }
    }
}

/// Each leg must be a withdrawal with the accounts decode derives for it.
fn withdrawals(
    transfers: &[SettlementTransfer],
    accounts: &[TransactInterfaceTransferAccounts],
) -> Result<Vec<WithdrawalWire>, RelayProofInputsError> {
    if transfers.len() != accounts.len() {
        return Err(RelayProofInputsError::Settlement {
            index: transfers.len().min(accounts.len()),
        });
    }
    transfers
        .iter()
        .zip(accounts)
        .enumerate()
        .map(|(index, (transfer, accounts))| {
            let wire = match (*transfer, *accounts) {
                (
                    SettlementTransfer::Sol {
                        is_deposit: false,
                        amount,
                        user_sol_account,
                    },
                    TransactInterfaceTransferAccounts::Sol(_),
                ) => WithdrawalWire::Sol {
                    amount,
                    recipient: user_sol_account,
                },
                (
                    SettlementTransfer::Spl {
                        mint,
                        is_deposit: false,
                        amount,
                        user_spl_token,
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(withdrawal),
                ) => WithdrawalWire::Spl {
                    mint,
                    amount,
                    user_token_account: user_spl_token,
                    token_program: withdrawal.token_program,
                },
                _ => return Err(RelayProofInputsError::Settlement { index }),
            };
            match wire.legs().1 == *accounts {
                true => Ok(wire),
                false => Err(RelayProofInputsError::Settlement { index }),
            }
        })
        .collect()
}

fn check_nullifier_key(
    sender: &ShieldedAddress,
    nullifier_key: &NullifierKey,
) -> Result<(), RelayProofInputsError> {
    match nullifier_key.pubkey()? == sender.nullifier_pubkey {
        true => Ok(()),
        false => Err(RelayProofInputsError::NullifierKey),
    }
}
