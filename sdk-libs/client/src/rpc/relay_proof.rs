use solana_address::Address;
use spr_event::MessageData;
use spr_instruction::instruction::{
    CreateAssociatedTokenAccount, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplDepositAccounts, TransactSplWithdrawalAccounts,
};
use spr_interface::{
    instruction::{instruction_data::transact::TransactOutput, InterfaceTransfer},
    pda, MAX_OUTPUTS,
};
use spr_keypair::{
    constants::BLINDING_LEN, KeypairError, NullifierKey, ShieldedAddress, ViewingKey,
    X25519Keypair, X25519Pubkey, SHIELDED_ADDRESS_LEN,
};
use spr_transaction::{
    instructions::transact::{CacheAccounts, ExternalData, SettlementTransfer, SppProofInputs},
    utxo::SppProofInputUtxo,
    Data, Mint, SppProofOutputUtxo, TransactionError, Utxo, WalletUtxo,
};
use thiserror::Error;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_transaction::AnonymousPlan;

use super::{RelayOperation, TokenAccountSetup};

pub struct RelayProofInputs {
    pub rail: RelayRail,
    pub ring_program_id: Address,
    /// Owns every real input no co-owner owns.
    pub sender: ShieldedAddress,
    pub nullifier_key: NullifierKey,
    /// Encoding sends only the co-owners a spend names.
    pub co_owners: Vec<RelayCoOwner>,
    /// Set on a frame that discloses its approval totals, drawn apart from `tx_viewing_key`.
    pub approval_blinder: Option<[u8; 32]>,
    pub tx_viewing_key: ViewingKey,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    /// One per interface transfer.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    /// Salts of owners the nullifier key does not derive.
    pub list_salts: Vec<SubjectListSalt>,
    /// The owner sealed under the wide key, the relayer proves on it.
    pub wide_owners: bool,
}

/// A public owner of later inputs, it signs the relay's message and the prover holds its secret.
#[derive(Clone)]
pub struct RelayCoOwner {
    pub owner: Address,
    pub nullifier_key: NullifierKey,
}

/// The leaf's `list_tag` refuses a wrong salt.
#[derive(Clone, Copy, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct SubjectListSalt {
    pub member: [u8; 32],
    pub list_salt: [u8; 32],
}

pub enum RelayRail {
    Anonymous {
        plan: Box<AnonymousPlan>,
        exit_token_owner: Option<Address>,
    },
    Confidential,
    Delegate {
        delegate: Address,
        /// Present exactly on an anonymous ring, the frame's sender bundle reads it.
        plan: Option<Box<AnonymousPlan>>,
    },
    /// Spends only dummies, the funder signs the returned message.
    Deposit {
        /// Present exactly on an anonymous ring.
        plan: Option<Box<AnonymousPlan>>,
    },
}

/// Ring RPC derives the merged note from the nullifier key.
pub struct RelayMergeInputs {
    pub ring_program_id: Address,
    /// Owns every input.
    pub sender: ShieldedAddress,
    pub nullifier_key: NullifierKey,
    pub inputs: Vec<WalletUtxo>,
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
    #[error("interface transfer {index} does not match its accounts")]
    Settlement { index: usize },
    #[error("nullifier key does not match the sender")]
    NullifierKey,
    #[error("merge input {index} is not a spend of the sender")]
    MergeInput { index: usize },
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum TokenAccountSetupError {
    #[error("token account setup {index} names no withdrawal into its associated account")]
    NoWithdrawal { index: usize },
    #[error("token account setup {index} repeats an earlier account")]
    Repeated { index: usize },
}

impl RelayRail {
    pub const fn operation(&self) -> RelayOperation {
        match self {
            Self::Anonymous { .. } => RelayOperation::Anonymous,
            Self::Confidential => RelayOperation::Confidential,
            Self::Delegate { .. } => RelayOperation::Delegate,
            Self::Deposit { .. } => RelayOperation::Deposit,
        }
    }
}

/// The key signing for a deposit leg, a withdrawal names none.
pub fn deposit_funder(
    transfer: &InterfaceTransfer,
    accounts: &TransactInterfaceTransferAccounts,
) -> Option<Address> {
    match accounts {
        TransactInterfaceTransferAccounts::Sol(sol) => {
            transfer.is_deposit().then_some(sol.recipient)
        }
        TransactInterfaceTransferAccounts::SplDeposit(spl) => Some(spl.token_authority),
        TransactInterfaceTransferAccounts::SplWithdrawal(_) => None,
    }
}

impl RelayProofInputs {
    /// In leg order.
    pub fn deposit_funders(&self) -> impl Iterator<Item = Address> + '_ {
        self.external_data
            .interface_transfers
            .iter()
            .zip(&self.interface_transfer_accounts)
            .filter_map(|(transfer, accounts)| {
                deposit_funder(&transfer.interface_transfer(), accounts)
            })
    }

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

    /// Idempotent creates funded by `payer`, each for an account a withdrawal of its mint pays.
    pub fn token_account_setup(
        &self,
        payer: Address,
        setup: &[TokenAccountSetup],
    ) -> Result<Vec<CreateAssociatedTokenAccount>, TokenAccountSetupError> {
        let mut created: Vec<Address> = Vec::with_capacity(setup.len());
        setup
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let create = self
                    .interface_transfer_accounts
                    .iter()
                    .find_map(|accounts| match accounts {
                        TransactInterfaceTransferAccounts::SplWithdrawal(withdrawal)
                            if withdrawal.mint == entry.mint.0 =>
                        {
                            let create = CreateAssociatedTokenAccount {
                                payer,
                                owner: entry.owner.0,
                                mint: withdrawal.mint,
                                token_program: withdrawal.token_program,
                            };
                            (create.address() == withdrawal.user_token_account).then_some(create)
                        }
                        _ => None,
                    })
                    .ok_or(TokenAccountSetupError::NoWithdrawal { index })?;
                if created.contains(&create.address()) {
                    return Err(TokenAccountSetupError::Repeated { index });
                }
                created.push(create.address());
                Ok(create)
            })
            .collect()
    }
}

impl RelayMergeInputs {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelayProofInputsError> {
        check_nullifier_key(&self.sender, &self.nullifier_key)?;
        let wire = MergeWire {
            ring_program_id: self.ring_program_id,
            sender: self.sender.to_bytes(),
            nullifier_secret: *self.nullifier_key.secret(),
            inputs: self
                .inputs
                .iter()
                .enumerate()
                .map(|(index, input)| {
                    SpendWire::of(&SppProofInputUtxo::from(input), &self.sender, &[])
                        .ok_or(RelayProofInputsError::MergeInput { index })
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Zeroizing::new(wincode::serialize(&wire)?))
    }

    /// Derives each input hash and nullifier again from its opening and the nullifier key.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        let wire: MergeWire = wincode::deserialize_exact(bytes)?;
        let sender = ShieldedAddress::from_bytes(&wire.sender)?;
        let nullifier_key = NullifierKey::from_secret(wire.nullifier_secret);
        check_nullifier_key(&sender, &nullifier_key)?;
        let inputs = wire
            .inputs
            .iter()
            .map(|spend| {
                let input = spend.input(&sender, &nullifier_key, &[])?;
                Ok(WalletUtxo {
                    utxo: input.utxo,
                    nullifier_pubkey: input.nullifier_pubkey,
                    utxo_hash: input.utxo_hash,
                    nullifier: input.nullifier,
                    tx_viewing_key: None,
                    data_hash: input.data_hash,
                    ring_data_hash: input.ring_data_hash,
                    tree_id: input.tree_id,
                    leaf_index: input.leaf_index,
                    latest_tree_id: None,
                    slot: 0,
                    tx_signature: Default::default(),
                    slot_index: 0,
                })
            })
            .collect::<Result<_, RelayProofInputsError>>()?;
        Ok(Self {
            ring_program_id: wire.ring_program_id,
            sender,
            nullifier_key,
            inputs,
        })
    }
}

#[derive(SchemaWrite, SchemaRead)]
struct MergeWire {
    ring_program_id: Address,
    sender: [u8; SHIELDED_ADDRESS_LEN],
    nullifier_secret: [u8; BLINDING_LEN],
    #[wincode(with = "containers::Vec<SpendWire, FixIntLen<u8>>")]
    inputs: Vec<SpendWire>,
}

impl Drop for MergeWire {
    fn drop(&mut self) {
        self.nullifier_secret.zeroize();
    }
}

#[derive(SchemaWrite, SchemaRead)]
struct ProofInputsWire {
    rail: RailWire,
    ring_program_id: Address,
    sender: [u8; SHIELDED_ADDRESS_LEN],
    nullifier_secret: [u8; BLINDING_LEN],
    tx_viewing_secret: [u8; 32],
    #[wincode(with = "containers::Vec<InputWire, FixIntLen<u8>>")]
    inputs: Vec<InputWire>,
    #[wincode(with = "containers::Vec<OutputWire, FixIntLen<u8>>")]
    outputs: Vec<OutputWire>,
    external_data: ExternalDataWire,
    blinding_seed: [u8; 32],
    output_tree_id: u16,
    #[wincode(with = "containers::Vec<SubjectListSalt, FixIntLen<u8>>")]
    list_salts: Vec<SubjectListSalt>,
    wide_owners: bool,
    #[wincode(with = "containers::Vec<CoOwnerWire, FixIntLen<u8>>")]
    co_owners: Vec<CoOwnerWire>,
    approval_blinder: Option<[u8; 32]>,
}

#[derive(SchemaWrite, SchemaRead)]
struct CoOwnerWire {
    owner: Address,
    nullifier_secret: [u8; BLINDING_LEN],
}

impl Drop for ProofInputsWire {
    fn drop(&mut self) {
        self.clear_secrets();
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
        plan: Option<Box<PlanWire>>,
    },
    Deposit {
        plan: Option<Box<PlanWire>>,
    },
}

#[derive(SchemaWrite, SchemaRead)]
struct PlanWire {
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    recipients: Vec<[u8; 33]>,
    dummy_preimages: [[u8; 32]; MAX_OUTPUTS],
}

#[derive(SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u8")]
enum InputWire {
    Spend(Box<SpendWire>),
    Dummy { blinding: [u8; 32], tree_id: u16 },
    Compact { tree_id: u16 },
}

#[derive(SchemaWrite, SchemaRead)]
struct SpendWire {
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
    /// Unset on the sender's input.
    co_owner: Option<Address>,
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
    #[wincode(with = "containers::Vec<LegWire, FixIntLen<u8>>")]
    legs: Vec<LegWire>,
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
enum LegWire {
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
    SolDeposit {
        amount: u64,
        funder: Address,
    },
    SplDeposit {
        mint: Address,
        amount: u64,
        token_authority: Address,
        user_token_account: Address,
        token_program: Address,
    },
}

impl ProofInputsWire {
    fn clear_secrets(&mut self) {
        self.nullifier_secret.zeroize();
        self.tx_viewing_secret.zeroize();
        self.blinding_seed.zeroize();
        self.approval_blinder.zeroize();
        for co_owner in &mut self.co_owners {
            co_owner.nullifier_secret.zeroize();
        }
    }

    fn of(inputs: &RelayProofInputs) -> Result<Self, RelayProofInputsError> {
        check_nullifier_key(&inputs.sender, &inputs.nullifier_key)?;
        let external = &inputs.external_data;
        // 1. Each spend matches its owner by address and nullifier key, the co-owner secrets below follow the match.
        let spends: Vec<InputWire> = inputs
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                InputWire::of(input, &inputs.sender, &inputs.co_owners)
                    .ok_or(RelayProofInputsError::Input { index })
            })
            .collect::<Result<_, _>>()?;
        // 2. The relayer gets no nullifier secret of a co-owner no spend names, a spend matches the first held key per owner.
        let named = |owner: Address| {
            spends.iter().any(
                |wire| matches!(wire, InputWire::Spend(spend) if spend.co_owner == Some(owner)),
            )
        };
        let co_owners = inputs
            .co_owners
            .iter()
            .enumerate()
            .filter(|(index, held)| {
                named(held.owner)
                    && inputs
                        .co_owners
                        .iter()
                        .position(|first| first.owner == held.owner)
                        == Some(*index)
            })
            .map(|(_, held)| CoOwnerWire {
                owner: held.owner,
                nullifier_secret: *held.nullifier_key.secret(),
            })
            .collect();
        Ok(Self {
            rail: RailWire::of(&inputs.rail),
            ring_program_id: inputs.ring_program_id,
            sender: inputs.sender.to_bytes(),
            nullifier_secret: *inputs.nullifier_key.secret(),
            tx_viewing_secret: *inputs.tx_viewing_key.secret_bytes(),
            inputs: spends,
            outputs: inputs
                .outputs
                .iter()
                .enumerate()
                .map(|(index, output)| OutputWire::of(output, index))
                .collect::<Result<_, _>>()?,
            external_data: ExternalDataWire {
                instruction_discriminator: external.instruction_discriminator,
                expiry_unix_ts: external.expiry_unix_ts,
                legs: legs(
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
            list_salts: inputs.list_salts.clone(),
            wide_owners: inputs.wide_owners,
            co_owners,
            approval_blinder: inputs.approval_blinder,
        })
    }

    fn proof_inputs(&self) -> Result<RelayProofInputs, RelayProofInputsError> {
        let sender = ShieldedAddress::from_bytes(&self.sender)?;
        let nullifier_key = NullifierKey::from_secret(self.nullifier_secret);
        check_nullifier_key(&sender, &nullifier_key)?;
        let external = &self.external_data;
        let (interface_transfers, interface_transfer_accounts) =
            external.legs.iter().map(LegWire::settlement).unzip();
        let co_owners: Vec<RelayCoOwner> = self
            .co_owners
            .iter()
            .map(|co_owner| RelayCoOwner {
                owner: co_owner.owner,
                nullifier_key: NullifierKey::from_secret(co_owner.nullifier_secret),
            })
            .collect();
        Ok(RelayProofInputs {
            rail: self.rail.rail()?,
            ring_program_id: self.ring_program_id,
            inputs: self
                .inputs
                .iter()
                .map(|input| input.input(&sender, &nullifier_key, &co_owners))
                .collect::<Result<_, _>>()?,
            co_owners,
            approval_blinder: self.approval_blinder,
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
            list_salts: self.list_salts.clone(),
            wide_owners: self.wide_owners,
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
                plan: Box::new(PlanWire::of(plan)),
                exit_token_owner: *exit_token_owner,
            },
            RelayRail::Confidential => Self::Confidential,
            RelayRail::Delegate { delegate, plan } => Self::Delegate {
                delegate: *delegate,
                plan: plan.as_deref().map(|plan| Box::new(PlanWire::of(plan))),
            },
            RelayRail::Deposit { plan } => Self::Deposit {
                plan: plan.as_deref().map(|plan| Box::new(PlanWire::of(plan))),
            },
        }
    }

    fn rail(&self) -> Result<RelayRail, RelayProofInputsError> {
        Ok(match self {
            Self::Anonymous {
                plan,
                exit_token_owner,
            } => RelayRail::Anonymous {
                plan: Box::new(plan.plan()?),
                exit_token_owner: *exit_token_owner,
            },
            Self::Confidential => RelayRail::Confidential,
            Self::Delegate { delegate, plan } => RelayRail::Delegate {
                delegate: *delegate,
                plan: plan
                    .as_deref()
                    .map(|plan| plan.plan().map(Box::new))
                    .transpose()?,
            },
            Self::Deposit { plan } => RelayRail::Deposit {
                plan: plan
                    .as_deref()
                    .map(|plan| plan.plan().map(Box::new))
                    .transpose()?,
            },
        })
    }
}

impl PlanWire {
    fn of(plan: &AnonymousPlan) -> Self {
        Self {
            recipients: plan
                .recipients()
                .iter()
                .map(|recipient| *recipient.as_bytes())
                .collect(),
            dummy_preimages: *plan.dummy_preimages(),
        }
    }

    fn plan(&self) -> Result<AnonymousPlan, RelayProofInputsError> {
        Ok(AnonymousPlan::from_parts(
            self.recipients
                .iter()
                .map(|recipient| X25519Pubkey::from_bytes(*recipient))
                .collect::<Result<_, KeypairError>>()?,
            self.dummy_preimages,
        ))
    }
}

impl InputWire {
    fn of(
        input: &SppProofInputUtxo,
        sender: &ShieldedAddress,
        co_owners: &[RelayCoOwner],
    ) -> Option<Self> {
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
        SpendWire::of(input, sender, co_owners).map(|spend| Self::Spend(Box::new(spend)))
    }

    fn input(
        &self,
        sender: &ShieldedAddress,
        nullifier_key: &NullifierKey,
        co_owners: &[RelayCoOwner],
    ) -> Result<SppProofInputUtxo, RelayProofInputsError> {
        Ok(match self {
            Self::Compact { tree_id } => SppProofInputUtxo::compact(*tree_id)?,
            Self::Dummy { blinding, tree_id } => {
                SppProofInputUtxo::dummy_with_blinding(*blinding, *tree_id)?
            }
            Self::Spend(spend) => spend.input(sender, nullifier_key, co_owners)?,
        })
    }
}

impl SpendWire {
    fn of(
        input: &SppProofInputUtxo,
        sender: &ShieldedAddress,
        co_owners: &[RelayCoOwner],
    ) -> Option<Self> {
        if input.is_address()
            || input.cache_slot.is_some()
            || input.is_compact()
            || input.is_dummy()
        {
            return None;
        }
        let utxo = &input.utxo;
        let spent_by_sender = utxo.owner == sender.signing_pubkey
            && input.nullifier_pubkey == sender.nullifier_pubkey;
        let co_owner = match spent_by_sender {
            true => None,
            false => {
                let named = Address::new_from_array(utxo.owner.as_ed25519().ok()?);
                let held = co_owners.iter().find(|co_owner| co_owner.owner == named)?;
                (held.nullifier_key.pubkey().ok()? == input.nullifier_pubkey).then_some(named)?;
                Some(named)
            }
        };
        Some(Self {
            asset: utxo.asset.asset,
            asset_id: utxo.asset.asset_id,
            amount: utxo.amount,
            blinding: utxo.blinding,
            ring_program_id: utxo.ring_program_id,
            data: utxo.data.clone(),
            data_hash: input.data_hash,
            ring_data_hash: input.ring_data_hash,
            tree_id: input.tree_id,
            leaf_index: input.leaf_index,
            co_owner,
        })
    }

    fn input(
        &self,
        sender: &ShieldedAddress,
        sender_key: &NullifierKey,
        co_owners: &[RelayCoOwner],
    ) -> Result<SppProofInputUtxo, RelayProofInputsError> {
        let (owner, nullifier_pubkey, nullifier_key) = match self.co_owner {
            None => (sender.signing_pubkey, sender.nullifier_pubkey, sender_key),
            Some(named) => {
                let held = co_owners
                    .iter()
                    .find(|co_owner| co_owner.owner == named)
                    .ok_or(RelayProofInputsError::NullifierKey)?;
                (
                    spr_keypair::PublicKey::from_ed25519(named.as_array()),
                    held.nullifier_key.pubkey()?,
                    &held.nullifier_key,
                )
            }
        };
        let utxo = Utxo {
            owner,
            asset: Mint::new(self.asset, self.asset_id),
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data.clone(),
        };
        let utxo_hash = utxo.hash(
            &nullifier_pubkey,
            &self.data_hash.unwrap_or_default(),
            &self.ring_data_hash.unwrap_or_default(),
            self.tree_id,
        )?;
        Ok(SppProofInputUtxo {
            address: false,
            nullifier: nullifier_key.nullifier(&utxo_hash, &self.blinding)?,
            utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
            cache_slot: None,
            compact: false,
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

impl LegWire {
    fn settlement(&self) -> (SettlementTransfer, TransactInterfaceTransferAccounts) {
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
            Self::SolDeposit { amount, funder } => (
                SettlementTransfer::Sol {
                    is_deposit: true,
                    amount,
                    user_sol_account: funder,
                },
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: funder,
                }),
            ),
            Self::SplDeposit {
                mint,
                amount,
                token_authority,
                user_token_account,
                token_program,
            } => (
                SettlementTransfer::Spl {
                    mint,
                    is_deposit: true,
                    amount,
                    user_spl_token: user_token_account,
                },
                TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    token_authority,
                    user_token_account,
                    token_program,
                }),
            ),
        }
    }
}

/// Each leg must carry the accounts decode derives for it.
fn legs(
    transfers: &[SettlementTransfer],
    accounts: &[TransactInterfaceTransferAccounts],
) -> Result<Vec<LegWire>, RelayProofInputsError> {
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
                ) => LegWire::Sol {
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
                ) => LegWire::Spl {
                    mint,
                    amount,
                    user_token_account: user_spl_token,
                    token_program: withdrawal.token_program,
                },
                (
                    SettlementTransfer::Sol {
                        is_deposit: true,
                        amount,
                        user_sol_account,
                    },
                    TransactInterfaceTransferAccounts::Sol(_),
                ) => LegWire::SolDeposit {
                    amount,
                    funder: user_sol_account,
                },
                (
                    SettlementTransfer::Spl {
                        mint,
                        is_deposit: true,
                        amount,
                        user_spl_token,
                    },
                    TransactInterfaceTransferAccounts::SplDeposit(deposit),
                ) => LegWire::SplDeposit {
                    mint,
                    amount,
                    token_authority: deposit.token_authority,
                    user_token_account: user_spl_token,
                    token_program: deposit.token_program,
                },
                _ => return Err(RelayProofInputsError::Settlement { index }),
            };
            match wire.settlement().1 == *accounts {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_wire_inputs_hold_no_secret_a_blinding_derives_from() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/rpc/relay_proof_inputs.json"
        ))
        .unwrap();
        let encoded: spr_indexer_api::Base64String =
            serde_json::from_value(vector["proofInputs"].clone()).unwrap();
        let mut wire: ProofInputsWire = wincode::deserialize_exact(&encoded.0).unwrap();
        wire.approval_blinder = Some([9; 32]);
        assert_ne!(wire.blinding_seed, [0; 32]);
        wire.clear_secrets();
        assert_eq!(wire.nullifier_secret, [0; BLINDING_LEN]);
        assert_eq!(wire.tx_viewing_secret, [0; 32]);
        assert_eq!(wire.blinding_seed, [0; 32]);
        assert_eq!(wire.approval_blinder, None);
    }
}
