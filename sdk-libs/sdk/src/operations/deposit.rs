//! A ring deposit is a transfer frame that spends only dummies. Public deposit legs fund one ring
//! output per recipient, and every check of the transfer statement runs on it.
//!
//! Read after `operations/pipeline/mod.rs`. Read before `operations/pipeline/relay.rs`.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};

use custom_ring_interface::{
    cosign::{ApprovalMask, CoSignDemand, CoSignOperation},
    CoSignScope, RingMode,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{AsyncRpc, ClientError};
use spr_indexer_api::SerializablePubkey;
use spr_interface::{pda, state::SplAssetRegistry, N_PUBLIC_SLOTS, PROGRAM_ID_PUBKEY};
use spr_keypair::{NullifierKey, ShieldedAddress, ShieldedKeypair};
use spr_program::instruction::{
    DepositAsset, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplDepositAccounts,
};
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, Data, Mint, SppProofOutputUtxo, Utxo,
    SOL_ASSET_ID, SOL_MINT,
};
use zolana_ring_client::rpc::{PrepareRelayRequest, ProofInputBytes, RelayIntent, RelayQuote};
use zolana_ring_keys::RingAddress;
use zolana_ring_policy::Member;

use crate::client::{RingClient, RingIndexerBackend};
use crate::SignatureHistory;
use crate::{
    co_signer::CoSignerChoice,
    pipeline::{
        AnonymousPayment, CustomRingTransfer, CustomRingTransferInput, HiddenOwner, NoteData,
        ProvenRingTransfer, PublicOwnerTransfer, RingSender,
    },
    relay_message::ExpectedMessage,
    tree_id, CustomRing, PreparedRelay, RingError, RingSubmission, SettledSubmission,
};

#[cfg(test)]
#[path = "../tests/operations/deposit.rs"]
mod tests;

/// The widest output row of a standard transfer key.
const MAX_DEPOSIT_RECIPIENTS: usize = 8;

#[derive(Clone, Copy)]
pub enum DepositRecipient<'a> {
    /// The member finds the note under its viewing key's tag.
    Confidential(ShieldedAddress),
    /// The depositor's own hidden owner on an anonymous ring, paid like any member.
    Anonymous { keys: &'a dyn RingSender },
    /// Another member of an anonymous ring.
    AnonymousPayment { to: &'a RingAddress },
}

#[derive(Clone, Copy)]
pub struct DepositOutput<'a> {
    pub recipient: DepositRecipient<'a>,
    pub asset: DepositAsset,
    pub amount: u64,
    /// A salted list refuses an enrolled recipient with none.
    pub list_salt: Option<[u8; 32]>,
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub recipient: DepositRecipient<'a>,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// Signs when a record covers deposits, the record must be its own.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
    /// A salted list refuses an enrolled recipient with none.
    pub list_salt: Option<[u8; 32]>,
}

#[must_use]
pub struct RingDepositBatch<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub tree: Address,
    /// In output order.
    pub outputs: Vec<DepositOutput<'a>>,
    /// Signs when a record covers deposits, the record must be its own.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

pub struct RingDepositBatchReceipt {
    pub signature: Signature,
    /// In output order.
    pub utxos: Vec<Utxo>,
}

/// One attempt proves once.
#[must_use]
pub struct PreparedRingDeposit {
    terms: DepositTerms,
    sender: ShieldedKeypair,
    /// Holds the deposit legs, outputs join it per proof.
    transaction: ConfidentialTransaction,
    priority_fee: Option<u64>,
    proved: AtomicBool,
    utxos: OnceLock<Vec<Utxo>>,
}

#[derive(Clone)]
struct DepositTerms {
    ring: CustomRing,
    mode: RingMode,
    tree_id: u16,
    fee_payer: Address,
    depositor: Address,
    cosigner: Option<Address>,
    outputs: Vec<NoteTerms>,
    legs: Vec<DepositLeg>,
}

#[derive(Clone)]
struct NoteTerms {
    recipient: ShieldedAddress,
    mint: Mint,
    amount: u64,
    list_salt: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
struct DepositLeg {
    asset: DepositAsset,
    mint: Mint,
    amount: u64,
}

enum DepositTransfer<'a> {
    Confidential(CustomRingTransfer<'a>),
    Anonymous(PublicOwnerTransfer<'a>),
}

impl<'a> RingDeposit<'a> {
    fn batch(&self) -> RingDepositBatch<'a> {
        RingDepositBatch {
            ring: self.ring,
            payer: self.payer,
            tree: self.tree,
            outputs: vec![DepositOutput {
                recipient: self.recipient,
                asset: self.asset,
                amount: self.amount,
                list_salt: self.list_salt,
            }],
            cosigner: self.cosigner,
        }
    }

    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        self.batch().prepare(rpc).await
    }

    /// The depositor signs the request here and the message Ring RPC answers with.
    pub async fn prepare_relay(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        self.batch().prepare_relay(rpc, quote).await
    }

    pub async fn send<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<RingDepositReceipt, RingError> {
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositReceipt, RingError> {
        let RingDepositBatchReceipt { signature, utxos } =
            self.batch().send_with_fee_payer(client, fee_payer).await?;
        let [utxo] = <[Utxo; 1]>::try_from(utxos).map_err(|_| RingError::DepositUnkeyed)?;
        Ok(RingDepositReceipt { signature, utxo })
    }
}

impl<'a> RingDepositBatch<'a> {
    /// The depositor pays the transaction fees.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        self.prepare_paid(rpc, self.payer.pubkey()).await
    }

    /// Ring RPC's fee payer pays, the depositor signs the request digest now and its legs later.
    pub async fn prepare_relay(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        let fee_payer = quote.fee_payer.0;
        // The fee payer signs whatever the relay sends, no leg may name it.
        if self.payer.pubkey() == fee_payer {
            return Err(RingError::RelayFeePayerFundsDeposit);
        }
        let prepared = self.prepare_paid(rpc, fee_payer).await?;
        prepared.check_public_signers([fee_payer])?;
        let (inputs, terms) = match prepared.transfer()? {
            DepositTransfer::Confidential(transfer) => transfer.deposit_relay(rpc).await?,
            DepositTransfer::Anonymous(transfer) => transfer.deposit_relay(rpc).await?,
        };
        let proof_inputs = ProofInputBytes::new(inputs.encode()?);
        let depositor_signature = self
            .payer
            .try_sign_message(&proof_inputs.deposit_request_digest())?
            .into();
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.ring.program_id()),
            quote,
            intent: RelayIntent::Deposit {
                proof_inputs,
                depositor_signature,
            },
            co_signers: prepared
                .terms
                .cosigner
                .into_iter()
                .map(SerializablePubkey)
                .collect(),
        })
        .expecting(ExpectedMessage::Sealed(terms)))
    }

    pub async fn send<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<RingDepositBatchReceipt, RingError> {
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc + SignatureHistory, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositBatchReceipt, RingError> {
        let prepared = self
            .prepare_paid(client.zolana(), fee_payer.pubkey())
            .await?;
        let signers = self.signers(&prepared);
        let mut submission = RingSubmission::new(prepared);
        submission.prove(client, fee_payer, &signers).await?;
        match submission
            .send_until_settled(client, fee_payer, &signers)
            .await?
        {
            SettledSubmission::Confirmed { signature, .. } => Ok(RingDepositBatchReceipt {
                signature,
                utxos: submission
                    .deposit_utxos()
                    .ok_or(RingError::DepositFrameReused)?
                    .to_vec(),
            }),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error })
            }
        }
    }

    /// A co-signer the ring does not demand is no account of the deposit and cannot sign it.
    pub(crate) fn signers(&self, prepared: &PreparedRingDeposit) -> Vec<&'a (dyn Signer + Sync)> {
        core::iter::once(self.payer)
            .chain(self.cosigner.filter(|_| prepared.terms.cosigner.is_some()))
            .collect()
    }

    async fn prepare_paid(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        fee_payer: Address,
    ) -> Result<PreparedRingDeposit, RingError> {
        // 1. A frame carries at most the widest output row and one public cell per leg, refused
        // before any account read.
        let legs = self.legs();
        if self.outputs.is_empty()
            || self.outputs.len() > MAX_DEPOSIT_RECIPIENTS
            || legs.len() > N_PUBLIC_SLOTS
        {
            return Err(RingError::DepositUnkeyed);
        }
        // 2. The ring's mode decides the rail, a confidential recipient on an anonymous ring would
        // publish its viewing key tag.
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let anonymous = config.mode == RingMode::Anonymous;
        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                let (recipient, list_salt) = output.recipient.address(self.ring, anonymous)?;
                Ok((output, recipient, list_salt.or(output.list_salt)))
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let mut notes = Vec::with_capacity(outputs.len());
        for (output, recipient, list_salt) in outputs {
            notes.push(NoteTerms {
                recipient,
                mint: mint_of(rpc, output.asset).await?,
                amount: output.amount,
                list_salt,
            });
        }
        let mut deposit_legs = Vec::with_capacity(legs.len());
        for (asset, amount) in legs {
            deposit_legs.push(DepositLeg {
                asset,
                mint: mint_of(rpc, asset).await?,
                amount,
            });
        }
        // 3. A deposit leg demands its class alone, no note is spent.
        let cosigner = CoSignerChoice {
            ring: self.ring,
            config: &config,
            demand: deposit_demand(),
            supplied: self
                .cosigner
                .map(|signer| signer.pubkey())
                .into_iter()
                .collect(),
        }
        .resolve(rpc)
        .await?
        .into_iter()
        .next();
        let terms = DepositTerms {
            ring: self.ring,
            mode: config.mode,
            tree_id: tree_id(rpc, self.tree).await?,
            fee_payer,
            depositor: self.payer.pubkey(),
            cosigner,
            outputs: notes,
            legs: deposit_legs,
        };
        let prepared = PreparedRingDeposit::draw(terms)?;
        prepared.check_public_signers(
            core::iter::once(self.payer.pubkey()).chain(prepared.terms.cosigner),
        )?;
        Ok(prepared)
    }

    /// One leg per asset source, the funder signs each.
    fn legs(&self) -> Vec<(DepositAsset, u64)> {
        let mut legs: Vec<(DepositAsset, u64)> = Vec::new();
        for output in &self.outputs {
            match legs.iter_mut().find(|(asset, _)| *asset == output.asset) {
                Some((_, amount)) => *amount = amount.saturating_add(output.amount),
                None => legs.push((output.asset, output.amount)),
            }
        }
        legs
    }
}

impl DepositRecipient<'_> {
    /// The recipient and the list salt its ring address carries.
    fn address(
        &self,
        ring: CustomRing,
        anonymous: bool,
    ) -> Result<(ShieldedAddress, Option<[u8; 32]>), RingError> {
        match (*self, anonymous) {
            (Self::Confidential(address), false) => Ok((address, None)),
            (Self::Anonymous { keys }, true) => Ok((keys.address()?, None)),
            (Self::AnonymousPayment { to }, true) => {
                if to.ring_program_id != ring.program_id() {
                    return Err(RingError::ForeignRingAddress {
                        address: to.ring_program_id,
                        ring: ring.program_id(),
                    });
                }
                Ok((to.recipient, Some(to.list_salt)))
            }
            (Self::Confidential(_), true) => Err(RingError::AnonymousDepositUntagged),
            (Self::Anonymous { .. } | Self::AnonymousPayment { .. }, false) => {
                Err(RingError::NotAnonymousRing)
            }
        }
    }
}

impl PreparedRingDeposit {
    /// The same deposit under a new sender and dummy input, nothing here reads a chain value.
    pub fn fresh_attempt(&self) -> Result<Self, RingError> {
        Ok(Self {
            priority_fee: self.priority_fee,
            ..Self::draw(self.terms.clone())?
        })
    }

    /// Lamports the v1 header carries, the size check measures the header it adds.
    pub fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    /// In output order, empty until the attempt proves.
    pub fn utxos(&self) -> &[Utxo] {
        self.utxos.get().map_or(&[], Vec::as_slice)
    }

    /// Signs every deposit leg.
    pub fn depositor(&self) -> Address {
        self.terms.depositor
    }

    /// `Some` when a record covers deposits.
    pub fn co_signer(&self) -> Option<Address> {
        self.terms.cosigner
    }

    pub fn co_sign_demand(&self) -> CoSignDemand {
        deposit_demand()
    }

    /// A second proof of the attempt is refused, a retry starts from [`Self::fresh_attempt`].
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Instruction, RingError> {
        self.prove_transfer(client).await?.instruction()
    }

    pub(crate) async fn prove_transfer<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        if self.proved.swap(true, Ordering::AcqRel) {
            return Err(RingError::DepositFrameReused);
        }
        let proven = match self.transfer()? {
            DepositTransfer::Confidential(transfer) => transfer.prove(client).await?,
            DepositTransfer::Anonymous(transfer) => transfer.prove(client).await?,
        };
        let sender = self.sender.shielded_address()?;
        let utxos = proven
            .outputs
            .iter()
            .filter_map(|output| deposited(output, &sender))
            .collect();
        // The attempt proves once, the cell is empty here.
        let _ = self.utxos.set(utxos);
        Ok(proven)
    }

    pub(crate) fn frame_spent(&self) -> bool {
        self.proved.load(Ordering::Acquire)
    }

    /// No public signer may name an anonymous recipient.
    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        if self.terms.mode != RingMode::Anonymous {
            return Ok(());
        }
        let signers: Vec<Address> = signers.into_iter().collect();
        self.terms.outputs.iter().try_for_each(|note| {
            HiddenOwner::of(&note.recipient.signing_pubkey)?.check_signers(signers.iter().copied())
        })
    }

    fn draw(terms: DepositTerms) -> Result<Self, RingError> {
        let mut transaction = ConfidentialTransaction::new_deposit_with_ring(
            terms.tree_id,
            terms.fee_payer,
            terms.ring.program_id(),
        )?;
        for leg in &terms.legs {
            match leg.asset {
                DepositAsset::Sol => transaction.deposit_sol(leg.amount, terms.depositor)?,
                DepositAsset::Spl(spl) => {
                    transaction.deposit(leg.mint, leg.amount, spl.user_token)?
                }
            };
        }
        // The fresh sender holds no tracking row, a zero SOL change it takes in a spare slot
        // refuses under any key but the zero key.
        let mut sender = ShieldedKeypair::new_ed25519()?;
        sender.nullifier_key = NullifierKey::from_secret([0; 31]);
        Ok(Self {
            sender,
            transaction,
            terms,
            priority_fee: None,
            proved: AtomicBool::new(false),
            utxos: OnceLock::new(),
        })
    }

    /// Recipients join in output order, salted owners read their list key.
    fn transfer(&self) -> Result<DepositTransfer<'_>, RingError> {
        let terms = &self.terms;
        let ring = terms.ring.program_id();
        let mut transaction = self.transaction.clone();
        if terms.mode == RingMode::Confidential {
            for note in &terms.outputs {
                transaction.transfer_with_ring(
                    &note.recipient,
                    note.mint,
                    note.amount,
                    Some(ring),
                )?;
            }
        }
        let accounts = terms
            .legs
            .iter()
            .map(|leg| leg.accounts(terms.depositor))
            .collect();
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: terms.ring,
            sender: &self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(accounts);
        if let Some(cosigner) = terms.cosigner {
            transfer = transfer.with_co_signer(cosigner);
        }
        if let Some(lamports) = self.priority_fee {
            transfer = transfer.with_priority_fee(lamports);
        }
        if terms.mode == RingMode::Confidential {
            for note in &terms.outputs {
                if let Some(salt) = note.list_salt {
                    transfer = transfer.with_list_salt(note.member()?, salt);
                }
            }
            return Ok(DepositTransfer::Confidential(transfer));
        }
        // An anonymous payment carries its salt in its ring address.
        let mut transfer = transfer.spend_public(self.sender.shielded_address()?.solana_address()?);
        for note in &terms.outputs {
            transfer = transfer.with_payment(AnonymousPayment {
                to: RingAddress {
                    recipient: note.recipient,
                    ring_program_id: ring,
                    list_salt: note.list_salt.unwrap_or_default(),
                },
                asset: note.mint,
                amount: note.amount,
                reply: None,
                data: NoteData::default(),
            })?;
        }
        Ok(DepositTransfer::Anonymous(transfer))
    }
}

impl NoteTerms {
    fn member(&self) -> Result<Member, RingError> {
        Ok(Member::from_bytes(
            self.recipient.signing_pubkey.owner_proof_input_hash()?,
        )?)
    }
}

impl DepositLeg {
    fn accounts(&self, depositor: Address) -> TransactInterfaceTransferAccounts {
        match self.asset {
            DepositAsset::Sol => {
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: depositor,
                })
            }
            DepositAsset::Spl(spl) => {
                TransactInterfaceTransferAccounts::SplDeposit(TransactSplDepositAccounts {
                    mint: spl.mint,
                    spl_interface: pda::spl_interface(&spl.mint),
                    token_authority: depositor,
                    user_token_account: spl.user_token,
                    token_program: spl.token_program,
                })
            }
        }
    }
}

fn deposit_demand() -> CoSignDemand {
    CoSignOperation {
        spends_note: false,
        public_legs: CoSignScope::DEPOSITS,
        approval: ApprovalMask::default(),
    }
    .demand()
}

/// A recipient's note, the sender's zero change and the padding left out.
fn deposited(output: &SppProofOutputUtxo, sender: &ShieldedAddress) -> Option<Utxo> {
    let owner = output
        .owner_address
        .filter(|owner| owner.signing_pubkey != sender.signing_pubkey)?;
    Some(Utxo {
        owner: owner.signing_pubkey,
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        ring_program_id: output.ring_program_id,
        data: Data::default(),
    })
}

async fn mint_of(rpc: &(impl AsyncRpc + ?Sized), asset: DepositAsset) -> Result<Mint, RingError> {
    let mint = match asset {
        DepositAsset::Sol => SOL_MINT,
        DepositAsset::Spl(spl) => spl.mint,
    };
    Ok(Mint::new(mint, fetch_asset_id_async(rpc, mint).await?))
}

/// The asset id SPP keys `asset` by, SOL without a read, an SPL mint from its registry account.
pub async fn fetch_asset_id_async<R: AsyncRpc + ?Sized>(
    rpc: &R,
    asset: Address,
) -> Result<u64, ClientError> {
    if asset == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    let not_registered = || ClientError::SplAssetNotRegistered { mint: asset };
    let account = rpc
        .get_account(pda::spl_asset_registry(&asset))
        .await?
        .ok_or_else(not_registered)?;
    // Any other owner means lamports were sent there, not that the mint was registered.
    if account.owner != PROGRAM_ID_PUBKEY {
        return Err(not_registered());
    }
    let invalid = || ClientError::InvalidSplAssetRegistry { mint: asset };
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
    if registry.mint != asset {
        return Err(invalid());
    }
    Ok(registry.asset_id)
}
