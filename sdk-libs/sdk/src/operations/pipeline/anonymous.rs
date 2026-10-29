//! The hidden owner signs inside the AnonymousRingEddsa proof.

use custom_ring_interface::{
    anonymous_exit::{AnonymousExitDestination, TokenAccountControl, TokenAccountState},
    CustomRingError, RingMode, RingRail,
};
use solana_account::Account;
use solana_address::Address;
use spr_client::{AsyncRpc, OwnerAuthorization, Shape};
use spr_interface::{pda, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
use spr_keypair::{Curve, NullifierKey, PublicKey, ShieldedAddress, SigningKey};
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, SettlementTransfer, SppProofInputs, SppProofOutputUtxo,
    },
    Mint, WalletUtxo,
};
use zolana_ring_client::{
    FirstContact, PaymentRecipient, TransferTagging, TransferTags, ViewingHistory,
};
use zolana_ring_keys::{RingAddress, RingPaymentRequest};
use zolana_ring_transaction::{RingDelivery, RingOutputRail};

use super::{
    canonical_shape,
    owner::{CustomRingTransferInput, Owner},
    pad_under_rail, sealed,
    selection::{payment_total, widest, Candidate, Funding},
    spends_default_ring,
    spp::HiddenSpend,
    transaction_key, Rail, RailKind, RingSender, RingTransfer, Spend, Staged, TransferAuthority,
};
use crate::{
    client::{RingClient, RingIndexerBackend},
    CustomRing, CustomRingConfig, RingError,
};

/// The tag follows the spec view tag selection over the sender's viewing history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousPayment {
    pub to: RingAddress,
    /// Paid until the pair is known.
    pub first_contact: FirstContact,
    pub asset: Mint,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingPayment {
    pub to: RingAddress,
    pub first_contact: FirstContact,
    pub amount: u64,
}

impl RingPayment {
    /// Under the recipient's bootstrap tag until the pair is known.
    pub fn bootstrap(to: RingAddress, amount: u64) -> Self {
        Self {
            to,
            first_contact: FirstContact::Bootstrap,
            amount,
        }
    }

    /// The request's amount when it names one.
    pub fn to_request(request: &RingPaymentRequest, amount: u64) -> Self {
        Self {
            to: request.address.clone(),
            first_contact: FirstContact::Request(request.request_view_tag),
            amount: request.amount.unwrap_or(amount),
        }
    }
}

#[must_use = "select the inputs of the move"]
pub struct AnonymousMove<'a> {
    pub ring: CustomRing,
    pub sender: &'a dyn RingSender,
    pub nullifier_key: &'a NullifierKey,
    pub signer: &'a SigningKey,
    pub history: &'a ViewingHistory,
    pub payer: Address,
    /// The sender's UTXOs on any tree.
    pub utxos: &'a [WalletUtxo],
    pub asset: Mint,
    /// The change returns to the sender.
    pub payments: Vec<RingPayment>,
    pub entry: EntrySpend,
    /// Read only when the ring demands a co-signer.
    pub co_signer: Option<Address>,
}

/// A default-ring spend publishes the hidden owner's key, a move takes one only when allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrySpend {
    Refuse,
    Allow,
}

/// The owner's spends on an anonymous ring, no transaction signer names the owner.
pub struct Anonymous<'a> {
    pub(super) owner: Owner<'a>,
    pub(super) signer: &'a SigningKey,
    history: &'a ViewingHistory,
    /// In declared order, the order of their ring outputs.
    payments: Vec<AnonymousPayment>,
    exit_token_owner: Option<Address>,
}

pub type AnonymousTransfer<'a> = RingTransfer<Anonymous<'a>>;

impl sealed::Sealed for Anonymous<'_> {}

impl Rail for Anonymous<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Anonymous(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    /// The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key.
    pub fn with_anonymous_signer(
        self,
        signer: &'a SigningKey,
        history: &'a ViewingHistory,
    ) -> RingTransfer<Anonymous<'a>> {
        RingTransfer {
            ring: self.ring,
            co_signer: self.co_signer,
            rail: Anonymous {
                owner: self.rail,
                signer,
                history,
                payments: Vec::new(),
                exit_token_owner: None,
            },
        }
    }
}

impl RingTransfer<Anonymous<'_>> {
    /// Every ring output owner other than the sender is paid here, before the transaction is padded.
    pub fn with_payment(mut self, payment: AnonymousPayment) -> Result<Self, RingError> {
        if payment.to.ring_program_id != self.ring.program_id() {
            return Err(RingError::ForeignRingAddress {
                address: payment.to.ring_program_id,
                ring: self.ring.program_id(),
            });
        }
        self.rail.owner.transaction.transfer_with_ring(
            &payment.to.recipient,
            payment.asset,
            payment.amount,
            Some(payment.to.ring_program_id),
        )?;
        self.rail.payments.push(payment);
        Ok(self)
    }

    /// Unset, staging pads to the smallest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape.is_supported() {
            return Err(spr_transaction::TransactionError::UnsupportedShape {
                n_in: shape.n_inputs(),
                n_out: shape.n_outputs(),
            }
            .into());
        }
        self.rail.owner.shape = Some(shape);
        Ok(self)
    }

    /// A missing exit token account must be the associated token account of `owner`.
    #[must_use = "use the updated transfer"]
    pub fn with_exit_token_owner(mut self, owner: Address) -> Self {
        self.rail.exit_token_owner = Some(owner);
        self
    }

    /// The sender's viewing history past the transfer's tags, stored before it is sent.
    pub fn viewing_history(&self) -> Result<ViewingHistory, RingError> {
        Ok(self.rail.tags()?.history)
    }

    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        HiddenOwner::of(&self.rail.owner.sender.address()?.signing_pubkey)?.check_signers(signers)
    }
}

impl<'a> AnonymousMove<'a> {
    /// As [`super::DelegateMove::select`], ring UTXOs before an entry spend.
    pub async fn select<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<AnonymousTransfer<'a>, RingError> {
        let amount = payment_total(self.payments.iter().map(|payment| payment.amount))?;
        let payments = self.payments.len();
        let owner = self.sender.address()?.signing_pubkey;
        let ring = Some(self.ring.program_id());
        let widest_spend = |key: AnonymousKey| widest(payments, |shape| key.serves(shape));
        let max_inputs = widest_spend(AnonymousKey::Commitment).ok_or(RingError::ShapeUnkeyed {
            rail: RingRail::Anonymous,
        })?;
        let funding = Funding {
            utxos: self.utxos,
            asset: self.asset.asset,
            amount,
            max_inputs,
        };
        let ring_only = funding
            .candidates(|utxo| utxo.utxo.owner == owner && utxo.utxo.ring_program_id == ring);
        let entry_width = match self.entry {
            EntrySpend::Allow => widest_spend(AnonymousKey::Entry),
            EntrySpend::Refuse => None,
        };
        let entries = entry_width.map_or_else(Vec::new, |max_inputs| {
            Funding {
                max_inputs,
                ..funding
            }
            .candidates(|utxo| {
                // The prover refuses a spend that mixes ring and default-ring UTXOs.
                utxo.utxo.owner == owner
                    && utxo.is_default_ring_spendable()
                    && carries_no_data([utxo.data_hash, utxo.ring_data_hash])
            })
        });
        let attempts = ring_only
            .iter()
            .map(|candidate| self.attempt(AnonymousKey::Commitment, candidate))
            .chain(
                entries
                    .iter()
                    .map(|candidate| self.attempt(AnonymousKey::Entry, candidate)),
            )
            .collect();
        funding.first_fit(attempts, client).await
    }

    fn attempt(
        &self,
        key: AnonymousKey,
        candidate: &Candidate,
    ) -> Result<AnonymousTransfer<'a>, RingError> {
        // Output 0 is always the sender change, a zero one when nothing returns.
        let with_change = Candidate {
            change: true,
            ..candidate.clone()
        };
        let shape = with_change
            .shape(self.payments.len(), |shape| key.serves(shape))
            .ok_or(RingError::ShapeUnkeyed {
                rail: RingRail::Anonymous,
            })?;
        let transaction = ConfidentialTransaction::new_with_ring(
            candidate.utxos.clone(),
            self.payer,
            self.ring.program_id(),
        )?;
        let transfer = RingTransfer {
            co_signer: self.co_signer,
            ..RingTransfer::<Owner<'a>>::new(CustomRingTransferInput {
                ring: self.ring,
                sender: self.sender,
                nullifier_key: Some(self.nullifier_key),
                transaction,
            })
        }
        .with_anonymous_signer(self.signer, self.history);
        self.payments
            .iter()
            .try_fold(transfer, |transfer, payment| {
                transfer.with_payment(AnonymousPayment {
                    to: payment.to.clone(),
                    first_contact: payment.first_contact,
                    asset: self.asset,
                    amount: payment.amount,
                })
            })?
            .with_shape(shape)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AnonymousKey {
    Commitment,
    Entry,
}

impl AnonymousKey {
    pub fn serves(self, shape: Shape) -> bool {
        shape.is_supported()
            && custom_ring_interface::AnonymousSpend {
                inputs: shape.n_inputs(),
                outputs: shape.n_outputs(),
                spends_default_ring: self == Self::Entry,
            }
            .audit_key()
            .is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HiddenOwner(pub Address);

pub(crate) struct AnonymousSpend<'a> {
    pub payer: Address,
    pub exit_destination: Option<Address>,
    pub token_owner: Option<Address>,
    pub signer: OwnerAuthorization<'a>,
    /// Past the transfer's tags, `None` when the wallet keeps its history.
    pub history: Option<ViewingHistory>,
}

impl AnonymousSpend<'_> {
    pub(super) fn hidden(&self) -> HiddenSpend<'_> {
        HiddenSpend { owner: self.signer }
    }

    /// Binds the signing co-signer, zero when none signs.
    pub(super) fn party_identities(
        &self,
        co_signer: Option<Address>,
    ) -> Result<[[u8; 32]; 3], RingError> {
        HiddenOwner::of(&self.signer.public_key())?.check_signers(co_signer)?;
        Ok(custom_ring_interface::AnonymousParties {
            payer: self.payer.as_array(),
            cosigner: co_signer.as_ref().map(Address::as_array),
            exit_destination: self.exit_destination.as_ref().map(Address::as_array),
        }
        .identities()?)
    }
}

impl HiddenOwner {
    pub(crate) fn of(key: &PublicKey) -> Result<Self, RingError> {
        Ok(Self(Address::new_from_array(key.as_ed25519()?)))
    }

    pub(crate) fn check_signers(
        self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        match signers.into_iter().any(|signer| signer == self.0) {
            true => Err(RingError::AnonymousPublicSignerLinksOwner),
            false => Ok(()),
        }
    }
}

impl Anonymous<'_> {
    /// The spec view tag selection over the stored history, the same on every attempt.
    fn tags(&self) -> Result<TransferTags, RingError> {
        let recipients: Vec<PaymentRecipient> = self
            .payments
            .iter()
            .map(|payment| PaymentRecipient {
                viewing_pubkey: payment.to.recipient.viewing_pubkey,
                first_contact: payment.first_contact,
            })
            .collect();
        Ok(TransferTagging {
            keys: self.owner.sender,
            history: self.history,
            recipients: &recipients,
        }
        .plan()?)
    }

    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        ring: CustomRing,
        client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        if config.mode != RingMode::Anonymous {
            return Err(RingError::NotAnonymousRing);
        }
        let keys = self.owner.sender;
        let sender = keys.address()?;
        if self.signer.pubkey() != sender.signing_pubkey {
            return Err(RingError::AnonymousSignerMismatch);
        }
        let owner = HiddenOwner::of(&sender.signing_pubkey)?;
        let payer = self.owner.transaction.payer();
        owner.check_signers([payer])?;
        self.owner.check_settlement_accounts()?;
        self.owner.check_payer_funds_deposits()?;
        let transfers = self.owner.transaction.interface_transfers()?;
        let exits = AnonymousExits {
            transfers: &transfers,
            hidden_owner: &owner.0,
            named_owner: self.exit_token_owner,
        }
        .owners(client)
        .await?;
        let tags = self.tags()?;
        let transaction = SenderChange {
            shape: self.owner.shape,
            sender: &sender,
            ring: ring.program_id(),
        }
        .ensure(self.owner.transaction.clone())?;
        let shape = match self.owner.shape {
            Some(shape) => shape,
            None => canonical_shape(&transaction, &sender)?,
        };
        let first_nullifier = *transaction.first_nullifier();
        let tx_viewing_key = transaction_key(keys, first_nullifier)?;
        let rail = RingOutputRail::new(
            tx_viewing_key,
            RingDelivery::Anonymous(Box::new(tags.anonymous_plan())),
        );
        let transaction = pad_under_rail(transaction, &rail, shape, &sender)?;
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        check_anonymous_inputs(&proof_inputs, &sender)?;
        Ok(Staged {
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: self.owner.nullifier_key.cloned(),
            },
            owner_signers: Vec::new(),
            interface_transfer_accounts: self.owner.interface_transfer_accounts.clone(),
            spend: Spend::Anonymous(Box::new(AnonymousSpend {
                payer,
                exit_destination: exits.destination,
                token_owner: exits.token_owner,
                signer: OwnerAuthorization::SigningKey(self.signer),
                history: Some(tags.history),
            })),
            presealed: None,
        })
    }
}

/// Every real input is the sender's, the anonymous audit key serves the spend.
pub(super) fn check_anonymous_inputs(
    inputs: &SppProofInputs,
    sender: &ShieldedAddress,
) -> Result<(), RingError> {
    check_anonymous_slots(inputs)?;
    if let Some(index) = inputs
        .input_utxos
        .iter()
        .position(|input| !input.is_dummy() && input.utxo.owner != sender.signing_pubkey)
    {
        return Err(RingError::MixedOwners { index });
    }
    check_entry_inputs(inputs)?;
    check_audit_key(inputs)
}

/// The anonymous rail takes uncached noncompact notes only, real outputs owned by Ed25519 keys.
fn check_anonymous_slots(inputs: &SppProofInputs) -> Result<(), RingError> {
    let input_open = inputs
        .input_utxos
        .iter()
        .any(|input| input.cache_slot.is_some() || input.is_compact() || input.is_address());
    let output_open = inputs.output_utxos.iter().any(|output| {
        output.cache_slot.is_some()
            || output.is_compact()
            || (!output.is_dummy()
                && output.owner_address.is_none_or(|address| {
                    address.signing_pubkey.curve().ok() != Some(Curve::Ed25519)
                }))
    });
    match input_open || output_open {
        true => Err(RingError::InvalidAnonymousSlot),
        false => Ok(()),
    }
}

/// A default-ring spend past the entry class must split, any other spend needs a commitment key.
fn check_audit_key(inputs: &SppProofInputs) -> Result<(), RingError> {
    let default_ring = spends_default_ring(&inputs.input_utxos);
    let published = inputs
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .count();
    let spend = custom_ring_interface::AnonymousSpend {
        inputs: published,
        outputs: inputs.output_utxos.len(),
        spends_default_ring: default_ring,
    };
    match (spend.audit_key(), default_ring) {
        (Some(_), _) => Ok(()),
        (None, true) => Err(RingError::DefaultRingSpendTooWide { inputs: published }),
        (None, false) => Err(RingError::ShapeUnkeyed {
            rail: RingRail::Anonymous,
        }),
    }
}

/// The entry key rebuilds every spent UTXO from its opening.
fn check_entry_inputs(inputs: &SppProofInputs) -> Result<(), RingError> {
    if !spends_default_ring(&inputs.input_utxos) {
        return Ok(());
    }
    inputs
        .input_utxos
        .iter()
        .enumerate()
        .filter(|(_, input)| !input.is_dummy())
        .try_for_each(|(index, input)| {
            if input.utxo.ring_program_id.is_some() {
                Err(RingError::EntryRingInput { index })
            } else if carries_no_data([input.data_hash, input.ring_data_hash]) {
                Ok(())
            } else {
                Err(RingError::EntryInputData { index })
            }
        })
}

fn carries_no_data(hashes: [Option<[u8; 32]>; 2]) -> bool {
    hashes
        .iter()
        .all(|hash| hash.is_none_or(|hash| hash == [0; 32]))
}

pub(super) struct AnonymousExits<'a> {
    pub transfers: &'a [SettlementTransfer],
    pub hidden_owner: &'a Address,
    pub named_owner: Option<Address>,
}

pub(super) struct ExitOwners {
    pub destination: Option<Address>,
    pub token_owner: Option<Address>,
}

struct SplExit {
    mint: Address,
    token_account: Address,
}

impl AnonymousExits<'_> {
    /// Refused unless every exit pays one destination.
    pub(super) async fn owners<R: AsyncRpc + ?Sized>(
        self,
        client: &R,
    ) -> Result<ExitOwners, RingError> {
        let sol_owner = self.transfers.iter().find_map(|transfer| match transfer {
            SettlementTransfer::Sol {
                user_sol_account, ..
            } if !transfer.is_deposit() => Some(*user_sol_account),
            _ => None,
        });
        let token_owner = self.token_owner(client).await?;
        if sol_owner
            .zip(token_owner)
            .is_some_and(|(sol, token)| sol != token)
        {
            return Err(CustomRingError::AnonymousExitDestinationsDiffer.into());
        }
        Ok(ExitOwners {
            destination: token_owner.or(sol_owner),
            token_owner,
        })
    }

    /// The SPL withdrawal's token owner, `None` without one.
    async fn token_owner<R: AsyncRpc + ?Sized>(
        self,
        client: &R,
    ) -> Result<Option<Address>, RingError> {
        let withdrawals = self
            .transfers
            .iter()
            .filter(|transfer| !transfer.is_deposit());
        if self.named_owner.is_some()
            && !withdrawals
                .clone()
                .any(|transfer| matches!(transfer, SettlementTransfer::Spl { .. }))
        {
            return Err(RingError::AnonymousExitTokenOwnerWithoutSplExit);
        }
        let mut token_owner: Option<Address> = None;
        for transfer in withdrawals {
            match *transfer {
                SettlementTransfer::Sol {
                    user_sol_account: recipient,
                    ..
                } => self.check_sol_exit(client, recipient).await?,
                SettlementTransfer::Spl {
                    mint,
                    user_spl_token: token_account,
                    ..
                } => {
                    let owner = self
                        .spl_exit_owner(
                            client,
                            SplExit {
                                mint,
                                token_account,
                            },
                        )
                        .await?;
                    if let Some(named) = self.named_owner.filter(|named| *named != owner) {
                        return Err(RingError::AnonymousExitNamedOwnerMismatch {
                            token_account,
                            named,
                            owner,
                        });
                    }
                    if token_owner
                        .replace(owner)
                        .is_some_and(|previous| previous != owner)
                    {
                        return Err(CustomRingError::AnonymousExitDestinationsDiffer.into());
                    }
                }
            }
        }
        Ok(token_owner)
    }

    async fn check_sol_exit<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
        recipient: Address,
    ) -> Result<(), RingError> {
        if recipient == *self.hidden_owner {
            return Err(RingError::AnonymousExitLinksOwner(recipient));
        }
        // SPP reads a missing account as a system account without data.
        let Some(account) = client.get_account(recipient).await? else {
            return Ok(());
        };
        AnonymousExitDestination::Sol {
            recipient: &recipient,
            owner: &account.owner,
            data_len: account.data.len(),
        }
        .named_key()
        .map_err(|refusal| exit_refused(refusal, recipient))?;
        Ok(())
    }

    async fn spl_exit_owner<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
        exit: SplExit,
    ) -> Result<Address, RingError> {
        let SplExit {
            mint,
            token_account,
        } = exit;
        let invalid = || RingError::AnonymousExitTokenAccountInvalid(token_account);
        let (control, token_program) = match client.get_account(token_account).await? {
            Some(account) => (
                token_account_state(&account, &mint)
                    .ok_or_else(invalid)?
                    .control,
                account.owner,
            ),
            // The associated token program creates it with the named owner and no other authority.
            None => {
                let owner = self.named_owner.ok_or_else(invalid)?;
                let token_program = client
                    .get_account(mint)
                    .await?
                    .map(|mint| mint.owner)
                    .filter(is_token_program)
                    .ok_or_else(invalid)?;
                if pda::associated_token_address_with_program(&owner, &mint, &token_program)
                    != token_account
                {
                    return Err(invalid());
                }
                (
                    TokenAccountControl::SoleOwner(owner.to_bytes()),
                    token_program,
                )
            }
        };
        let owner = Address::new_from_array(*control.owner());
        let hidden = *self.hidden_owner;
        // An associated token account stays derivable from its first owner.
        let associated = pda::associated_token_address_with_program(&hidden, &mint, &token_program);
        if [token_account, owner].contains(&hidden) || associated == token_account {
            return Err(RingError::AnonymousExitLinksOwner(token_account));
        }
        AnonymousExitDestination::Spl {
            token_account: &token_account,
            control: &control,
        }
        .named_key()
        .map_err(|refusal| exit_refused(refusal, token_account))?;
        Ok(owner)
    }
}

fn token_account_state(account: &Account, mint: &Address) -> Option<TokenAccountState> {
    if !is_token_program(&account.owner) {
        return None;
    }
    TokenAccountState::unpack(&account.data)
        .ok()
        .filter(|state| state.mint == mint.to_bytes())
}

fn is_token_program(program: &Address) -> bool {
    [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID].contains(program.as_array())
}

fn exit_refused(refusal: CustomRingError, destination: Address) -> RingError {
    match refusal {
        CustomRingError::AnonymousExitAccountHasData => {
            RingError::AnonymousExitAccountHasData(destination)
        }
        CustomRingError::AnonymousExitTokenAccountOnCurve => {
            RingError::AnonymousExitTokenAccountOnCurve(destination)
        }
        CustomRingError::AnonymousExitTokenAccountShared => {
            RingError::AnonymousExitTokenAccountShared(destination)
        }
        refusal => RingError::AnonymousExitRefused {
            destination,
            refusal,
        },
    }
}

/// A zero SOL change leads a transfer that returns nothing.
struct SenderChange<'a> {
    shape: Option<Shape>,
    sender: &'a ShieldedAddress,
    ring: Address,
}

impl SenderChange<'_> {
    fn ensure(
        self,
        mut transaction: ConfidentialTransaction,
    ) -> Result<ConfidentialTransaction, RingError> {
        let declared = transaction.outputs().len();
        let mut probe = transaction.clone();
        let shape = match self.shape {
            Some(shape) => shape,
            None => canonical_shape(&probe, self.sender)?,
        };
        probe.pad_utxos(shape, self.sender)?;
        let returns = probe.outputs()[declared..]
            .iter()
            .any(|output| output.owner_address == Some(*self.sender));
        if !returns {
            transaction.add_output_utxo(SppProofOutputUtxo {
                owner_address: Some(*self.sender),
                asset: Mint::SOL,
                ring_program_id: Some(self.ring),
                ..Default::default()
            })?;
        }
        Ok(transaction)
    }
}
