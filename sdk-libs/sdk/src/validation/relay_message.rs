//! The message a wallet signs for Ring RPC, checked against the request the wallet made.

use custom_ring_interface::{
    compute_unit_limit, tag, DepositPrefix, InstructionTag, RingRail, RingTransactData,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v1, VersionedMessage};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::MAX_LOADED_ACCOUNTS_DATA_SIZE;
use spr_keypair::ShieldedAddress;
use thiserror::Error;
use zolana_ring_client::rpc::{PrepareAuthorityTransferRequest, RelayQuote};
use zolana_ring_policy::Member;

use crate::{CustomRing, RingError};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MessageMismatch {
    #[error("the message does not decode as one valid canonical message")]
    Undecodable,
    #[error("the message is not a v1 message")]
    NotV1,
    #[error("the message fee payer is the signer or not the quoted relay fee payer")]
    FeePayer,
    #[error("the message budget is outside the operation's bounds")]
    Budget,
    #[error("the message carries instructions the request did not ask for")]
    Instructions,
    #[error("the message calls a program other than the ring")]
    Program,
    #[error("the message data differs from the request")]
    Data,
    #[error("the message accounts differ from the request")]
    Accounts,
    #[error("the message pays an owner the request does not name")]
    Recipients,
    #[error("the request asks for no signature")]
    Unrequested,
    #[error("the signing key is not the key the request names")]
    Signer,
}

/// Built from the wallet's own request, never from Ring RPC's answer.
#[derive(Clone, Debug)]
pub(crate) enum ExpectedMessage {
    Deposit(ExpectedDeposit),
    Delegate(ExpectedDelegate),
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedDeposit {
    pub ring: CustomRing,
    pub fee_payer: Address,
    pub depositor: Address,
    /// The SPP deposit the ring forwards unchanged.
    pub spp: Instruction,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedDelegate {
    pub ring: CustomRing,
    pub fee_payer: Address,
    pub delegate: Address,
    pub source: Member,
    /// In payment order.
    pub payees: Vec<Member>,
}

/// Only a check builds one.
#[must_use = "sign the verified message"]
#[derive(Debug)]
pub struct VerifiedMessage {
    bytes: Vec<u8>,
    signer: Address,
}

struct Envelope {
    ring: CustomRing,
    fee_payer: Address,
    signer: Address,
    tag: InstructionTag,
}

impl ExpectedMessage {
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        match self {
            Self::Deposit(deposit) => deposit.check(message),
            Self::Delegate(delegate) => delegate.check(message),
        }
    }
}

impl ExpectedDeposit {
    /// The ring prefix carries the proof and revisions, every SPP byte and account is the wallet's.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: self.ring,
            fee_payer: self.fee_payer,
            signer: self.depositor,
            tag: InstructionTag::Deposit,
        };
        let instruction = envelope.open(message)?;
        let spp_data = instruction
            .data
            .get(size_of::<DepositPrefix>()..)
            .filter(|_| instruction.data.first() == Some(&tag::DEPOSIT));
        if spp_data != Some(self.spp.data.as_slice()) {
            return Err(MessageMismatch::Data);
        }
        let ring_accounts = instruction
            .accounts
            .len()
            .checked_sub(self.spp.accounts.len())
            .ok_or(MessageMismatch::Accounts)?;
        let (prefix, spp_accounts) = instruction.accounts.split_at(ring_accounts);
        if spp_accounts != self.spp.accounts.as_slice() || !envelope.reads_only(prefix) {
            return Err(MessageMismatch::Accounts);
        }
        Ok(envelope.verified(message))
    }
}

impl ExpectedDelegate {
    pub fn new(
        request: &PrepareAuthorityTransferRequest,
        quote: &RelayQuote,
    ) -> Result<Self, RingError> {
        let owner = |address: &ShieldedAddress| {
            Ok::<_, RingError>(Member::from_bytes(
                address.signing_pubkey.owner_proof_input_hash()?,
            )?)
        };
        let transfer = &request.transfer;
        Ok(Self {
            ring: CustomRing::new(request.ring.0),
            fee_payer: quote.fee_payer.0,
            delegate: request.delegate.0,
            source: owner(&transfer.source.0)?,
            payees: transfer
                .payments
                .iter()
                .map(|payment| owner(&payment.recipient.0))
                .collect::<Result<_, _>>()?,
        })
    }

    /// Outputs are hidden, the check binds each output owner the policy proof publishes.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: self.ring,
            fee_payer: self.fee_payer,
            signer: self.delegate,
            tag: InstructionTag::AuthorityTransfer,
        };
        let instruction = envelope.open(message)?;
        let parsed = instruction
            .data
            .split_first()
            .filter(|(tag, _)| **tag == tag::AUTHORITY_TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, RingRail::Delegate).ok())
            .ok_or(MessageMismatch::Data)?;
        let data = parsed.data();
        if !data.interface_transfers.is_empty() {
            return Err(MessageMismatch::Data);
        }
        let recipients = data
            .policy_recipients()
            .map_err(|_| MessageMismatch::Data)?;
        let (paid, rest) = recipients
            .split_at_checked(self.payees.len())
            .ok_or(MessageMismatch::Recipients)?;
        let pays_each_payee = paid
            .iter()
            .zip(&self.payees)
            .all(|(slot, payee)| slot == payee.as_bytes());
        // Change returns to the source, a zero slot is padding.
        let returns_change = rest
            .iter()
            .all(|slot| slot == self.source.as_bytes() || *slot == [0; 32]);
        if !pays_each_payee || !returns_change {
            return Err(MessageMismatch::Recipients);
        }
        let mut named = instruction
            .accounts
            .iter()
            .filter(|meta| meta.pubkey == self.delegate);
        let signs_once = matches!(
            (named.next(), named.next()),
            (Some(meta), None) if meta.is_signer && !meta.is_writable
        );
        let ring_account = instruction.accounts.get(..1).unwrap_or_default();
        if !signs_once || !envelope.reads_only(ring_account) {
            return Err(MessageMismatch::Accounts);
        }
        Ok(envelope.verified(message))
    }
}

impl VerifiedMessage {
    pub fn signer(&self) -> Address {
        self.signer
    }

    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, RingError> {
        if signer.try_pubkey()? != self.signer {
            return Err(MessageMismatch::Signer.into());
        }
        Ok(signer.try_sign_message(&self.bytes)?)
    }
}

impl Envelope {
    /// One canonical v1 message the quoted fee payer pays, holding only the ring instruction.
    fn open(&self, bytes: &[u8]) -> Result<Instruction, MessageMismatch> {
        let message = match wincode::deserialize(bytes) {
            Ok(VersionedMessage::V1(message)) => message,
            Ok(VersionedMessage::Legacy(_) | VersionedMessage::V0(_)) => {
                return Err(MessageMismatch::NotV1)
            }
            Err(_) => return Err(MessageMismatch::Undecodable),
        };
        if message.validate().is_err() || message.serialize() != bytes {
            return Err(MessageMismatch::Undecodable);
        }
        if message.fee_payer() != Some(&self.fee_payer) || self.fee_payer == self.signer {
            return Err(MessageMismatch::FeePayer);
        }
        let config = message.config;
        let within_budget = config
            .compute_unit_limit
            .is_some_and(|units| units <= compute_unit_limit(self.tag))
            && config
                .loaded_accounts_data_size_limit
                .is_some_and(|size| size <= MAX_LOADED_ACCOUNTS_DATA_SIZE)
            && config.heap_size.is_none();
        if !within_budget {
            return Err(MessageMismatch::Budget);
        }
        let [compiled] = message.instructions.as_slice() else {
            return Err(MessageMismatch::Instructions);
        };
        let key = |index: u8| {
            message
                .account_keys
                .get(usize::from(index))
                .copied()
                .ok_or(MessageMismatch::Undecodable)
        };
        if key(compiled.program_id_index)? != self.ring.program_id() {
            return Err(MessageMismatch::Program);
        }
        let accounts = compiled
            .accounts
            .iter()
            .map(|&index| {
                Ok(AccountMeta {
                    pubkey: key(index)?,
                    is_signer: message.is_signer(usize::from(index)),
                    is_writable: requests_write(&message, usize::from(index)),
                })
            })
            .collect::<Result<_, MessageMismatch>>()?;
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts,
            data: compiled.data.clone(),
        })
    }

    /// The ring account first, then read only accounts that never name the signer.
    fn reads_only(&self, prefix: &[AccountMeta]) -> bool {
        match prefix.split_first() {
            Some((ring, rest)) => {
                *ring == AccountMeta::new_readonly(self.ring.policy_pda(), false)
                    && rest
                        .iter()
                        .all(|meta| !meta.is_writable && meta.pubkey != self.signer)
            }
            None => false,
        }
    }

    fn verified(&self, bytes: &[u8]) -> VerifiedMessage {
        VerifiedMessage {
            bytes: bytes.to_vec(),
            signer: self.signer,
        }
    }
}

/// The header's write role, the one `compile_message` assigns.
fn requests_write(message: &v1::Message, index: usize) -> bool {
    let header = message.header;
    let signers = usize::from(header.num_required_signatures);
    match index < signers {
        true => message.is_signer_writable(index),
        false => {
            index
                < message
                    .account_keys
                    .len()
                    .saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
        }
    }
}
