//! Proof refusals at frames up to the transaction ceiling do not establish settlement.

#[path = "../../../../program-tests/custom-ring/src/resource_frames.rs"]
mod resource_frames;

use resource_frames::{MaximumPayload, Payload};

use std::collections::HashSet;

use custom_ring_interface::{
    key_catalog::{FrameKey, TransferShape, TRANSFER_SHAPES},
    tag, CustomRingError, DisclosureFormat, RecipientBody, Replies, RingPolicy, RingRail,
    RingTransactData, RootRead, SlotBody, DATA_TAIL_LEN, MAX_CPI_DATA_LEN, MIN_REPLY_LEN,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::Signer;
use solana_message::v1;
use solana_transaction_error::TransactionError;
use spl_token_2022_interface::pod::PodAccount;
use spr_interface::{
    instruction::InterfaceTransfer, shape::Shape, MAX_INTERFACE_TRANSFERS,
    SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_PROGRAM_ID,
};

use crate::{
    common::{policy_pda, Ring, Sent, Setup, PROGRAM},
    transact_rules::{spp_list, Fixture},
};

const IN_PROOF_OWNER: [u8; 32] = [0x6e; 32];

#[derive(Clone, Copy)]
enum Legs {
    Sol(usize),
    Spl(usize),
}

impl Legs {
    fn count(self) -> usize {
        match self {
            Self::Sol(count) | Self::Spl(count) => count,
        }
    }

    fn with(self, count: usize) -> Self {
        match self {
            Self::Sol(_) => Self::Sol(count),
            Self::Spl(_) => Self::Spl(count),
        }
    }
}

#[derive(Clone, Copy)]
struct Wide {
    format: DisclosureFormat,
    setup: Setup,
    rail: RingRail,
    inputs: u8,
    outputs: u8,
    legs: Legs,
    policy: bool,
    exempt: bool,
    entry: bool,
    in_proof: bool,
    wide: bool,
    payload: Payload,
}

impl Wide {
    fn name(&self) -> String {
        let (legs, kind) = match self.legs {
            Legs::Sol(count) => (count, "sol"),
            Legs::Spl(count) => (count, "spl"),
        };
        format!(
            "{} {}x{} {legs} {kind}{}{}{}{}{}{}",
            self.rail,
            self.inputs,
            self.outputs,
            if self.policy { " policy" } else { "" },
            if self.exempt { " exempt" } else { "" },
            if self.entry { " entry" } else { "" },
            if self.in_proof { " in-proof" } else { "" },
            if self.wide { " wide" } else { "" },
            match self.payload {
                Payload::Base => "",
                Payload::MaximumBytes => " maximum bytes",
                Payload::MaximumMessages => " maximum messages",
            },
        )
    }
}

fn keyed_on(rail: RingRail) -> impl Iterator<Item = &'static TransferShape> {
    TRANSFER_SHAPES.iter().filter(move |shape| {
        (shape.format == DisclosureFormat::Standard || rail == RingRail::Confidential)
            && rail.supports(Shape::new(
                usize::from(shape.inputs),
                usize::from(shape.outputs),
            ))
    })
}

/// Per key, one input with the widest legs, the input class with them, and the class alone.
fn cases() -> Vec<Wide> {
    let mut cases = Vec::new();
    let mut push = |base: Wide, shape: &TransferShape| {
        if shape.format == DisclosureFormat::SingleAssetPayout {
            cases.push(base);
            return;
        }
        let legs = usize::from(shape.withdrawals);
        let fewest = usize::from(base.exempt);
        for (inputs, count) in [(1, legs), (shape.inputs, legs), (shape.inputs, fewest)] {
            cases.push(Wide {
                inputs,
                legs: base.legs.with(count),
                ..base
            });
        }
    };
    for shape in keyed_on(RingRail::Confidential).filter(|shape| !shape.entry) {
        let policy = Wide {
            format: shape.format,
            setup: Setup::Policy,
            rail: RingRail::Confidential,
            inputs: 1,
            outputs: shape.outputs,
            legs: Legs::Sol(0),
            policy: true,
            exempt: false,
            entry: false,
            in_proof: false,
            wide: shape.wide,
            payload: Payload::Base,
        };
        if shape.format == DisclosureFormat::SingleAssetPayout {
            push(policy, shape);
            push(
                Wide {
                    setup: Setup::AuditOnly,
                    policy: false,
                    ..policy
                },
                shape,
            );
            continue;
        }
        push(policy, shape);
        push(
            Wide {
                in_proof: true,
                ..policy
            },
            shape,
        );
        push(
            Wide {
                legs: Legs::Spl(0),
                ..policy
            },
            shape,
        );
        push(
            Wide {
                setup: Setup::AuditOnly,
                policy: false,
                exempt: true,
                ..policy
            },
            shape,
        );
    }
    for shape in keyed_on(RingRail::Anonymous) {
        push(
            Wide {
                format: shape.format,
                setup: Setup::AnonymousPolicy,
                rail: RingRail::Anonymous,
                inputs: 1,
                outputs: shape.outputs,
                legs: Legs::Sol(0),
                policy: true,
                exempt: false,
                entry: shape.entry,
                in_proof: false,
                payload: Payload::Base,
                wide: FrameKey {
                    format: custom_ring_interface::DisclosureFormat::Standard,
                    rail: RingRail::Anonymous,
                    inputs: usize::from(shape.inputs),
                    outputs: usize::from(shape.outputs),
                    spends_default_ring: shape.entry,
                    wide: false,
                }
                .shape()
                    != Some(*shape),
            },
            shape,
        );
    }
    let maximum_payloads: Vec<_> = cases
        .iter()
        .filter(|case| case.format == DisclosureFormat::Standard)
        .flat_map(|case| {
            [Payload::MaximumBytes, Payload::MaximumMessages]
                .map(|payload| Wide { payload, ..*case })
        })
        .collect();
    cases.extend(maximum_payloads);
    cases
}

fn frame<'a>(fixture: &'a Fixture, owners: &'a [[u8; 32]], case: Wide) -> RingTransactData<'a> {
    let mut data = match case.in_proof {
        true => fixture.in_proof_owner(&IN_PROOF_OWNER, case.inputs, case.outputs, case.policy),
        false => fixture.transfer(case.rail, case.inputs, case.outputs, case.policy),
    };
    data.entry = case.entry;
    data.wide_owners = case.wide;
    let count = case.legs.count();
    let amount = |leg: usize| 1_000 + leg as u64;
    data.interface_transfers = match case.legs {
        Legs::Sol(_) => (0..count)
            .map(|leg| InterfaceTransfer::SolWithdrawal {
                amount: amount(leg),
            })
            .collect(),
        Legs::Spl(_) => (0..count)
            .map(|leg| InterfaceTransfer::SplWithdrawal {
                amount: amount(leg),
                spl_interface_bump: 254,
            })
            .collect(),
    };
    if let Legs::Spl(_) = case.legs {
        data.spl_withdrawal_owners = &owners[..count];
    }
    fixture.fit_stream(&mut data);
    data
}

fn token_account(mint: Address, owner: [u8; 32]) -> Vec<u8> {
    bytemuck::bytes_of(&PodAccount {
        mint: mint.to_bytes().into(),
        owner: owner.into(),
        state: SPL_TOKEN_ACCOUNT_INITIALIZED,
        ..PodAccount::default()
    })
    .to_vec()
}

/// The settlement groups after the SPP list, one destination and one mint for every leg.
fn settlements(
    ring: &mut Ring,
    data: &RingTransactData<'_>,
    owners: &[[u8; 32]],
) -> Vec<AccountMeta> {
    let destination = Address::new_unique();
    let mint = Address::new_unique();
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let mut accounts = Vec::new();
    for (leg, transfer) in data.interface_transfers.iter().enumerate() {
        match transfer {
            InterfaceTransfer::SolWithdrawal { .. } => accounts.extend([
                AccountMeta::new(Address::new_unique(), false),
                AccountMeta::new(destination, false),
            ]),
            InterfaceTransfer::SplWithdrawal { .. } => {
                let token = Address::new_unique();
                ring.store(token, token_program, token_account(mint, owners[leg]));
                accounts.extend([
                    AccountMeta::new_readonly(Address::new_unique(), false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new(Address::new_unique(), false),
                    AccountMeta::new(token, false),
                    AccountMeta::new_readonly(token_program, false),
                ]);
            }
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => {
                unreachable!("a wide frame withdraws")
            }
        }
    }
    accounts
}

fn instruction(ring: &mut Ring, case: Wide) -> Option<Instruction> {
    let fixture = Fixture::new()
        .with_identity_proof()
        .with_format(case.format);
    let owners: Vec<[u8; 32]> = (0..MAX_INTERFACE_TRANSFERS)
        .map(|leg| [0x70 + leg as u8; 32])
        .collect();
    let mut data = frame(&fixture, &owners, case);
    let policy: RingPolicy = ring.read(&policy_pda());
    let body = RecipientBody {
        ring_data_hash: Some([0x5a; 32]),
        ..RecipientBody::default()
    }
    .encode()
    .unwrap();
    let tail = [0x7b; DATA_TAIL_LEN];
    let replies = vec![0x72; data.outputs.len() * MIN_REPLY_LEN];
    let message = vec![0x73; MAX_CPI_DATA_LEN];
    let message_tag = [0x74; 32];
    if case.payload != Payload::Base {
        data.has_data = true;
        for output in &mut data.outputs {
            output.tail = Some(&tail);
            output.body = SlotBody::Recipient(&body);
        }
        if case.rail == RingRail::Anonymous {
            data.replies = Some(Replies::new(MIN_REPLY_LEN as u16, &replies).unwrap());
        }
        fixture.fit_stream(&mut data);
        let filled = MaximumPayload {
            data: &mut data,
            policy: &policy,
            message: &message,
            view_tag: &message_tag,
        }
        .fill(case.payload);
        if !filled {
            return None;
        }
    }
    let payer = ring.payer.pubkey();
    let owner_run = match (case.rail, case.in_proof) {
        (RingRail::Confidential, false) => vec![AccountMeta::new_readonly(payer, true)],
        _ => Vec::new(),
    };
    let mut spp = spp_list(&payer, &data, &owner_run);
    spp.extend(settlements(ring, &data, &owners));
    let accounts = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        ring.registries(RootRead::transfer(&policy, false)),
        spp,
    ]
    .concat();
    Some(Instruction {
        program_id: PROGRAM,
        accounts,
        data: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
    })
}

fn send_widest(case: Wide) -> Option<(Wide, usize, Sent)> {
    let mut ring = Ring::new(case.setup);
    let instruction = instruction(&mut ring, case)?;
    let addresses = instruction
        .accounts
        .iter()
        .map(|account| account.pubkey)
        .chain([PROGRAM, ring.payer.pubkey()])
        .collect::<HashSet<_>>()
        .len();
    Some((case, addresses, ring.send(instruction, &[])))
}

#[test]
fn catalog_maxima_at_the_transaction_ceiling_reach_pairing_or_refuse_excess_addresses() {
    let pairing = InstructionError::Custom(CustomRingError::ProofVerificationFailed as u32);
    let missed: Vec<String> = cases()
        .into_iter()
        .filter_map(send_widest)
        .filter(|(_, addresses, sent)| {
            if *addresses > usize::from(v1::MAX_ADDRESSES) {
                !matches!(sent, Err((TransactionError::SanitizeFailure, _)))
            } else {
                !matches!(sent, Err((TransactionError::InstructionError(0, error), _)) if *error == pairing)
            }
        })
        .map(|(case, addresses, sent)| format!("{}, addresses {addresses}, got {sent:?}", case.name()))
        .collect();
    assert!(missed.is_empty(), "{missed:#?}");
}
