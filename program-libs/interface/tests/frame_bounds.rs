//! The frame check refuses an application message count or a public leg SPP would refuse, under a ring error.

mod frames;
mod ring_policy;

use custom_ring_interface::{
    max_application_messages, AppMessage, CustomRingError, RingTransactData, MAX_SPP_MESSAGES,
};
use frames::Fixture;
use spr_interface::{
    instruction::{InterfaceTransfer, TransactProof},
    MAX_INTERFACE_TRANSFERS,
};

const VIEW_TAG: [u8; 32] = [0xa7; 32];

fn with_messages<'a>(mut data: RingTransactData<'a>, count: usize) -> RingTransactData<'a> {
    data.extensions.messages = vec![
        AppMessage {
            view_tag: &VIEW_TAG,
            data: &[],
        };
        count
    ];
    data
}

fn with_legs<'a>(mut data: RingTransactData<'a>, amounts: &[u64]) -> RingTransactData<'a> {
    data.interface_transfers = amounts
        .iter()
        .map(|&amount| InterfaceTransfer::SolWithdrawal { amount })
        .collect();
    data
}

/// The encoding of one more item, from encodings with `n` and `n + 1` items of one count-prefixed list.
fn one_more(fewer: &[u8], more: &[u8]) -> Vec<u8> {
    let count = fewer
        .iter()
        .zip(more)
        .position(|(left, right)| left != right)
        .expect("the encodings differ at the count byte");
    let item = &more[count + 1..count + 1 + more.len() - fewer.len()];
    let mut grown = more.to_vec();
    grown[count] += 1;
    grown.splice(count + 1..count + 1, item.iter().copied());
    grown
}

fn parse_error(bytes: &[u8], data: &RingTransactData<'_>) -> CustomRingError {
    RingTransactData::parse(bytes, data.rail).expect_err("the frame check refuses it")
}

#[test]
fn the_message_limit_is_spp_s_beside_the_auditor_message_and_the_sender_bundle() {
    let fixture = Fixture::new();
    let ring = ring_policy::config();
    for (name, data) in fixture.cases() {
        let limit = max_application_messages(data.rail);
        assert_eq!(
            limit + 1 + usize::from(data.sender.is_some()),
            MAX_SPP_MESSAGES,
            "{name}"
        );

        let largest = with_messages(data.clone(), limit);
        let bytes = largest.encode().unwrap();
        RingTransactData::parse(&bytes, largest.rail).unwrap();
        let owned = largest
            .transact_ix_data(&ring, TransactProof::zeroed())
            .unwrap()
            .serialize()
            .unwrap();
        let borrowed = largest
            .spp_instruction_data_under(&ring, TransactProof::zeroed())
            .unwrap();
        assert_eq!(&borrowed[1..], owned, "{name}");

        let excess = with_messages(data.clone(), limit + 1);
        assert_eq!(
            excess.encode(),
            Err(CustomRingError::TooManyApplicationMessages),
            "{name}"
        );
        let fewer = with_messages(data.clone(), limit - 1).encode().unwrap();
        assert_eq!(
            parse_error(&one_more(&fewer, &bytes), &data),
            CustomRingError::TooManyApplicationMessages,
            "{name}"
        );
    }
}

#[test]
fn public_leg_refusals_carry_ring_errors() {
    let fixture = Fixture::new();
    let data = fixture.confidential_extensions();

    let zero = with_legs(data.clone(), &[0]);
    assert_eq!(zero.encode(), Err(CustomRingError::ZeroPublicLegAmount));
    let one = with_legs(data.clone(), &[1]).encode().unwrap();
    let two = with_legs(data.clone(), &[2]).encode().unwrap();
    let amount = one
        .iter()
        .zip(&two)
        .position(|(left, right)| left != right)
        .expect("the amounts differ");
    let mut zeroed = one.clone();
    zeroed[amount..amount + 8].fill(0);
    assert_eq!(
        parse_error(&zeroed, &data),
        CustomRingError::ZeroPublicLegAmount
    );

    let full = vec![1; MAX_INTERFACE_TRANSFERS];
    let excess = with_legs(data.clone(), &[1; MAX_INTERFACE_TRANSFERS + 1]);
    assert_eq!(excess.encode(), Err(CustomRingError::TooManyPublicLegs));
    let largest = with_legs(data.clone(), &full).encode().unwrap();
    let fewer = with_legs(data.clone(), &full[1..]).encode().unwrap();
    assert_eq!(
        parse_error(&one_more(&fewer, &largest), &data),
        CustomRingError::TooManyPublicLegs
    );
}
