use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use solana_address::Address;
use spr_interface::pda;
use zolana_ring_client::{FirstContact, PaymentRecipient, StreamCounter, TransferTagging};
use zolana_ring_keys::RingAddress;

use crate::{
    tests::support::{
        history, keypair, owner_identity, ring, Chain, Registry, RingSettings, TREE_ID,
    },
    DepositAsset, DepositRecipient, RingDeposit, RingError,
};

fn deposit<'a>(
    payer: &'a (dyn solana_signer::Signer + Sync),
    recipient: DepositRecipient<'a>,
) -> RingDeposit<'a> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient,
        tree: pda::tree(TREE_ID),
        asset: DepositAsset::Sol,
        amount: 5,
        cosigner: None,
    }
}

#[tokio::test]
async fn an_anonymous_ring_takes_deposits_only_for_the_depositors_hidden_owner() {
    let member = keypair(1);
    let payer = keypair(9);
    let anonymous = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let confidential = Chain::ring(RingSettings::new(RingMode::Confidential));
    let address = member.shielded_address().unwrap();
    let history = history(&member);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        history: &history,
    };
    assert!(matches!(
        deposit(&payer, DepositRecipient::Confidential(address))
            .prepare(&anonymous)
            .await,
        Err(RingError::Program(CustomRingError::AnonymousRingRefused))
    ));
    assert!(matches!(
        deposit(&payer, hidden).prepare(&confidential).await,
        Err(RingError::NotAnonymousRing)
    ));
    assert!(matches!(
        deposit(&member, hidden).prepare(&anonymous).await,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let prepared = deposit(&payer, hidden).prepare(&anonymous).await.unwrap();
    assert_eq!(
        (prepared.utxo().owner, prepared.utxo().amount),
        (member.signing_pubkey(), 5)
    );
}

#[tokio::test]
async fn an_escrowed_ring_refuses_a_deposit_to_a_member_without_an_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&registered, 1)]),
        &crate::tests::pipeline_rules(),
    );
    let client = chain.client();
    let prepared = deposit(
        &payer,
        DepositRecipient::Confidential(stranger.shielded_address().unwrap()),
    )
    .prepare(client.zolana())
    .await
    .unwrap();
    let owner = owner_identity(&stranger);
    assert!(matches!(
        prepared.prove(&client).await,
        Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
    ));
}

#[tokio::test]
async fn a_deposit_names_the_co_signer_a_deposit_scope_demands() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let chain = Chain::ring(RingSettings {
        co_signer: Some((
            solana_signer::Signer::pubkey(&co_signer),
            CoSignScope::DEPOSITS,
        )),
        ..RingSettings::new(RingMode::Confidential)
    });
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    assert!(matches!(
        deposit(&payer, recipient).prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
    let named = RingDeposit {
        cosigner: Some(&co_signer),
        ..deposit(&payer, recipient)
    };
    assert!(named.prepare(&chain).await.is_ok());
    let stranger = keypair(7);
    let wrong = RingDeposit {
        cosigner: Some(&stranger),
        ..deposit(&payer, recipient)
    };
    assert!(matches!(
        wrong.prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
}

#[tokio::test]
async fn a_co_signer_outside_the_deposit_scope_does_not_sign() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    for (scope, signs) in [
        (CoSignScope::WITHDRAWALS, false),
        (CoSignScope::DEPOSITS, true),
    ] {
        let chain = Chain::ring(RingSettings {
            co_signer: Some((solana_signer::Signer::pubkey(&co_signer), scope)),
            ..RingSettings::new(RingMode::Confidential)
        });
        let named = RingDeposit {
            cosigner: Some(&co_signer),
            ..deposit(&payer, recipient)
        };
        let prepared = named.prepare(&chain).await.unwrap();
        assert_eq!(named.signers(&prepared).len(), 1 + usize::from(signs));
    }
}

fn publishes(prepared: &crate::PreparedRingDeposit, tag: &[u8; 32]) -> bool {
    prepared
        .spp
        .data
        .windows(tag.len())
        .any(|bytes| bytes == tag)
}

#[tokio::test]
async fn an_own_deposit_takes_the_sender_tag_at_tx_count_and_advances_it() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let hidden = deposit(
        &payer,
        DepositRecipient::Anonymous {
            keys: &member,
            history: &history,
        },
    );
    let prepared = hidden.prepare(&chain).await.unwrap();
    assert!(publishes(
        &prepared,
        &member.get_sender_view_tag(0).unwrap()
    ));
    let advanced = prepared.viewing_history().unwrap();
    assert_eq!(advanced.current().tx_count(), 1);
    assert_eq!(hidden.viewing_history().unwrap().as_ref(), Some(advanced));
}

#[tokio::test]
async fn a_deposit_from_the_stored_history_takes_the_next_sender_tag() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let own = |history| {
        deposit(
            &payer,
            DepositRecipient::Anonymous {
                keys: &member,
                history,
            },
        )
    };
    let stored = own(&history).viewing_history().unwrap().unwrap();
    let next = own(&stored).prepare(&chain).await.unwrap();
    assert!(publishes(&next, &member.get_sender_view_tag(1).unwrap()));
    assert!(!publishes(&next, &member.get_sender_view_tag(0).unwrap()));
    assert_eq!(next.viewing_history().unwrap().current().tx_count(), 2);
}

#[tokio::test]
async fn a_deposit_to_another_member_takes_a_first_contact_tag_until_a_transfer_pairs() {
    let member = keypair(1);
    let recipient = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let to = RingAddress {
        recipient: recipient.shielded_address().unwrap(),
        ring_program_id: ring().program_id(),
    };
    let request = recipient.get_recipient_request_view_tag(0).unwrap();
    let history = history(&member);
    let paid = |history, first_contact| {
        deposit(
            &payer,
            DepositRecipient::AnonymousPayment {
                keys: &member,
                history,
                to: &to,
                first_contact,
            },
        )
    };
    let bootstrap = paid(&history, FirstContact::Bootstrap)
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(&bootstrap, &recipient.viewing_pubkey().u()));
    let requested = paid(&history, FirstContact::Request(request))
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(&requested, &request));
    let unpaired = bootstrap.viewing_history().unwrap().clone();
    assert_eq!(
        unpaired.current().tx_count(),
        0,
        "a deposit spends no sender tag"
    );
    assert!(
        unpaired.current().known_recipients().is_empty(),
        "a deposit names no sender, so it pairs nothing"
    );
    let paired = TransferTagging {
        keys: &member,
        history: &unpaired,
        recipients: &[PaymentRecipient {
            viewing_pubkey: recipient.viewing_pubkey(),
            first_contact: FirstContact::Bootstrap,
        }],
    }
    .plan()
    .unwrap()
    .history;
    let shared = paid(&paired, FirstContact::Request(request))
        .prepare(&chain)
        .await
        .unwrap();
    assert!(publishes(
        &shared,
        &member
            .get_send_shared_view_tag(&recipient.viewing_pubkey(), 0)
            .unwrap()
    ));
    assert_eq!(
        shared
            .viewing_history()
            .unwrap()
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(1)
    );
}

#[tokio::test]
async fn a_deposit_refuses_an_address_of_another_ring() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let other = Address::new_from_array([0x47; 32]);
    let to = RingAddress {
        recipient: keypair(2).shielded_address().unwrap(),
        ring_program_id: other,
    };
    let history = history(&member);
    let paid = DepositRecipient::AnonymousPayment {
        keys: &member,
        history: &history,
        to: &to,
        first_contact: FirstContact::Bootstrap,
    };
    assert!(matches!(
        deposit(&payer, paid).prepare(&chain).await,
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == other && paid == ring().program_id()
    ));
}
