//! A child of `pipeline`, every rail stages and assembles through its private items.

use custom_ring_interface::{
    anonymous_recipient_output_body, anonymous_sender_output_body, CustomRingError, RingMode,
    RingRail, RingTransactData,
};
use solana_address::Address;
use spl_token_2022_interface::pod::{PodAccount, PodCOption};
use spr_client::ClientError;
use spr_interface::{
    instruction::instruction_data::transact::OwnerTag, pda, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID,
};
use spr_keypair::ShieldedKeypair;
use spr_program::instruction::{TransactSolTransferAccounts, TransactSplWithdrawalAccounts};
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, AssetRegistry, Mint, WalletUtxo,
};
use zolana_ring_client::{FirstContact, StreamCounter, ViewingHistory};
use zolana_ring_keys::RingAddress;
use zolana_ring_transaction::{
    listed_recipients, AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    RingDelivery,
};

use super::*;
use crate::client::RingClient;
use crate::tests::support::{
    account, empty, history, ring, ring_utxo, Chain, RingSettings, TREE_ID,
};

fn anonymous() -> RingSettings {
    RingSettings::new(RingMode::Anonymous)
}

fn ring_transaction(utxos: Vec<WalletUtxo>) -> ConfidentialTransaction {
    paid_ring_transaction(utxos, crate::tests::support::payer())
}

fn paid_ring_transaction(utxos: Vec<WalletUtxo>, payer: Address) -> ConfidentialTransaction {
    ConfidentialTransaction::new_with_ring(utxos, payer, ring().program_id()).unwrap()
}

fn owner_transfer(
    sender: &ShieldedKeypair,
    transaction: ConfidentialTransaction,
) -> CustomRingTransfer<'_> {
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
}

fn ring_address(owner: &ShieldedKeypair) -> RingAddress {
    RingAddress {
        recipient: owner.shielded_address().unwrap(),
        ring_program_id: ring().program_id(),
    }
}

fn payment(to: &RingAddress, amount: u64) -> AnonymousPayment {
    AnonymousPayment {
        to: to.clone(),
        first_contact: FirstContact::Bootstrap,
        asset: Mint::SOL,
        amount,
    }
}

async fn stage_anonymous<'a>(
    transfer: &'a AnonymousTransfer<'a>,
    chain: &Chain,
) -> Result<Staged<'a>, RingError> {
    let config = ring().require_config(chain).await?;
    transfer.rail.stage(ring(), chain, &config).await
}

async fn exit_owner(
    transfer: AnonymousTransfer<'_>,
    named: Option<Address>,
    chain: Chain,
) -> Result<(), RingError> {
    let transfer = match named {
        Some(owner) => transfer.with_exit_token_owner(owner),
        None => transfer,
    };
    match stage_anonymous(&transfer, &chain).await?.spend {
        Spend::Anonymous(_) => Ok(()),
        Spend::Owner | Spend::Delegate { .. } => unreachable!("an anonymous ring stages its rail"),
    }
}

fn token_state(mint: Address, owner: Address) -> PodAccount {
    PodAccount {
        mint: mint.to_bytes().into(),
        owner: owner.to_bytes().into(),
        state: SPL_TOKEN_ACCOUNT_INITIALIZED,
        ..PodAccount::default()
    }
}

fn token_account(state: PodAccount) -> solana_account::Account {
    account(Address::new_from_array(SPL_TOKEN_PROGRAM_ID), &state)
}

#[tokio::test]
async fn an_anonymous_spl_exit_names_neither_the_hidden_owner_nor_a_second_key() {
    let sender = &crate::tests::support::keypair(1);
    let state = &history(sender);
    let hidden = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
    let mint = Address::new_from_array([0x31; 32]);
    let stranger = Address::new_from_array([0x32; 32]);
    let other = Address::new_from_array([0x35; 32]);
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let destination = pda::associated_token_address_with_program(&stranger, &mint, &token_program);
    let associated = pda::associated_token_address_with_program(&hidden, &mint, &token_program);
    let chain = || Chain::ring(anonymous());
    let stage = |to: Address, named: Option<Address>, chain: Chain| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::new(mint, 2), 10, 0)]);
        transaction.withdraw(mint, 4, to).unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![
                TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account: to,
                    token_program,
                }),
            ])
            .with_anonymous_signer(&sender.signing_key, state);
        exit_owner(transfer, named, chain)
    };
    for (to, owner) in [
        (destination, hidden),
        (hidden, stranger),
        (associated, stranger),
    ] {
        let refused = stage(
            to,
            None,
            chain().with(to, token_account(token_state(mint, owner))),
        )
        .await;
        assert!(
            matches!(refused, Err(RingError::AnonymousExitLinksOwner(exit)) if exit == to),
            "{to} owned by {owner}"
        );
    }
    let key = PodCOption::some(stranger.to_bytes().into());
    for state in [
        PodAccount {
            delegate: key,
            ..token_state(mint, stranger)
        },
        PodAccount {
            close_authority: key,
            ..token_state(mint, stranger)
        },
    ] {
        assert!(matches!(
            stage(destination, None, chain().with(destination, token_account(state))).await,
            Err(RingError::AnonymousExitTokenAccountShared(exit)) if exit == destination
        ));
    }
    let foreign_mint = chain().with(destination, token_account(token_state(stranger, stranger)));
    assert!(matches!(
        stage(destination, None, foreign_mint).await,
        Err(RingError::AnonymousExitTokenAccountInvalid(exit)) if exit == destination
    ));
    let keypair_address = Address::new_from_array([0x33; 32]);
    assert!(keypair_address.is_on_curve());
    let on_curve = chain().with(keypair_address, token_account(token_state(mint, stranger)));
    assert!(matches!(
        stage(keypair_address, None, on_curve).await,
        Err(RingError::AnonymousExitTokenAccountOnCurve(exit)) if exit == keypair_address
    ));
    let existing = || chain().with(destination, token_account(token_state(mint, stranger)));
    for named in [None, Some(stranger)] {
        stage(destination, named, existing()).await.unwrap();
    }
    assert!(matches!(
        stage(destination, Some(other), existing()).await,
        Err(RingError::AnonymousExitNamedOwnerMismatch { token_account, named, owner })
            if token_account == destination && named == other && owner == stranger
    ));
    // The transaction creates the associated token account before SPP reads it.
    let minted = || chain().with(mint, empty(token_program));
    stage(destination, Some(stranger), minted()).await.unwrap();
    for (named, chain) in [
        (None, minted()),
        (Some(other), minted()),
        (Some(stranger), chain()),
    ] {
        assert!(matches!(
            stage(destination, named, chain).await,
            Err(RingError::AnonymousExitTokenAccountInvalid(exit)) if exit == destination
        ));
    }
    assert!(matches!(
        stage(associated, Some(hidden), minted()).await,
        Err(RingError::AnonymousExitLinksOwner(exit)) if exit == associated
    ));
}

/// SPP binds a SOL exit's recipient alone, a program owner, data or the hidden owner there is
/// refused before proving.
#[tokio::test]
async fn an_anonymous_sol_exit_leaves_to_a_wallet_other_than_the_hidden_owner() {
    let sender = &crate::tests::support::keypair(1);
    let state = &history(sender);
    let hidden = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
    let stage = |to: Address, named: Option<Address>, chain: Chain| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.withdraw_sol(4, to).unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: to },
            )])
            .with_anonymous_signer(&sender.signing_key, state);
        exit_owner(transfer, named, chain)
    };
    assert!(matches!(
        stage(hidden, None, Chain::ring(anonymous())).await,
        Err(RingError::AnonymousExitLinksOwner(exit)) if exit == hidden
    ));
    let wallet = Address::new_from_array([0x34; 32]);
    let mut nonce = empty(Address::default());
    nonce.data = vec![0; 80];
    for held in [empty(Address::new_from_array(SPL_TOKEN_PROGRAM_ID)), nonce] {
        assert!(matches!(
            stage(wallet, None, Chain::ring(anonymous()).with(wallet, held)).await,
            Err(RingError::AnonymousExitAccountHasData(exit)) if exit == wallet
        ));
    }
    for chain in [
        Chain::ring(anonymous()),
        Chain::ring(anonymous()).with(wallet, empty(Address::default())),
    ] {
        stage(wallet, None, chain).await.unwrap();
    }
    assert!(matches!(
        stage(wallet, Some(wallet), Chain::ring(anonymous())).await,
        Err(RingError::AnonymousExitTokenOwnerWithoutSplExit)
    ));
}

#[test]
fn a_payment_to_another_rings_address_is_refused() {
    let sender = &crate::tests::support::keypair(1);
    let state = history(sender);
    let foreign = RingAddress {
        ring_program_id: Address::new_from_array([43; 32]),
        ..ring_address(&crate::tests::support::keypair(2))
    };
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    assert!(matches!(
        owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&foreign, 3)),
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == foreign.ring_program_id && paid == ring().program_id()
    ));
}

/// The published owner tag and recipient body of every slot, `None` on a change output.
fn published<'s>(staged: &'s Staged<'_>) -> Vec<([u8; 32], Option<&'s [u8]>)> {
    staged
        .proof_inputs
        .external_data
        .outputs
        .iter()
        .map(|output| {
            let OwnerTag::Inline(tag) = output.owner_tag else {
                panic!("an anonymous slot is tagged inline, {:?}", output.owner_tag);
            };
            let body = output.data.as_deref().map(|data| {
                anonymous_recipient_output_body(data).expect("a scheme 1 recipient body")
            });
            (tag, body)
        })
        .collect()
}

fn opened(
    staged: &Staged<'_>,
    reader: &ShieldedKeypair,
    ciphertext: &[u8],
    slot: usize,
) -> Vec<u8> {
    let external = &staged.proof_inputs.external_data;
    reader
        .viewing_key
        .decrypt_utxo(
            ciphertext,
            &spr_keypair::X25519Pubkey::from_bytes(external.tx_viewing_pk).unwrap(),
            external.salt,
            slot as u32,
        )
        .unwrap()
}

fn payment_at(
    staged: &Staged<'_>,
    reader: &ShieldedKeypair,
    position: usize,
) -> AnonymousTransferRecipientPlaintext {
    let body = published(staged)[position].1.expect("a recipient body");
    AnonymousTransferRecipientPlaintext::deserialize(&opened(staged, reader, body, position))
        .unwrap()
}

/// The sender bundle, the first message, opened under the sender's own viewing key.
fn bundle(staged: &Staged<'_>, sender: &ShieldedKeypair) -> AnonymousTransferSenderPlaintext {
    let external = &staged.proof_inputs.external_data;
    let message = &external.messages[0];
    assert_eq!(message.view_tag, published(staged)[0].0);
    let body = anonymous_sender_output_body(&message.data).expect("a scheme 2 sender bundle");
    let plaintext = opened(staged, sender, body, external.outputs.len());
    AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap()
}

/// Change leads with no body, SPL before SOL.
#[tokio::test]
async fn an_anonymous_transfer_publishes_each_payment_and_the_sender_bundle() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let bootstrap = keypair(2);
    let requester = keypair(3);
    let usdc = Mint::new(Address::new_from_array([0x31; 32]), 2);
    let request = requester.get_recipient_request_view_tag(0).unwrap();
    let state = history(sender);
    let transaction = ring_transaction(vec![
        ring_utxo(sender, usdc, 10, 0),
        ring_utxo(sender, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(AnonymousPayment {
            asset: usdc,
            ..payment(&ring_address(&bootstrap), 3)
        })
        .unwrap()
        .with_payment(AnonymousPayment {
            first_contact: FirstContact::Request(request),
            ..payment(&ring_address(&requester), 2)
        })
        .unwrap()
        .with_shape(spr_client::Shape::IN2_OUT8)
        .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let outputs = &staged.proof_inputs.output_utxos;
    let sender_address = sender.shielded_address().unwrap();
    assert_eq!(
        outputs[..2]
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        [
            (Some(sender_address), usdc, 7),
            (Some(sender_address), Mint::SOL, 8)
        ]
    );
    let slots = published(&staged);
    let sender_tag = sender.get_sender_view_tag(0).unwrap();
    assert_eq!(slots[0].0, sender_tag);
    assert_ne!(slots[1].0, sender_tag);
    assert_eq!(slots[2].0, bootstrap.viewing_pubkey().u());
    assert_eq!(slots[3].0, request);
    assert!(slots[..2].iter().all(|(_, body)| body.is_none()));
    assert!(slots[2..].iter().all(|(_, body)| body.is_some()));
    for (tag, _) in &slots[3..] {
        assert_eq!(tag[0], 0, "a request or dummy tag is zero-led");
    }
    let sent = bundle(&staged, sender);
    assert_eq!(
        (
            sent.verified.spl_mint,
            sent.verified.spl_amount,
            sent.verified.sol_amount
        ),
        (usdc.asset, 7, 8)
    );
    assert_eq!(
        sent.verified.recipient_viewing_pks.len(),
        outputs.len() - 2,
        "one entry per non-change output"
    );
    assert_eq!(
        listed_recipients(&sent).copied().collect::<Vec<_>>(),
        [bootstrap.viewing_pubkey(), requester.viewing_pubkey()]
    );
    let paid = payment_at(&staged, &bootstrap, 2);
    assert_eq!(
        (
            paid.verified.owner_pubkey,
            paid.verified.mint,
            paid.verified.amount,
            paid.unverified.sender_pubkey
        ),
        (
            bootstrap.signing_pubkey(),
            usdc.asset,
            3,
            sender.viewing_pubkey()
        )
    );
}

#[tokio::test]
async fn a_transfer_returning_nothing_leads_with_a_zero_sol_change() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(sender);
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key, &state)
    .with_payment(payment(&paid, 10))
    .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let leading = &staged.proof_inputs.output_utxos[0];
    assert_eq!(
        (leading.owner_address, leading.asset, leading.amount),
        (Some(sender.shielded_address().unwrap()), Mint::SOL, 0)
    );
    let sent = bundle(&staged, sender);
    assert_eq!(
        (sent.verified.sol_amount, listed_recipients(&sent).count()),
        (0, 1)
    );
}

/// A first payment pairs the recipient, the next one takes the shared tag at index 0.
#[tokio::test]
async fn a_known_recipient_takes_the_shared_tag_and_the_history_advances() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let recipient = keypair(2);
    let paid = ring_address(&recipient);
    let pay = |state: &ViewingHistory| {
        owner_transfer(
            sender,
            ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
        )
        .with_anonymous_signer(&sender.signing_key, state)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .viewing_history()
        .unwrap()
    };
    let first = pay(&history(sender));
    assert_eq!(first.current().tx_count(), 1);
    assert_eq!(
        first
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(0)
    );
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key, &first)
    .with_payment(payment(&paid, 4))
    .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let slots = published(&staged);
    assert_eq!(slots[0].0, sender.get_sender_view_tag(1).unwrap());
    assert_eq!(
        slots[1].0,
        sender
            .get_send_shared_view_tag(&recipient.viewing_pubkey(), 0)
            .unwrap()
    );
    let Spend::Anonymous(spend) = staged.spend else {
        panic!("an anonymous ring stages its rail");
    };
    let second = &spend.history;
    assert_eq!(second, &pay(&first));
    assert_eq!(second.current().tx_count(), 2);
    assert_eq!(
        second
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(1)
    );
}

/// SPP publishes the hidden owner's key beside a default-ring spend, the preview sizes it.
#[tokio::test]
async fn a_default_ring_spend_previews_the_hidden_owners_published_key() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let entry = crate::tests::support::wallet(
        spr_transaction::Utxo {
            owner: sender.signing_pubkey(),
            asset: Mint::SOL,
            amount: 10,
            blinding: spr_keypair::random_blinding(),
            ring_program_id: None,
            data: spr_transaction::Data::default(),
        },
        &sender.nullifier_key,
        TREE_ID,
        0,
    );
    let transfer = owner_transfer(sender, ring_transaction(vec![entry]))
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let unwitnessed = transfer
        .frame(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let instruction = unwitnessed.instruction().unwrap();
    let parsed = RingTransactData::parse(&instruction.data[1..], RingRail::Anonymous).unwrap();
    assert_eq!(
        parsed.data().anonymous.unwrap().default_owner_tag,
        Some(&sender.signing_pubkey().as_ed25519().unwrap())
    );
}

struct MoveSender<'a> {
    sender: &'a ShieldedKeypair,
    state: &'a ViewingHistory,
    payer: Address,
}

impl<'a> MoveSender<'a> {
    fn anonymous_move(
        &self,
        utxos: &'a [WalletUtxo],
        payments: Vec<RingPayment>,
    ) -> AnonymousMove<'a> {
        AnonymousMove {
            ring: ring(),
            sender: self.sender,
            nullifier_key: &self.sender.nullifier_key,
            signer: &self.sender.signing_key,
            history: self.state,
            payer: self.payer,
            utxos,
            asset: Mint::SOL,
            payments,
            entry: EntrySpend::Allow,
            co_signer: None,
        }
    }
}

fn default_ring_utxo(owner: &ShieldedKeypair, amount: u64, leaf: u64) -> WalletUtxo {
    crate::tests::support::wallet(
        spr_transaction::Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount,
            blinding: spr_keypair::random_blinding(),
            ring_program_id: None,
            data: spr_transaction::Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

/// Ordinary padding publishes the shape's inputs, 16 at 2 outputs is the widest keyed spend.
#[tokio::test]
async fn an_anonymous_move_takes_the_widest_keyed_spend_and_refuses_past_it() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let client = Chain::ring(anonymous()).client();
    let utxos: Vec<WalletUtxo> = (0..36)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay =
        |amount| owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), amount)]);
    let widest = pay(16).select(&client).await.unwrap();
    let assembled = widest.assemble(&client).await.unwrap();
    assert_eq!(
        assembled.frame.proof_inputs.check_shape().unwrap(),
        spr_client::Shape::IN16_OUT2
    );
    assert!(matches!(
        pay(17).select(&client).await,
        Err(RingError::Unfunded {
            amount: 17,
            max_inputs: 16,
            ..
        })
    ));
}

/// Five payments and the change pad to 8 outputs, an anonymous ring fits 5 inputs there and not 6.
#[tokio::test]
async fn an_anonymous_move_past_the_transaction_size_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let recipients: Vec<ShieldedKeypair> = (10..15).map(keypair).collect();
    let client = Chain::ring(anonymous()).client();
    let state = history(&sender);
    let utxos: Vec<WalletUtxo> = (0..8)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay = |first: u64| {
        owner.anonymous_move(
            &utxos,
            recipients
                .iter()
                .zip(core::iter::once(first).chain(core::iter::repeat(1)))
                .map(|(recipient, amount)| RingPayment::bootstrap(ring_address(recipient), amount))
                .collect(),
        )
    };
    let fits = pay(1).select(&client).await.unwrap();
    assert_eq!(
        fits.assemble(&client)
            .await
            .unwrap()
            .frame
            .proof_inputs
            .check_shape()
            .unwrap(),
        spr_client::Shape::IN5_OUT8
    );
    assert!(matches!(
        pay(2).select(&client).await,
        Err(RingError::TransactionTooLarge { bytes, limit }) if bytes > limit
    ));
}

/// An entry spend publishes the hidden owner's key, ring UTXOs fund the move first.
#[tokio::test]
async fn an_anonymous_move_spends_ring_utxos_before_an_entry() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let chain = Chain::ring(anonymous()).client();
    let client = &chain;
    let mut utxos = vec![default_ring_utxo(&sender, 50, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let spend = |amount| {
        let anonymous_move =
            owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), amount)]);
        async move {
            let transfer = anonymous_move.select(client).await.unwrap();
            transfer.assemble(client).await.unwrap()
        }
    };
    let ring_only = spend(20).await;
    assert!(!ring_only.frame.parts.full_openings);
    assert_eq!(
        ring_only
            .frame
            .proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .count(),
        4
    );
    assert!(spend(30).await.frame.parts.full_openings);
    let refused = AnonymousMove {
        entry: EntrySpend::Refuse,
        ..owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 30)])
    };
    assert!(matches!(
        refused.select(client).await,
        Err(RingError::Unfunded { amount: 30, .. })
    ));
}

/// Only a mix of ring and default-ring UTXOs funds the move, the prover refuses one.
#[tokio::test]
async fn an_anonymous_move_never_mixes_ring_and_default_ring_utxos() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let mut utxos = vec![default_ring_utxo(&sender, 25, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 30)])
        .select(&Chain::ring(anonymous()).client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::Unfunded { amount: 30, .. })
    ));
}

/// Nine inputs exceed the entry class, the mix is refused before the width.
#[tokio::test]
async fn an_anonymous_spend_of_ring_and_default_ring_utxos_is_refused_before_proving() {
    let sender = crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(&sender);
    let mut utxos = vec![default_ring_utxo(&sender, 5, 10)];
    utxos.extend((0..8).map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf)));
    let transaction = ring_transaction(utxos);
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::EntryRingInput { index: 1 })
    ));
}

#[tokio::test]
async fn an_anonymous_transfer_reserving_an_address_is_refused_before_signing() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    for note in [
        ring_utxo(sender, Mint::SOL, 10, 0),
        default_ring_utxo(sender, 10, 0),
    ] {
        let address =
            SppProofInputUtxo::new_address(sender.signing_pubkey(), [7; 32], TREE_ID).unwrap();
        let transaction = ConfidentialTransaction::new_with_addresses(
            vec![note],
            vec![address],
            crate::tests::support::payer(),
        )
        .unwrap();
        // A ring-less change would exit to the sender and fail first.
        let transfer = owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&paid, 10))
            .unwrap();
        assert!(matches!(
            stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
            Err(RingError::InvalidAnonymousSlot)
        ));
    }
}

/// The entry key rebuilds every spent UTXO from its opening, a data hash breaks the audit proof.
#[tokio::test]
async fn an_entry_spend_of_a_utxo_carrying_data_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let chain = Chain::ring(anonymous());
    let mut entry = default_ring_utxo(&sender, 50, 10);
    entry.data_hash = Some([7; 32]);
    entry.utxo_hash = entry
        .utxo
        .hash(&entry.nullifier_pubkey, &[7; 32], &[0; 32], TREE_ID)
        .unwrap();
    entry.nullifier = sender
        .nullifier_key
        .nullifier(&entry.utxo_hash, &entry.utxo.blinding)
        .unwrap();
    let transfer = owner_transfer(&sender, ring_transaction(vec![entry.clone()]))
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &chain).await,
        Err(RingError::EntryInputData { index: 0 })
    ));
    let utxos = [entry];
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 4)])
        .select(&chain.client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::Unfunded { amount: 4, .. })
    ));
}

/// The fee payer is a public signer, the hidden owner may not pay its move.
#[tokio::test]
async fn an_anonymous_move_its_owner_would_pay_is_refused_before_proving() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let utxos = [ring_utxo(&sender, Mint::SOL, 5, 0)];
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: HiddenOwner::of(&sender.signing_pubkey()).unwrap().0,
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 5)])
        .select(&Chain::ring(anonymous()).client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
}

/// The transaction payer differs from the hidden owner, the submission's signers do not.
#[tokio::test]
async fn an_anonymous_transfer_its_owner_would_sign_in_public_is_refused_before_proving() {
    use solana_signer::Signer;
    let sender = &crate::tests::support::keypair(1);
    let payer = crate::tests::support::keypair(9);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let client = Chain::ring(anonymous()).client();
    let unsigned: &[&(dyn Signer + Sync)] = &[];
    for (fee_payer, signers) in [
        (sender, unsigned),
        (&payer, &[sender as &(dyn Signer + Sync)]),
    ] {
        let transfer = owner_transfer(
            sender,
            ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
        )
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
        let refused = crate::RingSubmission::new(transfer)
            .send(&client, fee_payer, signers)
            .await;
        assert!(matches!(
            refused,
            Err(RingError::AnonymousPublicSignerLinksOwner)
        ));
    }
}

#[tokio::test]
async fn only_the_configured_delegate_moves_utxos_on_an_escrowed_policy_ring() {
    let member = &crate::tests::support::keypair(1);
    let stranger = &crate::tests::support::keypair(3);
    let delegate = Address::new_from_array([0x44; 32]);
    let escrowed = RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let stage = |settings: RingSettings, signer: Address, key: &ShieldedKeypair, inputs| {
        stage_delegate(DelegateCase {
            settings,
            delegate: signer,
            member,
            key: key.nullifier_key.clone(),
            inputs,
        })
    };
    let utxos = |count: u64| -> Vec<WalletUtxo> {
        (0..count)
            .map(|leaf| ring_utxo(member, Mint::SOL, 1, leaf))
            .collect()
    };
    assert!(stage(escrowed, delegate, member, utxos(2)).await.is_ok());
    assert!(matches!(
        stage(
            RingSettings {
                delegate: None,
                ..escrowed
            },
            delegate,
            member,
            utxos(2)
        )
        .await,
        Err(RingError::MissingDelegate)
    ));
    assert!(matches!(
        stage(
            escrowed,
            Address::new_from_array([0x45; 32]),
            member,
            utxos(2)
        )
        .await,
        Err(RingError::Program(CustomRingError::UnauthorizedDelegate))
    ));
    for settings in [
        RingSettings {
            has_policy: false,
            ..escrowed
        },
        RingSettings {
            mode: RingMode::Confidential,
            ..escrowed
        },
    ] {
        assert!(matches!(
            stage(settings, delegate, member, utxos(2)).await,
            Err(RingError::DelegateRequiresEscrow)
        ));
    }
    assert!(matches!(
        stage(escrowed, delegate, stranger, utxos(2)).await,
        Err(RingError::NullifierKeyMismatch)
    ));
    let mut mixed = utxos(1);
    mixed.push(ring_utxo(stranger, Mint::SOL, 1, 1));
    assert!(matches!(
        stage(escrowed, delegate, member, mixed).await,
        Err(RingError::MixedOwners { index: 1 })
    ));
    assert!(matches!(
        stage(escrowed, delegate, member, utxos(41)).await,
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
}

#[test]
fn an_unkeyed_shape_names_its_rail_in_words() {
    assert_eq!(
        RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        }
        .to_string(),
        "the transfer needs a shape no delegate key serves"
    );
}

#[tokio::test]
async fn a_delegate_move_pads_to_any_ring_authority_shape_it_is_given() {
    use spr_client::Shape;
    let member = &crate::tests::support::keypair(1);
    let delegate = Address::new_from_array([0x44; 32]);
    let source = member.shielded_address().unwrap();
    let assets = AssetRegistry::default();
    let transfer = || {
        DelegateTransfer::new(DelegateTransferInput {
            ring: ring(),
            delegate,
            payer: crate::tests::support::payer(),
            source,
            source_nullifier_key: &member.nullifier_key,
            inputs: vec![ring_utxo(member, Mint::SOL, 3, 0)],
            outputs: vec![DelegateOutput {
                recipient: source,
                asset: Mint::SOL.asset,
                amount: 2,
            }],
        })
        .with_assets(&assets)
    };
    assert!(matches!(
        transfer().with_shape(Shape::IN48_OUT2),
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    });
    let config = ring().require_config(&chain).await.unwrap();
    let automatic = transfer();
    let staged = automatic.rail.stage(ring(), &chain, &config).await.unwrap();
    assert_eq!(staged.proof_inputs.check_shape().unwrap(), Shape::IN2_OUT2);
    assert!(matches!(staged.rail.delivery(), RingDelivery::Delivered));
    let shaped = transfer().with_shape(Shape::IN4_OUT4).unwrap();
    let staged = shaped.rail.stage(ring(), &chain, &config).await.unwrap();
    assert_eq!(staged.proof_inputs.check_shape().unwrap(), Shape::IN4_OUT4);
    assert!(matches!(staged.rail.delivery(), RingDelivery::Delivered));
}

struct MoveFixture<'a> {
    member: &'a ShieldedKeypair,
    recipient: spr_keypair::ShieldedAddress,
    delegate: Address,
    assets: &'a AssetRegistry,
}

struct MoveCase<'a> {
    utxos: &'a [WalletUtxo],
    payer: Address,
    amounts: &'a [u64],
}

impl<'a> MoveFixture<'a> {
    fn delegate_move(&self, case: MoveCase<'a>) -> DelegateMove<'a> {
        DelegateMove {
            ring: ring(),
            delegate: self.delegate,
            payer: case.payer,
            source: self.member.shielded_address().unwrap(),
            source_nullifier_key: &self.member.nullifier_key,
            utxos: case.utxos,
            mint: Mint::SOL.asset,
            payments: case
                .amounts
                .iter()
                .map(|amount| DelegatePayment {
                    recipient: self.recipient,
                    amount: *amount,
                })
                .collect(),
            assets: self.assets,
            co_signer: None,
        }
    }
}

/// The selected move's shape and the tree its inputs sit on.
async fn selected(
    transfer: DelegateTransfer<'_>,
    client: &RingClient<Chain, Chain>,
) -> (spr_client::Shape, u16) {
    let assembled = transfer.assemble(client).await.unwrap();
    (
        assembled.frame.proof_inputs.check_shape().unwrap(),
        assembled.frame.proof_inputs.input_utxos[0].tree_id,
    )
}

/// A delegate move on a policy ring with one member paying another.
fn move_chain(members: [&ShieldedKeypair; 2], delegate: Address) -> Chain {
    use crate::tests::support::Registry;
    Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_tree(1)
    .with_registry(
        Registry::new(&members.map(|member| (member, 1))),
        &crate::tests::pipeline_rules(),
    )
}

/// Four UTXOs fill the widest delegate shape, one large UTXO takes the narrowest whoever pays.
#[tokio::test]
async fn a_delegate_move_takes_the_fewest_utxos() {
    use crate::tests::support::{keypair, payer, wallet};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = move_chain([&member, &recipient], delegate).client();
    let assets = AssetRegistry::default();
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let mut utxos: Vec<WalletUtxo> = (0..8)
        .map(|leaf| ring_utxo(&member, Mint::SOL, 1, leaf))
        .collect();
    let lean = fixture.delegate_move(MoveCase {
        utxos: &utxos,
        payer: delegate,
        amounts: &[4],
    });
    assert_eq!(
        selected(lean.select(&client).await.unwrap(), &client).await,
        (spr_client::Shape::IN4_OUT4, TREE_ID)
    );
    let short = fixture.delegate_move(MoveCase {
        utxos: &utxos,
        payer: delegate,
        amounts: &[5],
    });
    assert!(matches!(
        short.select(&client).await,
        Err(RingError::Unfunded {
            amount: 5,
            max_inputs: 4,
            ..
        })
    ));
    let large = ring_utxo(&member, Mint::SOL, 50, 8);
    utxos.push(wallet(large.utxo, &member.nullifier_key, 1, 8));
    for payer in [delegate, payer()] {
        let wide = fixture.delegate_move(MoveCase {
            utxos: &utxos,
            payer,
            amounts: &[4],
        });
        assert_eq!(
            selected(wide.select(&client).await.unwrap(), &client).await,
            (spr_client::Shape::IN2_OUT2, 1)
        );
    }
}

/// Every tree funds the move, the assembly reads the first tree's inputs alone.
#[tokio::test]
async fn a_selection_over_three_candidates_reads_only_the_chosen_inputs() {
    use crate::tests::support::{keypair, wallet};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let chain = move_chain([&member, &recipient], delegate)
        .with_tree(2)
        .with_tree(3);
    let client = chain.clone().witness_client();
    let assets = AssetRegistry::default();
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let utxos: Vec<WalletUtxo> = [1u16, 2, 3]
        .into_iter()
        .flat_map(|tree| (0..4).map(move |leaf| (tree, leaf)))
        .map(|(tree, leaf)| WalletUtxo {
            latest_tree_id: Some(3),
            ..wallet(
                ring_utxo(&member, Mint::SOL, 1, leaf).utxo,
                &member.nullifier_key,
                tree,
                leaf,
            )
        })
        .collect();
    let chosen = fixture
        .delegate_move(MoveCase {
            utxos: &utxos,
            payer: delegate,
            amounts: &[4],
        })
        .select(&client)
        .await
        .unwrap();
    assert!(chain.witness_requests.lock().unwrap().is_empty());
    assert!(matches!(
        chosen.assemble(&client).await,
        Err(RingError::Client(ClientError::NoInputs))
    ));
    let mut chosen_inputs: Vec<[u8; 32]> = utxos
        .iter()
        .filter(|utxo| utxo.tree_id == 1)
        .map(|utxo| utxo.utxo_hash)
        .collect();
    chosen_inputs.sort_unstable();
    let requests = chain.witness_requests.lock().unwrap().clone();
    let [requested] = requests.as_slice() else {
        panic!("one witness read, {requests:?}");
    };
    let mut requested = requested.clone();
    requested.sort_unstable();
    assert_eq!(requested, chosen_inputs);
}

/// Four payments fill the widest delegate output count, an exact funding needs no change slot.
#[tokio::test]
async fn a_delegate_move_takes_a_change_slot_only_for_change() {
    use crate::tests::support::keypair;
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = move_chain([&member, &recipient], delegate).client();
    let assets = AssetRegistry::default();
    let exact = [ring_utxo(&member, Mint::SOL, 4, 0)];
    let over = [ring_utxo(&member, Mint::SOL, 5, 0)];
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let four = |utxos| {
        fixture.delegate_move(MoveCase {
            utxos,
            payer: delegate,
            amounts: &[1; 4],
        })
    };
    assert_eq!(
        selected(four(&exact).select(&client).await.unwrap(), &client).await,
        (spr_client::Shape::IN4_OUT4, TREE_ID)
    );
    assert!(matches!(
        four(&over).select(&client).await,
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
}

struct DelegateCase<'a> {
    settings: RingSettings,
    delegate: Address,
    member: &'a ShieldedKeypair,
    key: spr_keypair::NullifierKey,
    inputs: Vec<WalletUtxo>,
}

async fn stage_delegate(case: DelegateCase<'_>) -> Result<(), RingError> {
    let assets = AssetRegistry::default();
    let source = case.member.shielded_address()?;
    let transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate: case.delegate,
        payer: crate::tests::support::payer(),
        source,
        source_nullifier_key: &case.key,
        inputs: case.inputs,
        outputs: vec![DelegateOutput {
            recipient: source,
            asset: Mint::SOL.asset,
            amount: 2,
        }],
    })
    .with_assets(&assets);
    let chain = Chain::ring(case.settings);
    let config = ring().require_config(&chain).await?;
    transfer
        .rail
        .stage(ring(), &chain, &config)
        .await
        .map(|_| ())
}

/// Every string a request draws, hashes or derives keeps only its length.
fn request_layout(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(format!("str{}", text.len())),
        serde_json::Value::Array(items) => items.iter().map(request_layout).collect(),
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(key, field)| (key.clone(), request_layout(field)))
            .collect(),
        other => other.clone(),
    }
}

fn nonzero(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .bytes()
        .any(|digit| digit != b'0')
}

/// Each output slot as the anonymous audit circuit reads it, change the slots `sender_key` owns.
fn slot_kinds(request: &serde_json::Value, sender_key: &[u8; 32]) -> Vec<&'static str> {
    let sender_key = format!("0x{}", hex::encode(sender_key));
    request["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| {
            let opening = &slot["output"];
            match (
                nonzero(&opening["ownerPkHash"]),
                nonzero(&opening["ringProgramId"]),
            ) {
                (false, _) => "padding",
                (true, false) => "exit",
                (true, true) if slot["ownerKey"] == sender_key.as_str() => "change",
                (true, true) => "payment",
            }
        })
        .collect()
}

/// `UPDATE_PROVER_JSON=1` rewrites the pinned request.
#[tokio::test]
async fn the_anonymous_audit_request_of_an_exit_a_payment_and_change_keeps_its_pinned_layout() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let exit = crate::tests::support::keypair(3)
        .shielded_address()
        .unwrap();
    let state = history(sender);
    let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(&exit, Mint::SOL, 3, None)
        .unwrap();
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .with_shape(spr_client::Shape::IN1_OUT4)
        .unwrap();
    let assembled = transfer
        .assemble(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let request = assembled.audit().unwrap().request().unwrap();
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    let sender_key = sender.signing_pubkey().as_ed25519().unwrap();
    assert_eq!(
        slot_kinds(&built, &sender_key),
        ["change", "exit", "payment", "padding"]
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-audit-anonymous-exit.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
    assert_eq!(
        slot_kinds(&pinned, &sender_key),
        slot_kinds(&built, &sender_key)
    );
}

/// The program refuses dual control the owner would satisfy itself.
#[tokio::test]
async fn an_approval_its_owner_would_co_sign_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    use zolana_ring_policy::{ListId, Member, OutflowLimit, Rule, RuleTable, Subject};
    let sender = keypair(1);
    let recipient = keypair(2);
    let owner = Address::new_from_array(sender.signing_pubkey().confidential_view_tag().unwrap());
    let limit = OutflowLimit::of(&Member::asset(&Mint::SOL.asset).unwrap()).with_cosign_above(1);
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build();
    // The deposit scope leaves the approval as the transfer's only demand.
    let settings = RingSettings {
        has_policy: true,
        co_signer: Some((owner, custom_ring_interface::CoSignScope::DEPOSITS)),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 1)]).with_mint(
                Mint::SOL.asset,
                zolana_ring_policy::MintPolicy {
                    cosign_above: limit.cosign_above,
                    ..Default::default()
                },
            ),
            &rules,
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction)
            .with_co_signer(owner)
            .assemble(&client)
            .await,
        Err(RingError::Program(CustomRingError::CoSignerIsOwner))
    ));
}

/// The transfer scope demands the co-signer on every transfer, an owner signer cannot be it.
#[tokio::test]
async fn a_scope_co_signer_among_the_owner_signers_is_refused_before_proving() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let recipient = keypair(2);
    let owner = Address::new_from_array(sender.signing_pubkey().confidential_view_tag().unwrap());
    let client = Chain::ring(RingSettings {
        co_signer: Some((owner, custom_ring_interface::CoSignScope::TRANSFERS)),
        ..RingSettings::new(RingMode::Confidential)
    })
    .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction)
            .with_co_signer(owner)
            .assemble(&client)
            .await,
        Err(RingError::Program(CustomRingError::CoSignerIsOwner))
    ));
}

/// The hidden owner signs for every spent note, a note of another owner fails both proofs.
#[tokio::test]
async fn an_anonymous_transfer_of_another_owners_utxo_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let other = &crate::tests::support::keypair(3);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let transaction = ring_transaction(vec![
        ring_utxo(sender, Mint::SOL, 10, 0),
        ring_utxo(other, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::MixedOwners { index: 1 })
    ));
}

/// A policy transfer spends one owner's notes, the program takes exactly one owner signer.
#[tokio::test]
async fn a_policy_transfer_of_two_owners_utxos_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    let sender = keypair(1);
    let other = keypair(2);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&other, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let transaction = ring_transaction(vec![
        ring_utxo(&sender, Mint::SOL, 10, 0),
        ring_utxo(&other, Mint::SOL, 10, 1),
    ]);
    assert!(matches!(
        owner_transfer(&sender, transaction).assemble(&client).await,
        Err(RingError::Program(CustomRingError::OwnerSignerCount))
    ));
}

/// The refusal of a recipient off the allow list names its rule and output.
#[tokio::test]
async fn a_recipient_the_rules_refuse_fails_before_proving() {
    use crate::tests::support::{keypair, Registry};
    use zolana_ring_policy::{RuleRefusal, TransferSubject};
    let sender = keypair(1);
    let recipient = keypair(2);
    let settings = RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 0)]),
            &crate::tests::pipeline_rules(),
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction).assemble(&client).await,
        Err(RingError::PolicyRuleUnsatisfied(RuleRefusal::Lists {
            rule: 1,
            subject: TransferSubject::Owner(0),
        }))
    ));
}

/// `UPDATE_PROVER_JSON=1` rewrites the shared pooled request Go solves and TS rebuilds.
#[tokio::test]
async fn the_member_policy_request_opens_each_subject_once_in_padded_pools() {
    use crate::tests::support::{keypair, Registry};
    let sender = keypair(1);
    let recipient = keypair(2);
    let settings = RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 1)]),
            &crate::tests::pipeline_rules(),
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    let assembled = owner_transfer(&sender, transaction)
        .assemble(&client)
        .await
        .unwrap();
    let request = assembled.policy_request().unwrap().unwrap();
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    let subjects = |pool: &str| -> Vec<String> {
        built[pool]
            .as_array()
            .unwrap()
            .iter()
            .map(|subject| subject["member"].as_str().unwrap().to_owned())
            .collect()
    };
    let own = subjects("ownSubjects");
    // The sender, the recipient and the asset, cycled to the pool width.
    assert_eq!(
        own[..3]
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(own
        .iter()
        .enumerate()
        .all(|(index, member)| *member == own[index % 3]));
    assert_eq!(built["ownRecords"].as_array().unwrap().len(), own.len());
    let name = built["circuitType"].as_str().unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/{name}.json"));
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measured {
    Confidential,
    ConfidentialPolicy,
    Anonymous,
    AnonymousPolicy,
    Delegate,
}

impl Measured {
    const COLUMNS: [Self; 5] = [
        Self::Confidential,
        Self::ConfidentialPolicy,
        Self::Anonymous,
        Self::AnonymousPolicy,
        Self::Delegate,
    ];

    /// A delegate moves only on a policy ring.
    fn policy(self) -> bool {
        !matches!(self, Self::Confidential | Self::Anonymous)
    }

    fn keyed(self, shape: spr_client::Shape) -> bool {
        let rail = match self {
            Self::Confidential | Self::ConfidentialPolicy => RingRail::Confidential,
            Self::Anonymous | Self::AnonymousPolicy => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        };
        shape_keyed(rail, shape)
    }
}

#[derive(Clone, Copy)]
enum Payer {
    Outsider,
    Owner,
}

impl Payer {
    fn address(self, owner: &ShieldedKeypair) -> Address {
        match self {
            Self::Outsider => crate::tests::support::payer(),
            Self::Owner => owner.shielded_address().unwrap().solana_address().unwrap(),
        }
    }
}

const MEASURED_CO_SIGNER: (Address, custom_ring_interface::CoSignScope) = (
    Address::new_from_array([0x46; 32]),
    custom_ring_interface::CoSignScope::TRANSFERS,
);

/// The transfer filling `shape`, every output but the change paying another member.
#[derive(Clone, Copy)]
struct Measure {
    rail: Measured,
    shape: spr_client::Shape,
    payer: Payer,
    co_signer: Option<(Address, custom_ring_interface::CoSignScope)>,
}

impl Measure {
    fn pinned(rail: Measured, shape: spr_client::Shape) -> Self {
        Self {
            rail,
            shape,
            payer: Payer::Outsider,
            co_signer: rail.policy().then_some(MEASURED_CO_SIGNER),
        }
    }

    async fn bytes(self) -> usize {
        use crate::tests::support::{keypair, Registry};
        let Self {
            rail,
            shape,
            payer,
            co_signer,
        } = self;
        let policy = rail.policy();
        let sender = keypair(1);
        let payer = payer.address(&sender);
        let recipients: Vec<ShieldedKeypair> = (0..shape.n_outputs() - 1)
            .map(|index| keypair(10 + index as u8))
            .collect();
        let utxos: Vec<WalletUtxo> = (0..shape.n_inputs() as u64)
            .map(|leaf| ring_utxo(&sender, Mint::SOL, 100, leaf))
            .collect();
        let delegate = Address::new_from_array([0x44; 32]);
        let mode = match rail {
            Measured::Anonymous | Measured::AnonymousPolicy => RingMode::Anonymous,
            Measured::ConfidentialPolicy | Measured::Delegate => RingMode::ConfidentialEscrow,
            Measured::Confidential => RingMode::Confidential,
        };
        let settings = RingSettings {
            has_policy: policy,
            co_signer,
            delegate: (rail == Measured::Delegate).then_some(delegate),
            ..RingSettings::new(mode)
        };
        let owners: Vec<(&ShieldedKeypair, u64)> = core::iter::once(&sender)
            .chain(&recipients)
            .map(|owner| (owner, 1))
            .collect();
        let chain = match policy {
            true => Chain::ring(settings)
                .with_registry(Registry::new(&owners), &crate::tests::pipeline_rules()),
            false => Chain::ring(settings),
        };
        let client = chain.client();
        let state = history(&sender);
        let assets = AssetRegistry::default();
        let size = FrameSize {
            client: &client,
            rail,
            shape,
            payer,
            co_signer: co_signer.map(|(signer, _)| signer),
        };
        match rail {
            Measured::Confidential | Measured::ConfidentialPolicy => {
                let mut transaction = paid_ring_transaction(utxos, payer);
                for recipient in &recipients {
                    transaction
                        .transfer_with_ring(
                            &recipient.shielded_address().unwrap(),
                            Mint::SOL,
                            1,
                            Some(ring().program_id()),
                        )
                        .unwrap();
                }
                size.of(owner_transfer(&sender, transaction)).await
            }
            Measured::Anonymous | Measured::AnonymousPolicy => {
                let mut transfer = owner_transfer(&sender, paid_ring_transaction(utxos, payer))
                    .with_anonymous_signer(&sender.signing_key, &state);
                for recipient in &recipients {
                    transfer = transfer
                        .with_payment(payment(&ring_address(recipient), 1))
                        .unwrap();
                }
                size.of(transfer).await
            }
            Measured::Delegate => {
                let transfer = DelegateTransfer::new(DelegateTransferInput {
                    ring: ring(),
                    delegate,
                    payer,
                    source: sender.shielded_address().unwrap(),
                    source_nullifier_key: &sender.nullifier_key,
                    inputs: utxos,
                    outputs: recipients
                        .iter()
                        .map(|recipient| DelegateOutput {
                            recipient: recipient.shielded_address().unwrap(),
                            asset: Mint::SOL.asset,
                            amount: 1,
                        })
                        .collect(),
                })
                .with_assets(&assets);
                size.of(transfer).await
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FrameSize<'c> {
    client: &'c RingClient<Chain, Chain>,
    rail: Measured,
    shape: spr_client::Shape,
    payer: Address,
    co_signer: Option<Address>,
}

impl FrameSize<'_> {
    /// A refusal past the v1 ceiling carries the bytes of the framed transfer.
    async fn of<R: Rail>(self, transfer: RingTransfer<R>) -> usize {
        let transfer = match self.co_signer {
            Some(signer) => transfer.with_co_signer(signer),
            None => transfer,
        };
        match transfer.frame(self.client).await {
            Ok(unwitnessed) => {
                assert_eq!(
                    unwitnessed.frame.proof_inputs.check_shape().unwrap(),
                    self.shape
                );
                spr_client::transaction_size(
                    &self.payer,
                    &[unwitnessed.instruction().unwrap()],
                    ComputeBudgetConfig::new(0),
                )
                .unwrap()
                .bytes
            }
            Err(RingError::TransactionTooLarge { bytes, .. }) => bytes,
            Err(error) => panic!("{:?} {:?}: {error}", self.rail, self.shape),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SizePin {
    n_in: usize,
    n_out: usize,
    /// One per [`Measured::COLUMNS`] entry, `None` for a shape the rail has no key for.
    bytes: [Option<usize>; Measured::COLUMNS.len()],
}

/// A policy ring demands its co-signer, a value past `MAX_TRANSACTION_SIZE` fails assembly.
const SIZE_PINS: [SizePin; 38] = [
    SizePin {
        n_in: 1,
        n_out: 2,
        bytes: [Some(1357), Some(1656), Some(1668), Some(2063), None],
    },
    SizePin {
        n_in: 1,
        n_out: 4,
        bytes: [Some(1693), Some(1928), Some(2370), Some(2765), None],
    },
    SizePin {
        n_in: 1,
        n_out: 8,
        bytes: [Some(2365), Some(2472), Some(3742), Some(4137), None],
    },
    SizePin {
        n_in: 2,
        n_out: 2,
        bytes: [Some(1422), Some(1721), Some(1765), Some(2160), Some(1721)],
    },
    SizePin {
        n_in: 2,
        n_out: 4,
        bytes: [Some(1758), Some(1993), Some(2467), Some(2862), None],
    },
    SizePin {
        n_in: 1,
        n_out: 16,
        bytes: [Some(3710), Some(3561), None, None, None],
    },
    SizePin {
        n_in: 2,
        n_out: 8,
        bytes: [Some(2430), Some(2537), Some(3839), Some(4234), None],
    },
    SizePin {
        n_in: 3,
        n_out: 2,
        bytes: [Some(1487), Some(1786), Some(1830), Some(2225), None],
    },
    SizePin {
        n_in: 3,
        n_out: 4,
        bytes: [Some(1823), Some(2058), Some(2532), Some(2927), None],
    },
    SizePin {
        n_in: 2,
        n_out: 16,
        bytes: [Some(3775), Some(3626), None, None, None],
    },
    SizePin {
        n_in: 3,
        n_out: 8,
        bytes: [Some(2495), Some(2602), Some(3904), Some(4299), None],
    },
    SizePin {
        n_in: 4,
        n_out: 2,
        bytes: [Some(1552), Some(1851), Some(1927), Some(2322), None],
    },
    SizePin {
        n_in: 4,
        n_out: 4,
        bytes: [Some(1888), Some(2123), Some(2629), Some(3024), Some(2123)],
    },
    SizePin {
        n_in: 4,
        n_out: 8,
        bytes: [Some(2560), Some(2667), Some(4001), Some(4396), None],
    },
    SizePin {
        n_in: 5,
        n_out: 2,
        bytes: [Some(1617), Some(1916), Some(1992), Some(2387), None],
    },
    SizePin {
        n_in: 5,
        n_out: 4,
        bytes: [Some(1953), Some(2188), Some(2694), Some(3089), None],
    },
    SizePin {
        n_in: 4,
        n_out: 16,
        bytes: [Some(3905), Some(3756), None, None, None],
    },
    SizePin {
        n_in: 5,
        n_out: 8,
        bytes: [Some(2625), Some(2732), Some(4066), Some(4461), None],
    },
    SizePin {
        n_in: 6,
        n_out: 2,
        bytes: [Some(1682), Some(1981), Some(2089), Some(2484), None],
    },
    SizePin {
        n_in: 6,
        n_out: 4,
        bytes: [Some(2018), Some(2253), Some(2791), Some(3186), None],
    },
    SizePin {
        n_in: 5,
        n_out: 16,
        bytes: [Some(3970), Some(3821), None, None, None],
    },
    SizePin {
        n_in: 6,
        n_out: 8,
        bytes: [Some(2690), Some(2797), Some(4163), Some(4558), None],
    },
    SizePin {
        n_in: 8,
        n_out: 2,
        bytes: [Some(1812), Some(2111), Some(2251), Some(2646), None],
    },
    SizePin {
        n_in: 8,
        n_out: 4,
        bytes: [Some(2148), Some(2383), Some(2953), Some(3348), None],
    },
    SizePin {
        n_in: 8,
        n_out: 8,
        bytes: [Some(2820), Some(2927), Some(4325), Some(4720), None],
    },
    SizePin {
        n_in: 8,
        n_out: 16,
        bytes: [Some(4165), Some(4016), None, None, None],
    },
    SizePin {
        n_in: 12,
        n_out: 2,
        bytes: [Some(2072), Some(2371), Some(2575), Some(2970), None],
    },
    SizePin {
        n_in: 12,
        n_out: 4,
        bytes: [Some(2408), Some(2643), Some(3277), Some(3672), None],
    },
    SizePin {
        n_in: 12,
        n_out: 8,
        bytes: [Some(3080), Some(3187), None, None, None],
    },
    SizePin {
        n_in: 16,
        n_out: 2,
        bytes: [Some(2332), Some(2631), Some(2899), Some(3294), None],
    },
    SizePin {
        n_in: 16,
        n_out: 4,
        bytes: [Some(2668), Some(2903), Some(3601), Some(3996), None],
    },
    SizePin {
        n_in: 16,
        n_out: 8,
        bytes: [Some(3340), Some(3447), None, None, None],
    },
    SizePin {
        n_in: 24,
        n_out: 2,
        bytes: [Some(2852), Some(3151), None, None, None],
    },
    SizePin {
        n_in: 24,
        n_out: 4,
        bytes: [Some(3188), Some(3423), None, None, None],
    },
    SizePin {
        n_in: 32,
        n_out: 2,
        bytes: [Some(3372), Some(3671), None, None, None],
    },
    SizePin {
        n_in: 40,
        n_out: 2,
        bytes: [Some(3892), Some(4191), None, None, None],
    },
    SizePin {
        n_in: 48,
        n_out: 2,
        bytes: [Some(4412), Some(4711), None, None, None],
    },
    SizePin {
        n_in: 49,
        n_out: 2,
        bytes: [None, None, None, None, None],
    },
];

/// The program cannot depend on the SDK's ciphertexts, the SDK pins the sizes.
#[tokio::test]
async fn every_transfer_shape_takes_its_pinned_transaction_size() {
    let mut measured = Vec::new();
    for shape in spr_client::SPP_SUPPORTED_SHAPES {
        let mut bytes = [None; Measured::COLUMNS.len()];
        for (rail, slot) in Measured::COLUMNS.into_iter().zip(&mut bytes) {
            if rail.keyed(shape) {
                *slot = Some(Measure::pinned(rail, shape).bytes().await);
            }
        }
        measured.push(SizePin {
            n_in: shape.n_inputs(),
            n_out: shape.n_outputs(),
            bytes,
        });
    }
    let table: String = measured
        .iter()
        .map(|SizePin { n_in, n_out, bytes }| {
            format!("    SizePin {{ n_in: {n_in}, n_out: {n_out}, bytes: {bytes:?} }},\n")
        })
        .collect();
    assert_eq!(measured, SIZE_PINS, "measured:\n{table}");
}

#[tokio::test]
async fn a_confidential_ring_fits_its_widest_shapes_only_when_the_owner_pays() {
    let fits = |measure: Measure| async move {
        measure.bytes().await <= solana_message::v1::MAX_TRANSACTION_SIZE
    };
    let audit_only = Measure {
        rail: Measured::Confidential,
        shape: spr_client::Shape::IN8_OUT16,
        payer: Payer::Owner,
        co_signer: None,
    };
    assert!(fits(audit_only).await);
    assert!(
        !fits(Measure {
            payer: Payer::Outsider,
            ..audit_only
        })
        .await
    );
    let policy = Measure {
        rail: Measured::ConfidentialPolicy,
        shape: spr_client::Shape::IN40_OUT2,
        co_signer: Some(MEASURED_CO_SIGNER),
        ..audit_only
    };
    assert!(fits(policy).await);
    assert!(
        !fits(Measure {
            payer: Payer::Outsider,
            ..policy
        })
        .await
    );
}

/// The transfers scope demands the co-signer on every move.
#[tokio::test]
async fn a_delegate_its_own_co_signer_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        co_signer: Some((delegate, custom_ring_interface::CoSignScope::TRANSFERS)),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&member, 1), (&recipient, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let assets = AssetRegistry::default();
    let transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate,
        payer: delegate,
        source: member.shielded_address().unwrap(),
        source_nullifier_key: &member.nullifier_key,
        inputs: vec![ring_utxo(&member, Mint::SOL, 10, 0)],
        outputs: vec![DelegateOutput {
            recipient: recipient.shielded_address().unwrap(),
            asset: Mint::SOL.asset,
            amount: 3,
        }],
    })
    .with_assets(&assets)
    .with_shape(spr_client::Shape::IN2_OUT2)
    .unwrap();
    assert!(matches!(
        transfer.with_co_signer(delegate).assemble(&client).await,
        Err(RingError::Program(CustomRingError::CoSignerIsDelegate))
    ));
}

#[tokio::test]
async fn an_anonymous_deposit_leg_another_key_funds_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let stage = |funder: Address| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.deposit_sol(5, funder).unwrap();
        owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: funder },
            )])
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&paid, 4))
            .unwrap()
    };
    let chain = Chain::ring(anonymous());
    assert!(
        stage_anonymous(&stage(crate::tests::support::payer()), &chain)
            .await
            .is_ok()
    );
    assert!(matches!(
        stage_anonymous(&stage(Address::new_from_array([0x66; 32])), &chain).await,
        Err(RingError::Program(CustomRingError::InvalidAnonymousSigner))
    ));
}

#[test]
fn a_payment_total_past_a_u64_is_refused() {
    assert!(matches!(
        super::selection::payment_total([u64::MAX, 1]),
        Err(RingError::PaymentOverflow)
    ));
}

#[tokio::test]
async fn audit_only_withdrawal_exemptions_use_records_and_gross_totals() {
    use crate::tests::support::Registry;
    use custom_ring_interface::{CoSignScope, PublicLeg};
    use spr_interface::instruction::InterfaceTransfer;
    use zolana_ring_policy::{MintPolicy, RuleTable};
    let mut registry = Registry::new(&[]);
    for i in 1..=12 {
        registry = registry.with_mint(
            Address::new_from_array([i; 32]),
            MintPolicy {
                withdrawal_threshold: 100,
                ..MintPolicy::EMPTY
            },
        );
    }
    let chain = Chain::ring(RingSettings {
        co_signer: Some((Address::new_from_array([77; 32]), CoSignScope::WITHDRAWALS)),
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(registry, &RuleTable::empty());
    let config = ring().require_config(&chain).await.unwrap();
    let leg = |amount| PublicLeg {
        transfer: InterfaceTransfer::SplWithdrawal {
            spl_interface_bump: 0,
            amount,
        },
        mint: Some([9; 32]),
    };
    let demand = CoSignDemand::transact(false, &[leg(40), leg(60)]);
    let exemption = withdrawals::Exemption::read(ring(), &config, &demand, None, &chain)
        .await
        .unwrap();
    assert!(
        exemption.is_some(),
        "ninth mint at its threshold is exempt on an audit-only ring"
    );
    let demand = CoSignDemand::transact(
        false,
        &[
            leg(60),
            leg(60),
            PublicLeg {
                transfer: InterfaceTransfer::SplDeposit {
                    spl_interface_bump: 0,
                    amount: 100,
                },
                mint: Some([9; 32]),
            },
        ],
    );
    assert!(
        withdrawals::Exemption::read(ring(), &config, &demand, None, &chain)
            .await
            .unwrap()
            .is_none(),
        "deposits never offset gross withdrawals"
    );
    let demand = CoSignDemand::transact(
        false,
        &[PublicLeg {
            transfer: InterfaceTransfer::SplWithdrawal {
                spl_interface_bump: 0,
                amount: 1,
            },
            mint: Some([13; 32]),
        }],
    );
    assert!(
        withdrawals::Exemption::read(ring(), &config, &demand, None, &chain)
            .await
            .unwrap()
            .is_none(),
        "missing records still require the co-signer"
    );
}
