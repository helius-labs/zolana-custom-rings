//! Two rings share one member registry on localnet + photon + prover. The
//! subscriber's Block list reads the curator ring's registry, so one curator
//! write refuses the subscriber's transfer, and clearing the bit or re-pointing
//! the source re-admits it.

use anyhow::Result;
use custom_ring_interface::CustomRingError;
use custom_ring_sdk::{DepositAsset, ListRegistry, SourceOwner};
use custom_ring_test_validator::{
    policy::{
        owner_member, policy_registry, CuratedRings, PolicyTransfer, RegistryWrite, RingNotes,
        BLOCK_ONLY, DEPOSIT, TRANSFER_AMOUNT,
    },
    ring_rpc::RingRpcSpec,
    shared::{send, ExpectRejection, RegisterRing, Tier},
};
use solana_signer::Signer;
use spr_keypair::X25519Keypair;
use spr_program_test::Rejection;
use spr_transaction::Utxo;
use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

#[test]
fn a_curator_sourced_blocklist_governs_the_subscriber_ring() -> Result<()> {
    let rings = CuratedRings::setup()?;
    let CuratedRings {
        ref env,
        curator,
        subscriber,
    } = rings;
    let rpc = env.client.rpc();
    let authority = env.payer.pubkey();
    let transfer = |note: &Utxo| PolicyTransfer {
        ring: subscriber,
        sender: &env.sender.keypair,
        recipient: &env.recipient.keypair,
        note: note.clone(),
        amount: TRANSFER_AMOUNT,
        env,
    };

    // 1. The subscriber pins behind the curator's pin, its Block slot names
    //    the curator's member registry, and it registers with SPP only behind
    //    its own pin.
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring: subscriber,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::Policy {
            rules: &BLOCK_ONLY,
            shared_sources: vec![(ListId::Block, curator)],
        },
    }
    .send(&env.client)?;
    custom_ring_test_validator::policy::enroll_actors(env, subscriber)?;
    let _ring_rpc = RingRpcSpec {
        env,
        ring: subscriber.program_id(),
        auditor,
    }
    .serve()?;
    let stored = policy_registry(subscriber, env)?;
    assert_eq!(
        stored.registry_for(ListId::Block),
        Some(ListRegistry::Curator(
            policy_registry(curator, env)?.records
        )),
        "the Block slot names the curator registry"
    );
    assert_eq!(stored.generation(), 1);

    // 2. Three subscriber-ring notes, one transfer per policy phase.
    let notes = RingNotes {
        ring: subscriber,
        owner: &env.sender.keypair,
        amount: DEPOSIT,
        asset: DepositAsset::Sol,
        count: 3,
        env,
    }
    .deposit()?;

    // 3. The curator registry holds no member yet, the transfer passes on
    //    the absence proof against it.
    transfer(&notes[0]).land()?;

    // 4. One curator write refuses the next transfer before proving.
    let member = owner_member(&env.recipient.keypair)?;
    let curator_block = |present| {
        RegistryWrite {
            ring: curator,
            list_id: ListId::Block,
            member,
            present,
            env,
        }
        .send()
    };
    curator_block(true)?;
    transfer(&notes[1]).expect_refusal()?;

    // 5. Clearing the bit re-admits the refused note, an unrelated deposit
    //    moves the state root between the record read and the proof.
    curator_block(false)?;
    RingNotes {
        ring: subscriber,
        owner: &env.sender.keypair,
        amount: DEPOSIT,
        asset: DepositAsset::Sol,
        count: 1,
        env,
    }
    .deposit()?;
    transfer(&notes[1]).land()?;

    // 6. With the bit set again, re-pointing Block to the subscriber's own
    //    registry turns curator enforcement off.
    curator_block(true)?;
    send(
        rpc,
        &env.payer,
        &[custom_ring_sdk::UpdatePolicy {
            ring: subscriber,
            authority,
            current: &*policy_registry(subscriber, env)?,
            update: custom_ring_sdk::PolicyUpdate::Source {
                list_id: ListId::Block,
                source: SourceOwner::Own,
            },
        }
        .instruction()?],
    )?;
    let repointed = policy_registry(subscriber, env)?;
    assert_eq!(
        repointed.registry_for(ListId::Block),
        Some(ListRegistry::Own),
        "the Block slot is back on the subscriber registry"
    );
    assert_eq!(repointed.generation(), 2, "a re-point counts a generation");
    assert!(repointed.generation_slot() > stored.generation_slot());
    transfer(&notes[2]).land()?;

    Ok(())
}

const PRIVATE_BLOCK_ONLY: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::OutputOwner, ListId::PrivateBlock))
    .build();

/// A private list read through another ring's records pins that ring's tracking registry, a
/// subscriber's floor would count the wrong registry's revisions.
#[test]
fn a_private_list_on_another_rings_records_is_refused() -> Result<()> {
    let rings = CuratedRings::setup()?;
    let CuratedRings {
        ref env,
        curator,
        subscriber,
    } = rings;
    RegisterRing {
        ring: subscriber,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::Policy {
            rules: &PRIVATE_BLOCK_ONLY,
            shared_sources: Vec::new(),
        },
    }
    .send(&env.client)?;
    let current = policy_registry(subscriber, env)?;
    let foreign = policy_registry(curator, env)?.records;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[custom_ring_sdk::UpdatePolicy {
            ring: subscriber,
            authority: env.payer.pubkey(),
            current: &current,
            update: custom_ring_sdk::PolicyUpdate::Source {
                list_id: ListId::PrivateBlock,
                source: SourceOwner::Curator(foreign),
            },
        }
        .instruction()?],
    }
    .send(env.client.rpc())?;
    Rejection::custom(CustomRingError::SaltedSourceOtherTracking as u32)
        .at(0)
        .assert_client(&rejection);
    assert_eq!(
        policy_registry(subscriber, env)?.registry_for(ListId::PrivateBlock),
        Some(ListRegistry::Own),
        "a refused write leaves the stored account"
    );
    Ok(())
}
