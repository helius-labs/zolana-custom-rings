use super::*;
use custom_ring_interface::{tag, RingRail, RingTransactData};

const AMOUNT: u64 = 100_000_000;

/// A batch deposit is a transfer frame that spends no note.
#[test]
fn an_sdk_batch_deposit_settles_through_a_transfer() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    enroll_actors(&env, ring)?;
    let recipients = [
        env.sender.keypair.shielded_address()?,
        env.recipient.keypair.shielded_address()?,
    ];
    let client = env.client.ring_client();
    for notes in [3_usize, 5] {
        let batch = custom_ring_sdk::RingDepositBatch {
            ring,
            payer: &env.payer,
            tree: env.tree,
            outputs: (0..notes)
                .map(|slot| custom_ring_sdk::DepositOutput {
                    recipient: DepositRecipient::Confidential(recipients[slot % 2]),
                    asset: DepositAsset::Sol,
                    amount: AMOUNT,
                    list_salt: None,
                })
                .collect(),
            cosigner: None,
        };
        let prepared = env.run(batch.prepare(client.zolana()))?;
        let instruction = env.run(prepared.prove(client))?;
        let (frame_tag, frame) = instruction
            .data
            .split_first()
            .context("an empty deposit instruction")?;
        ensure!(
            *frame_tag == tag::TRANSFER,
            "a deposit under tag {frame_tag}"
        );
        let parsed = RingTransactData::parse(frame, RingRail::Confidential)?;
        let data = parsed.data();
        ensure!(data.no_spend, "the deposit spent a note");
        ensure!(
            data.outputs.len() >= notes,
            "{notes} notes in {} outputs",
            data.outputs.len()
        );
        let tree_before = fetch_account(env.client.rpc(), &env.tree)?;
        send(env.client.rpc(), &env.payer, &[instruction])?;
        ensure!(
            fetch_account(env.client.rpc(), &env.tree)?.data != tree_before.data,
            "the {notes} note batch did not change the tree"
        );
    }
    Ok(())
}
