//! A SOL withdrawal within the asset record's threshold needs no co-signer.

use super::*;
use custom_ring_interface::{cosign::ApprovalMask, storage::Revision, RootRead};
use custom_ring_sdk::{live_registry, SetCoSigner};
use spr_program::instruction::TransactSolTransferAccounts;
use spr_test_utils::test_validator_asserts::assert_optional_account_unchanged;
use zolana_ring_policy::MintPolicy;

const NOTE: u64 = 1_000_000_000;
const THRESHOLD: u64 = 300_000_000;
const PAYMENT: u64 = 100_000_000;
const OFFSET: u64 = 20_000_000;
/// Rent-exempt before the first withdrawal lands on it.
const DESTINATION_FUNDING: u64 = 1_000_000;
const INDEXING_DEADLINE: Duration = Duration::from_secs(90);

struct ExemptRing<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    auditor: X25519Keypair,
    mode: RingMode,
    cosigner: Keypair,
    destination: Address,
    policy: bool,
}

struct Withdrawal {
    amount: u64,
    deposit: Option<u64>,
    cosigner: bool,
}

impl<'a> ExemptRing<'a> {
    fn configure(env: &'a TestEnv, tier: Tier) -> Result<Self> {
        let policy = matches!(tier, Tier::Policy { .. });
        let ring = CustomRing::new(custom_ring_program_id()?);
        let auditor = X25519Keypair::new();
        RegisterRing {
            ring,
            payer: &env.payer,
            auditor_pubkey: auditor.pubkey(),
            tier,
        }
        .send(&env.client)?;
        enroll_actors(env, ring)?;
        let cosigner = env.funded_keypair()?;
        let cosign_admin = RingRoleKeys::of(&env.payer).cosign_admin;
        SendAs {
            rpc: env.client.rpc(),
            payer: &env.payer,
            holder: &cosign_admin,
        }
        .send(&[SetCoSigner {
            ring,
            payer: env.payer.pubkey(),
            authority: cosign_admin.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::APPROVE_WITHDRAWAL,
        }
        .instruction()?])?;
        let destination = Keypair::new().pubkey();
        env.fund(destination, DESTINATION_FUNDING)?;
        let mode = env.run(ring.require_config(env.client.as_async()))?.mode;
        let ring = Self {
            env,
            ring,
            auditor,
            mode,
            cosigner,
            destination,
            policy,
        };
        ring.set_threshold(THRESHOLD)?;
        Ok(ring)
    }

    /// Writes the SOL record's threshold, the registry's revision once written.
    fn set_threshold(&self, threshold: u64) -> Result<Revision> {
        StorageRecords::mint_policy(
            self.ring,
            Member::asset(&SOL_MINT)?,
            MintPolicy {
                withdrawal_threshold: threshold,
                ..Default::default()
            },
            self.env,
        )
        .send()?;
        self.revision()
    }

    fn records(&self) -> Result<Address> {
        Ok(policy_registry(self.ring, self.env)?.records)
    }

    fn revision(&self) -> Result<Revision> {
        let registry = self
            .env
            .run(live_registry(self.records()?, self.env.client.as_async()))?;
        Ok(registry.newest().revision)
    }

    fn note(&self) -> Result<WalletUtxo> {
        let env = self.env;
        let notes = RingNotes {
            ring: self.ring,
            owner: &env.sender.keypair,
            amount: NOTE,
            asset: DepositAsset::Sol,
            count: 1,
            env,
        }
        .deposit_from(&env.payer)?;
        let [utxo] =
            <[Utxo; 1]>::try_from(notes).map_err(|notes| anyhow!("{} notes", notes.len()))?;
        indexed_note(utxo, &env.sender.keypair, env, env.tree)
    }

    fn prove(
        &self,
        note: &WalletUtxo,
        withdrawal: &Withdrawal,
    ) -> Result<Result<ProvenRingTransfer, RingError>> {
        let env = self.env;
        let sender = &env.sender.keypair;
        let recipient = env.recipient.keypair.shielded_address()?;
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![note.clone()],
            sender.pubkey(),
            self.ring.program_id(),
        )?;
        transaction.transfer_sol(&recipient, PAYMENT)?;
        let mut settlements =
            vec![transaction.withdraw_to(SOL_MINT, withdrawal.amount, self.destination, None)?];
        if let Some(amount) = withdrawal.deposit {
            transaction.deposit_sol(amount, sender.pubkey())?;
            settlements.push(TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: sender.pubkey(),
                },
            ));
        }
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(settlements);
        let transfer = match withdrawal.cosigner {
            true => transfer.with_co_signer(self.cosigner.pubkey()),
            false => transfer,
        };
        Ok(env.run(transfer.prove(env.client.ring_client())))
    }

    /// A record write lands ahead of the index the empty mask reads.
    fn prove_exempt(&self, note: &WalletUtxo, amount: u64) -> Result<ProvenRingTransfer> {
        let withdrawal = Withdrawal {
            amount,
            deposit: None,
            cosigner: false,
        };
        let deadline = std::time::Instant::now() + INDEXING_DEADLINE;
        loop {
            match self.prove(note, &withdrawal)? {
                Ok(proven) => return Ok(proven),
                Err(error) if std::time::Instant::now() >= deadline => {
                    return Err(error).context("the SOL record was not indexed in time")
                }
                Err(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    fn altered(
        &self,
        proven: &ProvenRingTransfer,
        edit: impl FnOnce(&mut RingTransactData<'_>),
    ) -> Result<Instruction> {
        let instruction = proven.instruction()?;
        let (tag, body) = instruction
            .data
            .split_first()
            .context("a tagged ring instruction")?;
        let mut data = RingTransactData::parse(body, RingRail::Confidential)?.into_data();
        edit(&mut data);
        let data = std::iter::once(*tag).chain(data.encode()?).collect();
        Ok(Instruction {
            data,
            ..instruction.clone()
        })
    }

    /// The co-signer slot sits after the ring account and its registries.
    fn co_signer_slot(&self) -> Result<usize> {
        let policy = policy_registry(self.ring, self.env)?;
        Ok(1 + policy
            .root_registries(RootRead::transfer(&policy, false))
            .count())
    }

    fn forged_exemption(&self, proven: &ProvenRingTransfer) -> Result<Instruction> {
        let mut instruction = self.altered(proven, |data| {
            data.approval = ApprovalMask::default();
        })?;
        let metas = self.ring.co_signer_metas(self.cosigner.pubkey());
        instruction
            .accounts
            .retain(|meta| metas.iter().all(|dropped| dropped.pubkey != meta.pubkey));
        Ok(instruction)
    }

    fn cleared_exemption(&self, proven: &ProvenRingTransfer) -> Result<Instruction> {
        let mut instruction = self.altered(proven, |data| {
            data.approval = ApprovalMask::WITHDRAWAL;
        })?;
        let slot = self.co_signer_slot()?;
        for (offset, meta) in self
            .ring
            .co_signer_metas(self.cosigner.pubkey())
            .into_iter()
            .enumerate()
        {
            instruction.accounts.insert(slot + offset, meta);
        }
        Ok(instruction)
    }

    /// `instruction` fails with `error`, the destination, the tree and the spent note stay as they were.
    fn refused(
        &self,
        instruction: Instruction,
        signers: &[&dyn Signer],
        error: CustomRingError,
        nullifier: &[u8; 32],
    ) -> Result<()> {
        let rpc = self.env.client.rpc();
        let nullifier_pda = pda::nullifier_pda(&self.env.tree, nullifier).0;
        let destination = fetch_account(rpc, &self.destination)?;
        let tree = fetch_account(rpc, &self.env.tree)?;
        let rejection = RejectedTransact {
            payer: &self.env.sender.keypair,
            signers,
            instruction,
        }
        .send(rpc)?;
        Rejection::custom(error as u32)
            .at(0)
            .assert_client(&rejection);
        assert_account_unchanged(rpc, &self.destination, &destination)?;
        assert_account_unchanged(rpc, &self.env.tree, &tree)?;
        assert_optional_account_unchanged(rpc, &nullifier_pda, &None)?;
        Ok(())
    }

    /// `proven` settles, the destination gains the withdrawal and the auditor opens the payment and the change.
    fn landed(
        &self,
        proven: &ProvenRingTransfer,
        signers: &[&(dyn Signer + Sync)],
        withdrawal: &Withdrawal,
    ) -> Result<()> {
        let env = self.env;
        let rpc = env.client.rpc();
        let before = fetch_account(rpc, &self.destination)?.lamports;
        let signature = land(env, proven.instruction()?, &env.sender.keypair, signers)?;
        assert_eq!(
            fetch_account(rpc, &self.destination)?.lamports,
            before + withdrawal.amount,
            "destination after the withdrawal"
        );
        let audited = AuditLookup {
            scan: RingScan::new(self.ring.program_id(), self.auditor.pubkey()).with_mode(self.mode),
            auditor: &self.auditor,
            signature,
        }
        .run(env)?;
        let mut amounts: Vec<u64> = opened(&audited)
            .iter()
            .map(|output| output.amount)
            .collect();
        amounts.sort_unstable();
        let mut expected = vec![
            PAYMENT,
            NOTE - PAYMENT - withdrawal.amount + withdrawal.deposit.unwrap_or(0),
        ];
        expected.sort_unstable();
        assert_eq!(amounts, expected, "audited ring outputs");
        Ok(())
    }

    /// The proof binds the mask, the revision and every leg.
    fn within_threshold(&self) -> Result<()> {
        let note = self.note()?;
        let proven = self.prove_exempt(&note, THRESHOLD)?;
        assert_eq!(
            proven.co_signers,
            Vec::new(),
            "an empty mask demands no co-signer"
        );
        let instruction = proven.instruction()?;
        let data = frame(&instruction, RingRail::Confidential)?;
        assert!(data.approval.is_empty());
        let revision = data
            .own_revision
            .context("a frame under a threshold names the own revision")?;
        assert_eq!(data.policy.is_some(), self.policy);
        let nullifier = data.nullifiers[0];
        let altered_leg = self.altered(&proven, |data| {
            data.interface_transfers[0] = InterfaceTransfer::SolWithdrawal {
                amount: THRESHOLD - 1,
            };
        })?;
        self.refused(
            altered_leg,
            &[],
            CustomRingError::ProofVerificationFailed,
            &nullifier,
        )?;
        self.refused(
            self.cleared_exemption(&proven)?,
            &[&self.cosigner],
            CustomRingError::ProofVerificationFailed,
            &nullifier,
        )?;
        // A lower threshold is restrictive, its write retires the root the proof opened at once.
        let next = self.set_threshold(THRESHOLD - 1)?;
        assert_ne!(next, revision, "a record write moves the revision");
        self.refused(
            self.altered(&proven, |data| data.own_revision = Some(next))?,
            &[],
            CustomRingError::ProofVerificationFailed,
            &nullifier,
        )?;
        self.refused(
            proven.instruction()?,
            &[],
            CustomRingError::RootNotServed,
            &nullifier,
        )?;
        let proven = self.prove_exempt(&note, THRESHOLD - 1)?;
        let instruction = proven.instruction()?;
        assert_eq!(
            frame(&instruction, RingRail::Confidential)?.own_revision,
            Some(next),
            "a new proof opens the newest root"
        );
        let withdrawal = Withdrawal {
            amount: THRESHOLD - 1,
            deposit: None,
            cosigner: false,
        };
        self.landed(&proven, &[], &withdrawal)
    }

    fn past_threshold(&self) -> Result<()> {
        let note = self.note()?;
        let mut withdrawal = Withdrawal {
            amount: THRESHOLD + 1,
            deposit: None,
            cosigner: false,
        };
        match self.prove(&note, &withdrawal)?.map(drop) {
            Err(RingError::Program(CustomRingError::MissingCoSigner)) => {}
            other => bail!("expected the co-signer demand, got {other:?}"),
        }
        withdrawal.cosigner = true;
        let proven = self.prove(&note, &withdrawal)??;
        assert_eq!(
            proven.co_signers.first().copied(),
            Some(self.cosigner.pubkey())
        );
        let instruction = proven.instruction()?;
        let data = frame(&instruction, RingRail::Confidential)?;
        assert_eq!(data.approval, ApprovalMask::WITHDRAWAL);
        let nullifier = data.nullifiers[0];
        self.refused(
            self.forged_exemption(&proven)?,
            &[],
            CustomRingError::ProofVerificationFailed,
            &nullifier,
        )?;
        self.refused(
            without_signer(instruction, self.cosigner.pubkey()),
            &[],
            CustomRingError::MissingCoSigner,
            &nullifier,
        )?;
        self.landed(&proven, &[&self.cosigner], &withdrawal)
    }

    /// A deposit of the same mint lowers the net and never the gross.
    fn deposit_offsets_no_gross(&self) -> Result<()> {
        let note = self.note()?;
        let withdrawal = Withdrawal {
            amount: THRESHOLD + OFFSET,
            deposit: Some(2 * OFFSET),
            cosigner: true,
        };
        let proven = self.prove(&note, &withdrawal)??;
        assert_eq!(
            proven.co_signers.first().copied(),
            Some(self.cosigner.pubkey())
        );
        let instruction = proven.instruction()?;
        let data = frame(&instruction, RingRail::Confidential)?;
        assert_eq!(data.approval, ApprovalMask::WITHDRAWAL);
        let nullifier = data.nullifiers[0];
        self.refused(
            self.forged_exemption(&proven)?,
            &[],
            CustomRingError::ProofVerificationFailed,
            &nullifier,
        )?;
        self.landed(&proven, &[&self.cosigner], &withdrawal)
    }
}

fn exempt_withdrawals(tier: Tier) -> Result<()> {
    let env = setup()?;
    let ring = ExemptRing::configure(&env, tier)?;
    ring.within_threshold()?;
    ring.past_threshold()?;
    ring.deposit_offsets_no_gross()
}

#[test]
fn an_exempt_withdrawal_settles_without_the_co_signer_on_a_policy_ring() -> Result<()> {
    exempt_withdrawals(Tier::policy(&EMPTY))
}

#[test]
fn an_exempt_withdrawal_settles_without_the_co_signer_on_an_audit_only_ring() -> Result<()> {
    exempt_withdrawals(Tier::AuditOnly)
}
