//! Every transfer shape of the five basic rails settles or is refused before proving as too large.
//! Registry sources and withdrawal/batch capacities have separate circuit and verifier tests.

use super::*;
use custom_ring_interface::{
    key_catalog::{RingCircuit, RING_KEYS},
    ParsedTransact, ANONYMOUS_ENTRY_OUTPUTS, MERGE_WIDTHS,
};
use custom_ring_test_validator::{policy::RingNotes, shared::restart_prover};
use spr_client::{Shape, SPP_SUPPORTED_SHAPES};

const UTXO_AMOUNT: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    Confidential,
    ConfidentialPolicy,
    Anonymous,
    AnonymousPolicy,
    Delegate,
}

impl Column {
    fn tier(self) -> Tier {
        match self {
            Self::Confidential => Tier::AuditOnly,
            Self::ConfidentialPolicy | Self::Delegate => Tier::policy(&EMPTY),
            Self::Anonymous => Tier::AnonymousAuditOnly,
            Self::AnonymousPolicy => Tier::anonymous_policy(&EMPTY),
        }
    }

    fn rail(self) -> RingRail {
        match self {
            Self::Confidential | Self::ConfidentialPolicy => RingRail::Confidential,
            Self::Anonymous | Self::AnonymousPolicy => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        }
    }

    /// The widest shapes a spend padded to its full published width still fits.
    const fn widest(self) -> &'static [Shape] {
        match self {
            Self::Anonymous => &[Shape::IN16_OUT2, Shape::IN16_OUT4, Shape::IN5_OUT8],
            Self::AnonymousPolicy => &[Shape::IN16_OUT2, Shape::IN16_OUT4],
            Self::Confidential | Self::ConfidentialPolicy | Self::Delegate => &[],
        }
    }

    fn keyed(self, shape: Shape) -> bool {
        custom_ring_sdk::shape_keyed(self.rail(), shape)
    }
}

#[derive(Default)]
struct Coverage {
    circuits: Vec<RingCircuit>,
}

impl Coverage {
    fn cover(&mut self, circuit: RingCircuit) {
        if !self.circuits.contains(&circuit) {
            self.circuits.push(circuit);
        }
    }

    fn assert_transfer_keys(&self, column: Column) {
        let missing: Vec<RingCircuit> = RING_KEYS
            .iter()
            .map(|key| key.circuit)
            .filter(|circuit| match circuit {
                RingCircuit::MemberPolicy {
                    withdrawals,
                    own_only,
                    ..
                } => *withdrawals == 0 && *own_only,
                RingCircuit::DelegatePolicy { own_only, .. } => *own_only,
                RingCircuit::Deposit { capacity } => *capacity == 1,
                RingCircuit::ApplyRecords { writes } => matches!(writes, 1 | 2),
                // Threshold exemptions are covered by the withdrawal controls suite.
                RingCircuit::WithdrawalExemption => false,
                _ => true,
            })
            // Each required key belongs to one independently runnable sweep.
            .filter(|circuit| {
                let owner = match circuit {
                    RingCircuit::DeliveredAudit { .. } | RingCircuit::Deposit { .. } => {
                        Column::Confidential
                    }
                    RingCircuit::AnonymousAudit { .. }
                    | RingCircuit::AnonymousEntryAudit { .. }
                    | RingCircuit::Merge { .. } => Column::Anonymous,
                    RingCircuit::MemberPolicy { .. }
                    | RingCircuit::RegisterKey
                    | RingCircuit::WithdrawalExemption => Column::ConfidentialPolicy,
                    RingCircuit::ApplyRecords { writes: 1 } => Column::ConfidentialPolicy,
                    RingCircuit::ApplyRecords { .. } | RingCircuit::DelegatePolicy { .. } => {
                        Column::Delegate
                    }
                };
                owner == column
            })
            .filter(|circuit| !self.circuits.contains(circuit))
            .collect();
        assert!(missing.is_empty(), "no landed operation proved {missing:?}");
        assert!(self
            .circuits
            .iter()
            .all(|circuit| RING_KEYS.iter().any(|key| key.circuit == *circuit)));
    }
}

struct ShapeTransfer {
    shape: Shape,
    inputs: Vec<WalletUtxo>,
}

enum Proven {
    Transfer(Box<ProvenRingTransfer>),
    TooLarge { bytes: usize },
}

enum Settlement {
    Settled,
    TooLarge,
}

#[must_use]
struct ColumnSetup<'a> {
    env: &'a TestEnv,
    column: Column,
    program: Address,
}

struct ShapeRing<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    column: Column,
    auditor: X25519Keypair,
    /// Signs and pays every move of the delegate rail.
    delegate: Keypair,
    mode: RingMode,
    /// The anonymous sender's history, advanced past every proven transfer.
    sender: std::cell::RefCell<ViewingHistory>,
    escrowed: HashMap<[u8; 32], [u8; 32]>,
}

impl<'a> ColumnSetup<'a> {
    fn configure(self, coverage: &mut Coverage) -> Result<ShapeRing<'a>> {
        let env = self.env;
        let ring = CustomRing::new(self.program);
        let auditor = X25519Keypair::new();
        RegisterRing {
            ring,
            payer: &env.payer,
            auditor_pubkey: auditor.pubkey(),
            tier: self.column.tier(),
        }
        .send(&env.client)?;
        let delegate = env.funded_keypair()?;
        let members = [&env.sender.keypair, &env.recipient.keypair];
        let queue = QueueHead { env, ring };
        let applied = match self.column {
            Column::ConfidentialPolicy => Some(queue.applied_by(|| {
                register_key(env, ring, &env.sender.keypair)?;
                Queued::now(&env.client, ring)?.apply(&env.client, &env.payer)
            })?),
            Column::Delegate => {
                let applied = queue.applied_by(|| {
                    EscrowedDelegate {
                        ring,
                        delegate: &delegate,
                        members: &members,
                    }
                    .set(env)
                })?;
                env.enable_authority_rail(ring)?;
                Some(applied)
            }
            Column::Confidential | Column::Anonymous | Column::AnonymousPolicy => None,
        };
        if let Some(applied) = applied {
            coverage.cover(RingCircuit::RegisterKey);
            coverage.cover(RingCircuit::apply_records(applied));
        }
        let config = env.run(ring.require_config(env.client.as_async()))?;
        let escrowed = match config.mode {
            RingMode::ConfidentialEscrow => members
                .into_iter()
                .map(|member| {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
                    let nullifier_pk = loop {
                        match env
                            .member_record(ring, owner_member(member)?)
                            .and_then(|read| {
                                read.nullifier_pk
                                    .context("the member's record escrows no nullifier key")
                            }) {
                            Ok(key) => break key,
                            Err(error) if std::time::Instant::now() >= deadline => {
                                return Err(error).context("member escrow was not indexed in time")
                            }
                            Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
                        }
                    };
                    Ok((
                        member.signing_pubkey().confidential_view_tag()?,
                        nullifier_pk,
                    ))
                })
                .collect::<Result<_>>()?,
            RingMode::Confidential | RingMode::Anonymous => HashMap::new(),
        };
        Ok(ShapeRing {
            env,
            ring,
            column: self.column,
            auditor,
            delegate,
            mode: config.mode,
            sender: std::cell::RefCell::new(ViewingHistory::new(
                env.sender.keypair.viewing_pubkey(),
                0,
            )),
            escrowed,
        })
    }
}

struct QueueHead<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
}

impl QueueHead<'_> {
    /// The writes `apply` moved the record queue head past.
    fn applied_by(self, apply: impl FnOnce() -> Result<()>) -> Result<u64> {
        let head = || -> Result<u64> {
            Ok(self
                .env
                .run(self.ring.require_queue(self.env.client.as_async()))?
                .head())
        };
        let before = head()?;
        apply()?;
        Ok(head()? - before)
    }
}

impl ShapeRing<'_> {
    fn sweep(&self, coverage: &mut Coverage) -> Result<()> {
        let (mut settled, mut too_large) = (Vec::new(), Vec::new());
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| self.column.keyed(*shape))
        {
            restart_prover()?;
            let transfer = ShapeTransfer {
                shape,
                inputs: self.utxos(1, coverage)?,
            };
            match self.settle(transfer, coverage)? {
                Settlement::Settled => settled.push(shape),
                Settlement::TooLarge => too_large.push(shape),
            }
        }
        println!("RING_SHAPES {:?} too_large={too_large:?}", self.column);
        let unfit: Vec<Shape> = self
            .column
            .widest()
            .iter()
            .copied()
            .filter(|shape| !settled.contains(shape))
            .collect();
        ensure!(
            unfit.is_empty(),
            "{:?} {unfit:?} must settle at full width",
            self.column
        );
        Ok(())
    }

    /// A spend of a default-ring note opens every input under the entry keys.
    fn entries(&self, coverage: &mut Coverage) -> Result<()> {
        let env = self.env;
        for outputs in ANONYMOUS_ENTRY_OUTPUTS {
            restart_prover()?;
            let utxo = DefaultRingDeposit {
                depositor: &env.sender.keypair,
                tree: env.tree,
                asset: DepositAsset::Sol,
                amount: UTXO_AMOUNT,
            }
            .send(env.client.rpc(), env.client.indexer(), &env.assets)?;
            let transfer = ShapeTransfer {
                shape: Shape::new(1, outputs),
                inputs: vec![utxo.input_utxo(env)?],
            };
            self.settled(transfer, coverage)?;
        }
        Ok(())
    }

    /// Each merge takes one note more than the next narrower width holds.
    fn merges(&self, coverage: &mut Coverage) -> Result<()> {
        let env = self.env;
        let tree_id = env.tree_id(env.tree)?;
        let mut count = 2;
        for width in MERGE_WIDTHS {
            restart_prover()?;
            let prepared = CustomRingMerge::new(self.ring, self.utxos(count, coverage)?, None)?
                .with_output_tree_id(tree_id)
                .encrypt(&env.sender.keypair)?;
            let proved = u8::try_from(prepared.inputs().len())?;
            assert_eq!(
                usize::from(proved),
                width,
                "{count} notes merge at width {width}"
            );
            let merge = RingMergeOperation::new(
                prepared,
                MergeProofInput {
                    nullifier_key: env.sender.keypair.nullifier_key.clone(),
                    input_tree: env.tree,
                    output_tree: env.tree,
                    co_signer: None,
                },
            );
            land(env, merge, &env.payer, &[])?;
            coverage.cover(RingCircuit::Merge { width: proved });
            count = width + 1;
        }
        Ok(())
    }

    /// Each deposit proves under the deposit key.
    fn utxos(&self, count: usize, coverage: &mut Coverage) -> Result<Vec<WalletUtxo>> {
        let env = self.env;
        let utxos = RingNotes {
            ring: self.ring,
            owner: &env.sender.keypair,
            amount: UTXO_AMOUNT,
            count,
            env,
        };
        let deposited = match self.column.rail() {
            RingRail::Anonymous => utxos.deposit_hidden_from(&env.payer)?,
            RingRail::Confidential | RingRail::Delegate => utxos.deposit_from(&env.payer)?,
        };
        coverage.cover(RingCircuit::deposit(1));
        deposited
            .into_iter()
            .map(|utxo| indexed_note(utxo, &env.sender.keypair, env, env.tree))
            .collect()
    }

    fn settled(&self, transfer: ShapeTransfer, coverage: &mut Coverage) -> Result<()> {
        let shape = transfer.shape;
        match self.settle(transfer, coverage)? {
            Settlement::Settled => Ok(()),
            Settlement::TooLarge => Err(anyhow!("{:?} {shape:?} must fit", self.column)),
        }
    }

    fn settle(&self, transfer: ShapeTransfer, coverage: &mut Coverage) -> Result<Settlement> {
        let env = self.env;
        let rpc = env.client.rpc();
        let label = format!(
            "{:?} {}x{} inputs={}",
            self.column,
            transfer.shape.n_inputs(),
            transfer.shape.n_outputs(),
            transfer.inputs.len()
        );
        let proven = match self
            .prove(transfer)
            .with_context(|| format!("prove {label}"))?
        {
            Proven::Transfer(proven) => proven,
            Proven::TooLarge { bytes } => {
                println!("RING_TOO_LARGE {label} bytes={bytes}");
                return Ok(Settlement::TooLarge);
            }
        };
        let instruction = proven.instruction()?;
        let parsed = ParsedTransact::new(frame(&instruction, self.column.rail())?)?;
        let data = parsed.data();
        coverage.cover(RingCircuit::audit(parsed.layout(), data.n_out));
        if data.policy.is_some() {
            coverage.cover(RingCircuit::policy(
                data.rail, data.n_in, data.n_out, 0, true,
            ));
        }
        let tag = instruction
            .data
            .first()
            .context("a tagged ring instruction")?;
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::try_from(*tag)?));
        let payer = self.payer();
        let size = spr_client::transaction_size(
            &payer.pubkey(),
            std::slice::from_ref(&instruction),
            budget,
        )?;
        let signature = land(env, instruction, payer, &[])?;
        let units = assert_transaction_compute_units(
            rpc,
            &signature,
            &label,
            CUSTOM_RING_TRANSACT_CU_LIMIT,
        )?;
        let audited = AuditLookup {
            ring: self.ring.program_id(),
            scan: RingScan::new(self.ring.program_id(), self.auditor.pubkey())
                .with_mode(self.mode)
                .with_escrowed_keys(self.escrowed.clone()),
            auditor: &self.auditor,
            signature,
        }
        .run(env)?;
        assert_eq!(opened(&audited), ring_openings(&proven.outputs)?, "{label}");
        println!(
            "RING_SETTLEMENT {label} bytes={} addresses={} cu={units}",
            size.bytes, size.addresses
        );
        Ok(Settlement::Settled)
    }

    /// Anonymous payments go to fresh recipients, each a bootstrap payment.
    fn prove(&self, transfer: ShapeTransfer) -> Result<Proven> {
        let env = self.env;
        let client = env.client.ring_client();
        let sender = &env.sender.keypair;
        let program = self.ring.program_id();
        let ShapeTransfer { shape, inputs } = transfer;
        let total: u64 = inputs.iter().map(|input| input.utxo.amount).sum();
        let amount = total / (2 * shape.n_outputs() as u64);
        let payments = 1..shape.n_outputs();
        let transaction =
            |payer: Address| ConfidentialTransaction::new_with_ring(inputs.clone(), payer, program);
        let owner_transfer = |transaction| {
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: self.ring,
                sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
        };
        let proven = match self.column.rail() {
            RingRail::Confidential => {
                let recipient = env.recipient.keypair.shielded_address()?;
                let mut transaction = transaction(sender.pubkey())?;
                for _ in payments {
                    transaction.transfer_sol(&recipient, amount)?;
                }
                env.run(owner_transfer(transaction).with_shape(shape)?.prove(client))
            }
            RingRail::Anonymous => {
                let history = self.sender.borrow().clone();
                let mut anonymous = owner_transfer(transaction(env.payer.pubkey())?)
                    .with_anonymous_signer(&sender.signing_key, &history);
                for _ in payments {
                    anonymous = anonymous.with_payment(custom_ring_sdk::AnonymousPayment {
                        to: ring_address(&ShieldedKeypair::new_ed25519()?, program)?,
                        first_contact: custom_ring_sdk::FirstContact::Bootstrap,
                        asset: Mint::SOL,
                        amount,
                    })?;
                }
                let anonymous = anonymous.with_shape(shape)?;
                *self.sender.borrow_mut() = anonymous.viewing_history()?;
                env.run(anonymous.prove(client))
            }
            RingRail::Delegate => {
                let recipient = env.recipient.keypair.shielded_address()?;
                let delegated = DelegateTransfer::new(DelegateTransferInput {
                    ring: self.ring,
                    delegate: self.delegate.pubkey(),
                    payer: self.delegate.pubkey(),
                    source: sender.shielded_address()?,
                    source_nullifier_key: &sender.nullifier_key,
                    inputs,
                    outputs: payments
                        .map(|_| DelegateOutput {
                            recipient,
                            asset: SOL_MINT,
                            amount,
                        })
                        .collect(),
                })
                .with_assets(&env.assets)
                .with_shape(shape)?;
                env.run(delegated.prove(client))
            }
        };
        match proven {
            Ok(proven) => Ok(Proven::Transfer(Box::new(proven))),
            Err(RingError::TransferTooWide { bytes, .. }) => Ok(Proven::TooLarge { bytes }),
            Err(error) => Err(error.into()),
        }
    }

    /// The anonymous rail's owner never signs, the payer alone does.
    fn payer(&self) -> &(dyn Signer + Sync) {
        match self.column.rail() {
            RingRail::Confidential => &self.env.sender.keypair,
            RingRail::Anonymous => &self.env.payer,
            RingRail::Delegate => &self.delegate,
        }
    }
}

/// What the auditor must open for every output the proof binds, padding left out.
fn ring_openings(outputs: &[SppProofOutputUtxo]) -> Result<Vec<Opened>> {
    outputs
        .iter()
        .enumerate()
        .filter_map(|(slot, output)| output.owner_address.map(|owner| (slot, output, owner)))
        .map(|(slot, output, owner)| {
            Ok(Opened {
                slot_index: u32::try_from(slot)?,
                exit: false,
                owner_key: owner.signing_pubkey.confidential_view_tag()?,
                mint: Some(output.asset.asset),
                amount: output.amount,
                blinding: output.blinding,
            })
        })
        .collect()
}

#[test]
fn anonymous_widest_eight_output_transfer_settles() -> Result<()> {
    let env = setup()?;
    let mut coverage = Coverage::default();
    let ring = ColumnSetup {
        env: &env,
        column: Column::Anonymous,
        program: custom_ring_program_id()?,
    }
    .configure(&mut coverage)?;
    ring.settled(
        ShapeTransfer {
            shape: Shape::IN5_OUT8,
            inputs: ring.utxos(5, &mut coverage)?,
        },
        &mut coverage,
    )
}

#[test]
fn sweep_confidential() -> Result<()> {
    sweep(Column::Confidential)
}

#[test]
fn sweep_confidential_policy() -> Result<()> {
    sweep(Column::ConfidentialPolicy)
}

#[test]
fn sweep_anonymous() -> Result<()> {
    sweep(Column::Anonymous)
}

#[test]
fn sweep_anonymous_policy() -> Result<()> {
    sweep(Column::AnonymousPolicy)
}

#[test]
fn sweep_delegate() -> Result<()> {
    sweep(Column::Delegate)
}

fn sweep(column: Column) -> Result<()> {
    let env = setup()?;
    let mut coverage = Coverage::default();
    let ring = ColumnSetup {
        env: &env,
        column,
        program: custom_ring_program_id()?,
    }
    .configure(&mut coverage)?;
    ring.sweep(&mut coverage)?;
    if column == Column::Anonymous {
        ring.entries(&mut coverage)?;
    }
    // One column per rail proves the merges, the delegate one also opens the key escrow record.
    if matches!(
        column,
        Column::Anonymous | Column::Confidential | Column::Delegate
    ) {
        ring.merges(&mut coverage)?;
    }
    coverage.assert_transfer_keys(column);
    Ok(())
}
