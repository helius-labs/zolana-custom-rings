//! End-to-end custom-ring lifecycle against localnet + photon + prover.
//!
//! [`lifecycle::localnet_bring_up_is_live`] proves the bring-up in `shared.rs` is real: the
//! four programs are deployed and executable, the protocol is bootstrapped with
//! the settings the ring flows need, the tree account deserializes, and the
//! indexer and prover both answer.
//!
//! [`transfers::auditor_sees_every_ring_transfer`] is the capstone: it walks the whole
//! lifecycle (create the config holding the auditor key, register the ring with
//! SPP, ring-deposit SOL, then a ring transact whose proof binds the verifiable
//! encryption of the transaction viewing key to that auditor key) and asserts
//! that the amounts, assets and blindings the AUDITOR CLIENT decrypts are the
//! ones the sender actually sent -- not merely that decryption succeeded.
//!
//! [`transfers::an_audit_only_ring_audits_every_transfer`] runs the lighter tier, no
//! policy and the audit statement alone, with the same auditor recovery.
//! Its second hop, like the capstone's, is proven through the blocking client and
//! through a native async client, and lands the native proof (see [`AsyncHopParity`]).
//!
//! [`anonymous::an_anonymous_ring_hides_owners_and_preserves_auditor_access`] pays ring
//! addresses under bootstrap, request and shared view tags, and fresh wallets find every
//! payment, the change and a merge by exact tags.
//!
//! [`transfers::ring_value_leaves_and_enters_through_audited_transfers`] crosses the ring
//! boundary in both directions under the auditor and pins that a note of
//! another ring is refused before proving.

#[path = "ring_shapes.rs"]
mod shapes;

#[path = "ring/anonymous.rs"]
mod anonymous;
#[path = "ring/lifecycle.rs"]
mod lifecycle;
#[path = "ring/merge.rs"]
mod merge;
#[path = "ring/migration.rs"]
mod migration;
#[path = "ring/policy.rs"]
mod policy;
#[path = "ring/relay.rs"]
mod relay;
#[path = "ring/transfers.rs"]
mod transfers;

use std::{
    collections::HashMap,
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, ensure, Context, Result};
use custom_ring_cli::{wait_for, Landing, ModeName, Probe};
use custom_ring_interface::{
    anonymous_recipient_output_body, anonymous_sender_output_body, AnonymousProofData,
    CustomRingError, RingMode, RingPolicy, RingRail, RingRole, RingTransactData, RING_POLICY,
    RING_POLICY_PDA_SEED,
};
use custom_ring_sdk::{
    compute_unit_limit, AnonymousTransfer, CoSignScope, CustomRing, CustomRingMerge,
    CustomRingTransfer, CustomRingTransferInput, DelegateOutput, DelegateTransfer,
    DelegateTransferInput, DepositRecipient, FirstContact, InstructionTag, KeyRegistration,
    MergeProofInput, ProvenRingTransfer, RingClient, RingDeposit, RingDepositReceipt, RingError,
    RingMergeOperation, RingOperation, RingRegistration,
};
use custom_ring_test_validator::{
    cli::{merged, RingProject, RingToml},
    policy::{
        owner_member, policy_registry, RegistryWrite, RingNotes, StorageRecords, EMPTY, LIMIT_CAP,
        LIMIT_COSIGN_ABOVE,
    },
    ring_rpc::RingRpcSpec,
    ring_wallet::RingWallet,
    shared::{
        custom_ring_program_id, prover_url, send, send_expecting_rejection, setup, ExpectRejection,
        RegisterRing, RejectedTransact, RingRoleKeys, SendAs, TestEnv, Tier, WalletSync,
        USDC_ASSET_ID,
    },
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::v1::MAX_TRANSACTION_SIZE;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    compile_message, sign_transaction, AsyncProverClient, AsyncSolanaRpc, AsyncZolanaClient,
    AsyncZolanaIndexer, ComputeBudgetConfig, ProofDataSource, Rpc, ShieldedTransaction, SolanaRpc,
    ZolanaIndexer,
};
use spr_interface::{
    error::ShieldedPoolError,
    pda,
    state::{
        discriminator::{PROTOCOL_CONFIG, RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        tree_account_size, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID, ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::{random_blinding, ShieldedAddress, ShieldedKeypair, X25519Keypair};
use spr_program::instruction::{
    AssetDeposit, Deposit as SppDeposit, DepositAsset, DepositSplAccounts,
    TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts, UpdateRingConfig,
};
use spr_program_test::Rejection;
use spr_test_utils::wallet::Wallet;
use spr_test_utils::{
    localnet::isolated_temp_path,
    smart_account,
    spl::{create_token_account, mint_to},
    test_validator_asserts::{
        assert_account_unchanged, assert_transaction_compute_units, fetch_account, fetch_state,
        token_amount, wait_for_indexed_transaction, wait_for_merkle_proof,
    },
};
use spr_transaction::{
    decrypt_spendable,
    instructions::transact::{canonical_shape, ConfidentialTransaction, SppProofOutputUtxo},
    AssetRegistry, Data, Mint, Utxo, WalletUtxo, SOL_ASSET_ID, SOL_MINT,
};
use spr_tree::TreeAccount;
use spr_user_registry_interface::user_registry_program_id;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{write_auditor_key, CreateAuditorKeyRequest, RecordUpdateEntry},
    AuditedTransaction, OutputOpening, RingRecovery, RingScan, SourceMember, ViewingHistory,
};
use zolana_ring_keys::{RingAddress, RingPaymentRequest};
use zolana_ring_policy::{ListId, Member, Rule, RuleTable, Subject};
use zolana_ring_rpc::{
    ChainSource, Hub, RingRpcError, RootSecret, ServiceIdentity, TransactionSource, Unauthorized,
    Upstreams,
};

/// Lamports moved by the two transaction-shape probes. Small enough that the
/// payer's airdrop covers both plus fees.
const PROBE_TRANSFER: u64 = 1_234_567;

/// The protocol has no live transaction under an arbitrary view tag, so this
/// tag is only used to make the indexer answer a well-formed query.
const UNUSED_VIEW_TAG: [u8; 32] = [7u8; 32];

/// The two ring SOL deposits the custom-ring transfer spends. Two inputs and two
/// outputs (sender change, recipient) are the (2, 2) transfer shape, which the
/// ring eddsa prover and SPP's `transfer_ring_2_2` verifying key both support.
const RING_DEPOSIT_A: u64 = 3_000_000_000;
const RING_DEPOSIT_B: u64 = 2_000_000_000;
/// What the sender sends the recipient. Every auditor-side expectation is
/// derived from this and the deposits, never read back out of the audit result.
const RING_TRANSFER_AMOUNT: u64 = 1_500_000_000;
/// The SOL change the sender keeps. A confidential transfer charges no protocol
/// fee, so the deposited total minus the sent amount is exact; evaluating it as
/// a `const` makes an arithmetic slip a compile error rather than a test that
/// asserts the audit against itself.
const RING_CHANGE: u64 = RING_DEPOSIT_A + RING_DEPOSIT_B - RING_TRANSFER_AMOUNT;
const SECOND_HOP_AMOUNT: u64 = 400_000_000;
const PAIR_AMOUNT: u64 = 250_000_000;
const MERGED_AMOUNT: u64 = RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT + PAIR_AMOUNT;
const MERGED_SPEND: u64 = 100_000_000;

/// Output slot layout this test publishes: the sender's change first, the
/// recipient second. A slot's index is what its ciphertext is bound to, so these
/// are also the `slot_index` values the auditor must report.
const CHANGE_SLOT: u32 = 1;
const RECIPIENT_SLOT: u32 = 0;

/// The program audit's estimate for the widest keyed transfer.
const WIDEST_TRANSACT_ESTIMATE_CU: u64 = 720_000;
const CUSTOM_RING_TRANSACT_CU_LIMIT: u64 = 1_000_000;

// Below the requested budget a confirmed transfer can still exceed the ceiling.
const _: () = assert!(
    WIDEST_TRANSACT_ESTIMATE_CU <= CUSTOM_RING_TRANSACT_CU_LIMIT
        && CUSTOM_RING_TRANSACT_CU_LIMIT < compute_unit_limit(InstructionTag::Transfer) as u64
);

const DEFAULT_DEPOSIT: u64 = 4_000_000_000;
const ENTRY_AMOUNT: u64 = 2_500_000_000;
const ENTRY_CHANGE: u64 = DEFAULT_DEPOSIT - ENTRY_AMOUNT;
const EXIT_AMOUNT: u64 = 1_000_000_000;
const EXIT_CHANGE: u64 = ENTRY_CHANGE - EXIT_AMOUNT;
const REFUSED_AMOUNT: u64 = 100_000_000;
const FOREIGN_RING: Address = Address::new_from_array([9; 32]);

const USDC_FUNDING: u64 = 50_000_000;
const USDC_DEFAULT_DEPOSIT: u64 = 40_000_000;
const USDC_ENTRY_AMOUNT: u64 = 25_000_000;
const USDC_ENTRY_CHANGE: u64 = USDC_DEFAULT_DEPOSIT - USDC_ENTRY_AMOUNT;
const USDC_HOP_AMOUNT: u64 = 10_000_000;
const USDC_HOP_CHANGE: u64 = USDC_ENTRY_CHANGE - USDC_HOP_AMOUNT;
const USDC_RING_DEPOSIT: u64 = 5_000_000;
const USDC_EXIT_AMOUNT: u64 = 6_000_000;
const USDC_EXIT_CHANGE: u64 = USDC_HOP_CHANGE + USDC_RING_DEPOSIT - USDC_EXIT_AMOUNT;
const USDC_WITHDRAW_AMOUNT: u64 = 2_500_000;
const USDC_FINAL_SEND: u64 = 1_000_000;
const USDC_FINAL_CHANGE: u64 = USDC_EXIT_CHANGE - USDC_WITHDRAW_AMOUNT - USDC_FINAL_SEND;

fn cli_merge_fragments(amounts: &[u64]) -> Result<()> {
    let count = amounts.len().to_string();
    let merged_count = amounts.len().min(custom_ring_sdk::MAX_RING_MERGE_INPUTS);
    let total: u64 = amounts[..merged_count].iter().sum();
    let env = setup()?;
    let tree = env.register_default_tree()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    let ring_rpc = RingRpcSpec {
        env: &env,
        ring: ring.program_id(),
        auditor: auditor.clone(),
    }
    .serve()?;
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: &ring_rpc.url,
        policy: None,
        mode: ModeName::Anonymous,
    })?;
    project.run(&["init"])?;

    // The first run creates the persistent sender key, but correctly refuses
    // to manufacture a merge from fewer than two notes.
    let empty = project.output(&["merge", "--count", &count])?;
    assert!(!empty.status.success(), "an empty wallet cannot merge");
    let empty_text = merged(&empty);
    assert!(
        empty_text.contains("found only 0 mergeable notes"),
        "{empty_text}"
    );
    let sender = project.demo_sender()?;
    let mut history = ViewingHistory::new(sender.viewing_pubkey(), 0);

    for &amount in amounts {
        let deposit = RingDeposit {
            ring,
            payer: &env.payer,
            recipient: DepositRecipient::Anonymous {
                keys: &sender,
                history: &history,
            },
            tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let next = deposit
            .viewing_history()?
            .context("an anonymous deposit advances its history")?;
        let receipt = env.run(deposit.send(env.client.ring_client()))?;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, receipt.signature)?;
        history = next;
    }

    let output = project.run(&[
        "--fee-payer-keypair",
        "upgrade.json",
        "merge",
        "--count",
        &count,
    ])?;
    for line in [
        format!("inputs      {merged_count}"),
        format!("amount      {total}"),
        "merge preserves value".to_owned(),
    ] {
        assert!(output.contains(&line), "{line} in\n{output}");
    }

    let mut wallet = RingWallet::new(&sender, env.ring_assets()?, ring.program_id());
    wallet.sync(&env)?;
    let mut actual: Vec<_> = wallet.unspent().map(|note| note.utxo.amount).collect();
    let mut expected = amounts[merged_count..].to_vec();
    expected.push(total);
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "an independent scan finds the merged value and any unselected notes"
    );

    let signature = output
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("merge"))
                .then(|| fields.next()?.parse::<Signature>().ok())
                .flatten()
        })
        .context("merge CLI did not print its confirmed signature")?;
    let confirmed: serde_json::Value = env.client.rpc().client().send(
        solana_rpc_client_api::request::RpcRequest::GetTransaction,
        serde_json::json!([signature.to_string(), {
            "encoding": "base64",
            "commitment": "confirmed",
            "maxSupportedTransactionVersion": 1,
        }]),
    )?;
    assert!(confirmed["meta"]["err"].is_null(), "{confirmed}");
    let encoded = confirmed["transaction"][0]
        .as_str()
        .context("confirmed merge has no base64 transaction")?;
    let bytes = encoded.len() / 4 * 3 - encoded.bytes().rev().take_while(|b| *b == b'=').count();
    assert!(bytes <= MAX_TRANSACTION_SIZE, "merge has {bytes} bytes");
    println!(
        "merge inputs={count} amount={total} bytes={bytes} compute_units={} signature={signature}",
        confirmed["meta"]["computeUnitsConsumed"]
    );
    project.remove()?;
    Ok(())
}

/// A Frozen hidden sender is refused.
const FROZEN_SENDERS: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .build();

/// Registers every member in the pinned registry before the delegate turns key escrow on.
struct EscrowedDelegate<'a> {
    ring: CustomRing,
    delegate: &'a Keypair,
    members: &'a [&'a ShieldedKeypair],
}

impl EscrowedDelegate<'_> {
    fn set(self, env: &TestEnv) -> Result<()> {
        register_keys(env, self.ring, self.members)?;
        DelegateAppointment {
            ring: self.ring,
            delegate: self.delegate,
        }
        .send(env)
    }
}

/// The delegate signs its appointment beside the config authority.
struct DelegateAppointment<'a> {
    ring: CustomRing,
    delegate: &'a Keypair,
}

impl DelegateAppointment<'_> {
    fn send(self, env: &TestEnv) -> Result<()> {
        let admin = RingRoleKeys::of(&env.payer).admin;
        env.client.rpc().create_and_send_transaction(
            &[custom_ring_sdk::SetDelegate {
                ring: self.ring,
                authority: admin.pubkey(),
                delegate: self.delegate.pubkey(),
            }
            .instruction()],
            env.payer.pubkey(),
            &[&env.payer, &admin, self.delegate],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
        Ok(())
    }
}

fn lamports<R: Rpc>(rpc: &R, address: Address) -> Result<u64> {
    Ok(rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("account {address} not found"))?
        .lamports)
}

fn registration(env: &TestEnv, ring: CustomRing) -> Result<RingRegistration> {
    env.run(ring.registration(env.client.as_async()))?
        .ok_or_else(|| anyhow!("SPP ring config of {}", ring.program_id()))
}

/// Proves, signs and settles one ring operation, a failed one is an error.
fn land<'a>(
    env: &TestEnv,
    operation: impl Into<RingOperation<'a>>,
    payer: &(dyn Signer + Sync),
    signers: &[&(dyn Signer + Sync)],
) -> Result<Signature> {
    Landing {
        operation: operation.into(),
        payer,
        signers,
    }
    .settle(&env.client)
}

/// Every member's escrow write in one update.
fn register_keys(env: &TestEnv, ring: CustomRing, members: &[&ShieldedKeypair]) -> Result<()> {
    let writes = members
        .iter()
        .map(|member| {
            let registration = env.run(
                KeyRegistration {
                    ring,
                    member: member.shielded_address()?,
                    authority: *member,
                }
                .prove(env.client.ring_client()),
            )?;
            Ok(RecordUpdateEntry::Escrow(registration).write(&member.pubkey())?)
        })
        .collect::<Result<Vec<_>>>()?;
    StorageRecords { ring, writes, env }.send()?;
    Ok(())
}

fn frame(instruction: &Instruction, rail: RingRail) -> Result<RingTransactData<'_>> {
    let (_, body) = instruction
        .data
        .split_first()
        .context("a tagged ring instruction")?;
    Ok(RingTransactData::parse(body, rail)?.into_data())
}

/// SPP's anonymous rail hides `owner`, the delivered audit publishes it.
fn assert_anonymous_spp_rail(instruction: &Instruction, owner: &[u8; 32]) -> Result<()> {
    let data = frame(instruction, RingRail::Confidential)?;
    ensure!(
        matches!(
            data.circuit(),
            spr_interface::instruction::CircuitId::AnonymousRingEddsa(.., proof)
                if proof.default_owner_tag.is_none()
        ),
        "the in-proof owner proves on SPP's anonymous rail"
    );
    ensure!(
        data.in_proof_owner.map(|published| *published.owner) == Some(*owner),
        "the frame publishes the in-proof owner"
    );
    Ok(())
}

fn reframed(instruction: &Instruction, frame: &RingTransactData<'_>) -> Result<Instruction> {
    Ok(Instruction {
        data: [&instruction.data[..1], frame.encode()?.as_slice()].concat(),
        ..instruction.clone()
    })
}

fn signers(instruction: &Instruction) -> Vec<Address> {
    instruction
        .accounts
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
        .collect()
}

/// Lets the transaction compile without `signer`'s signature.
fn without_signer(mut instruction: Instruction, signer: Address) -> Instruction {
    for meta in &mut instruction.accounts {
        if meta.pubkey == signer {
            meta.is_signer = false;
        }
    }
    instruction
}

/// The test's own view of a note, spent and audited from the same values.
#[derive(Clone, Copy)]
struct Note<'a> {
    owner: &'a ShieldedKeypair,
    asset: Address,
    amount: u64,
    blinding: [u8; 32],
    ring_program_id: Option<Address>,
}

impl Note<'_> {
    fn input_utxo(self, env: &TestEnv) -> Result<WalletUtxo> {
        let utxo = Utxo {
            owner: self.owner.signing_pubkey(),
            asset: env.assets.mint(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: Data::default(),
        };
        if self.ring_program_id == Some(FOREIGN_RING) {
            return spr_test_utils::utxo::wallet(utxo, &self.owner.nullifier_key, 0, 0, None, None);
        }
        indexed_note(utxo, self.owner, env, env.tree)
    }

    fn opened(self, slot_index: u32) -> Result<Opened> {
        Ok(Opened {
            slot_index,
            exit: self.ring_program_id.is_none(),
            owner_key: self.owner.signing_pubkey().confidential_view_tag()?,
            mint: Some(self.asset),
            amount: self.amount,
            blinding: self.blinding,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Opened {
    slot_index: u32,
    exit: bool,
    owner_key: [u8; 32],
    mint: Option<Address>,
    amount: u64,
    blinding: [u8; 32],
}

fn opened(audited: &AuditedTransaction) -> Vec<Opened> {
    audited
        .outputs
        .iter()
        .filter_map(|output| {
            let (utxo, exit) = match &output.opening {
                OutputOpening::Ring { utxo, .. } => (utxo, false),
                OutputOpening::Exit(utxo) => (utxo, true),
                OutputOpening::Dummy => return None,
            };
            Some(Opened {
                slot_index: output.slot_index,
                exit,
                owner_key: utxo.owner_key,
                mint: utxo.mint,
                amount: utxo.amount,
                blinding: utxo.blinding,
            })
        })
        .collect()
}

fn ring_amounts(audited: &AuditedTransaction) -> Result<Vec<u64>> {
    opened(audited)
        .into_iter()
        .map(|opened| match opened.exit {
            false => Ok(opened.amount),
            true => Err(anyhow!("slot {} left the ring", opened.slot_index)),
        })
        .collect()
}

fn output_blinding(outputs: &[SppProofOutputUtxo], slot: u32) -> Result<[u8; 32]> {
    Ok(outputs
        .get(usize::try_from(slot)?)
        .with_context(|| format!("output slot {slot}"))?
        .blinding)
}

struct DefaultRingDeposit<'a> {
    depositor: &'a ShieldedKeypair,
    tree: Address,
    asset: DepositAsset,
    amount: u64,
}

impl<'a> DefaultRingDeposit<'a> {
    fn send(
        self,
        rpc: &SolanaRpc,
        indexer: &ZolanaIndexer,
        assets: &AssetRegistry,
    ) -> Result<Note<'a>> {
        let address = self.depositor.shielded_address()?;
        let view_tag = address.viewing_pubkey.u();
        let deposit = SppDeposit {
            tree: self.tree,
            depositor: self.depositor.pubkey(),
            deposits: vec![AssetDeposit {
                asset: self.asset,
                view_tag,
                owner: address.owner_hash()?,
                amount: self.amount,
                memo: None,
            }],
        }
        .instruction()?;
        let signature = send(rpc, self.depositor, &[deposit])?;
        // A proofless deposit publishes its UTXO in the clear, so read it back
        // from the indexer.
        let indexed = wait_for_indexed_transaction(indexer, view_tag, signature);
        let mint = self.asset.mint();
        let balances = decrypt_spendable(self.depositor, std::slice::from_ref(&indexed), assets)
            .map_err(|e| anyhow!("decrypt deposit {signature}: {e:?}"))?
            .balances;
        let deposited = balances
            .get_balance(mint)
            .and_then(|balance| balance.utxos.first())
            .ok_or_else(|| anyhow!("deposit {signature} not indexed for {mint}"))?;
        assert_eq!(deposited.utxo.amount, self.amount, "deposited amount");
        Ok(Note {
            owner: self.depositor,
            asset: mint,
            amount: self.amount,
            blinding: deposited.utxo.blinding,
            ring_program_id: None,
        })
    }
}

/// `cosigner` must hold a record covering every class the transfer demands.
struct OwnerTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    prepared: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    auditor_tag: [u8; 32],
    cosigner: Option<&'a Keypair>,
}

struct TransferReceipt {
    signature: Signature,
    indexed: ShieldedTransaction,
    /// Indexed by slot, padding included.
    outputs: Vec<SppProofOutputUtxo>,
}

impl OwnerTransfer<'_> {
    fn send(self, env: &TestEnv) -> Result<TransferReceipt> {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.prepared,
        })
        .with_interface_transfer_accounts(self.interface_transfer_accounts);
        let transfer = match self.cosigner {
            Some(cosigner) => transfer.with_co_signer(cosigner.pubkey()),
            None => transfer,
        };
        let proven = env.run(transfer.prove(env.client.ring_client()))?;
        assert_eq!(
            proven.co_signer,
            self.cosigner.map(|cosigner| cosigner.pubkey()),
            "the proven transfer carries the demanded co-signer"
        );
        let signers: Vec<&(dyn Signer + Sync)> = self
            .cosigner
            .into_iter()
            .map(|keypair| keypair as &(dyn Signer + Sync))
            .collect();
        let signature = land(env, proven.instruction()?, self.sender, &signers)?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(TransferReceipt {
            signature,
            indexed,
            outputs: proven.outputs,
        })
    }
}

/// The recipient's note `received` paid back to the sender in the note's ring.
fn second_hop(env: &TestEnv, received: Utxo) -> Result<ConfidentialTransaction> {
    let ring = received.ring_program_id.context("a ring note")?;
    let mut hop = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(
            received,
            &env.recipient.keypair,
            env,
            env.tree,
        )?],
        env.recipient.keypair.pubkey(),
        ring,
    )?;
    hop.transfer_sol(&env.sender.keypair.shielded_address()?, SECOND_HOP_AMOUNT)?;
    Ok(hop)
}

struct AsyncHopParity<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    blocking: ConfidentialTransaction,
    asynchronous: ConfidentialTransaction,
    auditor_tag: [u8; 32],
}

impl AsyncHopParity<'_> {
    fn send(self, env: &TestEnv) -> Result<TransferReceipt> {
        let blocking = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.blocking,
        });
        let blocking = env.run(blocking.prove(env.client.ring_client()))?;

        // `local()` on both clients, a parity failure cannot be two different provers.
        let native = RingClient::new(
            AsyncZolanaClient::new(
                AsyncSolanaRpc::new(env.rpc_url.clone()),
                AsyncZolanaIndexer::new(env.indexer_url.clone()),
                AsyncProverClient::local(),
            ),
            AsyncProverClient::local(),
        );
        let runtime = tokio::runtime::Runtime::new()?;
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: self.asynchronous,
        });
        let proven = runtime.block_on(transfer.prove(&native))?;

        let (native_ix, blocking_ix) = (proven.instruction()?, blocking.instruction()?);
        let native_frame = frame(&native_ix, RingRail::Confidential)?;
        let blocking_frame = frame(&blocking_ix, RingRail::Confidential)?;
        assert_eq!(
            proven.tx_viewing_key.pubkey(),
            blocking.tx_viewing_key.pubkey(),
            "async and blocking derive the same transaction viewing key"
        );
        assert_eq!(
            native_frame.tx_viewing_u, blocking_frame.tx_viewing_u,
            "async and blocking publish the same tx_viewing_pk"
        );
        assert_eq!(
            native_frame.circuit(),
            blocking_frame.circuit(),
            "async and blocking select the same circuit"
        );
        assert_eq!(
            native_frame.nullifiers, blocking_frame.nullifiers,
            "async and blocking nullify the same note"
        );
        assert_eq!(
            signers(&native_ix),
            signers(&blocking_ix),
            "async and blocking require the same signatures"
        );
        assert_eq!(
            native_frame.expiry_unix_ts, blocking_frame.expiry_unix_ts,
            "async and blocking carry the same expiry"
        );
        assert_ne!(
            native_frame.private_tx_hash, blocking_frame.private_tx_hash,
            "each proof draws its own blindings, salt and auditor ciphertext"
        );

        let outputs = proven.outputs.clone();
        let signature = land(env, native_ix, self.sender, &[])?;
        let indexed =
            wait_for_indexed_transaction(env.client.indexer(), self.auditor_tag, signature);
        Ok(TransferReceipt {
            signature,
            indexed,
            outputs,
        })
    }
}

struct AuditLookup<'a> {
    ring: Address,
    scan: RingScan,
    auditor: &'a X25519Keypair,
    signature: Signature,
}

impl AuditLookup<'_> {
    fn run(self, env: &TestEnv) -> Result<AuditedTransaction> {
        custom_ring_cli::wait_for_indexed_transaction(&env.client, self.signature)?;
        let client = env.client.as_async();
        let created = env.client.block_on(
            zolana_ring_client::CreatedUtxoScan::new(self.ring, self.auditor)
                .run(client.indexer(), client.rpc()),
        )?;
        ensure!(
            created.next_cursor.is_none(),
            "created-note history is incomplete"
        );
        env.client
            .block_on(
                self.scan
                    .with_known_utxos(
                        created
                            .utxos
                            .into_iter()
                            .map(|note| (note.commitment, note.utxo))
                            .collect(),
                    )
                    .audit(
                        self.auditor,
                        client.indexer(),
                        client.rpc(),
                        &env.ring_assets()?,
                    ),
            )?
            .transactions
            .into_iter()
            .find(|tx| tx.tx_signature == self.signature)
            .ok_or_else(|| anyhow!("transaction {} audited", self.signature))
    }
}

/// An anonymous ring payment, the ring payer funds it so no public signer names the owner.
struct AnonymousPayment<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    /// The sender's counterparties pick the payment's tag.
    history: &'a ViewingHistory,
    payer: Address,
    inputs: Vec<WalletUtxo>,
    to: RingAddress,
    first_contact: FirstContact,
    amount: u64,
}

impl<'a> AnonymousPayment<'a> {
    fn transfer(self) -> Result<AnonymousTransfer<'a>> {
        let shape = canonical_shape(self.inputs.len(), 2)?;
        let transaction = ConfidentialTransaction::new_with_ring(
            self.inputs,
            self.payer,
            self.ring.program_id(),
        )?;
        Ok(CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_anonymous_signer(&self.sender.signing_key, self.history)
        .with_payment(custom_ring_sdk::AnonymousPayment {
            to: self.to,
            first_contact: self.first_contact,
            asset: Mint::SOL,
            amount: self.amount,
        })?
        .with_shape(shape)?)
    }
}

struct PaymentLanding<'a> {
    transfer: AnonymousTransfer<'a>,
    payer: &'a Keypair,
    auditor_tag: [u8; 32],
}

struct LandedPayment {
    indexed: ShieldedTransaction,
    /// The sender's history past the payment's tags, stored before it was sent.
    history: ViewingHistory,
}

impl PaymentLanding<'_> {
    fn land(self, env: &TestEnv) -> Result<LandedPayment> {
        let history = self.transfer.viewing_history()?;
        let signature = Landing {
            operation: self.transfer.into(),
            payer: self.payer,
            signers: &[],
        }
        .settle(&env.client)?;
        Ok(LandedPayment {
            indexed: wait_for_indexed_transaction(
                env.client.indexer(),
                self.auditor_tag,
                signature,
            ),
            history,
        })
    }
}

/// The wallet's spec identity on `ring`, its own viewing key the recipient key.
fn ring_address(owner: &ShieldedKeypair, ring: Address) -> Result<RingAddress> {
    Ok(RingAddress {
        recipient: owner.shielded_address()?,
        ring_program_id: ring,
    })
}

fn unspent_utxo(wallet: &Wallet, amount: u64) -> Result<Utxo> {
    wallet
        .unspent()
        .find(|held| held.utxo.amount == amount)
        .map(|held| held.utxo.clone())
        .ok_or_else(|| anyhow!("an unspent note of {amount}"))
}

fn sorted_unspent_notes(wallet: &Wallet) -> Vec<(Address, u64, Option<Address>)> {
    sorted_notes(wallet.unspent())
}

fn sorted_notes<'u>(
    unspent: impl Iterator<Item = &'u WalletUtxo>,
) -> Vec<(Address, u64, Option<Address>)> {
    let mut notes: Vec<_> = unspent
        .map(|held| {
            (
                held.utxo.asset.asset,
                held.utxo.amount,
                held.utxo.ring_program_id,
            )
        })
        .collect();
    notes.sort_unstable();
    notes
}

/// A ring note the indexer proves, its hash carrying the ring data the scan opened.
fn held_note(wallet: &RingWallet<'_>, env: &TestEnv, amount: u64) -> Result<WalletUtxo> {
    let held = wallet
        .unspent()
        .find(|held| held.utxo.amount == amount)
        .cloned()
        .ok_or_else(|| anyhow!("an unspent note of {amount}"))?;
    wait_for_merkle_proof(env.client.indexer(), env.tree, held.utxo_hash);
    Ok(held)
}

fn expect_foreign_ring(result: Result<ProvenRingTransfer, RingError>, ring: Address) -> Result<()> {
    match result {
        Err(RingError::ForeignRing(refused)) if refused == ring => Ok(()),
        Err(other) => Err(anyhow!("expected ForeignRing({ring}), got {other}")),
        Ok(_) => Err(anyhow!(
            "expected ForeignRing({ring}), the transfer was proven"
        )),
    }
}

fn indexed_note(
    utxo: Utxo,
    owner: &ShieldedKeypair,
    env: &TestEnv,
    tree: Address,
) -> Result<WalletUtxo> {
    let tree_id = env.tree_id(tree)?;
    let hash = utxo.hash(&owner.nullifier_key.pubkey()?, &[0; 32], &[0; 32], tree_id)?;
    let state = wait_for_merkle_proof(env.client.indexer(), tree, hash);
    spr_test_utils::utxo::wallet(
        utxo,
        &owner.nullifier_key,
        tree_id,
        state.leaf_index,
        None,
        None,
    )
}
