//! Measures each shape's frame under the frame encoders, SPP's account builders and the v1 compiler.
//!
//! `run` prints `test-vectors/proof/ring-frame-fit.md`, and a test pins the committed table.

use std::{collections::BTreeSet, fmt::Write};

use anyhow::{Context, Result};
use custom_ring_interface::{
    cosign::ApprovalMask,
    key_catalog::{RecordPools, TransferSpend},
    spl_withdrawal_count,
    statement::SignerDataCounts,
    storage::Revision,
    stream::slot_tag,
    tag, AnonymousProofData, AppMessage, BundleLayout, CustomRingError, CustomRingMergeIxData,
    CustomRingProof, FrameExtensions, FramedSenderBundle, InProofOwner, InputTrees,
    PlainGroth16Proof, PolicyProof, RecipientBody, Replies, RingOutput, RingPolicy, RingRail,
    RingTransactData, RootRead, SealedMergeRecord, SlotBody, AUDIT_RECORD_LEN, DATA_TAIL_LEN,
    MAX_CPI_DATA_LEN, MIN_REPLY_LEN, OPENING_RECORD_LEN, RECIPIENT_KEY_LEN, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::{MAX_ADDRESSES, MAX_SIGNATURES, MAX_TRANSACTION_SIZE};
use spr_client::{transaction_size, ComputeBudgetConfig};
use spr_interface::{
    instruction::{
        instruction_data::merge_ring::MergeRingAuthority,
        instruction_data::merge_transact::{
            MergeOutputEncryption, MergeProof, MergeTransactIxData, MERGE_SUPPORTED_INPUT_COUNTS,
        },
        InterfaceTransfer, TransactProof, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    MAX_INTERFACE_TRANSFERS, N_PUBLIC_SLOTS,
};
use spr_program::instruction::{
    MergeRing, RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
    TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use spr_transaction::{serialization::confidential::ConfidentialOutputPlaintext, Data, DataRecord};

pub mod inline_capacity;

/// The narrowest withdrawal capacity the catalog keys.
const LEGS: usize = 4;
/// `N_PUBLIC_SLOTS` distinct mints name the most SPL accounts.
const SPL_MINTS: usize = N_PUBLIC_SLOTS;

const RING_PROGRAM: Address = address(0xa0);
const PAYER: Address = address(0xa3);
const OWN: Address = address(0xa4);
const CURATOR: Address = address(0xa5);
const TRACKING: Address = address(0xa6);
const DELEGATE: Address = address(0xa8);
const COSIGNER_RECORD: Address = address(0xac);
const COSIGNER: Address = address(0xad);
const TOKEN_PROGRAM: Address = address(0xab);

const fn address(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

fn indexed(offset: u8, index: usize) -> Address {
    let mut bytes = [offset; 32];
    bytes[0] = index as u8;
    Address::new_from_array(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRail {
    Signer,
    InProof,
    Hidden,
    PublicOwners,
    SignerEntry,
    HiddenEntry,
    Delegate,
    AnonymousDelegate,
}

impl FrameRail {
    const ALL: [Self; 8] = [
        Self::Signer,
        Self::InProof,
        Self::Hidden,
        Self::PublicOwners,
        Self::SignerEntry,
        Self::HiddenEntry,
        Self::Delegate,
        Self::AnonymousDelegate,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Signer => "confidential signer",
            Self::InProof => "confidential in-proof",
            Self::Hidden => "anonymous hidden",
            Self::PublicOwners => "anonymous public owners",
            Self::SignerEntry => "confidential entry",
            Self::HiddenEntry => "anonymous entry",
            Self::Delegate => "delegate",
            Self::AnonymousDelegate => "anonymous delegate",
        }
    }

    const fn rail(self) -> RingRail {
        match self {
            Self::Signer | Self::InProof | Self::SignerEntry => RingRail::Confidential,
            Self::Hidden | Self::PublicOwners | Self::HiddenEntry => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
            Self::AnonymousDelegate => RingRail::AnonymousDelegate,
        }
    }

    const fn entry(self) -> bool {
        matches!(self, Self::SignerEntry | Self::HiddenEntry)
    }

    const fn hidden_sender(self) -> bool {
        matches!(self, Self::Hidden | Self::HiddenEntry)
    }

    /// The signers SPP's owner run must hold for a spend.
    const fn required_owners(self) -> usize {
        match self {
            Self::Signer | Self::PublicOwners | Self::SignerEntry => 1,
            Self::InProof | Self::Hidden | Self::HiddenEntry => 0,
            Self::Delegate | Self::AnonymousDelegate => 0,
        }
    }

    const fn has_owner_run(self) -> bool {
        !self.rail().is_delegate()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Legs {
    None,
    Sol,
    Spl,
}

#[derive(Clone, Copy)]
struct Load {
    name: &'static str,
    outsider_payer: bool,
    /// Own and curator roots precede the tracking registry.
    policy_roots: bool,
    /// The ring names a curator, its registry joins the policy roots.
    curator: bool,
    co_signer: bool,
    legs: Legs,
    priority_fee: bool,
    /// Every slot carries a body and the last slot exits.
    every_body: bool,
    has_data: bool,
    replies: bool,
    reply_len: usize,
    /// Every extension but the cache and the messages.
    extensions: bool,
    messages: usize,
    message_len: usize,
    second_tree: bool,
}

const MIN: Load = Load {
    name: "min",
    outsider_payer: false,
    policy_roots: false,
    curator: true,
    co_signer: false,
    legs: Legs::None,
    priority_fee: false,
    every_body: false,
    has_data: false,
    replies: false,
    reply_len: MIN_REPLY_LEN,
    extensions: false,
    messages: 0,
    message_len: 0,
    second_tree: false,
};
const FULL: Load = Load {
    name: "full",
    outsider_payer: true,
    policy_roots: true,
    co_signer: true,
    legs: Legs::Sol,
    priority_fee: true,
    every_body: true,
    ..MIN
};
const LOADS: [Load; 6] = [
    MIN,
    FULL,
    Load {
        name: "full+spl",
        legs: Legs::Spl,
        ..FULL
    },
    Load {
        name: "full+data",
        has_data: true,
        ..FULL
    },
    Load {
        name: "full+reply",
        replies: true,
        ..FULL
    },
    Load {
        name: "full+2tree",
        second_tree: true,
        ..FULL
    },
];

#[derive(Clone, Copy)]
struct Fit {
    bytes: usize,
    addresses: usize,
    signatures: usize,
}

impl Fit {
    const fn fits(self) -> bool {
        self.bytes <= MAX_TRANSACTION_SIZE
            && self.addresses <= MAX_ADDRESSES as usize
            && self.signatures <= MAX_SIGNATURES as usize
    }

    fn over(self) -> String {
        let mut over = Vec::new();
        if self.bytes > MAX_TRANSACTION_SIZE {
            over.push(format!("{} B", self.bytes - MAX_TRANSACTION_SIZE));
        }
        if self.addresses > MAX_ADDRESSES as usize {
            over.push(format!(
                "{} accounts",
                self.addresses - MAX_ADDRESSES as usize
            ));
        }
        if self.signatures > MAX_SIGNATURES as usize {
            over.push(format!(
                "{} signatures",
                self.signatures - MAX_SIGNATURES as usize
            ));
        }
        over.join(", ")
    }

    fn of(instruction: &Instruction, payer: &Address, priority_fee: bool) -> Result<Self> {
        let budget = ComputeBudgetConfig::new(0);
        let budget = match priority_fee {
            true => budget.with_priority_fee(1),
            false => budget,
        };
        let size = transaction_size(payer, std::slice::from_ref(instruction), budget)?;
        let signers: BTreeSet<_> = instruction
            .accounts
            .iter()
            .filter(|meta| meta.is_signer)
            .map(|meta| meta.pubkey)
            .chain([*payer])
            .collect();
        Ok(Self {
            bytes: size.bytes,
            addresses: size.addresses,
            signatures: signers.len(),
        })
    }
}

/// Every input and output slot of `shape` published.
#[derive(Clone, Copy)]
struct Transfer {
    frame: FrameRail,
    shape: Shape,
    load: Load,
    owners: usize,
    legs: usize,
}

enum TransferFit {
    Measured(Measured),
    Unkeyed,
}

impl TransferFit {
    fn limit(&self) -> String {
        match self {
            Self::Measured(measured) => measured.limits().join(", "),
            Self::Unkeyed => "catalog key".to_owned(),
        }
    }
}

struct Measured {
    fit: Fit,
    frame_len: usize,
    spp_cpi_len: usize,
}

impl Measured {
    fn limits(&self) -> Vec<String> {
        let mut limits = Vec::new();
        if !self.fit.fits() {
            limits.push(self.fit.over());
        }
        if self.spp_cpi_len > MAX_CPI_DATA_LEN {
            limits.push(format!("SPP CPI {} B", self.spp_cpi_len - MAX_CPI_DATA_LEN));
        }
        limits
    }

    fn fits(&self) -> bool {
        self.limits().is_empty()
    }
}

const fn fits_column(fits: bool) -> &'static str {
    match fits {
        true => "yes",
        false => "no",
    }
}

impl Transfer {
    fn measure(&self) -> Result<TransferFit> {
        let (frame, load) = (self.frame, self.load);
        let (inputs, outputs) = (self.shape.n_inputs(), self.shape.n_outputs());
        let rail = frame.rail();
        let delegate = rail.is_delegate();
        let policy_roots = load.policy_roots && !delegate;
        let co_signer = load.co_signer && !delegate;
        let read = match policy_roots {
            true => RootRead::Policy,
            false => RootRead::None,
        };
        let config = ring_config(load.curator);
        let anonymous_frame = rail.anonymous_frame();

        let proof = CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [1; 32],
                proof_b: [2; 64],
                proof_c: [3; 32],
            },
            commitment: [4; 32],
            commitment_pok: [5; 32],
        };
        let spp_proof = proof.groth16;
        let field = [6u8; 32];
        let record = [7u8; AUDIT_RECORD_LEN];
        let tail = [8u8; DATA_TAIL_LEN];
        let salt = [9u8; 16];
        let ring_data = load.has_data.then_some([10u8; 32]);
        let recipient_body = RecipientBody {
            ring_data_hash: ring_data,
            ..RecipientBody::default()
        }
        .encode()?;
        let exit_body = vec![
            11u8;
            RECIPIENT_KEY_LEN
                + ConfidentialOutputPlaintext {
                    asset_id: 1,
                    amount: 1,
                    blinding: [11; 32],
                    ring_program_id: None,
                    data: match ring_data {
                        Some(hash) => Data::new(vec![DataRecord::RingData(hash.to_vec())]),
                        None => Data::default(),
                    },
                }
                .serialize()?
                .len()
        ];
        let nullifiers: Vec<[u8; 32]> = (0..inputs)
            .map(|input| indexed(0xb0, input).to_bytes())
            .collect();
        let change = usize::from(anonymous_frame && !load.every_body);
        let bundle = vec![12u8; BundleLayout { outputs, change }.byte_len()];
        let revision = Revision::from(1);

        let legs = self.legs(frame);
        let interface_transfers: Vec<InterfaceTransfer> =
            legs.iter().map(|(transfer, _)| *transfer).collect();
        let withdrawal_owners = match policy_roots {
            true => vec![field; spl_withdrawal_count(&interface_transfers)],
            false => Vec::new(),
        };

        let slots: Vec<RingOutput<'_>> = (0..outputs)
            .map(|slot| RingOutput {
                hash: &field,
                owner_tag: slot_tag(field),
                body: match (load.every_body, anonymous_frame, slot) {
                    (true, _, slot) if slot + 1 == outputs => SlotBody::Exit(&exit_body),
                    (false, true, 0) => SlotBody::None,
                    _ => SlotBody::Recipient(&recipient_body),
                },
                record: &record,
                tail: load.has_data.then_some(&tail),
            })
            .collect();
        let reply_bodies = slots
            .iter()
            .filter(|slot| matches!(slot.body, SlotBody::Recipient(_)))
            .count();
        let reply_len = u16::try_from(load.reply_len)?;
        let reply_region = vec![13u8; load.reply_len * reply_bodies];
        let message_bytes = vec![15u8; load.message_len];
        let extensions = match load.extensions {
            true => FrameExtensions {
                format: custom_ring_interface::DisclosureFormat::Standard,
                data_hash: Some(&field),
                ring_data_hash: Some(&field),
                messages: vec![
                    AppMessage {
                        view_tag: &field,
                        data: &message_bytes,
                    };
                    load.messages
                ],
                cache: None,
                approval_totals: co_signer.then_some(&field),
                signer_data_counts: (!delegate).then(|| SignerDataCounts::new(1)).transpose()?,
            },
            false => FrameExtensions::default(),
        };

        let context = TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        let mut data = RingTransactData {
            rail,
            n_in: u8::try_from(inputs)?,
            n_out: u8::try_from(outputs)?,
            proof: &proof,
            tracking_revision: revision,
            own_revision: policy_roots.then_some(revision),
            policy: policy_roots.then_some(PolicyProof {
                curator_revision: Some(revision),
            }),
            spl_withdrawal_owners: &withdrawal_owners,
            approval: match co_signer {
                true => ApprovalMask::OUTFLOW,
                false => ApprovalMask::default(),
            },
            no_spend: false,
            public_owners: frame == FrameRail::PublicOwners,
            expiry_unix_ts: u32::MAX,
            tx_viewing_u: &field,
            salt: &salt,
            extensions,
            interface_transfers,
            has_data: load.has_data,
            entry: frame.entry(),
            wide_owners: TransferSpend {
                format: custom_ring_interface::DisclosureFormat::Standard,
                rail,
                inputs,
                outputs,
                spends_default_ring: frame.entry(),
                legs: if delegate { 0 } else { legs.len() },
                owners: 0,
                pools: RecordPools::default(),
                wide: false,
            }
            .fitted()
            .wide,
            outputs: slots,
            replies: (load.replies && anonymous_frame)
                .then(|| Replies::new(reply_len, &reply_region))
                .transpose()?,
            sender: anonymous_frame.then_some(FramedSenderBundle {
                tag: &field,
                body: &bundle,
            }),
            envelope: &[],
            private_tx_hash: &field,
            anonymous: frame.hidden_sender().then_some(AnonymousProofData {
                commitment: &field,
                commitment_pok: &field,
                default_owner_tag: frame.entry().then_some(&field),
            }),
            in_proof_owner: (frame == FrameRail::InProof).then_some(InProofOwner {
                owner: &field,
                commitment: &field,
                commitment_pok: &field,
            }),
            spp_proof: &spp_proof,
            nullifiers: &nullifiers,
            input_trees: match load.second_tree {
                true => InputTrees::Two {
                    first: context,
                    second: context,
                    second_inputs: 1,
                },
                false => InputTrees::One(context),
            },
        };
        let stream = match data.audit_stream() {
            Ok(stream) => stream,
            Err(CustomRingError::RingShapeUnkeyed) => return Ok(TransferFit::Unkeyed),
            Err(error) => return Err(error.into()),
        };
        let circuit_legs = if delegate {
            0
        } else {
            data.interface_transfers.len()
        };
        match data.transfer_circuit(circuit_legs) {
            Ok(_) => {}
            Err(CustomRingError::RingShapeUnkeyed) => return Ok(TransferFit::Unkeyed),
            Err(error) => return Err(error.into()),
        }
        let envelope = vec![14u8; stream.envelope().len];
        data.envelope = &envelope;
        let encoded = data
            .encode()
            .with_context(|| format!("{} {:?}", frame.name(), self.shape))?;
        let parsed = RingTransactData::parse(&encoded, rail)?;
        anyhow::ensure!(parsed.data() == &data, "parse reads another frame");

        let payer = match (load.outsider_payer, frame) {
            (false, FrameRail::Signer | FrameRail::SignerEntry | FrameRail::PublicOwners) => {
                indexed(0xc0, 0)
            }
            (false, FrameRail::InProof) if self.owners > 0 => indexed(0xc0, 0),
            (false, FrameRail::Delegate | FrameRail::AnonymousDelegate) => DELEGATE,
            _ => PAYER,
        };
        let owner_signers: Vec<Address> =
            (0..self.owners).map(|owner| indexed(0xc0, owner)).collect();
        let input_tree = spr_interface::pda::tree(0);
        let input_trees = match load.second_tree {
            true => vec![input_tree, spr_interface::pda::tree(1)],
            false => vec![input_tree],
        };
        let accounts: Vec<TransactInterfaceTransferAccounts> =
            legs.iter().map(|(_, accounts)| *accounts).collect();
        let expanded = data.transact_ix_data(&config, TransactProof::zeroed())?;
        let spp_cpi_len = 1 + expanded.serialize()?.len();
        let spp = match delegate {
            true => {
                RingAuthorityTransact {
                    payer,
                    input_trees,
                    output_tree: input_tree,
                    ring_program_id: RING_PROGRAM,
                    interface_transfer_accounts: accounts,
                    data: expanded,
                }
                .instruction()
                .accounts
            }
            false => {
                RingTransact {
                    payer,
                    input_trees,
                    output_tree: input_tree,
                    ring_program_id: RING_PROGRAM,
                    owner_signers,
                    interface_transfer_accounts: accounts,
                    data: expanded,
                }
                .instruction()
                .accounts
            }
        };
        if !delegate {
            let settlements = data
                .interface_transfers
                .iter()
                .map(|transfer| transfer.settlement_account_count())
                .sum();
            let read = data
                .owner_signers(&spp, settlements)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            anyhow::ensure!(
                read.len() == self.owners,
                "the program reads another owner run"
            );
        }

        let mut metas = RingPrefix {
            config: &config,
            read,
            co_signer,
        }
        .metas();
        if delegate {
            metas.push(AccountMeta::new_readonly(DELEGATE, true));
        }
        metas.extend(spp);
        let ring_tag = match delegate {
            true => tag::AUTHORITY_TRANSFER,
            false => tag::TRANSFER,
        };
        let frame_bytes = [&[ring_tag][..], &encoded].concat();
        let frame_len = frame_bytes.len();
        let instruction = Instruction {
            program_id: RING_PROGRAM,
            accounts: metas,
            data: frame_bytes,
        };
        Ok(TransferFit::Measured(Measured {
            fit: Fit::of(&instruction, &payer, load.priority_fee)?,
            frame_len,
            spp_cpi_len,
        }))
    }

    /// A hidden sender's exit names one destination.
    fn legs(
        &self,
        frame: FrameRail,
    ) -> Vec<(InterfaceTransfer, TransactInterfaceTransferAccounts)> {
        let destination = |leg: usize| match frame.hidden_sender() {
            true => indexed(0xd0, 0),
            false => indexed(0xd0, leg),
        };
        (0..self.legs)
            .filter_map(|leg| match self.load.legs {
                Legs::None => None,
                Legs::Sol => Some((
                    InterfaceTransfer::SolWithdrawal { amount: 1 },
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: destination(leg),
                    }),
                )),
                Legs::Spl => Some((
                    InterfaceTransfer::SplWithdrawal {
                        amount: 1,
                        spl_interface_bump: 255,
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(
                        TransactSplWithdrawalAccounts {
                            mint: indexed(0xa9, leg % SPL_MINTS),
                            spl_interface: indexed(0xaa, leg % SPL_MINTS),
                            user_token_account: destination(leg),
                            token_program: TOKEN_PROGRAM,
                        },
                    ),
                )),
            })
            .collect()
    }

    /// The most owner signers the ceilings admit, the catalog's rows bound a key apart.
    fn widest_settled_run(&self) -> Result<Option<(usize, Measured)>> {
        let mut widest = None;
        for owners in self.frame.required_owners()..=self.shape.n_inputs() {
            let TransferFit::Measured(measured) = (Self { owners, ..*self }).measure()? else {
                break;
            };
            if !measured.fits() {
                break;
            }
            widest = Some((owners, measured));
        }
        Ok(widest)
    }
}

fn ring_config(curator: bool) -> Box<RingPolicy> {
    let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
    config.auditor_pubkey[0] = 4;
    config.records = OWN;
    config.tracking = TRACKING;
    if curator {
        config.sources[0].registry = CURATOR;
    }
    config
}

fn tree() -> Address {
    spr_interface::pda::tree(0)
}

struct RingPrefix<'a> {
    config: &'a RingPolicy,
    read: RootRead,
    co_signer: bool,
}

impl RingPrefix<'_> {
    fn metas(self) -> Vec<AccountMeta> {
        let (policy, _) = Address::find_program_address(&[RingPolicy::SEED], &RING_PROGRAM);
        let mut metas = vec![AccountMeta::new_readonly(policy, false)];
        metas.extend(
            self.config
                .root_registries(self.read)
                .map(|registry| AccountMeta::new_readonly(registry, false)),
        );
        if self.co_signer {
            metas.push(AccountMeta::new_readonly(COSIGNER_RECORD, false));
            metas.push(AccountMeta::new_readonly(COSIGNER, true));
        }
        metas
    }
}

fn merge_fit(width: usize, authority: MergeRingAuthority) -> Result<Fit> {
    let merge = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [4; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [5; 16],
            ciphertext: [[6; 32]; 3],
        },
        private_tx_hash: [7; 32],
        nullifiers: (0..width)
            .map(|input| indexed(0xb0, input).to_bytes())
            .collect(),
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    };
    let encoded = CustomRingMergeIxData {
        tracking_revision: Revision::from(1),
        output_ring_data_hash: [8; 32],
        authority,
        sealed: SealedMergeRecord {
            proof: bytemuck::Zeroable::zeroed(),
            eph_pk: [9; TAGGED_X25519_KEY_LEN],
            ciphertext: [10; OPENING_RECORD_LEN],
        },
        merge: merge.clone(),
    }
    .serialize()?;
    let spp = MergeRing {
        input_tree: tree(),
        output_tree: tree(),
        ring_program_id: RING_PROGRAM,
        payer: PAYER,
        owner: matches!(authority, MergeRingAuthority::OwnerSigned).then_some(indexed(0xc0, 0)),
        data: merge,
        output_ring_data_hash: [8; 32],
        cache: None,
    }
    .instruction()
    .accounts;
    let mut metas = RingPrefix {
        config: &ring_config(true),
        read: RootRead::merge(),
        co_signer: false,
    }
    .metas();
    metas.extend(spp);
    let instruction = Instruction {
        program_id: RING_PROGRAM,
        accounts: metas,
        data: [&[tag::MERGE][..], &encoded].concat(),
    };
    Fit::of(&instruction, &PAYER, true)
}

pub fn run() -> Result<()> {
    print!("{}", table()?);
    Ok(())
}

fn table() -> Result<String> {
    let mut table = String::new();
    writeln!(
        table,
        "Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings {MAX_TRANSACTION_SIZE} B, {MAX_ADDRESSES} accounts, {MAX_SIGNATURES} signatures."
    )?;
    writeln!(table, "min: tracking root, no co-signer, no leg, no fee, the payer an owner where it may be. full: own, curator and tracking roots, one co-signer, {LEGS} SOL legs, a fee, an outside payer, a body on every slot and one exit. The owner run is the ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.")?;
    writeln!(table, "Every row is one transaction. fits: the row clears the transaction and CPI ceilings. limit: what refuses a row, rail for a shape the rail has no SPP key for, else the excess in accounts, signatures, bytes or CPI data at that row's load. A missing catalog key has no encoded measurement.")?;
    writeln!(table, "| shape | rail | load | catalog key | bytes | accounts | signatures | owner run | frame | SPP CPI | fits | limit |")?;
    writeln!(table, "|---|---|---|---|---|---|---|---|---|---|---|---|")?;
    for shape in SPP_SUPPORTED_SHAPES {
        for frame in FrameRail::ALL {
            if !frame.rail().supports(shape) {
                writeln!(
                    table,
                    "| {}x{} | {} | - | - | - | - | - | - | - | - | no | rail |",
                    shape.n_inputs(),
                    shape.n_outputs(),
                    frame.name(),
                )?;
                continue;
            }
            for load in LOADS {
                let transfer = Transfer {
                    frame,
                    shape,
                    load,
                    owners: frame.required_owners(),
                    legs: LEGS,
                };
                let TransferFit::Measured(measured) = transfer.measure()? else {
                    writeln!(
                        table,
                        "| {}x{} | {} | {} | none | - | - | - | - | - | - | no | catalog key |",
                        shape.n_inputs(),
                        shape.n_outputs(),
                        frame.name(),
                        load.name,
                    )?;
                    continue;
                };
                let widest = match frame.has_owner_run() && load.name == FULL.name {
                    true => transfer
                        .widest_settled_run()?
                        .map_or("none".to_owned(), |(owners, _)| owners.to_string()),
                    false => "-".to_owned(),
                };
                let fit = measured.fit;
                writeln!(
                    table,
                    "| {}x{} | {} | {} | yes | {} | {} | {} | {} | {} | {} | {} | {} |",
                    shape.n_inputs(),
                    shape.n_outputs(),
                    frame.name(),
                    load.name,
                    fit.bytes,
                    fit.addresses,
                    fit.signatures,
                    widest,
                    measured.frame_len,
                    measured.spp_cpi_len,
                    fits_column(measured.fits()),
                    measured.limits().join(", "),
                )?;
            }
        }
    }
    for width in MERGE_SUPPORTED_INPUT_COUNTS {
        for (name, authority) in [
            ("ring", MergeRingAuthority::Ring),
            ("owner signed", MergeRingAuthority::OwnerSigned),
        ] {
            let fit = merge_fit(width, authority)?;
            writeln!(
                table,
                "| {width}x1 | merge | {name} | yes | {} | {} | {} | - | - | - | {} | {} |",
                fit.bytes,
                fit.addresses,
                fit.signatures,
                fits_column(fit.fits()),
                fit.over(),
            )?;
        }
    }
    entry_capacities(&mut table)?;
    maxima(&mut table)?;
    Ok(table)
}

/// Widest owner runs at sampled leg counts, 12 to 24 input entries.
fn entry_capacities(table: &mut String) -> Result<()> {
    writeln!(table)?;
    writeln!(table, "Entry capacities at two outputs. Each row is the widest owner run one transaction clears at that leg count, rows = run + a hidden sender. A confidential leg names its own destination, a hidden sender's legs name one. over: what stops the next owner.")?;
    writeln!(table, "| shape | rail | load | legs | leg kind | owner run | rows | accounts | signatures | frame | SPP CPI | fits | over |")?;
    writeln!(
        table,
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    )?;
    let shapes = [Shape::new(12, 2), Shape::new(16, 2), Shape::new(24, 2)];
    for (shape, frame) in shapes.into_iter().flat_map(|shape| {
        [FrameRail::SignerEntry, FrameRail::HiddenEntry].map(|frame| (shape, frame))
    }) {
        for (kind, name) in [(Legs::Sol, "sol"), (Legs::Spl, "spl")] {
            for load in [
                Load { legs: kind, ..MIN },
                Load { legs: kind, ..FULL },
                Load {
                    name: "full+data+reply",
                    legs: kind,
                    has_data: true,
                    replies: true,
                    ..FULL
                },
            ] {
                for legs in (0..=MAX_INTERFACE_TRANSFERS).filter(|legs| legs % 4 == 0 || *legs < 2)
                {
                    let transfer = Transfer {
                        frame,
                        shape,
                        load,
                        owners: frame.required_owners(),
                        legs,
                    };
                    let Some((owners, measured)) = transfer.widest_settled_run()? else {
                        let limit = transfer.measure()?.limit();
                        writeln!(table, "| {}x{} | {} | {} | {legs} | {name} | none | - | - | - | - | - | no | {limit} |", shape.n_inputs(), shape.n_outputs(), frame.name(), load.name)?;
                        break;
                    };
                    let over = match owners == shape.n_inputs() {
                        true => "inputs".to_owned(),
                        false => (Transfer {
                            owners: owners + 1,
                            ..transfer
                        })
                        .measure()?
                        .limit(),
                    };
                    writeln!(
                        table,
                        "| {}x{} | {} | {} | {legs} | {name} | {owners} | {} | {} | {} | {} | {} | {} | {over} |",
                        shape.n_inputs(),
                        shape.n_outputs(),
                        frame.name(),
                        load.name,
                        owners + usize::from(frame.hidden_sender()),
                        measured.fit.addresses,
                        measured.fit.signatures,
                        measured.frame_len,
                        measured.spp_cpi_len,
                        fits_column(measured.fits()),
                    )?;
                }
            }
        }
    }
    Ok(())
}

const MAXIMUM: Load = Load {
    name: "max",
    has_data: true,
    replies: true,
    extensions: true,
    second_tree: true,
    ..FULL
};

#[derive(Clone, Copy)]
enum Axis {
    Reply,
    Messages,
    MessageBytes,
}

impl Axis {
    const ALL: [Self; 3] = [Self::Reply, Self::Messages, Self::MessageBytes];

    const fn name(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Messages => "messages",
            Self::MessageBytes => "message bytes",
        }
    }

    /// A confidential frame carries no reply region.
    const fn applies(self, frame: FrameRail) -> bool {
        !matches!(self, Self::Reply) || frame.rail().anonymous_frame()
    }

    /// The wire field's own range, the frame ceilings refuse earlier.
    fn range(self) -> core::ops::RangeInclusive<usize> {
        match self {
            Self::Reply => MIN_REPLY_LEN..=usize::from(u16::MAX),
            Self::Messages => 0..=usize::from(u8::MAX),
            Self::MessageBytes => 0..=usize::from(u16::MAX),
        }
    }

    const fn load(self, value: usize) -> Load {
        match self {
            Self::Reply => Load {
                reply_len: value,
                ..MAXIMUM
            },
            Self::Messages => Load {
                messages: value,
                ..MAXIMUM
            },
            Self::MessageBytes => Load {
                messages: 1,
                message_len: value,
                ..MAXIMUM
            },
        }
    }
}

enum Widening {
    Settled {
        value: usize,
        measured: Measured,
        over: String,
    },
    Refused(String),
}

impl Transfer {
    fn settles(&self) -> Option<Measured> {
        match self.measure() {
            Ok(TransferFit::Measured(measured)) if measured.fits() => Some(measured),
            _ => None,
        }
    }

    fn refusal(&self) -> String {
        match self.measure() {
            Ok(fit) => fit.limit(),
            Err(error) => format!("{error:#}"),
        }
    }

    /// Bytes grow on every axis, so the largest settling value bisects.
    fn widest(&self, axis: Axis) -> Widening {
        let at = |value| Self {
            load: axis.load(value),
            ..*self
        };
        let range = axis.range();
        let (mut low, mut high) = (*range.start(), *range.end());
        let Some(mut measured) = at(low).settles() else {
            return Widening::Refused(at(low).refusal());
        };
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            match at(middle).settles() {
                Some(wider) => (low, measured) = (middle, wider),
                None => high = middle - 1,
            }
        }
        let over = match low == *range.end() {
            true => "wire field".to_owned(),
            false => at(low + 1).refusal(),
        };
        Widening::Settled {
            value: low,
            measured,
            over,
        }
    }
}

fn maxima(table: &mut String) -> Result<()> {
    writeln!(table)?;
    writeln!(table, "Maxima. Load max is full with data tails, every extension but the cache, two SPP input trees, replies on anonymous frames. Each row widens one axis from that load to the largest value one transaction clears. reply: the reply length. messages: empty application messages. message bytes: one application message. over: what refuses one more step. Heap is not measured here.")?;
    writeln!(
        table,
        "| shape | rail | axis | widest | frame | SPP CPI | bytes | accounts | signatures | over |"
    )?;
    writeln!(table, "|---|---|---|---|---|---|---|---|---|---|")?;
    for shape in SPP_SUPPORTED_SHAPES {
        for frame in FrameRail::ALL {
            if !frame.rail().supports(shape) {
                continue;
            }
            let base = Transfer {
                frame,
                shape,
                load: MAXIMUM,
                owners: frame.required_owners(),
                legs: LEGS,
            };
            if matches!(base.measure()?, TransferFit::Unkeyed) {
                continue;
            }
            for axis in Axis::ALL.into_iter().filter(|axis| axis.applies(frame)) {
                write!(
                    table,
                    "| {}x{} | {} | {} | ",
                    shape.n_inputs(),
                    shape.n_outputs(),
                    frame.name(),
                    axis.name(),
                )?;
                match base.widest(axis) {
                    Widening::Refused(refusal) => {
                        writeln!(table, "none | - | - | - | - | - | {refusal} |")?
                    }
                    Widening::Settled {
                        value,
                        measured,
                        over,
                    } => writeln!(
                        table,
                        "{value} | {} | {} | {} | {} | {} | {over} |",
                        measured.frame_len,
                        measured.spp_cpi_len,
                        measured.fit.bytes,
                        measured.fit.addresses,
                        measured.fit.signatures,
                    )?,
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn frame_construction_covers_declared_loads() {
        use super::*;

        for shape in SPP_SUPPORTED_SHAPES {
            for frame in FrameRail::ALL {
                if !frame.rail().supports(shape) {
                    continue;
                }
                for load in LOADS {
                    Transfer {
                        frame,
                        shape,
                        load,
                        owners: frame.required_owners(),
                        legs: LEGS,
                    }
                    .measure()
                    .unwrap_or_else(|error| {
                        panic!("{} {shape:?} {} {error:#}", frame.name(), load.name)
                    });
                }
            }
        }

        let transfer = Transfer {
            frame: FrameRail::Signer,
            shape: Shape::new(2, 2),
            load: FULL,
            owners: 1,
            legs: LEGS,
        };
        let unkeyed = Transfer {
            frame: FrameRail::SignerEntry,
            shape: Shape::new(1, 16),
            load: MIN,
            ..transfer
        }
        .measure()
        .unwrap();
        assert!(matches!(unkeyed, TransferFit::Unkeyed));
    }

    /// Eleven co-owners sign the run and the in-proof owner signs inside SPP's proof, eight outputs and
    /// thirty two withdrawals to distinct destinations, under an own salted list with no curator.
    #[test]
    fn the_widest_in_proof_spend_is_refused_at_the_transaction_ceiling() {
        use super::*;

        let transfer = Transfer {
            frame: FrameRail::InProof,
            shape: Shape::new(12, 8),
            load: Load {
                name: "salted own",
                policy_roots: true,
                curator: false,
                legs: Legs::Sol,
                ..MIN
            },
            owners: 11,
            legs: MAX_INTERFACE_TRANSFERS,
        };
        let TransferFit::Measured(measured) = transfer.measure().unwrap() else {
            panic!("the spend has no catalog key");
        };
        assert_eq!(
            measured.limits(),
            [format!("{} B", measured.fit.bytes - MAX_TRANSACTION_SIZE)]
        );
    }

    #[test]
    fn the_table_is_the_committed_measurement() {
        let committed = include_str!("../../test-vectors/proof/ring-frame-fit.md");
        assert_eq!(super::table().unwrap(), committed);
    }
}
