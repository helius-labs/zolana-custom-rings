//! The policy section of a ring transfer, every record read under a root the statement binds.

use custom_ring_interface::{
    cosign::ApprovalMask,
    key_catalog::{RecordPools as PoolWidths, RingCircuit},
    CustomRingError, PolicyWithdrawal, PublicSlots, RingRail, RootRead, TransferRoots,
};
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_hasher::primitives::right_align;
use spr_interface::{N_PUBLIC_SLOTS, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::instructions::transact::SppProofInputs;
use zolana_ring_client::{records::RecordPoolRead, AsyncRingIndexer};
use zolana_ring_policy::{
    ApprovalInputs, EncodedRuleTable, Member, MintPolicy, OutputSubjects, OwnerDebit,
    PaymentSubjects, PublicGross, RecordLists, SourceMap,
};
use zolana_ring_transaction::ClassifiedInput;

use super::{
    audit::is_default_ring,
    plan::{PlannedTransfer, TransferPlanner},
    pool_subjects::{pool_at_width, KnownSalts, OwnerQuery, PoolSubjects, RecordPlan, SourceGates},
};
use crate::{
    limits::Outflows,
    records::{
        OutputKey, PoolRead, RecipientViewingKeys, SealedOutput, TrackingPoolRead, TrackingRead,
    },
    request::{
        owner_key, OwnerEntry, PolicyParams, PolicyTable, PolicyWithdrawalRequest, PoolEntry,
        RecordPools, TrackingParams,
    },
    submission::BoundRoot,
    CustomRingConfig, PinnedPolicy, RingError,
};

pub(super) struct PolicyInputs {
    /// Read once, every later stage takes its key and stream from here.
    pub plan: PlannedTransfer,
    widths: PoolWidths,
    /// The key's `N`, a frame on a wider key leaves the rest empty.
    slots: usize,
    pub read: RootRead,
    pub rows: Vec<[u8; 32]>,
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    withdrawals: Vec<PolicyWithdrawal>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    /// Zero off a policy, the gate of every rule.
    pub policy_hash: [u8; 32],
    /// Every rail reads it.
    pub tracking: BoundRoot,
    tracking_pool: TrackingPoolRead,
    row_entries: Vec<u32>,
    output_entries: Vec<u32>,
    /// Bound on a ring with own records off the delegate rails, `None` leaves the own root zero.
    pub own: Option<BoundRoot>,
    pub curator: Option<BoundRoot>,
    /// `None` is the unopened pool of a key whose queries are all off.
    own_pool: Option<RecordPoolRead>,
    curator_pool: Option<RecordPoolRead>,
    sender_entries: Vec<OwnerEntry>,
    owner_entries: Vec<OwnerEntry>,
    asset_entries: Vec<PoolEntry>,
    /// One per input slot of the key, past every payment in the request.
    input_asset_entries: Vec<PoolEntry>,
    public_asset_entries: Vec<u32>,
    pub approval: ApprovalMask,
    /// Empty while the ring reads no own records, the circuit then bounds no outflow.
    pub charged_outflows: Vec<OwnerDebit>,
}

pub(super) struct PolicyRead<'a> {
    pub token_owner_hint: Option<Address>,
    pub config: &'a CustomRingConfig,
    pub inputs: &'a SppProofInputs,
    pub public: &'a PublicSlots,
    pub salts: &'a KnownSalts,
    pub planner: TransferPlanner<'a>,
    /// The plan a relayed owner sealed under, `None` on a frame sealed after its read.
    pub sealed: Option<PlannedTransfer>,
}

#[derive(Default)]
struct PlannedEntries {
    senders: Vec<OwnerEntry>,
    output_owners: Vec<OwnerEntry>,
    output_assets: Vec<PoolEntry>,
    withdrawal_owners: Vec<OwnerEntry>,
    withdrawal_assets: Vec<PoolEntry>,
    public_assets: Vec<u32>,
    input_assets: Vec<PoolEntry>,
}

impl PlannedEntries {
    fn slotted(self, slots: usize) -> (Vec<OwnerEntry>, Vec<PoolEntry>) {
        let mut owners = self.output_owners;
        let mut assets = self.output_assets;
        owners.resize(slots, OwnerEntry::default());
        assets.resize(slots, PoolEntry::default());
        owners.extend(self.withdrawal_owners);
        assets.extend(self.withdrawal_assets);
        (owners, assets)
    }
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        let policy = self.config.account();
        let read = RootRead::transfer(policy, self.rail().is_delegate());
        let (withdrawals, spl_withdrawal_owners) = match read {
            RootRead::None => (Vec::new(), Vec::new()),
            RootRead::Own | RootRead::Policy => {
                read_withdrawals(
                    client,
                    &self.inputs.external_data.interface_transfers,
                    self.token_owner_hint,
                )
                .await?
            }
        };
        let pinned = match read {
            RootRead::Policy => Some(PinnedPolicy::of(policy)?),
            RootRead::Own | RootRead::None => None,
        };
        let gates = pinned.as_ref().map_or_else(SourceGates::default, |pinned| {
            SourceGates::of(&pinned.sources)
        });
        let live_rows = self.owner_rows()?;
        let live_owners = self.output_owners()?;
        let tracking = BoundRoot::tracking(policy, client).await?;
        let ring_owners = self.ring_owners()?;
        let mut tracked = PoolSubjects::default();
        let mut row_entries: Vec<u32> = live_rows
            .iter()
            .map(|row| tracked.index(Some(*row)))
            .collect();
        let mut output_entries: Vec<u32> = ring_owners
            .iter()
            .map(|owner| tracked.index(*owner))
            .collect();
        // Every screened owner's row decides the key width.
        let rows_read = match gates.any_salted() {
            true => {
                for owner in live_owners
                    .iter()
                    .flatten()
                    .chain(withdrawals.iter().map(|w| &w.owner))
                {
                    tracked.index(Some(*owner));
                }
                let members = tracked.opened();
                let read = TrackingRead {
                    root: tracking,
                    members,
                    openings: members.len(),
                };
                Some(read.read(client).await?)
            }
            false => None,
        };
        let live_assets = self.output_assets()?;
        let input_assets = self.input_assets()?;
        let public_assets = self.public.asset_fields()?;
        let mut plan = RecordPlan::new(gates);
        let mut planned = EntryPlan {
            read,
            rows: &live_rows,
            owners: &live_owners,
            assets: &live_assets,
            input_assets: &input_assets,
            withdrawals: &withdrawals,
            public_assets: &public_assets,
            tracked: &tracked,
            rows_read: rows_read.as_ref(),
            salts: self.salts,
        }
        .plan(&mut plan)?;
        // A direct frame and a relayed one select the same key from the same read. A relayed seal
        // carries over only where that key opens its stream, else the owner seals again.
        let read_plan = self.planner.plan(plan.pools(&tracked))?;
        let transfer_plan = match self.sealed {
            Some(sealed) => sealed.rekeyed(read_plan)?,
            None => read_plan,
        };
        let circuit = transfer_plan.key.circuit;
        let RingCircuit::Transfer {
            outputs,
            inputs: input_slots,
            ..
        } = circuit
        else {
            return Err(RingError::UncataloguedCircuit(circuit));
        };
        let slots = usize::from(outputs);
        let widths = circuit
            .record_pools()
            .ok_or(RingError::UnpinnedProvingKey(circuit))?;
        let capacity = circuit.owners().map_or(0, usize::from);
        let mut rows = live_rows;
        rows.resize(capacity, [0; 32]);
        row_entries.resize(capacity, 0);
        output_entries.resize(slots, 0);
        let tracking_pool = TrackingRead {
            root: tracking,
            members: tracked.opened(),
            openings: widths.tracking,
        }
        .read(client)
        .await?;
        self.check_input_keys(&tracking_pool)?;
        let sealed = self.check_output_keys(&tracking_pool, &ring_owners)?;
        RecipientViewingKeys {
            registry: tracking.registry,
            outputs: &sealed,
        }
        .check(client)
        .await?;
        let mut sender_entries = core::mem::take(&mut planned.senders);
        sender_entries.resize(capacity, OwnerEntry::default());
        let public_asset_entries = core::mem::take(&mut planned.public_assets);
        let mut input_asset_entries = core::mem::take(&mut planned.input_assets);
        input_asset_entries.resize(usize::from(input_slots), PoolEntry::default());
        let (owner_entries, asset_entries) = planned.slotted(slots);
        let mut inputs = PolicyInputs {
            plan: transfer_plan,
            widths,
            slots,
            read,
            rows,
            spl_withdrawal_owners,
            withdrawals,
            rules: EncodedRuleTable::default(),
            sources: SourceMap::default(),
            policy_hash: [0; 32],
            tracking,
            tracking_pool,
            row_entries,
            output_entries,
            own: None,
            curator: None,
            own_pool: None,
            curator_pool: None,
            sender_entries,
            owner_entries,
            asset_entries,
            input_asset_entries,
            public_asset_entries,
            approval: ApprovalMask::default(),
            charged_outflows: Vec::new(),
        };
        if read != RootRead::None {
            ScreenedRecords {
                spend: &self,
                plan: &plan,
                owners: &live_owners,
                assets: &live_assets,
                input_assets: &input_assets,
                public_assets: &public_assets,
                pinned: pinned.as_ref(),
            }
            .read(client, &mut inputs)
            .await?;
        }
        Ok(inputs)
    }

    fn rail(&self) -> RingRail {
        self.planner.subjects.rail
    }

    fn owner_rows(&self) -> Result<Vec<[u8; 32]>, RingError> {
        owner_rows(self.rail(), self.inputs)
    }

    fn ring_owners(&self) -> Result<Vec<Option<[u8; 32]>>, RingError> {
        self.inputs
            .output_utxos
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .filter(|_| output.ring_program_id.is_some() && !output.is_dummy())
                    .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                    .transpose()
                    .map_err(RingError::from)
            })
            .collect()
    }

    fn output_owners(&self) -> Result<Vec<Option<[u8; 32]>>, RingError> {
        self.inputs
            .output_utxos
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .filter(|_| !output.is_dummy())
                    .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                    .transpose()
                    .map_err(RingError::from)
            })
            .collect()
    }

    fn output_assets(&self) -> Result<Vec<Option<[u8; 32]>>, RingError> {
        self.inputs
            .output_utxos
            .iter()
            .map(|output| match output.is_dummy() {
                false => Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes())),
                true => Ok(None),
            })
            .collect()
    }

    /// One per published slot, the slots the circuit's input section opens. An address slot and padding read no asset.
    fn input_assets(&self) -> Result<Vec<Option<[u8; 32]>>, RingError> {
        self.inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .map(|input| match input.is_note() {
                false => Ok(None),
                true => Ok(Some(*Member::asset(&input.utxo.asset.asset)?.as_bytes())),
            })
            .collect()
    }

    /// A keyed ring note spends under its owner's enrolled key, a zero key waives the equality alone.
    fn check_input_keys(&self, pool: &TrackingPoolRead) -> Result<(), RingError> {
        for (index, input) in self.inputs.input_utxos.iter().enumerate() {
            if !input.is_note()
                || is_default_ring(input)
                || input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY
            {
                continue;
            }
            let member = input.utxo.owner.owner_proof_input_hash()?;
            if pool
                .record(&member)
                .is_none_or(|record| record.nullifier_pk != input.nullifier_pubkey)
            {
                return Err(RingError::InputKeyNotEnrolled { index });
            }
        }
        Ok(())
    }

    /// The outputs whose viewing key the owner's authorization must hold, a spending owner's outputs excluded.
    fn check_output_keys(
        &self,
        pool: &TrackingPoolRead,
        owners: &[Option<[u8; 32]>],
    ) -> Result<Vec<SealedOutput>, RingError> {
        let mut sealed = Vec::new();
        for (slot_index, (output, owner)) in self.inputs.output_utxos.iter().zip(owners).enumerate()
        {
            let (Some(address), Some(member)) = (output.owner_address, owner) else {
                continue;
            };
            let row = pool.record(member);
            OutputKey {
                row,
                nullifier_pk: &address.nullifier_pubkey,
                slot_index,
            }
            .check()?;
            // A spending owner holds every key it ever enrolled.
            let spends = self
                .inputs
                .input_utxos
                .iter()
                .any(|input| input.is_note() && input.utxo.owner == address.signing_pubkey);
            if row.is_some() && !spends {
                sealed.push(SealedOutput {
                    slot_index,
                    owner: Address::new_from_array(owner_key(&address.signing_pubkey)?),
                    viewing_u: address.viewing_pubkey.u(),
                });
            }
        }
        Ok(sealed)
    }
}

/// The distinct live input owners ascending, the delegate moves a zero-key note with no row.
pub(super) fn owner_rows(
    rail: RingRail,
    inputs: &SppProofInputs,
) -> Result<Vec<[u8; 32]>, RingError> {
    let delegate = rail.is_delegate();
    let mut rows = inputs
        .input_utxos
        .iter()
        .filter(|input| input.is_note())
        .filter(|input| !(delegate && input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY))
        .map(|input| Ok(input.utxo.owner.owner_proof_input_hash()?))
        .collect::<Result<Vec<_>, RingError>>()?;
    rows.sort_unstable();
    rows.dedup();
    Ok(rows)
}

struct EntryPlan<'a> {
    read: RootRead,
    rows: &'a [[u8; 32]],
    owners: &'a [Option<[u8; 32]>],
    assets: &'a [Option<[u8; 32]>],
    /// By published input slot.
    input_assets: &'a [Option<[u8; 32]>],
    withdrawals: &'a [PolicyWithdrawal],
    public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    tracked: &'a PoolSubjects,
    /// `None` off a table reading a salted list.
    rows_read: Option<&'a TrackingPoolRead>,
    salts: &'a KnownSalts,
}

impl EntryPlan<'_> {
    /// An owner opens a pool only under a policy.
    fn plan(self, plan: &mut RecordPlan) -> Result<PlannedEntries, RingError> {
        if self.read == RootRead::None {
            return Ok(PlannedEntries {
                public_assets: vec![0; N_PUBLIC_SLOTS],
                ..PlannedEntries::default()
            });
        }
        let screened = self.read == RootRead::Policy;
        let owner = |plan: &mut RecordPlan, member: [u8; 32]| -> Result<OwnerEntry, RingError> {
            let (tracking, salted) = match self.rows_read {
                Some(rows) => (
                    self.tracked.position(&member),
                    self.salts.salted_key(&member, rows.record(&member))?,
                ),
                None => (0, None),
            };
            Ok(plan.owner(OwnerQuery {
                member,
                tracking,
                salted,
            }))
        };
        let senders = self
            .rows
            .iter()
            .filter(|_| screened)
            .map(|row| owner(plan, *row))
            .collect::<Result<_, _>>()?;
        let mut planned = PlannedEntries {
            senders,
            ..PlannedEntries::default()
        };
        for (member, asset) in self.owners.iter().zip(self.assets) {
            planned
                .output_owners
                .push(match member.filter(|_| screened) {
                    Some(member) => owner(plan, member)?,
                    None => OwnerEntry::default(),
                });
            planned.output_assets.push(match asset {
                Some(asset) => plan.asset(*asset),
                None => PoolEntry::default(),
            });
        }
        for withdrawal in self.withdrawals {
            planned.withdrawal_owners.push(match screened {
                true => owner(plan, withdrawal.owner)?,
                false => OwnerEntry::default(),
            });
            planned.withdrawal_assets.push(plan.asset(withdrawal.asset));
        }
        planned.public_assets = self
            .public_assets
            .iter()
            .map(|asset| match *asset == [0; 32] {
                true => 0,
                false => plan.public_asset(*asset),
            })
            .collect();
        // A zero value input can name an asset no payment moves, only its own subject row screens
        // that note. The rows join the spend's pools, so key selection counts them. Thresholds read
        // no input asset, so an own read off a policy opens none and the circuit gates the slot off.
        planned.input_assets = self
            .input_assets
            .iter()
            .map(|asset| match asset.filter(|_| screened) {
                Some(asset) => plan.asset(asset),
                None => PoolEntry::default(),
            })
            .collect();
        Ok(planned)
    }
}

/// The thresholds read the own root on every read, the rules only under a policy.
struct ScreenedRecords<'a> {
    spend: &'a PolicyRead<'a>,
    plan: &'a RecordPlan,
    owners: &'a [Option<[u8; 32]>],
    assets: &'a [Option<[u8; 32]>],
    input_assets: &'a [Option<[u8; 32]>],
    public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pinned: Option<&'a PinnedPolicy>,
}

impl ScreenedRecords<'_> {
    async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
        inputs: &mut PolicyInputs,
    ) -> Result<(), RingError> {
        let Self {
            spend,
            plan,
            owners,
            assets,
            input_assets,
            public_assets,
            pinned,
        } = self;
        let policy = spend.config.account();
        let own = BoundRoot::own(policy, client).await?;
        let curator = match pinned {
            Some(_) => BoundRoot::curator(policy, client).await?,
            None => None,
        };
        let outputs = &spend.inputs.output_utxos;
        let own_pool = PoolRead {
            root: own,
            members: plan.own.opened(),
            openings: inputs.widths.own,
        }
        .read(client)
        .await?;
        let curator_pool = match curator {
            Some(curator) => Some(
                PoolRead {
                    root: curator,
                    members: plan.curator.opened(),
                    openings: inputs.widths.curator,
                }
                .read(client)
                .await?,
            ),
            None => None,
        };
        let mint_policy = |asset: &[u8; 32]| {
            own_pool
                .record(asset)
                .map_or(MintPolicy::EMPTY, |record| record.mint_policy)
        };
        let outflows = Outflows {
            senders: &inputs.rows,
            inputs: &spend.inputs.input_utxos,
            outputs,
            public_assets,
            public_gross: &spend.public.gross(),
        };
        if let Some(pinned) = pinned {
            let lists = |member: [u8; 32]| {
                let on = |pool: &RecordPoolRead, member: &[u8; 32]| {
                    pool.record(member).map_or(0, |record| record.lists)
                };
                plan.lists(
                    &member,
                    |member| on(&own_pool, member),
                    |member| curator_pool.as_ref().map_or(0, |pool| on(pool, member)),
                )
            };
            let subject =
                |ring: bool, owner: [u8; 32], asset: [u8; 32], amount: u64| OutputSubjects {
                    ring,
                    owner,
                    asset,
                    amount,
                    owner_lists: lists(owner),
                    asset_lists: lists(asset),
                    mint_policy: mint_policy(&asset),
                };
            let mut transfer_subjects = outputs
                .iter()
                .zip(owners.iter().zip(assets))
                .filter_map(|(output, (owner, asset))| {
                    Some(subject(
                        output.ring_program_id.is_some(),
                        (*owner)?,
                        (*asset)?,
                        output.amount,
                    ))
                })
                .collect::<Vec<_>>();
            transfer_subjects.extend(
                inputs
                    .withdrawals
                    .iter()
                    .map(|w| subject(false, w.owner, w.asset, w.amount)),
            );
            let ring_inputs = outflows.ring_inputs()?;
            // The circuit screens the rows and the payments apart, in that order. A public-funded
            // transfer with no live row still owes the payment rules, and a stand-in row would put
            // a deposit under the sender rules. A co-owner who receives nothing is screened too.
            let senders: Vec<RecordLists> = inputs
                .rows
                .iter()
                .filter(|sender| **sender != [0; 32])
                .map(|sender| lists(*sender))
                .collect();
            pinned.table.evaluate_senders(&pinned.sources, &senders)?;
            pinned.table.evaluate_payments(
                &pinned.sources,
                PaymentSubjects {
                    ring_inputs: &ring_inputs,
                    outputs: &transfer_subjects,
                },
            )?;
            let input_lists: Vec<RecordLists> = input_assets
                .iter()
                .flatten()
                .map(|asset| lists(*asset))
                .collect();
            pinned
                .table
                .evaluate_input_assets(&pinned.sources, &input_lists)?;
            inputs.rules = policy.rules;
            inputs.sources = pinned.sources;
            inputs.policy_hash = pinned.policy_hash;
        }
        let flows = outflows.flows()?;
        Outflows::check_caps(&flows, mint_policy)?;
        let public_gross: Vec<PublicGross> = public_assets
            .iter()
            .zip(spend.public.gross())
            .filter(|(asset, _)| **asset != [0; 32])
            .map(|(asset, gross)| PublicGross {
                asset: *asset,
                gross,
            })
            .collect();
        inputs.approval = ApprovalMask::new(
            ApprovalInputs {
                flows: &flows,
                public_gross: &public_gross,
            }
            .mask(mint_policy)
            .bits(),
        )
        .ok_or(CustomRingError::FlagNotAllowed)?;
        inputs.charged_outflows = flows;
        inputs.own = Some(own);
        inputs.curator = curator;
        inputs.own_pool = Some(own_pool);
        inputs.curator_pool = curator_pool;
        Ok(())
    }
}

pub(super) struct PolicyProving<'a> {
    pub ring_id: [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyInputs {
    pub fn circuit(&self) -> RingCircuit {
        self.plan.key.circuit
    }

    pub fn screened(&self) -> bool {
        self.policy_hash != [0; 32]
    }

    pub fn roots(&self) -> TransferRoots {
        TransferRoots {
            policy_hash: self.policy_hash,
            own_root: self.own.map_or([0; 32], |own| own.root),
            curator_root: self.curator.map_or([0; 32], |curator| curator.root),
            tracking_root: self.tracking.root,
        }
    }

    pub fn withdrawal_hash(&self) -> Result<[u8; 32], RingError> {
        Ok(custom_ring_interface::policy_withdrawal_hash(
            &self.withdrawals,
        )?)
    }

    pub fn tracking_params(&self) -> Result<TrackingParams, RingError> {
        Ok(TrackingParams {
            tracking_root: self.tracking.root,
            pool: self
                .tracking_pool
                .pool()
                .clone()
                .padded(self.widths.tracking)?,
            row_entries: self.row_entries.clone(),
            output_entries: self.output_entries.clone(),
        })
    }

    pub fn params(&self, proving: &PolicyProving<'_>) -> Result<PolicyParams<'_>, RingError> {
        let capacity = usize::from(
            self.circuit()
                .withdrawals()
                .ok_or(RingError::UncataloguedCircuit(self.circuit()))?,
        );
        let outputs = self.slots;
        let roots = self.roots();
        let mut withdrawals = self.withdrawals.clone();
        withdrawals.resize(capacity, PolicyWithdrawal::default());
        let mut owner_entries = self.owner_entries.clone();
        let mut asset_entries = self.asset_entries.clone();
        owner_entries.resize(outputs + capacity, OwnerEntry::default());
        asset_entries.resize(outputs + capacity, PoolEntry::default());
        asset_entries.extend_from_slice(&self.input_asset_entries);
        Ok(PolicyParams {
            withdrawal_count: self.withdrawals.len() as u8,
            withdrawal_hash: self.withdrawal_hash()?,
            withdrawals: withdrawals
                .iter()
                .map(|w| PolicyWithdrawalRequest {
                    owner: w.owner,
                    asset: w.asset,
                    amount: right_align(&w.amount.to_be_bytes()),
                })
                .collect(),
            policy_hash: self.policy_hash,
            ring_id: proving.ring_id,
            own_root: roots.own_root,
            curator_root: roots.curator_root,
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amounts.to_vec(),
            public_gross: proving.public_gross.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            pools: RecordPools {
                own: pool_at_width(self.own_pool.as_ref(), self.widths.own)?,
                curator: pool_at_width(self.curator_pool.as_ref(), self.widths.curator)?,
            },
            sender_entries: self.sender_entries.clone(),
            owner_entries,
            asset_entries,
            public_asset_entries: self.public_asset_entries.clone(),
        })
    }
}

/// Resolve token owners once; the program checks the snapshot again at execution.
async fn read_withdrawals<R: AsyncRpc + ?Sized>(
    client: &R,
    transfers: &[spr_transaction::instructions::transact::SettlementTransfer],
    hint: Option<Address>,
) -> Result<(Vec<PolicyWithdrawal>, Vec<[u8; 32]>), RingError> {
    use spr_interface::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
    use spr_transaction::instructions::transact::SettlementTransfer;
    let mut payments = Vec::new();
    let mut owners = Vec::new();
    for transfer in transfers.iter().filter(|t| !t.is_deposit()) {
        let payment = match *transfer {
            SettlementTransfer::Sol {
                user_sol_account,
                amount,
                ..
            } => PolicyWithdrawal::new(user_sol_account.as_array(), None, amount)?,
            SettlementTransfer::Spl {
                mint,
                user_spl_token,
                amount,
                ..
            } => {
                let invalid = || RingError::AnonymousExitTokenAccountInvalid(user_spl_token);
                let owner = match client.get_account(user_spl_token).await? {
                    Some(account) => {
                        if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID]
                            .contains(account.owner.as_array())
                        {
                            return Err(invalid());
                        }
                        let token =
                            custom_ring_interface::TokenAccountState::unpack(&account.data)?;
                        if token.mint != mint.to_bytes() {
                            return Err(invalid());
                        }
                        *token.control.owner()
                    }
                    None => {
                        let owner = hint.ok_or_else(invalid)?;
                        let program = client
                            .get_account(mint)
                            .await?
                            .map(|a| a.owner)
                            .ok_or_else(invalid)?;
                        if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID]
                            .contains(program.as_array())
                            || spr_interface::pda::associated_token_address_with_program(
                                &owner, &mint, &program,
                            ) != user_spl_token
                        {
                            return Err(invalid());
                        }
                        owner.to_bytes()
                    }
                };
                owners.push(owner);
                PolicyWithdrawal::new(&owner, Some(mint.as_array()), amount)?
            }
        };
        payments.push(payment);
    }
    Ok((payments, owners))
}
