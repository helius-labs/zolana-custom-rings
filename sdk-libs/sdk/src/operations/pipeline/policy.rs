//! The policy half of a ring transfer, every record read under a root the statement binds.

use std::collections::BTreeSet;

use custom_ring_interface::{
    key_catalog::RingCircuit, MemberRegistry, PolicyKey, PolicyStatement, RingAccount, RingMode,
    RingRail,
};
use serde::Serialize;
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::instructions::transact::SppProofInputs;
use zolana_ring_client::{records::RecordPoolRead, AsyncRingIndexer};
use zolana_ring_policy::{
    EncodedRuleTable, Member, OutputSubjects, RecordLists, SourceMap, TransferSubjects,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    limits::Outflows,
    prover::{to_instruction_proof, RingRequest},
    records::PoolRead,
    request::{
        DelegatePolicy, MemberPolicy, Opening, OutputOpening, PolicyParams, PolicyTable, PoolEntry,
        RecordPools,
    },
    submission::BoundRoot,
    CustomRing, CustomRingConfig, PinnedPolicy, RingError,
};

#[derive(Clone, Copy)]
struct OutputOwner {
    member: [u8; 32],
    nullifier_pk: [u8; 32],
}

pub(super) struct PolicyInputs {
    circuit: RingCircuit,
    pools: custom_ring_interface::key_catalog::RecordPools,
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    pub policy_hash: [u8; 32],
    pub own: BoundRoot,
    pub curator: Option<BoundCurator>,
    own_pool: RecordPoolRead,
    curator_pool: Option<RecordPoolRead>,
    sender_entry: PoolEntry,
    owner_entries: Vec<PoolEntry>,
    asset_entries: Vec<PoolEntry>,
    public_asset_entries: Vec<u32>,
    /// The escrowed key ciphertext hash of every UTXO output's owner, under key escrow.
    ct_hashes: Vec<Option<[u8; 32]>>,
    /// One per output slot, zero on a dummy and on the anonymous rail.
    pub recipients: Vec<[u8; 32]>,
    pub approval_required: bool,
    pub key_escrow: bool,
}

#[derive(Clone, Copy)]
pub(super) struct BoundCurator {
    pub address: Address,
    pub root: BoundRoot,
}

pub(super) struct PolicyRead<'a> {
    pub token_owner_hint: Option<Address>,
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    pub n_in: u8,
    pub n_out: u8,
    /// The owner identity the rules read as the sender.
    pub sender: [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [i128; N_PUBLIC_SLOTS],
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        let registry = self.ring.require_registry(client).await?;
        let pinned = PinnedPolicy::of(&registry)?;
        let own = BoundRoot::current(self.ring, &registry);
        let curator = match pinned.curator {
            Some(address) => Some(BoundCurator::read(client, address).await?),
            None => None,
        };
        let (withdrawals, spl_withdrawal_owners) = read_withdrawals(
            client,
            &self.inputs.external_data.interface_transfers,
            self.token_owner_hint,
        )
        .await?;
        let outputs = &self.inputs.output_utxos;
        let circuit = RingCircuit::policy(
            self.rail,
            self.n_in,
            self.n_out,
            withdrawals.len() as u8,
            curator.is_none(),
        );
        let pools = circuit
            .record_pools()
            .ok_or(RingError::UnpinnedProvingKey(circuit))?;
        let owners = outputs
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .map(|owner| {
                        Ok::<_, RingError>(OutputOwner {
                            member: owner.signing_pubkey.owner_proof_input_hash()?,
                            nullifier_pk: owner.nullifier_pubkey,
                        })
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let assets = outputs
            .iter()
            .map(|output| match output.is_dummy() {
                false => Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes())),
                _ => Ok(None),
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let publishes = self.rail.publishes_recipients();
        let recipients = owners
            .iter()
            .map(|owner| match owner {
                Some(owner) if publishes => owner.member,
                _ => [0; 32],
            })
            .collect();
        let mut subjects = PoolSubjects::default();
        let entry = |index| pool_entry(index, curator.as_ref());
        let sender_entry = entry(subjects.index(Some(self.sender)));
        let mut owner_entries = Vec::with_capacity(outputs.len() + withdrawals.len());
        let mut asset_entries = Vec::with_capacity(outputs.len() + withdrawals.len());
        let payments = owners
            .iter()
            .zip(&assets)
            .map(|(owner, asset)| (owner.map(|owner| owner.member), *asset))
            .chain(withdrawals.iter().map(|w| (Some(w.owner), Some(w.asset))));
        for (owner, asset) in payments {
            owner_entries.push(entry(subjects.index(owner)));
            asset_entries.push(entry(subjects.index(asset)));
        }
        // Public assets resolve in the own pool alone.
        let curator_members = subjects.members.clone();
        let public_asset_entries = match self.rail {
            RingRail::Delegate => Vec::new(),
            RingRail::Confidential | RingRail::Anonymous => self
                .public_assets
                .iter()
                .map(|asset| subjects.index((*asset != [0; 32]).then_some(*asset)))
                .collect(),
        };
        let own_pool = PoolRead {
            root: own,
            members: &subjects.members,
            openings: pools.own,
        }
        .read(client)
        .await?;
        let curator_pool = match curator {
            Some(curator) => Some(
                PoolRead {
                    root: curator.root,
                    members: &curator_members,
                    openings: pools.curator,
                }
                .read(client)
                .await?,
            ),
            None => None,
        };
        let lists = |member: [u8; 32]| {
            let on = |pool: &RecordPoolRead| pool.record(&member).map_or(0, |record| record.lists);
            RecordLists {
                own: on(&own_pool),
                curator: curator_pool.as_ref().map_or(0, on),
            }
        };
        let mint_policy = |asset: &[u8; 32]| {
            own_pool
                .record(asset)
                .map_or(zolana_ring_policy::MintPolicy::EMPTY, |record| {
                    record.mint_policy
                })
        };
        let mut transfer_subjects = outputs
            .iter()
            .zip(&owners)
            .filter_map(|(output, owner)| owner.map(|owner| (output, owner)))
            .map(|(output, owner)| {
                let asset = *Member::asset(&output.asset.asset)?.as_bytes();
                Ok(OutputSubjects {
                    owner: owner.member,
                    asset,
                    amount: output.amount,
                    owner_lists: lists(owner.member),
                    asset_lists: lists(asset),
                    mint_policy: mint_policy(&asset),
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        transfer_subjects.extend(withdrawals.iter().map(|w| OutputSubjects {
            owner: w.owner,
            asset: w.asset,
            amount: w.amount,
            owner_lists: lists(w.owner),
            asset_lists: lists(w.asset),
            mint_policy: mint_policy(&w.asset),
        }));
        pinned.table.admit(
            &pinned.sources,
            &TransferSubjects {
                sender: lists(self.sender),
                outputs: &transfer_subjects,
            },
        )?;
        let key_escrow = self.config.mode == RingMode::ConfidentialEscrow;
        let ct_hashes = owners
            .iter()
            .map(|owner| {
                owner
                    .filter(|_| key_escrow)
                    .map(|owner| -> Result<[u8; 32], RingError> {
                        own_pool
                            .escrowed_ct_hash(&owner.member, &owner.nullifier_pk)?
                            .ok_or(RingError::UnregisteredOutputKey {
                                owner: Member::from_bytes(owner.member)?,
                            })
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let limit_assets: BTreeSet<_> = assets
            .iter()
            .flatten()
            .copied()
            .chain(
                self.public_assets
                    .iter()
                    .copied()
                    .filter(|asset| *asset != [0; 32]),
            )
            .collect();
        let limits = limit_assets
            .iter()
            .filter_map(|asset| {
                let policy = mint_policy(asset);
                (policy.cap != 0 || policy.cosign_above != 0).then(|| {
                    let member = Member::from_bytes(*asset).expect("verified record member");
                    zolana_ring_policy::OutflowLimit::of(&member)
                        .with_cap(policy.cap)
                        .with_cosign_above(policy.cosign_above)
                })
            })
            .collect::<Vec<_>>();
        let approval_required = match self.rail {
            RingRail::Delegate => false,
            RingRail::Confidential | RingRail::Anonymous => Outflows {
                sender: self.sender,
                ring: self.ring.program_id(),
                outputs,
                public_assets: self.public_assets,
                public_amounts: self.public_amounts,
            }
            .approval_required(&limits)?,
        };
        Ok(PolicyInputs {
            circuit,
            pools,
            withdrawals,
            spl_withdrawal_owners,
            rules: registry.rules,
            sources: pinned.sources,
            policy_hash: pinned.policy_hash,
            own,
            curator,
            own_pool,
            curator_pool,
            sender_entry,
            owner_entries,
            asset_entries,
            public_asset_entries,
            ct_hashes,
            recipients,
            approval_required,
            key_escrow,
        })
    }
}

/// Distinct pool members in first use order, an absent subject takes index 0.
#[derive(Default)]
struct PoolSubjects {
    members: Vec<[u8; 32]>,
}

impl PoolSubjects {
    fn index(&mut self, member: Option<[u8; 32]>) -> u32 {
        let Some(member) = member else {
            return 0;
        };
        let index = match self.members.iter().position(|known| *known == member) {
            Some(index) => index,
            None => {
                self.members.push(member);
                self.members.len() - 1
            }
        };
        // At most `MAX_RING_MEMBER_PAGE_LIMIT` members, the pool read refuses more.
        index as u32
    }
}

/// The subject at `index` in both pools, a key without a curator pool reads none.
fn pool_entry(index: u32, curator: Option<&BoundCurator>) -> PoolEntry {
    PoolEntry {
        own: index,
        curator: curator.map(|_| index).into_iter().collect(),
    }
}

pub(crate) struct PolicyRequest<'a> {
    pub circuit: RingCircuit,
    pub public_input_hash: [u8; 32],
    pub body: PolicyBody<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum PolicyBody<'a> {
    Member(Box<MemberPolicy<'a>>),
    Delegate(Box<DelegatePolicy<'a>>),
}

pub(super) struct PolicyProving<'a> {
    pub ring_id: [u8; 32],
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    pub private_tx_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    /// The owner identity, the anonymous rail's sender commitment, zero on the delegate rail.
    pub sender: [u8; 32],
    pub sender_pk_hash: [u8; 32],
    pub public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyInputs {
    pub fn curator_root(&self) -> [u8; 32] {
        self.curator.map_or([0; 32], |curator| curator.root.root)
    }

    pub fn statement(&self, proving: &PolicyProving<'_>) -> Result<[u8; 32], RingError> {
        let key = proving.rail.policy_key();
        let delegate = key == PolicyKey::Delegate;
        Ok(PolicyStatement {
            withdrawal_hash: &custom_ring_interface::policy_withdrawal_hash(&self.withdrawals)?,
            key,
            private_tx_hash: &proving.private_tx_hash,
            policy_hash: &self.policy_hash,
            ring_id: &proving.ring_id,
            approval_required: self.approval_required,
            key_escrow: delegate || self.key_escrow,
            own_root: &self.own.root,
            curator_root: &self.curator_root(),
            sender: &proving.sender,
            recipients: &self.recipients,
            public_assets: &proving.public_assets,
            public_amounts: &proving.public_amount_fields,
        }
        .hash()?)
    }

    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        proving: &PolicyProving<'_>,
    ) -> Result<custom_ring_interface::CustomRingProof, RingError> {
        let request = self.request(proving)?;
        let proof = RingRequest::new(request.circuit, &request.body)?
            .prove(client, request.public_input_hash)
            .await?;
        to_instruction_proof(proof)
    }

    /// The circuit the shape and the pools select and the body it proves.
    pub fn request(&self, proving: &PolicyProving<'_>) -> Result<PolicyRequest<'_>, RingError> {
        let inputs = proving.inputs;
        let circuit = self.circuit;
        let pools = self.pools;
        let own_pool = self.own_pool.pool().clone().padded(pools.own)?;
        let curator_pool = self
            .curator_pool
            .as_ref()
            .map(|read| read.pool().clone().padded(pools.curator))
            .transpose()?;
        let public_input_hash = self.statement(proving)?;
        let outputs = inputs
            .output_utxos
            .iter()
            .zip(&self.ct_hashes)
            .map(|(output, ct_hash)| {
                Ok(OutputOpening {
                    opening: Opening::output(output, inputs.output_tree_id)?,
                    ct_hash: *ct_hash,
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let address_nullifiers: Vec<[u8; 32]> = inputs
            .input_utxos
            .iter()
            .map(|input| input.private_tx_address_nullifier())
            .collect();
        let capacity = usize::from(custom_ring_interface::key_catalog::withdrawal_capacity(
            self.withdrawals.len() as u8,
        ));
        let mut withdrawals = self.withdrawals.clone();
        withdrawals.resize(capacity, custom_ring_interface::PolicyWithdrawal::default());
        let mut owner_entries = self.owner_entries.clone();
        let mut asset_entries = self.asset_entries.clone();
        let absent = pool_entry(0, self.curator.as_ref());
        owner_entries.resize(outputs.len() + capacity, absent.clone());
        asset_entries.resize(outputs.len() + capacity, absent);
        let params = PolicyParams {
            withdrawal_count: self.withdrawals.len() as u8,
            withdrawal_hash: custom_ring_interface::policy_withdrawal_hash(&self.withdrawals)?,
            withdrawals: withdrawals
                .iter()
                .map(|w| crate::request::PolicyWithdrawalRequest {
                    owner: w.owner,
                    asset: w.asset,
                    amount: spr_hasher::primitives::right_align(&w.amount.to_be_bytes()),
                })
                .collect(),
            private_tx_hash: proving.private_tx_hash,
            policy_hash: self.policy_hash,
            ring_id: proving.ring_id,
            own_root: self.own.root,
            curator_root: self.curator_root(),
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amount_fields.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            address_chain: create_nonzero_hash_chain_from_slice(&address_nullifiers)?,
            private_tx_blinding: proving.private_tx_blinding,
            outputs,
            recipients: &self.recipients,
            sender_pk_hash: proving.sender_pk_hash,
            pools: RecordPools {
                own: own_pool,
                curator: curator_pool,
            },
            sender_entry: self.sender_entry.clone(),
            owner_entries,
            asset_entries,
            public_asset_entries: self.public_asset_entries.clone(),
        };
        let body = match proving.rail {
            RingRail::Delegate => PolicyBody::Delegate(Box::new(DelegatePolicy {
                public_input_hash,
                inputs: inputs
                    .input_utxos
                    .iter()
                    .map(Opening::input)
                    .collect::<Result<_, _>>()?,
                policy: params,
            })),
            RingRail::Confidential | RingRail::Anonymous => {
                let input_hashes: Vec<[u8; 32]> = inputs
                    .input_utxos
                    .iter()
                    .map(|input| input.private_tx_input_hash())
                    .collect();
                PolicyBody::Member(Box::new(MemberPolicy {
                    public_input_hash,
                    anonymous: proving.rail == RingRail::Anonymous,
                    approval_required: self.approval_required,
                    key_escrow: self.key_escrow,
                    sender: proving.sender,
                    input_chain: create_nonzero_hash_chain_from_slice(&input_hashes)?,
                    policy: params,
                }))
            }
        };
        Ok(PolicyRequest {
            circuit,
            public_input_hash,
            body,
        })
    }
}

impl BoundCurator {
    async fn read<R: AsyncRpc + ?Sized>(client: &R, address: Address) -> Result<Self, RingError> {
        let account = client
            .get_account(address)
            .await?
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        let registry = MemberRegistry::from_data(&account.data)
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        Ok(Self {
            address,
            root: BoundRoot::current(CustomRing::new(account.owner), registry),
        })
    }
}

/// Resolve token owners once; the program checks the snapshot again at execution.
async fn read_withdrawals<R: AsyncRpc + ?Sized>(
    client: &R,
    transfers: &[spr_transaction::instructions::transact::SettlementTransfer],
    hint: Option<Address>,
) -> Result<(Vec<custom_ring_interface::PolicyWithdrawal>, Vec<[u8; 32]>), RingError> {
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
            } => custom_ring_interface::PolicyWithdrawal::new(
                user_sol_account.as_array(),
                None,
                amount,
            )?,
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
                custom_ring_interface::PolicyWithdrawal::new(&owner, Some(mint.as_array()), amount)?
            }
        };
        payments.push(payment);
    }
    Ok((payments, owners))
}
