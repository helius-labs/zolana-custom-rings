//! Instructions of the ring authority and the upgrade authority.

use custom_ring_interface::SYSTEM_PROGRAM_ID;
use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, InitializeIxData, InstructionTag, PolicyBindingIxData,
    PolicySourceIxData, PolicyTableIxData, RingKind, SetCoSignerRecordIxData, SetPausedIxData,
    SourceSpec, UpdatePolicyIxData,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::ComputeBudgetConfig;
use spr_interface::pda;
use spr_keypair::X25519Pubkey;
use wincode::{config::DefaultConfig, SchemaWrite};
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, SourceMap};

use crate::{submission::check_transaction_size, CustomRing, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    /// A `StorageRegistry` of any authority.
    Curator(Address),
}

/// The upgrade authority signs and becomes the ring authority, SPP registers the ring in the same instruction.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct Initialize<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub auditor_pubkey: X25519Pubkey,
    pub kind: RingKind,
    /// Required on a policy ring, an audit-only ring takes it for its withdrawal exemptions.
    pub policy: Option<InitialPolicy<'a>>,
}

/// An audit-only ring takes an empty table.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct InitialPolicy<'a> {
    pub records: PolicyRecords,
    pub table: PolicyTable<'a>,
}

/// Both keys sign, a mistyped address cannot strand the config.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateAuthority {
    pub ring: CustomRing,
    pub authority: Address,
    pub new_authority: Address,
}

/// Creates the signer's record or rescopes it.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetCoSigner {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub signer: Address,
    pub scope: CoSignScope,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearCoSigner {
    pub ring: CustomRing,
    pub authority: Address,
    pub signer: Address,
    pub rent_recipient: Address,
}

/// The delegate signs and is permanent.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetDelegate {
    pub ring: CustomRing,
    pub authority: Address,
    pub delegate: Address,
}

#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct UpdatePolicy<'a> {
    pub ring: CustomRing,
    pub authority: Address,
    pub update: PolicyUpdate<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum PolicyUpdate<'a> {
    /// Replaces the pinned table and the complete source map.
    Rules(PolicyTable<'a>),
    /// Re-points one referenced list, the rows stay.
    Source {
        list_id: ListId,
        source: SourceOwner,
    },
    /// Own lists read the new records once `SyncRoots` mirrors them.
    Records(PolicyRecords),
}

/// A referenced list not shared reads the ring's own records.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct PolicyTable<'a> {
    pub rules: &'a RuleTable,
    /// Each list's curator `StorageRegistry`.
    pub shared_sources: &'a [(ListId, Address)],
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRecords {
    pub records: Address,
    /// The records may answer to it beside the config authority.
    pub storage_authority: Address,
}

struct TablePayload {
    data: PolicyTableIxData,
    curators: Vec<AccountMeta>,
}

impl Initialize<'_> {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(ring.config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        accounts.extend(ring.upgrade_metas());
        accounts.extend([
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring.ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ]);
        let policy = match self.policy {
            Some(InitialPolicy { records, table }) => {
                let TablePayload { data, curators } = table.payload()?;
                accounts.extend([
                    AccountMeta::new(ring.policy_pda(), false),
                    AccountMeta::new_readonly(records.records, false),
                ]);
                accounts.extend(curators);
                Some(PolicyBindingIxData {
                    storage_authority: records.storage_authority,
                    table: data,
                })
            }
            None => None,
        };
        let data = tagged(
            tag::INITIALIZE,
            &InitializeIxData {
                auditor_pubkey: *self.auditor_pubkey.as_bytes(),
                kind: self.kind,
                policy,
            },
        )?;
        SizedInstruction {
            payer: &self.payer,
            instruction_tag: InstructionTag::Initialize,
            instruction: ring.ix(accounts, data),
        }
        .check()
    }
}

impl UpdateAuthority {
    pub fn instruction(self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.new_authority, true),
            AccountMeta::new(self.ring.config_pda(), false),
        ];
        self.ring.ix(accounts, vec![tag::UPDATE_AUTHORITY])
    }
}

impl SetCoSigner {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let body = SetCoSignerRecordIxData {
            signer: self.signer,
            scope: self.scope.bits(),
        };
        body.check()?;
        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(ring.config_pda(), false),
            AccountMeta::new(ring.co_signer_pda(&self.signer), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        Ok(ring.ix(accounts, tagged(tag::SET_CO_SIGNER, &body)?))
    }
}

impl ClearCoSigner {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(ring.config_pda(), false),
            AccountMeta::new(ring.co_signer_pda(&self.signer), false),
            AccountMeta::new(self.rent_recipient, false),
        ];
        ring.ix(accounts, vec![tag::CLEAR_CO_SIGNER])
    }
}

impl SetDelegate {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let mut accounts = ring.config_write_metas(self.authority);
        accounts.extend([
            AccountMeta::new_readonly(self.delegate, true),
            AccountMeta::new_readonly(ring.policy_pda(), false),
        ]);
        ring.ix(accounts, vec![tag::SET_DELEGATE])
    }
}

impl UpdatePolicy<'_> {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let mut accounts = ring.policy_write_metas(self.authority);
        let update = match self.update {
            PolicyUpdate::Rules(table) => {
                let TablePayload { data, curators } = table.payload()?;
                accounts.extend(curators);
                UpdatePolicyIxData::Rules(data)
            }
            PolicyUpdate::Source { list_id, source } => {
                if let SourceOwner::Curator(curator) = source {
                    accounts.push(AccountMeta::new_readonly(curator, false));
                }
                UpdatePolicyIxData::Source(PolicySourceIxData {
                    list_id: list_id as u8,
                    source: u8::from(matches!(source, SourceOwner::Curator(_))),
                })
            }
            PolicyUpdate::Records(records) => {
                accounts.push(AccountMeta::new_readonly(records.records, false));
                UpdatePolicyIxData::Records {
                    storage_authority: records.storage_authority,
                }
            }
        };
        let data = tagged(tag::UPDATE_POLICY, &update)?;
        SizedInstruction {
            payer: &self.authority,
            instruction_tag: InstructionTag::UpdatePolicy,
            instruction: ring.ix(accounts, data),
        }
        .check()
    }
}

impl PolicyTable<'_> {
    /// Curator registries follow in first-use order.
    fn payload(&self) -> Result<TablePayload, RingError> {
        let Self {
            rules,
            shared_sources,
        } = *self;
        let referenced = rules.referenced();
        let mut named = ListSet::EMPTY;
        for &(list_id, _) in shared_sources {
            if !referenced.contains(list_id) {
                return Err(RingError::UnreferencedList(list_id));
            }
            if named.contains(list_id) {
                return Err(RingError::DuplicateSharedSource(list_id));
            }
            named = named.union(ListSet::single(list_id));
        }
        let mut curators: Vec<Address> = Vec::new();
        let mut entries = Vec::new();
        let sources: Vec<SourceSpec> = referenced
            .iter()
            .map(|list_id| {
                let shared = shared_sources.iter().find(|(shared, _)| *shared == list_id);
                entries.push((
                    list_id,
                    shared.map_or([0; 32], |(_, curator)| curator.to_bytes()),
                ));
                let source = shared.map_or(0, |&(_, curator)| {
                    let index = curators.iter().position(|known| *known == curator);
                    1 + index.unwrap_or_else(|| {
                        curators.push(curator);
                        curators.len() - 1
                    }) as u8
                });
                SourceSpec {
                    list_id: list_id as u8,
                    source,
                }
            })
            .collect();
        // The program stores one curator, the source map refuses a second.
        rules.encode().validate(&SourceMap::new(&entries)?)?;
        Ok(TablePayload {
            data: PolicyTableIxData {
                sources,
                rules: rules.rules().iter().map(Rule::encoded).collect(),
            },
            curators: curators
                .iter()
                .map(|curator| AccountMeta::new_readonly(*curator, false))
                .collect(),
        })
    }
}

impl CustomRing {
    pub fn pause(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: true })
    }

    pub fn resume(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: false })
    }

    fn set_paused(
        self,
        authority: Address,
        state: SetPausedIxData,
    ) -> Result<Instruction, RingError> {
        let accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        Ok(self.ix(accounts, tagged(tag::SET_PAUSED, &state)?))
    }

    fn ix(self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program_id(),
            accounts,
            data,
        }
    }

    fn upgrade_metas(self) -> [AccountMeta; 2] {
        [
            AccountMeta::new_readonly(self.program_id(), false),
            AccountMeta::new_readonly(self.program_data_pda(), false),
        ]
    }

    fn config_write_metas(self, authority: Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
        ]
    }

    fn policy_write_metas(self, authority: Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.policy_pda(), false),
        ]
    }
}

#[must_use]
struct SizedInstruction<'a> {
    payer: &'a Address,
    instruction_tag: InstructionTag,
    instruction: Instruction,
}

impl SizedInstruction<'_> {
    fn check(self) -> Result<Instruction, RingError> {
        check_transaction_size(
            self.payer,
            &self.instruction,
            ComputeBudgetConfig::new(compute_unit_limit(self.instruction_tag)),
        )?;
        Ok(self.instruction)
    }
}

pub(crate) fn tagged<T: SchemaWrite<DefaultConfig, Src = T>>(
    instruction_tag: u8,
    body: &T,
) -> Result<Vec<u8>, RingError> {
    let mut data = vec![instruction_tag];
    data.extend(wincode::serialize(body)?);
    Ok(data)
}
