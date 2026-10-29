//! Instructions of the ring authority and the upgrade authority.

use custom_ring_interface::SYSTEM_PROGRAM_ID;
use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CreateConfigIxData, CreatePolicyIxData, InstructionTag,
    PolicyTableIxData, ReaderIxData, RingKind, SetCoSignerRecordIxData, SetInsertFeeIxData,
    SetPausedIxData, SetPolicySourceIxData, SourceSpec,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::ComputeBudgetConfig;
use spr_interface::pda;
use spr_keypair::X25519Pubkey;
use wincode::{config::DefaultConfig, SchemaWrite};
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, SourceMap};

use crate::{submission::check_transaction_size, CustomRing, CustomRingConfig, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    /// A `StorageRegistry` of any authority.
    Curator(Address),
}

/// The upgrade authority signs and becomes the ring authority.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateConfig {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub auditor_pubkey: X25519Pubkey,
    pub kind: RingKind,
}

/// The program builds SPP's registration from the config, a policy ring after its policy.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct InitSppRingConfig<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub config: &'a CustomRingConfig,
}

/// The record queue is created beside the registry and its sentinel.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateMemberRegistry {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

/// Authorizes `reader` to read the ring through the ring RPC.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantReader {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub reader: ReaderKey,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeReader {
    pub ring: CustomRing,
    pub authority: Address,
    pub reader: ReaderKey,
    pub rent_recipient: Address,
}

/// Both keys sign, a mistyped address cannot strand the config.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAuthority {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetSourceOwner {
    pub ring: CustomRing,
    pub authority: Address,
    pub list_id: ListId,
    pub source: SourceOwner,
}

/// A referenced list not shared reads the ring's own records.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct PolicyRules<'a> {
    pub ring: CustomRing,
    pub authority: Address,
    pub rules: &'a RuleTable,
    /// Each list's curator `StorageRegistry`.
    pub shared_sources: &'a [(ListId, Address)],
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRecords {
    pub payer: Address,
    pub records: Address,
    /// The records may answer to it beside the config authority.
    pub storage_authority: Address,
}

struct TablePayload {
    data: PolicyTableIxData,
    curators: Vec<AccountMeta>,
}

impl CreateConfig {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let data = tagged(
            tag::CREATE_CONFIG,
            &CreateConfigIxData {
                auditor_pubkey: *self.auditor_pubkey.as_bytes(),
                kind: self.kind,
            },
        )?;
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.ring.config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        accounts.extend(self.ring.upgrade_metas());
        Ok(self.ring.ix(accounts, data))
    }
}

impl InitSppRingConfig<'_> {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring.ring_auth_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        if self.config.has_policy {
            accounts.push(AccountMeta::new_readonly(ring.policy_pda(), false));
        }
        ring.ix(accounts, vec![tag::INIT_SPP_RING_CONFIG])
    }
}

impl CreateMemberRegistry {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.registry_pda(), false),
            AccountMeta::new(ring.queue_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        ring.ix(accounts, vec![tag::CREATE_MEMBER_REGISTRY])
    }
}

impl GrantReader {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.read_access_record_pda(&self.reader), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        Ok(ring.ix(accounts, reader_data(tag::GRANT_READ_ACCESS, self.reader)?))
    }
}

impl RevokeReader {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.read_access_record_pda(&self.reader), false),
            AccountMeta::new(self.rent_recipient, false),
        ];
        Ok(ring.ix(accounts, reader_data(tag::REVOKE_READ_ACCESS, self.reader)?))
    }
}

impl SetAuthority {
    pub fn instruction(self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.new_authority, true),
            AccountMeta::new(self.ring.config_pda(), false),
        ];
        self.ring.ix(accounts, vec![tag::SET_AUTHORITY])
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

impl SetSourceOwner {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let mut accounts = ring.policy_write_metas(self.authority);
        if let SourceOwner::Curator(curator) = self.source {
            accounts.push(AccountMeta::new_readonly(curator, false));
        }
        let data = tagged(
            tag::SET_POLICY_SOURCE,
            &SetPolicySourceIxData {
                list_id: self.list_id as u8,
                source: u8::from(matches!(self.source, SourceOwner::Curator(_))),
            },
        )?;
        Ok(ring.ix(accounts, data))
    }
}

impl PolicyRules<'_> {
    /// Creates the ring policy over `records` and pins the table, an audit-only ring takes an empty one.
    pub fn create(self, records: PolicyRecords) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let TablePayload { data, curators } = self.table()?;
        let mut accounts = vec![
            AccountMeta::new(records.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.policy_pda(), false),
            AccountMeta::new_readonly(records.records, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        accounts.extend(curators);
        let data = tagged(
            tag::CREATE_POLICY,
            &CreatePolicyIxData {
                storage_authority: records.storage_authority,
                table: data,
            },
        )?;
        self.sized(InstructionTag::CreatePolicy, ring.ix(accounts, data))
    }

    /// Replaces the pinned table and the complete source map.
    pub fn replace(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let TablePayload { data, curators } = self.table()?;
        let mut accounts = ring.policy_write_metas(self.authority);
        accounts.extend(curators);
        let data = tagged(tag::SET_POLICY_RULES, &data)?;
        self.sized(InstructionTag::SetPolicyRules, ring.ix(accounts, data))
    }

    /// Curator registries follow in first-use order.
    fn table(&self) -> Result<TablePayload, RingError> {
        let Self {
            rules,
            shared_sources,
            ..
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

    fn sized(
        &self,
        instruction_tag: InstructionTag,
        instruction: Instruction,
    ) -> Result<Instruction, RingError> {
        check_transaction_size(
            &self.authority,
            &instruction,
            ComputeBudgetConfig::new(compute_unit_limit(instruction_tag)),
        )?;
        Ok(instruction)
    }
}

impl CustomRing {
    pub fn pause(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: true })
    }

    pub fn resume(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: false })
    }

    /// [`crate::CustomRingConfig::insert_fee`], zero writes free.
    pub fn set_insert_fee(self, authority: Address, fee: u64) -> Instruction {
        let mut data = vec![tag::SET_INSERT_FEE];
        data.extend_from_slice(bytemuck::bytes_of(&SetInsertFeeIxData {
            fee: fee.to_le_bytes(),
        }));
        self.ix(self.config_write_metas(authority), data)
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

pub(crate) fn tagged<T: SchemaWrite<DefaultConfig, Src = T>>(
    instruction_tag: u8,
    body: &T,
) -> Result<Vec<u8>, RingError> {
    let mut data = vec![instruction_tag];
    data.extend(wincode::serialize(body)?);
    Ok(data)
}

fn reader_data(instruction_tag: u8, reader: ReaderKey) -> Result<Vec<u8>, RingError> {
    tagged(
        instruction_tag,
        &ReaderIxData {
            reader: reader.to_bytes(),
        },
    )
}
