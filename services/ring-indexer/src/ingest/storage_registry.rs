use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Root, StorageRegistry},
    storage_instruction::{
        tag, InitializeIxData, StorageUpdateIxData, StorageWriteData, UpdateMode,
    },
    CustomRingError, ROOT_HISTORY,
};
use sea_orm::ConnectionTrait;
use solana_address::Address;
use spr_indexer_api::Hash;

use crate::{
    block::Instruction,
    indexer::{fault, from_storage, ApplyError},
    member_registry::{plant_tree, TreeRead},
    storage::{StorageRoot, StorageState, StorageStore, StoredRecord},
};

pub(crate) enum StorageCall<'a> {
    Initialize(StorageInit<'a>),
    Update(StorageUpdate<'a>),
    UpdateAuthority {
        authority: Address,
        new_authority: Address,
    },
}

pub(crate) struct StorageInit<'a> {
    pub creator: Address,
    pub data: &'a InitializeIxData,
}

pub(crate) struct StorageUpdate<'a> {
    pub mode: UpdateMode,
    pub authority: Address,
    pub data: StorageUpdateIxData<'a>,
}

/// `call` fails on data the program refuses.
pub(crate) struct StorageInstruction<'a> {
    pub registry: Address,
    pub call: Result<StorageCall<'a>, CustomRingError>,
}

/// Account order of the `custom_ring_sdk` storage builders.
pub(crate) fn decode(instruction: &Instruction) -> Option<StorageInstruction<'_>> {
    let (&tag, data) = instruction.data.split_first()?;
    let account = |index: usize| {
        instruction
            .accounts
            .get(index)
            .copied()
            .ok_or(CustomRingError::InvalidInstructionData)
    };
    let registry = |index: usize| account(index).ok();
    let instruction = match tag {
        tag::INITIALIZE => StorageInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|creator| {
                let data = bytemuck::try_from_bytes(data)
                    .map_err(|_| CustomRingError::InvalidInstructionData)?;
                Ok(StorageCall::Initialize(StorageInit { creator, data }))
            }),
        },
        tag::UPDATE | tag::UPDATE_IMMEDIATE => StorageInstruction {
            registry: registry(1)?,
            call: account(0).and_then(|authority| {
                let mode = match tag {
                    tag::UPDATE => UpdateMode::Graced,
                    _ => UpdateMode::Immediate,
                };
                Ok(StorageCall::Update(StorageUpdate {
                    mode,
                    authority,
                    data: StorageUpdateIxData::parse(data)?,
                }))
            }),
        },
        tag::UPDATE_AUTHORITY => StorageInstruction {
            registry: registry(2)?,
            call: account(0).and_then(|authority| {
                Ok(StorageCall::UpdateAuthority {
                    authority,
                    new_authority: account(1)?,
                })
            }),
        },
        _ => return None,
    };
    Some(instruction)
}

impl StorageInit<'_> {
    /// `None` off the canonical registry address, the program refuses it.
    pub fn state(&self, registry: Address) -> Option<StorageState> {
        let (canonical, _) = StorageRegistry::find_address(&self.creator, &self.data.registry_id);
        (canonical == registry).then(|| StorageState {
            registry: registry.to_bytes(),
            account: Box::new(StorageRegistry::new(self.creator, self.data.grace_slots())),
            fault: None,
        })
    }
}

pub(crate) async fn create<C: ConnectionTrait>(
    store: &StorageStore<'_, C>,
    state: &StorageState,
) -> anyhow::Result<()> {
    plant_tree(store.tree()).await?;
    store
        .save_root(&StorageRoot::current(&state.account))
        .await?;
    store.save_state(state).await
}

pub(crate) struct StorageProjection<'p, 'c, C> {
    pub store: &'p StorageStore<'c, C>,
    pub state: &'p mut StorageState,
    pub slot: u64,
}

impl<C: ConnectionTrait> StorageProjection<'_, '_, C> {
    /// A refusal of the program's own checks means the projection drifted.
    pub async fn project(self, call: StorageCall<'_>) -> Result<(), ApplyError> {
        match call {
            StorageCall::Initialize(_) => Err(fault("initialized twice")),
            StorageCall::Update(update) => self.update(update).await,
            StorageCall::UpdateAuthority {
                authority,
                new_authority,
            } => {
                self.authorize(&authority)?;
                self.state.account.authority = new_authority;
                Ok(())
            }
        }
    }

    async fn update(self, update: StorageUpdate<'_>) -> Result<(), ApplyError> {
        let StorageUpdate {
            mode,
            authority,
            data,
        } = update;
        // 1. The program admits the update at the projected revision.
        self.authorize(&authority)?;
        let account = &*self.state.account;
        if data.revision != account.roots[0].revision {
            return Err(fault(format!(
                "update names revision {}, projected {}",
                data.revision.value(),
                account.roots[0].revision.value()
            )));
        }
        if mode == UpdateMode::Graced && self.slot < account.roots[ROOT_HISTORY - 1].expires_at() {
            return Err(fault("graced update over a full root history"));
        }
        let revision = data
            .revision
            .value()
            .checked_add(1)
            .ok_or_else(|| fault("revision overflow"))?;
        // 2. The writes reach the root the program recorded.
        let entries = data
            .writes
            .iter()
            .map(StorageWriteData::entry)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| fault(format!("storage write refused ({error})")))?;
        let registry = Address::new_from_array(self.state.registry);
        let chain_start = storage_program::chain_start(&registry, data.revision)
            .map_err(|error| fault(format!("chain start failed ({error})")))?;
        let loaded = TreeRead::batch(StorageRoot::current(account).tree(), &entries)
            .load(self.store.tree())
            .await
            .map_err(from_storage)?;
        let batch = loaded
            .tree
            .apply_batch(chain_start, &entries)
            .map_err(|error| fault(format!("records do not apply ({error})")))?;
        let inputs = &batch.inputs;
        let recorded_next_index = u64::from(data.apply.new_next_index());
        if inputs.new_root != data.apply.new_root || inputs.new_next_index != recorded_next_index {
            return Err(fault(format!(
                "applied root mismatch at revision {revision}, projected {} at {}, program {} at {}",
                Hash(inputs.new_root),
                inputs.new_next_index,
                Hash(data.apply.new_root),
                recorded_next_index
            )));
        }
        // 3. Rows at the new revision hold the new tree.
        let records = batch
            .rows
            .records
            .values()
            .map(|record| StoredRecord {
                record: *record,
                seal: None,
            })
            .collect::<Vec<_>>();
        self.store.tree().save_records(&records, revision).await?;
        self.store
            .tree()
            .save_nodes(&batch.rows.nodes, revision)
            .await?;
        // 4. The roots rotate as the program rotates them.
        let account = &mut *self.state.account;
        match mode {
            UpdateMode::Graced => {
                account.roots[0].expires_at = self
                    .slot
                    .saturating_add(account.grace_slots())
                    .to_le_bytes();
                account.roots.rotate_right(1);
            }
            UpdateMode::Immediate => account.roots.fill(Root::zeroed()),
        }
        account.roots[0] = Root {
            hash: data.apply.new_root,
            revision: revision.into(),
            expires_at: [0; 8],
        };
        account.next_index = data.apply.new_next_index;
        self.store.save_root(&StorageRoot::current(account)).await?;
        Ok(())
    }

    fn authorize(&self, signer: &Address) -> Result<(), ApplyError> {
        if *signer == self.state.account.authority {
            Ok(())
        } else {
            Err(fault("signer is not the registry authority"))
        }
    }
}
