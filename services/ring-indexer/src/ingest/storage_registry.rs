use custom_ring_interface::{
    storage::{chain_start, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{tag, InitializeIxData, StorageUpdateIxData},
    QUAD_HEIGHT,
};
use sea_orm::ConnectionTrait;
use solana_address::Address;
use zolana_ring_indexer::tree::MemberRecord;

use crate::{
    block::Instruction,
    indexer::{fault, ApplyError, Projection, RegistryCall, RegistryInstruction},
    member_registry::{plant_tree, AppliedBatch},
    storage::{StorageRoot, StorageState, StorageStore},
};

pub(crate) enum StorageCall<'a> {
    Initialize(StorageInit<'a>),
    Update(Box<StorageUpdate<'a>>),
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
    pub authority: Address,
    /// Named only by a batch with private writes.
    pub tracking_registry: Option<Address>,
    pub data: StorageUpdateIxData<'a>,
}

/// Account order the tags document in `storage_instruction`.
pub(crate) fn decode(instruction: &Instruction) -> Option<RegistryInstruction<StorageCall<'_>>> {
    let (&tag, data) = instruction.data.split_first()?;
    let account = |index: usize| {
        instruction
            .accounts
            .get(index)
            .copied()
            .ok_or(StorageError::MissingAccounts)
    };
    let registry = |index: usize| account(index).ok();
    let instruction = match tag {
        tag::INITIALIZE => RegistryInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|creator| {
                let data = bytemuck::try_from_bytes(data)
                    .map_err(|_| StorageError::InvalidInstructionData)?;
                Ok(StorageCall::Initialize(StorageInit { creator, data }))
            }),
        },
        tag::UPDATE => RegistryInstruction {
            registry: registry(1)?,
            call: account(0).and_then(|authority| {
                Ok(StorageCall::Update(Box::new(StorageUpdate {
                    authority,
                    tracking_registry: account(2).ok(),
                    data: StorageUpdateIxData::parse(data)?,
                })))
            }),
        },
        tag::UPDATE_AUTHORITY => RegistryInstruction {
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

impl RegistryCall<StorageRegistry> for StorageCall<'_> {
    fn created(&self, registry: Address) -> Option<StorageState> {
        let Self::Initialize(init) = self else {
            return None;
        };
        let (canonical, _) = StorageRegistry::find_address(&init.creator, &init.data.registry_id);
        (canonical == registry).then(|| StorageState {
            registry: registry.to_bytes(),
            account: Box::new(StorageRegistry::new(init.creator, init.data)),
            fault: None,
        })
    }

    async fn create<C: ConnectionTrait>(
        store: &StorageStore<'_, C>,
        state: &StorageState,
    ) -> anyhow::Result<()> {
        plant_tree::<_, _, QUAD_HEIGHT>(store.tree()).await?;
        store
            .save_root(&StorageRoot::current(&*state.account))
            .await?;
        store.save_state(state).await
    }

    /// A refusal of the program's own checks means the projection drifted.
    async fn project<C: ConnectionTrait>(
        self,
        projection: Projection<'_, '_, C, StorageRegistry>,
    ) -> Result<(), ApplyError> {
        match self {
            Self::Initialize(_) => Err(fault("initialized twice")),
            Self::Update(update) => projection.update(*update).await,
            Self::UpdateAuthority {
                authority,
                new_authority,
            } => {
                projection.authorize(&authority)?;
                projection.state.account.authority = new_authority;
                Ok(())
            }
        }
    }
}

impl<C: ConnectionTrait> Projection<'_, '_, C, StorageRegistry> {
    async fn update(self, update: StorageUpdate<'_>) -> Result<(), ApplyError> {
        let StorageUpdate {
            authority,
            tracking_registry,
            data,
        } = update;
        // 1. The program admits the update at the projected revision.
        self.authorize(&authority)?;
        let account = &*self.state.account;
        // A landed update proved its rows under the pinned registry at the named revision.
        if data.tracking_revision.is_some() && tracking_registry != Some(account.tracking_registry)
        {
            return Err(fault("the update names another tracking registry"));
        }
        let mut rotated = *account;
        rotated
            .update(RootUpdate {
                slot: self.slot,
                data: &data,
            })
            .map_err(|error| fault(format!("update refused ({error})")))?;
        let revision = rotated.roots[0].revision.value();
        // 2. The writes reach the root the program recorded.
        let entries = data
            .writes
            .iter()
            .map(|write| {
                write
                    .storage_entry()
                    .map_err(|error| fault(format!("storage write refused ({error})")))
            })
            .collect::<Result<Vec<_>, ApplyError>>()?;
        let registry = Address::new_from_array(self.state.registry);
        let chain_start = chain_start(&registry, data.revision)
            .map_err(|error| fault(format!("chain start failed ({error})")))?;
        AppliedBatch::<MemberRecord, QUAD_HEIGHT> {
            at: StorageRoot::current(account).tree(),
            chain_start,
            entries: &entries,
            new_root: data.apply.new_root,
            new_next_index: u64::from(data.apply.new_next_index()),
            revision,
        }
        .save(self.store.tree())
        .await?;
        // 3. The roots rotate as the program rotates them.
        *self.state.account = rotated;
        self.store
            .save_root(&StorageRoot::current(&rotated))
            .await?;
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
