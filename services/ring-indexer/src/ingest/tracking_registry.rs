use custom_ring_interface::{
    storage::StorageError,
    storage_instruction::{tag, ApplyEnrollmentsIxData, EnrollRequest, InitializeTrackingIxData},
    tracking::{
        tracking_chain_start, TrackingAuthorization, TrackingEntry, TrackingRegistry,
        TrackingRootUpdate, TRACKING_QUAD_HEIGHT,
    },
};
use sea_orm::ConnectionTrait;
use solana_address::Address;
use zolana_ring_indexer::tree::TrackingRecord;

use crate::{
    block::Instruction,
    indexer::{fault, from_storage, ApplyError, Projection, RegistryCall, RegistryInstruction},
    member_registry::{plant_tree, AppliedBatch},
    storage::{Enrollment, StorageRoot, TrackingState, TrackingStore},
};

pub(crate) enum TrackingCall<'a> {
    Initialize(TrackingInit<'a>),
    Enroll(EnrollCall<'a>),
    Apply(ApplyCall<'a>),
}

pub(crate) struct TrackingInit<'a> {
    pub creator: Address,
    pub data: &'a InitializeTrackingIxData,
}

pub(crate) struct EnrollCall<'a> {
    pub owner: Address,
    pub authorization: Address,
    pub request: EnrollRequest<'a>,
}

pub(crate) struct ApplyCall<'a> {
    pub data: &'a ApplyEnrollmentsIxData,
    /// In chain order.
    pub authorizations: &'a [Address],
}

/// Account order the tags document in `storage_instruction`.
pub(crate) fn decode(instruction: &Instruction) -> Option<RegistryInstruction<TrackingCall<'_>>> {
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
        tag::INITIALIZE_TRACKING => RegistryInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|creator| {
                let data = bytemuck::try_from_bytes(data)
                    .map_err(|_| StorageError::InvalidInstructionData)?;
                Ok(TrackingCall::Initialize(TrackingInit { creator, data }))
            }),
        },
        tag::ENROLL => RegistryInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|owner| {
                Ok(TrackingCall::Enroll(EnrollCall {
                    owner,
                    authorization: account(3)?,
                    request: EnrollRequest::parse(data)?,
                }))
            }),
        },
        tag::APPLY_ENROLLMENTS => RegistryInstruction {
            registry: registry(0)?,
            call: bytemuck::try_from_bytes(data)
                .map_err(|_| StorageError::InvalidInstructionData)
                .and_then(|data| {
                    let authorizations = &instruction.accounts[1..];
                    ApplyEnrollmentsIxData::check_count(authorizations.len())?;
                    Ok(TrackingCall::Apply(ApplyCall {
                        data,
                        authorizations,
                    }))
                }),
        },
        _ => return None,
    };
    Some(instruction)
}

impl RegistryCall<TrackingRegistry> for TrackingCall<'_> {
    fn created(&self, registry: Address) -> Option<TrackingState> {
        let Self::Initialize(init) = self else {
            return None;
        };
        let (canonical, _) = TrackingRegistry::find_address(&init.creator, &init.data.ring_id);
        (canonical == registry).then(|| TrackingState {
            registry: registry.to_bytes(),
            account: Box::new(TrackingRegistry::new(init.data)),
            fault: None,
        })
    }

    async fn create<C: ConnectionTrait>(
        store: &TrackingStore<'_, C>,
        state: &TrackingState,
    ) -> anyhow::Result<()> {
        plant_tree::<_, _, TRACKING_QUAD_HEIGHT>(store.tree()).await?;
        store
            .save_root(&StorageRoot::current(&*state.account))
            .await?;
        store.save_state(state).await
    }

    /// A refusal of the program's own checks means the projection drifted.
    async fn project<C: ConnectionTrait>(
        self,
        projection: Projection<'_, '_, C, TrackingRegistry>,
    ) -> Result<(), ApplyError> {
        match self {
            Self::Initialize(_) => Err(fault("initialized twice")),
            Self::Enroll(enroll) => projection.enroll(enroll).await,
            Self::Apply(apply) => projection.apply(apply).await,
        }
    }
}

impl<C: ConnectionTrait> Projection<'_, '_, C, TrackingRegistry> {
    async fn enroll(self, call: EnrollCall<'_>) -> Result<(), ApplyError> {
        let held = self
            .store
            .enrollment(&call.owner.to_bytes())
            .await
            .map_err(from_storage)?;
        match held {
            None => self.first_enrollment(call).await,
            Some(held) => self.rotation(call, held).await,
        }
    }

    /// Final fields read from the account at any later slot.
    async fn first_enrollment(self, call: EnrollCall<'_>) -> Result<(), ApplyError> {
        let EnrollCall {
            owner,
            authorization,
            request,
        } = call;
        if request.proof.is_none() {
            return Err(fault("a first enrollment carries no proof"));
        }
        let held = self.authorization(&authorization).await?;
        if held.registry.to_bytes() != self.state.registry || held.owner != owner {
            return Err(fault("the authorization names another owner"));
        }
        let entry = held
            .entry()
            .map_err(|error| fault(format!("entry hash failed ({error})")))?;
        let first = Enrollment {
            owner: owner.to_bytes(),
            authorization: authorization.to_bytes(),
            member: entry.member,
            nullifier_pk: held.nullifier_pk,
            ct_hash: entry.ct_hash,
            list_tag: held.list_tag,
            eph_u: held.eph_u,
            ciphertext: held.ciphertext,
            applied: false,
        };
        self.store
            .save_first(&first, self.slot)
            .await
            .map_err(from_storage)
    }

    /// The program's final field check, a rotation moves no root and leaves no pending row.
    async fn rotation(self, call: EnrollCall<'_>, held: Enrollment) -> Result<(), ApplyError> {
        let EnrollCall { request, .. } = call;
        if request.proof.is_some() {
            return Err(fault("a rotation carries a proof"));
        }
        held.account(self.state.registry)
            .rotate(request.ix)
            .map_err(|error| fault(format!("rotation refused ({error})")))
    }

    /// An absent account retries, a stale read or a fork.
    async fn authorization(&self, address: &Address) -> Result<TrackingAuthorization, ApplyError> {
        self.rpc
            .get_multiple_accounts_from_slot(&[*address], self.slot)
            .await?
            .into_iter()
            .flatten()
            .next()
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
            .ok_or_else(|| {
                ApplyError::Retry(anyhow::anyhow!("no tracking authorization at {address}"))
            })
    }

    async fn apply(self, call: ApplyCall<'_>) -> Result<(), ApplyError> {
        let ApplyCall {
            data,
            authorizations,
        } = call;
        let root = StorageRoot::current(&*self.state.account);
        let mut rotated = *self.state.account;
        rotated
            .update(TrackingRootUpdate {
                revision: data.revision,
                slot: self.slot,
                new_root: data.new_root,
                new_next_index: data.new_next_index(),
            })
            .map_err(|error| fault(format!("apply refused ({error})")))?;
        let revision = rotated.newest().revision.value();
        let entries = self.applied_entries(authorizations).await?;
        let registry = Address::new_from_array(self.state.registry);
        let chain_start = tracking_chain_start(&registry, data.revision)
            .map_err(|error| fault(format!("chain start failed ({error})")))?;
        AppliedBatch::<TrackingRecord, TRACKING_QUAD_HEIGHT> {
            at: root.tree(),
            chain_start,
            entries: &entries,
            new_root: data.new_root,
            new_next_index: data.new_next_index(),
            revision,
        }
        .save(self.store.tree())
        .await?;
        *self.state.account = rotated;
        self.store
            .save_root(&StorageRoot::current(&rotated))
            .await?;
        Ok(())
    }

    /// Each named owner's entry in the order the apply names it.
    async fn applied_entries(
        &self,
        authorizations: &[Address],
    ) -> Result<Vec<TrackingEntry>, ApplyError> {
        let mut entries = Vec::with_capacity(authorizations.len());
        for authorization in authorizations {
            let held = self
                .store
                .enrollment_at(&authorization.to_bytes())
                .await
                .map_err(from_storage)?
                .ok_or_else(|| fault("an apply names no enrollment"))?;
            let entry = held
                .account(self.state.registry)
                .apply()
                .map_err(|error| fault(format!("apply refused ({error})")))?;
            self.store
                .mark_applied(&held.owner, self.slot)
                .await
                .map_err(from_storage)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}
