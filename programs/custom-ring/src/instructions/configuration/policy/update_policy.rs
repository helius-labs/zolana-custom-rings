//! Rewrites a ring's rule table, one list's source, or its records registry.
//!
//! A statement reads `policy_hash` and the own root from live state, so each write changes what the next proof names.
//! A delegate frame reads neither, a policy write cannot fail it. `RingPolicy::set_policy` validates each table it stores.
//!
//! The instruction guarantees:
//!
//! 1. Only the policy authority writes.
//! 2. An audit-only ring keeps no rules, the table and source writes refuse it.
//! 3. A source moves only for a list the rules reference, and at most one curator serves the ring.
//! 4. The records registry carries the ring's id.
//! 5. Each salted source of the proposed account pairs with the ring, a refused write leaves the stored account unchanged.
//!
//! The trailing accounts hold the registries the write names, then each registry a salted list of the
//! proposed account reads that the write does not name. Accounts match by address.
//!
//! Read after `instructions/verification/policy_binding.rs`. Read before `program-libs/interface/src/accounts/state.rs`.

use custom_ring_interface::{
    CustomRingError, PolicySourceIxData, PolicyTableIxData, PolicyUpdate, RingPolicy, RingRole,
    SourceSlot, UpdatePolicyIxData,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::instructions::{
    instruction_runtime::parse,
    loader::RoleHolder,
    policy_binding::{ProposedSources, TableBinding},
};

#[inline(never)]
pub fn process_update_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdatePolicyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("policy_authority")?;
    let ring = iter.next_mut("ring")?;
    let trailing = iter.remaining_unchecked()?;

    // 1. Only the policy authority rewrites the policy.
    let mut policy = RoleHolder {
        program_id,
        role: RingRole::Policy,
        signer: authority,
    }
    .load_mut(ring)?;
    let write = PolicyWrite {
        program_id,
        policy: &mut policy,
        trailing,
        slot: Clock::get()?.slot,
    };
    // 2. Every write repins the hash or the records, a proof over the old state is refused.
    match ix {
        UpdatePolicyIxData::Rules(table) => write.replace_rules(&table),
        UpdatePolicyIxData::Source(source) => write.move_source(source),
        UpdatePolicyIxData::Records => write.rebind_records(),
    }
}

#[must_use]
struct PolicyWrite<'a> {
    program_id: &'a Address,
    policy: &'a mut RingPolicy,
    trailing: &'a [AccountView],
    slot: u64,
}

impl PolicyWrite<'_> {
    /// Refused on an audit-only ring, sources name exactly the lists the rules reference.
    #[inline(never)]
    fn replace_rules(self, table: &PolicyTableIxData) -> ProgramResult {
        self.policy.policy_hash()?;
        let bound = TableBinding {
            table,
            curators: self.trailing,
        }
        .bind()?;
        let slot = self.slot;
        self.commit(Named::Curator, |proposed| {
            proposed.set_policy(PolicyUpdate {
                sources: bound.sources,
                rules: bound.rules,
                slot,
            })
        })
    }

    /// Only a list the rules reference has a source, the own records or one curator.
    #[inline(never)]
    fn move_source(self, source: PolicySourceIxData) -> ProgramResult {
        let list_id =
            ListId::try_from(source.list_id).map_err(|_| CustomRingError::InvalidListId)?;
        let (registry, named) = match (source.source, self.trailing) {
            (0, _) => (Address::default(), Named::Nothing),
            (1, [curator, ..]) => (*curator.address(), Named::Curator),
            _ => return Err(CustomRingError::InvalidSource.into()),
        };
        if self.policy.sources[list_id.slot()].list_id == 0 {
            return Err(CustomRingError::InvalidSource.into());
        }
        let slot = self.slot;
        // The rehashed source map refuses a second distinct curator.
        self.commit(named, |proposed| {
            let mut sources = proposed.sources;
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry,
            };
            let rules = proposed.rules;
            proposed.set_policy(PolicyUpdate {
                sources,
                rules,
                slot,
            })
        })
    }

    #[inline(never)]
    fn rebind_records(self) -> ProgramResult {
        let [records, ..] = self.trailing else {
            return Err(CustomRingError::InvalidStorageRegistry.into());
        };
        let (records, slot) = (*records.address(), self.slot);
        self.commit(Named::Records, |proposed| {
            proposed.rebind_records(records, slot)
        })
    }

    /// Stores the proposed account only after its named and salted registries pass.
    #[inline(never)]
    fn commit(
        self,
        named: Named,
        write: impl FnOnce(&mut RingPolicy) -> Result<(), CustomRingError>,
    ) -> ProgramResult {
        // 1. Boxed off the SBF stack, the stored account stays untouched until every check passes.
        let mut proposed: Box<RingPolicy> = bytemuck::zeroed_box();
        *proposed = *self.policy;
        write(&mut proposed)?;
        // 2. The named registry and every salted source of the proposed account load once and pair with the ring.
        let named = match named {
            Named::Nothing => None,
            Named::Curator => proposed.curator(),
            Named::Records => Some(proposed.records),
        };
        ProposedSources {
            program_id: self.program_id,
            proposed: &proposed,
            registries: self.trailing,
        }
        .check(named)?;
        *self.policy = *proposed;
        Ok(())
    }
}

/// The registry a write sets, loaded even when no salted list reads it.
#[derive(Clone, Copy)]
enum Named {
    Nothing,
    Curator,
    Records,
}
