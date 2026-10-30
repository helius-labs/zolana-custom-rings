use custom_ring_interface::{
    CustomRingError, PolicySourceIxData, PolicyTableIxData, RingPolicy, RingRole, SourceSlot,
    UpdatePolicyIxData,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::instructions::{
    instruction_runtime::parse,
    loader::{load_storage_registry, RoleHolder},
    policy_binding::{curator_source, TableBinding},
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
            records: &self.policy.records,
            table,
            curators: self.trailing,
        }
        .bind()?;
        self.policy
            .set_policy(bound.sources, bound.rules, self.slot)?;
        Ok(())
    }

    /// Only a list the rules reference has a source, the own records or one curator.
    #[inline(never)]
    fn move_source(self, source: PolicySourceIxData) -> ProgramResult {
        let list_id =
            ListId::try_from(source.list_id).map_err(|_| CustomRingError::InvalidListId)?;
        let registry = match (source.source, self.trailing) {
            (0, []) => Address::default(),
            (1, [curator]) => curator_source(&self.policy.records, curator)?,
            _ => return Err(CustomRingError::InvalidSource.into()),
        };
        let mut sources = self.policy.sources;
        if sources[list_id.slot()].list_id == 0 {
            return Err(CustomRingError::InvalidSource.into());
        }
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            registry,
        };
        // The rehashed source map refuses a second distinct curator.
        let rules = self.policy.rules;
        self.policy.set_policy(sources, rules, self.slot)?;
        Ok(())
    }

    #[inline(never)]
    fn rebind_records(self) -> ProgramResult {
        let [records] = self.trailing else {
            return Err(CustomRingError::InvalidStorageRegistry.into());
        };
        load_storage_registry(records)?;
        self.policy.rebind_records(*records.address(), self.slot)?;
        Ok(())
    }
}
