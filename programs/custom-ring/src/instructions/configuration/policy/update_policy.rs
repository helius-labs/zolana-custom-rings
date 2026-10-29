use custom_ring_interface::{
    CustomRingError, PolicySourceIxData, PolicyTableIxData, RingPolicy, SourceSlot,
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
    loader::{load_authorized_config, load_policy_mut},
    policy_binding::{curator_source, RecordsBinding, TableBinding},
};

#[inline(never)]
pub fn process_update_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdatePolicyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let policy = iter.next_mut("policy")?;
    let trailing = iter.remaining_unchecked()?;

    // 1. Only the config authority rewrites the policy.
    let config = load_authorized_config(program_id, config, authority)?;
    let mut policy = load_policy_mut(program_id, policy)?;
    let write = PolicyWrite {
        config_authority: &config.authority,
        policy: &mut policy,
        trailing,
        slot: Clock::get()?.slot,
    };
    // 2. Every write repins the hash or the records, a proof over the old state is refused.
    match ix {
        UpdatePolicyIxData::Rules(table) => write.replace_rules(&table),
        UpdatePolicyIxData::Source(source) => write.move_source(source),
        UpdatePolicyIxData::Records { storage_authority } => {
            write.rebind_records(&storage_authority)
        }
    }
}

#[must_use]
struct PolicyWrite<'a> {
    config_authority: &'a Address,
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
    fn rebind_records(self, storage_authority: &Address) -> ProgramResult {
        let [records] = self.trailing else {
            return Err(CustomRingError::InvalidStorageRegistry.into());
        };
        RecordsBinding {
            records,
            config_authority: self.config_authority,
            storage_authority,
        }
        .check()?;
        self.policy.rebind_records(*records.address(), self.slot)?;
        Ok(())
    }
}
