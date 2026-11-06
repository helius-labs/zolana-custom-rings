//! Turns instruction table data into the rule table and source slots a ring stores, and checks the
//! registries a proposed configuration names before it is stored.
//!
//! The policy hash covers the rules and their source map, and every policy proof binds that hash. A
//! source for a list no rule reads would change the hash with no rule behind it.
//!
//! A salted list reads tracking roots at or above its source's floor, and only a private write proving
//! a row of the tracking registry the source pins raises that floor. Every configuration write checks the pairing of each salted
//! source of the account it proposes, so a refused pairing never reaches the stored account. The
//! policy reads in `instructions/accounts/loader.rs` check it again on the stored account.
//!
//! Read after `instructions/configuration/setup/initialize.rs`. Read before `instructions/configuration/policy/update_policy.rs`.

use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, PolicyTableIxData, RingPolicy, SourceSlot, N_SOURCE_SLOTS,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_ring_policy::{EncodedRuleTable, ListId, ListSet, TableParts};

use crate::instructions::loader::{load_records_registry, load_storage_registry};

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

#[must_use]
pub(crate) struct TableBinding<'a> {
    pub table: &'a PolicyTableIxData,
    pub curators: &'a [AccountView],
}

#[must_use]
pub(crate) struct ProposedSources<'a> {
    pub program_id: &'a Address,
    pub proposed: &'a RingPolicy,
    pub registries: &'a [AccountView],
}

impl TableBinding<'_> {
    /// Boxed off the SBF stack, the sources name only lists the table references.
    #[inline(never)]
    pub fn bind(self) -> Result<Box<BoundTable>, ProgramError> {
        let table = self.table;
        let rules = TableParts { rows: &table.rules }
            .encode()
            .map_err(CustomRingError::from)?;
        let sources = self.sources(rules.referenced())?;
        Ok(Box::new(BoundTable { rules, sources }))
    }

    /// `ProposedSources::check` loads the curators, after the source map admits at most one.
    #[inline(never)]
    fn sources(&self, referenced: ListSet) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        let mut seen = ListSet::EMPTY;
        for spec in &self.table.sources {
            let list_id =
                ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
            if !referenced.contains(list_id) || seen.contains(list_id) {
                return Err(CustomRingError::InvalidSource.into());
            }
            seen = seen.union(ListSet::single(list_id));
            let registry = match spec.source {
                0 => Address::default(),
                n => *self
                    .curators
                    .get(usize::from(n) - 1)
                    .ok_or(CustomRingError::InvalidSource)?
                    .address(),
            };
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry,
            };
        }
        Ok(sources)
    }
}

impl ProposedSources<'_> {
    /// Loads each registry the write names and each registry a salted list of the proposed account
    /// reads, once each, before the proposed account is stored.
    ///
    /// 1. Every listed registry is among the write's accounts, a missing one refuses the write.
    /// 2. The ring's records carry the ring id, any other registry is a Storage registry of any authority.
    /// 3. A registry a salted list reads pairs with the ring.
    #[inline(never)]
    pub fn check(self, named: impl IntoIterator<Item = Address>) -> ProgramResult {
        let mut checked: Vec<Address> = Vec::new();
        for address in named.into_iter().chain(self.proposed.salted_registries()) {
            if checked.contains(&address) {
                continue;
            }
            checked.push(address);
            let account = self
                .registries
                .iter()
                .find(|account| *account.address() == address)
                .ok_or(CustomRingError::MissingRegistry)?;
            let registry = match address == self.proposed.records {
                true => load_records_registry(self.program_id, account)?,
                false => load_storage_registry(account)?,
            };
            self.proposed.check_source_pair(&address, &registry)?;
        }
        Ok(())
    }
}
