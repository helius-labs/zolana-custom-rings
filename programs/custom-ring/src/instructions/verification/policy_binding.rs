use bytemuck::Zeroable;
use custom_ring_interface::{CustomRingError, PolicyTableIxData, SourceSlot, N_SOURCE_SLOTS};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_ring_policy::{EncodedRuleTable, ListId, ListSet, TableParts};

use crate::instructions::loader::load_storage_registry;

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

#[must_use]
pub(crate) struct TableBinding<'a> {
    pub records: &'a Address,
    pub table: &'a PolicyTableIxData,
    pub curators: &'a [AccountView],
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

    #[inline(never)]
    fn sources(&self, referenced: ListSet) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        let mut seen = ListSet::EMPTY;
        // Lists sharing a curator load its registry once.
        let mut loaded: Vec<Address> = Vec::new();
        for spec in &self.table.sources {
            let list_id =
                ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
            if !referenced.contains(list_id) || seen.contains(list_id) {
                return Err(CustomRingError::InvalidSource.into());
            }
            seen = seen.union(ListSet::single(list_id));
            let registry = match spec.source {
                0 => Address::default(),
                n => {
                    let curator = self
                        .curators
                        .get(usize::from(n) - 1)
                        .ok_or(CustomRingError::InvalidSource)?;
                    if !loaded.contains(curator.address()) {
                        loaded.push(curator_source(self.records, curator)?);
                    }
                    *curator.address()
                }
            };
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry,
            };
        }
        Ok(sources)
    }
}

/// The records answer to the policy authority or to the storage authority it names.
#[must_use]
pub(crate) struct RecordsBinding<'a> {
    pub records: &'a AccountView,
    pub policy_authority: &'a Address,
    pub storage_authority: &'a Address,
}

impl RecordsBinding<'_> {
    pub fn check(self) -> Result<(), ProgramError> {
        let records_authority = load_storage_registry(self.records)?.authority;
        if records_authority != *self.policy_authority
            && records_authority != *self.storage_authority
        {
            return Err(CustomRingError::StorageAuthorityMismatch.into());
        }
        Ok(())
    }
}

/// A curator source names a registry of any authority other than the ring's records.
pub(crate) fn curator_source(
    records: &Address,
    curator: &AccountView,
) -> Result<Address, ProgramError> {
    if curator.address() == records {
        return Err(CustomRingError::InvalidSource.into());
    }
    load_storage_registry(curator)?;
    Ok(*curator.address())
}
