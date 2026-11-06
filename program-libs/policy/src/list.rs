//! The nine lists, their writers and the polarity a rule reads each by, one bit each in a member record.
//!
//! A bit position is a circuit constant. The writer split and `RuleTable::validate` keep a list its
//! members write out of every rule, so an owner admits itself to nothing.
//!
//! Read after `program-libs/policy/src/lib.rs`. Read before `program-libs/policy/src/member.rs`, `program-libs/policy/src/rule_table/mod.rs`.

use thiserror::Error;

use crate::MAX_SOURCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    Authority,
    Member,
}

impl Writer {
    pub const fn writable(self) -> ListSet {
        match self {
            Self::Authority => ListSet::AUTHORITY_WRITES,
            Self::Member => ListSet::MEMBER_WRITES,
        }
    }
}

macro_rules! lists {
    ($($variant:ident = $id:literal, $name:literal => $writer:ident,)*) => {
        /// Never `0`, the byte of an empty source slot.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum ListId {
            $($variant = $id,)*
        }

        impl ListId {
            /// Source-slot order, the id of `ALL[i]` is `i + 1`.
            pub const ALL: [Self; MAX_SOURCES] = [$(Self::$variant,)*];

            pub const fn writer(self) -> Writer {
                match self {
                    $(Self::$variant => Writer::$writer,)*
                }
            }

            /// Lowercase kebab-case, the one spelling of the list.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

lists! {
    Allow = 1, "allow" => Authority,
    Block = 2, "block" => Authority,
    Frozen = 3, "frozen" => Authority,
    RingViewing = 4, "ring-viewing" => Member,
    PrivateBlock = 5, "private-block" => Authority,
    Reader = 6, "reader" => Authority,
    Approval = 7, "approval" => Authority,
    PrivateAllow = 8, "private-allow" => Authority,
    PrivateFrozen = 9, "private-frozen" => Authority,
}

impl ListId {
    /// Index into the source map and into `ALL`.
    pub const fn slot(self) -> usize {
        self as usize - 1
    }

    const fn mask_bit(self) -> u16 {
        1 << self.slot()
    }

    pub const fn record_bit(self) -> u64 {
        ListSet::single(self).record_bits()
    }
}

/// A set of lists, bit `i` is list `i + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListSet(u16);

impl ListSet {
    pub const EMPTY: Self = Self(0);
    pub const MEMBER_LISTS: Self = Self::written_by(Writer::Member);
    pub const MEMBER_WRITES: Self = Self::MEMBER_LISTS;
    pub const AUTHORITY_WRITES: Self = Self::written_by(Writer::Authority);
    /// The lists a rule reads, a reader grant moves no funds.
    pub const POLICY_LISTS: Self = Self::AUTHORITY_WRITES.difference(Self::single(ListId::Reader));
    /// A rule reads these by presence, a set bit grants.
    pub const GRANT_LISTS: Self =
        Self::of(&[ListId::Allow, ListId::Approval, ListId::PrivateAllow]);
    /// A rule reads these by absence, a set bit denies.
    pub const DENY_LISTS: Self = Self::of(&[
        ListId::Block,
        ListId::Frozen,
        ListId::PrivateBlock,
        ListId::PrivateFrozen,
    ]);
    /// Always salted.
    pub const PRIVATE_LISTS: Self = Self::of(&[
        ListId::PrivateAllow,
        ListId::PrivateBlock,
        ListId::PrivateFrozen,
    ]);
    /// A bit past these names no list.
    const NAMED: Self = Self(((1u32 << MAX_SOURCES) - 1) as u16);
    pub const STORAGE_WRITES: Self = Self::AUTHORITY_WRITES.union(Self::MEMBER_WRITES);

    /// The private lists a source map serves, `mapped` reads one slot and hashes nothing.
    pub fn salted_among(mapped: impl Fn(ListId) -> bool) -> Self {
        Self::PRIVATE_LISTS
            .iter()
            .filter(|list_id| mapped(*list_id))
            .fold(Self::EMPTY, |set, list_id| set.union(Self::single(list_id)))
    }

    pub const fn written_by(writer: Writer) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < MAX_SOURCES {
            if ListId::ALL[i].writer() as u8 == writer as u8 {
                set = set.union(Self::single(ListId::ALL[i]));
            }
            i += 1;
        }
        set
    }

    /// `None` when a bit past the named lists is set, no list owns it.
    pub const fn from_record_bits(bits: u64) -> Option<Self> {
        if bits & !Self::NAMED.record_bits() != 0 {
            return None;
        }
        Some(Self(bits as u16))
    }

    /// Drops bits past the named lists, a rule reads the low `MAX_SOURCES` record bits alone.
    pub const fn named_in(bits: u64) -> Self {
        Self((bits & Self::NAMED.record_bits()) as u16)
    }

    pub const fn of(lists: &[ListId]) -> Self {
        let mut set = Self::EMPTY;
        let mut i = 0;
        while i < lists.len() {
            set = set.union(Self::single(lists[i]));
            i += 1;
        }
        set
    }

    pub const fn single(list_id: ListId) -> Self {
        Self(list_id.mask_bit())
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The low bits of a record's `lists` bitmap, the bits a `ListId` names.
    pub const fn record_bits(self) -> u64 {
        self.0 as u64
    }

    pub const fn contains(self, list_id: ListId) -> bool {
        self.0 & list_id.mask_bit() != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn is_subset(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// In `ALL` order.
    pub fn iter(self) -> impl Iterator<Item = ListId> {
        ListId::ALL
            .into_iter()
            .filter(move |list_id| self.contains(*list_id))
    }
}

/// Every list has a bit in a `ListSet`.
const _: () = {
    assert!(MAX_SOURCES <= u16::BITS as usize);
    let mut i = 0;
    while i < MAX_SOURCES {
        assert!(ListId::ALL[i].slot() == i);
        i += 1;
    }
};

/// A rule reads each policy list by one polarity, `RuleTable::validate` refuses the other.
const _: () = {
    assert!(ListSet::GRANT_LISTS.union(ListSet::DENY_LISTS).bits() == ListSet::POLICY_LISTS.bits());
    assert!(!ListSet::GRANT_LISTS.intersects(ListSet::DENY_LISTS));
};

impl TryFrom<u8> for ListId {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        usize::from(value)
            .checked_sub(1)
            .and_then(|slot| Self::ALL.get(slot).copied())
            .ok_or(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListWrite {
    set: ListSet,
    clear: ListSet,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListChange {
    pub set: ListSet,
    pub clear: ListSet,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ListWriteError {
    #[error("a list write changes no list")]
    Empty,
    #[error("a list is both set and cleared")]
    SetAndCleared,
}

impl ListChange {
    pub const fn check(self) -> Result<ListWrite, ListWriteError> {
        let Self { set, clear } = self;
        if set.union(clear).is_empty() {
            return Err(ListWriteError::Empty);
        }
        if set.intersects(clear) {
            return Err(ListWriteError::SetAndCleared);
        }
        Ok(ListWrite { set, clear })
    }
}

impl ListWrite {
    pub const fn set(self) -> ListSet {
        self.set
    }

    pub const fn clear(self) -> ListSet {
        self.clear
    }

    pub const fn mask(self) -> u64 {
        self.set.union(self.clear).record_bits()
    }

    pub const fn value(self) -> u64 {
        self.set.record_bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_writes_split_the_lists_between_the_member_and_the_authority() {
        assert_eq!(ListSet::MEMBER_LISTS, ListSet::single(ListId::RingViewing));
        assert_eq!(
            ListSet::AUTHORITY_WRITES,
            ListSet::of(&[
                ListId::Allow,
                ListId::Block,
                ListId::Frozen,
                ListId::PrivateBlock,
                ListId::Reader,
                ListId::Approval,
                ListId::PrivateAllow,
                ListId::PrivateFrozen,
            ])
        );
        assert!(!ListSet::MEMBER_LISTS.intersects(ListSet::AUTHORITY_WRITES));
    }

    #[test]
    fn a_rule_reads_the_authority_lists_but_the_reader_list() {
        assert_eq!(
            ListSet::POLICY_LISTS,
            ListSet::of(&[
                ListId::Allow,
                ListId::Block,
                ListId::Frozen,
                ListId::PrivateBlock,
                ListId::Approval,
                ListId::PrivateAllow,
                ListId::PrivateFrozen,
            ])
        );
    }

    #[test]
    fn a_list_write_masks_both_sets_and_values_only_the_set() {
        let write = ListChange {
            set: ListSet::single(ListId::Allow),
            clear: ListSet::single(ListId::Block),
        }
        .check()
        .unwrap();
        assert_eq!((write.mask(), write.value()), (0b11, 0b01));
        let member = ListChange {
            set: ListSet::EMPTY,
            clear: ListSet::single(ListId::RingViewing),
        }
        .check()
        .unwrap();
        assert_eq!((member.mask(), member.value()), (0b1000, 0));
    }

    #[test]
    fn a_list_write_refuses_no_list_and_a_list_both_set_and_cleared() {
        let write = |set, clear| ListChange { set, clear }.check();
        assert_eq!(
            write(ListSet::EMPTY, ListSet::EMPTY),
            Err(ListWriteError::Empty)
        );
        let allow = ListSet::single(ListId::Allow);
        assert_eq!(write(allow, allow), Err(ListWriteError::SetAndCleared));
    }

    #[test]
    fn record_bits_past_the_named_lists_have_no_set() {
        let named = ListSet::from_record_bits(0x1ff).unwrap();
        assert_eq!(named.len(), MAX_SOURCES);
        assert_eq!(ListSet::from_record_bits(0x200), None);
        assert_eq!(ListSet::named_in(0x3ff), named);
    }

    #[test]
    fn every_slot_of_all_parses_and_nothing_else_does() {
        for (slot, list_id) in ListId::ALL.into_iter().enumerate() {
            assert_eq!(ListId::try_from(slot as u8 + 1), Ok(list_id));
            assert_eq!(list_id.slot(), slot);
            assert_eq!(list_id.record_bit(), 1 << slot);
        }
        assert_eq!(ListId::try_from(0), Err(()));
        assert_eq!(ListId::try_from(MAX_SOURCES as u8 + 1), Err(()));
    }

    #[test]
    fn a_list_set_iterates_in_slot_order_and_ignores_repeats() {
        let set = ListSet::of(&[ListId::Frozen, ListId::Allow, ListId::Frozen]);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [ListId::Allow, ListId::Frozen]
        );
        assert_eq!(set.len(), 2);
        assert_eq!(set.bits(), 0b0000_0101);
        assert_eq!(set.record_bits(), 0b0000_0101);
        assert!(set.contains(ListId::Frozen));
        assert!(!set.contains(ListId::Block));
        assert!(set.intersects(ListSet::single(ListId::Allow)));
        assert!(!set.intersects(ListSet::of(&[ListId::Block, ListId::PrivateAllow])));
        assert_eq!(
            set.union(ListSet::single(ListId::PrivateAllow)).bits(),
            0b1000_0101
        );
        assert!(ListSet::EMPTY.is_empty());
    }
}
