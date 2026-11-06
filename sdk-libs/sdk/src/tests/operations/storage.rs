use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::Revision, storage_instruction::tag as storage_tag, RecordWriteData,
};
use zolana_ring_policy::ListId;

use super::*;
use crate::tests::support::ring;

const AUTHORITY: Address = Address::new_from_array([3; 32]);
const REGISTRY: Address = Address::new_from_array([4; 32]);
const TRACKING: Address = Address::new_from_array([5; 32]);

fn write_of(list: ListId) -> RecordWriteData {
    let mut write = RecordWriteData::zeroed();
    write.member = [1; 32];
    write.lists.mask = list.record_bit().to_le_bytes();
    write
}

fn update(list: ListId, tracking_revision: Option<Revision>) -> Result<Instruction, RingError> {
    let apply = ApplyRecordsIxData::zeroed();
    UpdateStorage {
        authority: AUTHORITY,
        registry: REGISTRY,
        tracking_registry: TRACKING,
        data: StorageUpdateIxData {
            revision: Revision::from(1),
            writes: vec![write_of(list)],
            asset_writes: Vec::new(),
            tracking_revision,
            apply: &apply,
        },
    }
    .instruction()
}

#[test]
fn a_rings_records_pin_its_tracking_registry_at_their_own_address() {
    let storage = InitializeStorage::records(ring(), AUTHORITY);
    assert_eq!(
        storage.tracking_registry,
        ring().tracking_registry().unwrap()
    );
    assert_eq!(
        storage.registry(),
        StorageRegistry::find_address(&AUTHORITY, &RegistryId(ring().program_id().to_bytes())).0
    );
    let data = storage.instruction().data;
    assert_eq!(data[0], storage_tag::INITIALIZE);
    let sent: &InitializeIxData = bytemuck::from_bytes(&data[1..]);
    assert_eq!(sent.tracking_registry, storage.tracking_registry);
}

#[test]
fn a_public_write_names_the_authority_and_registry_alone() {
    let accounts = update(ListId::Block, None).unwrap().accounts;
    assert_eq!(
        accounts.iter().map(|meta| meta.pubkey).collect::<Vec<_>>(),
        [AUTHORITY, REGISTRY]
    );
}

#[test]
fn a_private_write_reads_the_pinned_tracking_registry() {
    let accounts = update(ListId::PrivateBlock, Some(Revision::from(2)))
        .unwrap()
        .accounts;
    assert_eq!(
        accounts.iter().map(|meta| meta.pubkey).collect::<Vec<_>>(),
        [AUTHORITY, REGISTRY, TRACKING]
    );
    assert!(!accounts[2].is_writable && !accounts[2].is_signer);
}
