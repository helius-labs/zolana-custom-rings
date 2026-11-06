mod frames;
mod ring_policy;

use custom_ring_interface::{
    encode_confidential_output, AppMessage, ParsedTransact, RingPolicy, RingTransactData,
    Settlement, SlotBody,
};
use frames::Fixture;
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use spr_interface::instruction::{
    instruction_data::transact::CacheAccess, ExternalDataPreimage, TransactIxDataRef, TransactProof,
};

#[test]
fn borrowed_expansion_matches_owned_bytes_and_hashes_on_every_rail() {
    let fixture = Fixture::new();
    let ring = ring_policy::config();
    for (_, data) in fixture.cases() {
        assert_owned_parity(&data, &ring);
    }
}

#[test]
fn cached_expansion_preserves_the_owned_selector_and_hash_boundary() {
    let fixture = Fixture::new();
    let ring = ring_policy::config();
    let mut data = fixture.confidential_extensions();
    data.extensions.cache = Some(CacheAccess {
        read_bitmap: 1,
        write_slots: CacheAccess::NO_WRITES,
    });
    assert_owned_parity(&data, &ring);
}

#[test]
fn nullifier_digest_binds_published_count_order_and_capacity_padding() {
    let fixture = Fixture::new();
    let data = fixture.confidential_extensions();
    let parsed = ParsedTransact::new(data.clone()).unwrap();
    let capacity = parsed.audit_stream().key.class();
    let mut expected = vec![right_align(&2u64.to_be_bytes())];
    expected.extend_from_slice(data.nullifiers);
    expected.resize(1 + capacity, [0; 32]);
    let digest = parsed.input_nullifier_chain().unwrap();
    assert_eq!(digest, create_hash_chain_4_from_slice(&expected).unwrap());

    let reordered = [data.nullifiers[1], data.nullifiers[0]];
    let mut changed = data.clone();
    changed.nullifiers = &reordered;
    assert_ne!(
        ParsedTransact::new(changed)
            .unwrap()
            .input_nullifier_chain()
            .unwrap(),
        digest
    );

    let mut shortened = data;
    shortened.nullifiers = &shortened.nullifiers[..1];
    let shortened = ParsedTransact::new(shortened).unwrap();
    expected[0] = right_align(&1u64.to_be_bytes());
    expected[2] = [0; 32];
    assert_eq!(
        shortened.input_nullifier_chain().unwrap(),
        create_hash_chain_4_from_slice(&expected).unwrap()
    );
    assert_ne!(shortened.input_nullifier_chain().unwrap(), digest);
}

#[test]
fn borrowed_message_length_has_the_same_u16_boundary_as_the_owned_codec() {
    let fixture = Fixture::new();
    let ring = ring_policy::config();
    let bytes = vec![0x6a; usize::from(u16::MAX) + 1];
    let mut data = fixture.confidential_extensions();
    data.extensions.messages = vec![AppMessage {
        view_tag: &fixture.bytes[0],
        data: &bytes[..usize::from(u16::MAX)],
    }];
    assert_owned_parity(&data, &ring);

    data.extensions.messages[0].data = &bytes;
    assert!(data
        .transact_ix_data(&ring, TransactProof::zeroed())
        .is_err());
    assert!(data
        .spp_instruction_data_under(&ring, TransactProof::zeroed())
        .is_err());
    assert!(data.external_data_hash(&ring, &[]).is_err());
}

#[test]
fn borrowed_output_length_includes_the_encrypted_output_prefix() {
    let fixture = Fixture::new();
    let ring = ring_policy::config();
    let prefix_len = encode_confidential_output(&[]).unwrap().len();
    let max_payload_len = usize::from(u16::MAX) - prefix_len;
    let bytes = vec![0x6b; max_payload_len + 1];
    let mut data = fixture.confidential_data();
    data.outputs[1].body = SlotBody::Exit(&bytes[..max_payload_len]);
    assert_owned_parity(&data, &ring);

    data.outputs[1].body = SlotBody::Exit(&bytes);
    assert!(data
        .transact_ix_data(&ring, TransactProof::zeroed())
        .unwrap()
        .serialize()
        .is_err());
    assert!(data
        .spp_instruction_data_under(&ring, TransactProof::zeroed())
        .is_err());
    assert!(data.external_data_hash(&ring, &[]).is_err());
}

fn assert_owned_parity(data: &RingTransactData<'_>, ring: &RingPolicy) {
    let owned = data
        .transact_ix_data(ring, TransactProof::zeroed())
        .unwrap()
        .serialize()
        .unwrap();
    let tag = [data.rail.spp_tag()];
    let actual = data
        .spp_instruction_data_under(ring, TransactProof::zeroed())
        .unwrap();
    assert_eq!(actual.len(), 1 + owned.len());
    assert_eq!(&actual[..1], &tag);
    assert_eq!(&actual[1..], owned);

    let (_, prefix) = TransactIxDataRef::parse_with_external_data_prefix(&owned).unwrap();
    let accounts: Vec<_> = (0..data.interface_transfers.len())
        .map(|index| [[index as u8 + 1; 32], [index as u8 + 65; 32]])
        .collect();
    let settlements: Vec<_> = accounts
        .iter()
        .map(|[asset_account, user_account]| Settlement {
            asset_account,
            user_account,
        })
        .collect();
    let mut preimage = ExternalDataPreimage::new(&tag, prefix);
    for settlement in &settlements {
        preimage
            .push_settlement(settlement.asset_account, settlement.user_account)
            .unwrap();
    }
    assert_eq!(
        data.external_data_hash(ring, &settlements).unwrap(),
        preimage.finish().unwrap()
    );
}
