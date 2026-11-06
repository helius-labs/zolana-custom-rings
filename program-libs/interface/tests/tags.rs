use custom_ring_interface::{compute_unit_limit, tag, CustomRingError, InstructionTag};

#[test]
fn ring_dispatch_tags_do_not_collide_with_forwarded_spp_tags() {
    use spr_interface::instruction::tag as spp;

    let tags = [
        spp::RING_TRANSACT,
        spp::RING_AUTHORITY_TRANSACT,
        spp::RING_MERGE_TRANSACT,
        tag::INITIALIZE,
        tag::UPDATE_POLICY,
        tag::TRANSFER,
        tag::MERGE,
        tag::UPDATE_AUTHORITY,
        tag::SET_PAUSED,
        tag::SET_CO_SIGNER,
        tag::CLEAR_CO_SIGNER,
        tag::SET_DELEGATE,
        tag::AUTHORITY_TRANSFER,
    ];
    let unique: std::collections::BTreeSet<_> = tags.into_iter().collect();
    assert_eq!(unique.len(), tags.len());
}

#[test]
fn frame_tags_stay_pinned() {
    assert_eq!(
        (tag::TRANSFER, tag::AUTHORITY_TRANSFER, tag::MERGE),
        (55, 56, 57)
    );
}

#[test]
fn unassigned_tags_name_no_instruction() {
    for unassigned in [
        1, 2, 4, 5, 7, 8, 9, 10, 12, 18, 21, 22, 23, 24, 26, 28, 29, 30, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 48, 3, 25, 31, 43, 44, 45, 46, 47, 58, 59, 60, 61, 63,
    ] {
        assert_eq!(
            InstructionTag::try_from(unassigned),
            Err(CustomRingError::InvalidInstructionData),
            "{unassigned}"
        );
    }
}

#[test]
fn every_tag_names_one_instruction_and_its_budget() {
    for value in 0..=u8::MAX {
        if let Ok(tag) = InstructionTag::try_from(value) {
            assert!((50_000..=1_400_000).contains(&compute_unit_limit(tag)));
        }
    }
    assert_eq!(
        InstructionTag::try_from(0),
        Err(CustomRingError::InvalidInstructionData)
    );
    assert_eq!(compute_unit_limit(InstructionTag::SetPaused), 50_000);
    assert_eq!(compute_unit_limit(InstructionTag::UpdatePolicy), 150_000);
    assert_eq!(compute_unit_limit(InstructionTag::Transfer), 1_400_000);
}
