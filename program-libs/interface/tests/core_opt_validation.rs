mod frames;

use custom_ring_interface::{CustomRingError, ParsedTransact, Replies, MIN_REPLY_LEN};
use frames::Fixture;

#[test]
fn checked_frames_accept_the_supported_authorization_modes() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        assert!(ParsedTransact::new(data).is_ok(), "{name}");
    }
}

#[test]
fn checked_frames_reject_hidden_owner_proofs_on_other_authorization_modes() {
    let fixture = Fixture::new();
    let hidden = fixture.anonymous_compact().anonymous;
    for mut data in [
        fixture.confidential_policy(),
        fixture.confidential_in_proof_owner(),
        fixture.anonymous_public_owners(),
        fixture.delegate(),
        fixture.anonymous_delegate(),
    ] {
        data.anonymous = hidden;
        assert_eq!(
            ParsedTransact::new(data),
            Err(CustomRingError::FlagNotAllowed)
        );
    }
}

#[test]
fn checked_frames_require_the_hidden_owner_proof() {
    let fixture = Fixture::new();
    let mut data = fixture.anonymous();
    data.anonymous = None;
    assert_eq!(
        ParsedTransact::new(data),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn checked_frames_reject_confidential_owner_proofs_on_other_rails() {
    let fixture = Fixture::new();
    let owner = fixture.confidential_in_proof_owner().in_proof_owner;
    for mut data in [
        fixture.anonymous(),
        fixture.anonymous_public_owners(),
        fixture.delegate(),
        fixture.anonymous_delegate(),
    ] {
        data.in_proof_owner = owner;
        assert_eq!(
            ParsedTransact::new(data),
            Err(CustomRingError::FlagNotAllowed)
        );
    }
}

#[test]
fn checked_frames_reject_public_owners_on_other_rails() {
    let fixture = Fixture::new();
    for mut data in [
        fixture.confidential_policy(),
        fixture.delegate(),
        fixture.anonymous_delegate(),
    ] {
        data.public_owners = true;
        assert_eq!(
            ParsedTransact::new(data),
            Err(CustomRingError::FlagNotAllowed)
        );
    }
}

#[test]
fn reply_construction_rejects_zero_and_short_chunks() {
    for len in [0, 1, (MIN_REPLY_LEN - 1) as u16] {
        for region in [&[][..], &[0; MIN_REPLY_LEN][..]] {
            assert_eq!(Replies::new(len, region), Err(CustomRingError::ReplyLength));
        }
    }
}

#[test]
fn reply_construction_rejects_incomplete_chunks() {
    let region = [0; MIN_REPLY_LEN * 2 + 1];
    for len in [MIN_REPLY_LEN - 1, MIN_REPLY_LEN + 1, region.len()] {
        assert_eq!(
            Replies::new(MIN_REPLY_LEN as u16, &region[..len]),
            Err(CustomRingError::ReplyLength)
        );
    }
}

#[test]
fn checked_frames_require_one_reply_per_recipient_body() {
    let fixture = Fixture::new();
    let valid = fixture.anonymous_replies(MIN_REPLY_LEN as u16);
    assert!(ParsedTransact::new(valid.clone()).is_ok());
    let region = [0; MIN_REPLY_LEN * 4];
    for chunks in [0, 1, 3, 4] {
        let mut data = valid.clone();
        data.replies =
            Some(Replies::new(MIN_REPLY_LEN as u16, &region[..MIN_REPLY_LEN * chunks]).unwrap());
        assert_eq!(ParsedTransact::new(data), Err(CustomRingError::ReplyLength));
    }
}

#[test]
fn checked_frames_keep_reply_chunks_on_their_recipient_slots() {
    let fixture = Fixture::new();
    let data = fixture.anonymous_replies(MIN_REPLY_LEN as u16);
    let replies = data.replies.unwrap();
    assert_eq!(usize::from(replies.byte_len()), MIN_REPLY_LEN);
    let parsed = ParsedTransact::new(data).unwrap();
    let slots: Vec<_> = parsed.data().slot_replies().collect();
    assert!(slots[0].is_empty());
    assert_eq!(slots[1], &replies.region()[..MIN_REPLY_LEN]);
    assert!(slots[2].is_empty());
    assert_eq!(slots[3], &replies.region()[MIN_REPLY_LEN..]);
}
