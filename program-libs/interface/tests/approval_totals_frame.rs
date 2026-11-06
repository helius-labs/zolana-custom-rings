//! Pins `test-vectors/proof/approval_totals_frame.json` for the TS SDK.

mod frames;

use custom_ring_interface::{extension_flag, RingRail, RingTransactData};
use frames::Fixture;
use serde::Serialize;

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/approval_totals_frame.json"
);

#[derive(Serialize)]
struct Vector {
    description: &'static str,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Case {
    name: &'static str,
    base: String,
    frame: String,
    digest: String,
    extension_offset: usize,
    extension_byte: u8,
    digest_offset: usize,
}

fn offset_of(frame: &[u8], field: &[u8; 32]) -> usize {
    let mut found = frame.windows(32).enumerate().filter(|(_, at)| at == field);
    let (offset, _) = found.next().expect("field in the frame");
    assert!(found.next().is_none());
    offset
}

fn case<'a>(name: &'static str, digest: &'a [u8; 32], mut data: RingTransactData<'a>) -> Case {
    let base = data.encode().unwrap();
    data.extensions.approval_totals = Some(digest);
    let frame = data.encode().unwrap();
    let parsed = RingTransactData::parse(&frame, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert_eq!(parsed.extensions.approval_totals, Some(digest));
    let digest_offset = offset_of(&frame, digest);
    // The flags byte sits ahead of the first extension field.
    let extension_offset = offset_of(&frame, data.extensions.data_hash.unwrap_or(digest)) - 1;
    let extension_byte = frame[extension_offset];
    assert_ne!(extension_byte & extension_flag::APPROVAL_TOTALS, 0);
    Case {
        name,
        base: hex::encode(base),
        frame: hex::encode(frame),
        digest: hex::encode(digest),
        extension_offset,
        extension_byte,
        digest_offset,
    }
}

fn vector_text() -> String {
    let fixture = Fixture::new();
    let digest = &fixture.fields[73];
    let frame = |name: &str| {
        let (_, data) = fixture
            .cases()
            .into_iter()
            .find(|(case, _)| *case == name)
            .expect("named frame");
        data
    };
    let vector = Vector {
        description: "A confidential frame with no other extension and one with every other \
                      SPP extension, each with the approval totals digest under bit 4 of the \
                      extension byte. base is the same frame with no digest.",
        cases: vec![
            case("alone", digest, frame("confidential_thresholds")),
            case("withOthers", digest, frame("confidential_extensions")),
        ],
    };
    serde_json::to_string_pretty(&vector).expect("json") + "\n"
}

#[test]
fn the_digest_frames_are_the_shared_vector() {
    assert_eq!(
        std::fs::read_to_string(VECTOR).expect("vector file"),
        vector_text()
    );
}

#[test]
#[ignore = "rewrites test-vectors/proof/approval_totals_frame.json"]
fn write_approval_totals_frame_vector() {
    std::fs::write(VECTOR, vector_text()).expect("write vector file");
}
