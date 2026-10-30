//! `test-vectors/wallet/ring_address.json` pins the `zolana:` payment request form for every
//! implementation, the ignored `print_ring_address_vectors` regenerates it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_ring_keys::{
    ring_address::{RING_ADDRESS_CHECKSUM_DOMAIN, RING_ADDRESS_VERSION},
    RingAddress, RingKeyError, RingPaymentRequest,
};

const VECTORS_JSON: &str = include_str!("../../../test-vectors/wallet/ring_address.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RingAddressVectors {
    valid: Vec<ValidCase>,
    rejected: Vec<RejectedCase>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ValidCase {
    name: String,
    uri: String,
    recipient: String,
    ring_program_id: String,
    request_view_tag: String,
    amount: Option<String>,
    mint: Option<String>,
    label: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RejectedCase {
    name: String,
    uri: String,
    error: String,
}

const RING: Address = Address::new_from_array([0x11; 32]);

fn viewing_key() -> ViewingKey {
    ViewingKey::from_bytes(&[0x21; 32])
}

/// The wallet's signing and nullifier keys beside its viewing key.
fn fixture_address() -> RingAddress {
    let wallet = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32]))
        .unwrap()
        .shielded_address()
        .unwrap();
    RingAddress {
        recipient: ShieldedAddress {
            viewing_pubkey: viewing_key().pubkey(),
            ..wallet
        },
        ring_program_id: RING,
    }
}

fn fixture_request() -> RingPaymentRequest {
    RingPaymentRequest::new(
        fixture_address(),
        viewing_key().get_recipient_request_view_tag(0).unwrap(),
    )
}

fn valid_case(name: &str, request: &RingPaymentRequest) -> ValidCase {
    ValidCase {
        name: name.into(),
        uri: request.to_string(),
        recipient: hex::encode(request.address.recipient.to_bytes()),
        ring_program_id: request.address.ring_program_id.to_string(),
        request_view_tag: hex::encode(request.request_view_tag),
        amount: request.amount.map(|amount| amount.to_string()),
        mint: request.mint.map(|mint| mint.to_string()),
        label: request.label.clone(),
    }
}

/// `payload` with its checksum recomputed over the bytes before it.
fn with_checksum(mut payload: Vec<u8>) -> Vec<u8> {
    let body_len = payload.len() - 4;
    let digest = Sha256::new()
        .chain_update(RING_ADDRESS_CHECKSUM_DOMAIN)
        .chain_update(&payload[..body_len])
        .finalize();
    payload[body_len..].copy_from_slice(&digest[..4]);
    payload
}

/// A key error names the keypair variant, the name every implementation shares.
fn variant_name(error: RingKeyError) -> String {
    let debug = match error {
        RingKeyError::Keypair(error) => format!("{error:?}"),
        error => format!("{error:?}"),
    };
    debug.split('(').next().unwrap_or(&debug).to_string()
}

fn compute() -> RingAddressVectors {
    let bare = fixture_request();
    let full = RingPaymentRequest {
        amount: Some(1_500_000),
        mint: Some(Address::new_from_array([0x33; 32])),
        label: Some("Coffee & cake ☕ 100%".into()),
        ..bare.clone()
    };
    let labelled = RingPaymentRequest {
        label: Some("rent".into()),
        ..bare.clone()
    };
    let valid = vec![
        valid_case("bare", &bare),
        valid_case("amount_mint_label", &full),
        valid_case("label_only", &labelled),
    ];

    let address = &bare.address;
    let payload = address.to_bytes().to_vec();
    let base58 = address.to_base58();
    let tag = hex::encode(bare.request_view_tag);
    let uri = |payload: &[u8]| format!("zolana:{}?tag={tag}", bs58::encode(payload).into_string());
    let mut wrong_version = payload.clone();
    wrong_version[0] = RING_ADDRESS_VERSION - 1;
    let mut bad_checksum = payload.clone();
    *bad_checksum.last_mut().unwrap() ^= 1;
    let mut bad_viewing_key = payload.clone();
    bad_viewing_key[1 + 34 + 32] = 5;
    let mut nonzero_lead = bare.request_view_tag;
    nonzero_lead[0] = 1;
    let rejected = vec![
        ("missing_scheme", format!("{base58}?tag={tag}")),
        ("non_base58", format!("zolana:0{}?tag={tag}", &base58[1..])),
        ("short_payload", uri(&payload[..payload.len() - 1])),
        ("long_payload", uri(&[payload.as_slice(), &[0]].concat())),
        ("unknown_version", uri(&with_checksum(wrong_version))),
        ("bad_checksum", uri(&bad_checksum)),
        ("bad_viewing_key", uri(&with_checksum(bad_viewing_key))),
        ("missing_tag", format!("zolana:{base58}")),
        (
            "uppercase_tag",
            format!("zolana:{base58}?tag={}", tag.to_uppercase()),
        ),
        ("short_tag", format!("zolana:{base58}?tag={}", &tag[2..])),
        (
            "tag_without_zero_byte",
            format!("zolana:{base58}?tag={}", hex::encode(nonzero_lead)),
        ),
        ("unknown_query_key", format!("{bare}&memo=hi")),
        ("duplicate_query_key", format!("{bare}&amount=1&amount=2")),
        ("fractional_amount", format!("{bare}&amount=1.5")),
        ("signed_amount", format!("{bare}&amount=+1")),
        ("bad_mint", format!("{bare}&mint=notAnAddress")),
        ("bad_label_escape", format!("{bare}&label=%zz")),
    ]
    .into_iter()
    .map(|(name, uri)| RejectedCase {
        name: name.into(),
        error: variant_name(uri.parse::<RingPaymentRequest>().unwrap_err()),
        uri,
    })
    .collect();
    RingAddressVectors { valid, rejected }
}

#[test]
fn shared_vectors_match() {
    let committed: RingAddressVectors = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(committed, compute());
    for case in &committed.valid {
        let request: RingPaymentRequest = case.uri.parse().unwrap();
        assert_eq!(request.to_string(), case.uri, "{}", case.name);
        assert_eq!(
            hex::encode(request.address.recipient.to_bytes()),
            case.recipient
        );
        assert_eq!(
            request.address.ring_program_id.to_string(),
            case.ring_program_id
        );
        assert_eq!(hex::encode(request.request_view_tag), case.request_view_tag);
        assert_eq!(
            request.address,
            RingAddress::from_base58(&request.address.to_base58()).unwrap()
        );
    }
    let expected_errors = [
        ("missing_scheme", "InvalidRingAddressScheme"),
        ("non_base58", "InvalidRingAddressBase58"),
        ("short_payload", "InvalidRingAddressLength"),
        ("long_payload", "InvalidRingAddressLength"),
        ("unknown_version", "UnknownRingAddressVersion"),
        ("bad_checksum", "InvalidRingAddressChecksum"),
        ("bad_viewing_key", "InvalidPublicKey"),
        ("missing_tag", "MissingRingPaymentTag"),
        ("uppercase_tag", "InvalidRingPaymentTag"),
        ("short_tag", "InvalidRingPaymentTag"),
        ("tag_without_zero_byte", "InvalidRingPaymentTag"),
        ("unknown_query_key", "UnknownRingPaymentKey"),
        ("duplicate_query_key", "DuplicateRingPaymentKey"),
        ("fractional_amount", "InvalidRingPaymentAmount"),
        ("signed_amount", "InvalidRingPaymentAmount"),
        ("bad_mint", "InvalidRingPaymentMint"),
        ("bad_label_escape", "InvalidRingPaymentLabel"),
    ];
    assert_eq!(committed.rejected.len(), expected_errors.len());
    for (case, (name, error)) in committed.rejected.iter().zip(expected_errors) {
        assert_eq!((case.name.as_str(), case.error.as_str()), (name, error));
    }
}

#[test]
fn request_round_trips_every_field() {
    let request = RingPaymentRequest {
        amount: Some(u64::MAX),
        mint: Some(Address::new_from_array([0x44; 32])),
        label: Some("a=b&c?d/é".into()),
        ..fixture_request()
    };
    assert_eq!(
        request.to_string().parse::<RingPaymentRequest>().unwrap(),
        request
    );
}

#[test]
fn a_request_prints_neither_its_recipient_keys_nor_its_tag() {
    let request = fixture_request();
    let address = &request.address;
    for printed in [format!("{address:?}"), format!("{request:?}")] {
        for key in [
            format!("{:?}", address.recipient.viewing_pubkey),
            format!("{:?}", address.recipient.signing_pubkey),
            format!("{:?}", request.request_view_tag),
        ] {
            assert!(!printed.contains(&key), "{printed}");
        }
    }
}

#[test]
#[ignore = "regenerates test-vectors/wallet/ring_address.json; run with --nocapture and commit the output"]
fn print_ring_address_vectors() {
    println!("{}", serde_json::to_string_pretty(&compute()).unwrap());
}
