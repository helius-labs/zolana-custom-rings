# Envelope

The envelope seals a secret to the ring's X25519 auditor key. A ring uses it for a transfer's auditor stream, an enrolling owner's nullifier secret and list salt, and a merge's opening record. The stream schedule also keys every recipient body, reply and sender bundle from a slot secret, outside every proof. [Spec](../../spec.md) [Hashing](hashing.md) [Disclosure](disclosure.md)

The ring program verifies the transfer and merge proofs. The Storage program verifies the register key proof in `Enroll` on an owner's first enrollment. In each, the ciphertext's hash in the statement fixes the plaintext.

## Key encoding

- A tagged X25519 key is `0x04 || u`, 33 bytes, with `u` the canonical 32-byte little-endian coordinate below `2^255 - 19`.
- Ring `Initialize` refuses an auditor key whose `u` is one of the 5 low-order values. The program supplies the auditor key from the ring account, so a prover cannot pick the recipient.
- The auditor view tag is `u` without the tag byte.
- Secret scalars are clamped as RFC 7748. The audit circuit asserts that `tx_viewing_sk` is clamped.

## Shared secret

```text
dh     = X25519(eph_sk, auditor_u)                   // canonical u, all-zero output refused
eph_pk = 0x04 || X25519(eph_sk, 9)
secret = Poseidon(CR_S, pack_be(dh), pack_be(eph_pk), pack_be(auditor_pk))   // 7 inputs
salted = Poseidon(secret, right_align(salt))         // auditor stream only
```

The auditor stream takes `tx_viewing_sk` as `eph_sk`, so `eph_pk` is SPP's `tx_viewing_pk`. The stream keys its schedule from `salted` with SPP's 16-byte `salt`. A resend under one first nullifier repeats `tx_viewing_sk`, and the SDKs draw a fresh salt per build, so the keystream differs. The register key and merge lines key their schedule from `secret` under a fresh `eph_sk`. The circuit proves neither freshness. A reused key and salt under one auditor key repeats the keystream.

## Stream schedule

Every ring encryption line uses one schedule, with a 9-byte label as a parameter:

```text
head  = Poseidon(right_align(label || 0x00), secret)
tail  = Poseidon(right_align(label || 0x01), secret)
key   = low31_be(head) || low13_be(tail)[0]          // 32 bytes
nonce = low13_be(tail)[1..13]                        // 12 bytes
ciphertext = AES-256-CTR(key, nonce || u32be(counter), plaintext), counter from 2
```

`lowN_be` takes the low `N` bytes of the canonical field value. The label enters the first Poseidon input, so one secret gives one key per label.

| Label | Line | Secret |
|---|---|---|
| `CRING/adt` | auditor stream | `salted` above, `eph_sk = tx_viewing_sk` |
| `CRING/rcp` | recipient body, scheme 10 or 11 | [slot secret](hashing.md#slot-secret) at `i` |
| `CRING/rpl` | reply metadata | the secret of slot `i`'s body |
| `CRING/snd` | sender bundle, scheme 9 | slot secret at `m` under the sender's viewing key |
| `CRING/nfk` | register key | `secret` above |
| `CRING/mrg` | merge | `secret` above |

One label per ciphertext kind gives each kind its own key and nonce, so a reply never restarts the body's counter. On an anonymous frame, the ring output tags and the bundle tag each take one more Poseidon output of the slot secret keying the ciphertext. Each tag has its own [domain](hashing.md#domain-tags). An exit's scheme 3 body takes zolana's [AES Key derivation](../../../zolana/docs/spec.md#aes-key-derivation) outside every circuit.

## Envelope uses

No line has an authentication tag. Integrity comes from the statement, or for a line outside every proof from SPP's external data hash over its bytes alone.

| Use | Schedule | Plaintext | Statement binds |
|---|---|---|---|
| Auditor stream | `CRING/adt` | the envelope, records and tails of [Disclosure](disclosure.md) | `pack_be` of `tx_viewing_pk` and of the auditor key, the salt, `digest(envelope_ct)`, `HashChain4(hash_bytes(record_ct_i))` and `HashChain4(hash_bytes(tail_ct_i))` zero filled to `N`, the tail chain `0` without `has_data` |
| Recipient body | `CRING/rcp`, slot secret | the [recipient body](disclosure.md#recipient-body) | no statement, SPP's external data hash binds the bytes |
| Reply metadata | `CRING/rpl`, slot secret | the [reply](disclosure.md#reply-metadata) | no statement, SPP's external data hash binds the bytes |
| Sender bundle | `CRING/snd`, slot secret | the [sender bundle](disclosure.md#sender-bundle) | no statement, SPP's external data hash binds the bytes |
| Register key | `CRING/nfk` | `fe32(nullifier_secret) \|\| fe32(list_salt)`, 64 bytes, each with a zero lead byte | `pack_be` of both tagged keys, `hash_bytes(ciphertext)` |
| Merge | `CRING/mrg` | one 144-byte [opening record](disclosure.md#merges), its secret the merge seed | `pack_be` of both tagged keys, `hash_bytes(ciphertext)` |

A merge record's `owner_key` is the key whose `solana_owner_identity` is the note's `owner_pk_hash`. The merge's `eph_pk` and ciphertext travel in the ring instruction, since SPP's merge publishes no auditor message.
