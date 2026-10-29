# Envelope

The envelope seals a secret to the ring's X25519 auditor key. A ring uses it for the transaction viewing secret, a member's nullifier secret, deposit openings and the merge disclosure key. The same stream cipher keys every delivered body from its slot secret. Each circuit proves every step, so the ciphertext's hash in the statement fixes the plaintext. [Spec](../../spec.md) [Hashing](hashing.md)

## Key encoding

- A tagged X25519 key is `0x04 || u`, 33 bytes, with `u` the canonical 32-byte little-endian coordinate below `2^255 - 19`.
- `CreateConfig` refuses an auditor key whose `u` is one of the 5 low-order values. The program supplies the auditor key from the config, so a prover cannot pick the recipient.
- The auditor view tag is `u` without the tag byte.
- Secret scalars are clamped as RFC 7748. The audit circuit asserts that `tx_viewing_sk` is clamped.

## Shared secret

```text
dh     = X25519(eph_sk, auditor_u)                   // canonical u, all-zero output refused
eph_pk = 0x04 || X25519(eph_sk, 9)
secret = Poseidon(CR_S, pack_be(dh), pack_be(eph_pk), pack_be(auditor_pk))   // 7 inputs
```

The circuit does not prove that `eph_sk` is fresh. A reused `eph_sk` under one auditor key repeats the keystream. The SDKs draw a fresh key per envelope.

## Audit stream schedule

The audit envelope and every delivered body use the following schedule, with `info = "CRING/adt1"`:

```text
head  = Poseidon(right_align(info || 0x00), secret)
tail  = Poseidon(right_align(info || 0x01), secret)
key   = low31_be(head) || low13_be(tail)[0]          // 32 bytes
nonce = low13_be(tail)[1..13]                        // 12 bytes
ciphertext = AES-256-CTR(key, nonce || u32be(counter), plaintext), counter from 2
```

`lowN_be` takes the low `N` bytes of the canonical field value. For a body, `secret` is the slot secret of [Slot secret and sender commitment](hashing.md#slot-secret-and-sender-commitment). An anonymous body takes zolana's [AES Key derivation](../../../zolana/docs/spec.md#aes-key-derivation) outside every circuit.

## Labelled schedule

The register key, deposit and merge envelopes use the zolana verifiable encryption schedule with a 10-byte label:

```text
siloed = Poseidon(TMSI, secret, PackBytesBE(label)[0])
key    = low16_be(Poseidon(TMSL, siloed)) || low16_be(Poseidon(TMSK, siloed))
nonce  = low12_be(Poseidon(TMSN, siloed))
ciphertext = AES-256-CTR(key, nonce || u32be(counter), plaintext), counter from 2
```

The cipher carries no authentication tag. Integrity comes from `hash_bytes(ciphertext)` in the statement.

## Envelope uses

| Use | Schedule | Plaintext | Statement binds |
|---|---|---|---|
| Audit envelope | audit stream | `tx_viewing_sk`, 32 bytes | `hash_bytes(sealed)` |
| Delivered body | audit stream, slot secret | `fe32(blinding) \|\| u64be(amount)`, 40 bytes | `hash_bytes(body)` per slot |
| Register key | `CRING/nfk1` | the 32-byte nullifier secret, first byte zero | `hash_bytes(ciphertext)` |
| Deposit | `CRING/dep1` | per note `fe32(owner_hash) \|\| fe32(blinding) \|\| owner_key`, 96 bytes, one stream for the batch | `hash_bytes` of each 96-byte slot |
| Merge | `CRING/mrg1` | the 32-byte disclosure key of [Merge disclosure](disclosure.md#merge-disclosure) | `hash_bytes(ciphertext)` |

The deposit owner key is the Ed25519 key on an anonymous ring and 32 zero bytes otherwise.

## Deposit capsule

Each SPP deposit entry's ciphertext starts with a capsule the program parses:

```text
magic       "CRDEP001"
slot_index  u8, below 8, equal to the entry's position
eph_pk      [33], tag 0x04, equal across the batch
ciphertext  [96], bytes 96 i .. 96 i + 96 of the batch stream
recipient   the rest, the recipient's RingDepositPlaintext ciphertext, not proven
```

The capsule header is 138 bytes. The auditor opens the batch from one ECDH and checks each owner hash and blinding against the published `owner_utxo_hash`.
