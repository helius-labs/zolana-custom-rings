# Disclosure

The disclosure is the field list of the auditor message after `0x04 || eph_u || sealed`. It opens every output of a transfer to the holder of the transaction viewing secret. On the anonymous rail it also covers the spent notes. The commitment key (`AnonymousAudit`) names each spent note by hash or prefix. The entry key (`AnonymousEntryAudit`) serves a spend of default-ring notes and opens each one. [Spec](../../spec.md) [Envelope](envelope.md)

## Pad

```text
seed   = Poseidon(CROD, sk_0, sk_1, right_align(salt))   // (sk_0, sk_1) = PackBytesBE(tx_viewing_sk)
pad_j  = Poseidon(seed, j)
field_j = plaintext_j + pad_j  (mod q)
```

The salt is the 16-byte SPP salt of the transfer. A reused salt under one transaction viewing key repeats the pad. The program refuses a zero published field, because the disclosure chain hashes trailing zeros alike and honest fields are nonzero after the pad.

The auditor opens the envelope, derives the pad, subtracts it, and rebuilds each output commitment from the disclosed fields and the blinding `TXOB(n0, TXOS(n0, CRBS(tx_viewing_sk, salt)), i)`. Under exits the disclosure also carries `seed_out = TXOS(n0, CRBS(tx_viewing_sk, salt))` as its first field.

## Layout bits

| Bit | Name | Set when |
|---|---|---|
| 1 | exits | some output goes to the default ring |
| 2 | key escrow | the ring is in `ConfidentialEscrow` mode. Output nullifier keys are withheld, the escrow records give them. |
| 4 | reserved | always clear, every key accepts either value |
| 8 | full openings | an anonymous transfer spends default-ring notes |

The delivered key varies exits and key escrow. The anonymous key varies exits and pins key escrow to `0`. The entry key varies exits, pins full openings to `1` and pins key escrow to `0`.

## Fields per layout

`[x]` is present only when its condition holds. `pack` is `pack_disclosure`.

| Layout | Fields in order |
|---|---|
| Delivered, capacity `c` | `[seed_out if exits]`, `[nullifier_pk × c unless key escrow]`, `pack(slot × c)` with 40-byte slots under exits and 32-byte slots otherwise |
| Anonymous, commitment key | `[seed_out if exits]`, `nullifier_pk × outputs`, `pack(slot × outputs)` with 72-byte slots, `hash_0`, then the `n - 1` other prefixes in `floor(n / 2)` pairs |
| Anonymous, entry key | `[seed_out if exits]`, `sender_nullifier_pk`, `nullifier_pk × outputs`, `pack(sender_key \|\| slot × outputs)`, `pack(u64be(amount_i) × 8)` (3 fields), `(asset_i, blinding_i) × n` |

Slot bytes:

| Layout | Ring output | Exit | Dummy |
|---|---|---|---|
| Delivered | `owner_key \|\| 0^8` | `fe32(asset) \|\| u64be(amount)` | zeros |
| Anonymous | `owner_key \|\| fe32(asset) \|\| u64be(amount)` | `0^32 \|\| fe32(asset) \|\| u64be(amount)` | zeros |

A delivered ring output's amount and blinding are in its body, not in the disclosure. The auditor rebuilds the slot secret from `tx_viewing_sk` and the published `u`, and opens the body. An anonymous slot opens the asset and the amount of every live output, the auditor derives the blinding, and no anonymous body enters the disclosure.

## Spent notes on the anonymous rail

- The commitment key discloses `hash_0`, the full hash of the first spent note, and the 16-byte prefix `p_k = hash_k >> 128` of every other. Prefixes pack in pairs as `p_k * 2^126 + p_{k+1}`, the last half zero for an odd count. Each prefix is below `2^126`.
- The auditor finds `hash_0` among the notes it opened before, and matches every prefix among the sender's ring notes. Several matches leave candidates, no match leaves the input unseen.
- The entry key spends default-ring notes, which the auditor never opened. It discloses every spent note's amount, asset and blinding, and the sender's key and nullifier key.

## Merge disclosure

A merge seals a fresh 32-byte disclosure key under `CRING/mrg1` and masks its fields with:

```text
seed  = Poseidon(CR_MD, PackBytesBE(disclosure_key), right_align(salt))
pad_i = Poseidon(seed, i)
plaintext = owner_key || fe32(nullifier_pk) || mint || u64be(amount) || fe32(output_blinding) || fe32(input_hash) × width
fields    = pack(plaintext) + pad
```

The salt is the SPP merge output salt. The field count is 13 at width 8 and 30 at width 24.
