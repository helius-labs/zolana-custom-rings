# Hashing

Every commitment and statement of a custom ring is a Poseidon hash over BN254. This file pins each encoding two implementations could choose differently. [Spec](../../spec.md)

## Poseidon

`Poseidon(x_1, ..., x_n)` is the zolana BN254 Poseidon of width `n + 1`, at most 12 inputs. `q` is the BN254 scalar field modulus. Every input is a canonical field element, a 32-byte big-endian value below `q`.

## Folds

- `HashChain([x_0, ..., x_n])` is the left fold `h = x_0`, then `h = Poseidon(h, x_i)`. An empty list hashes to `0`.
- `NonZeroHashChain(xs)` is `HashChain` over the nonzero elements of `xs`, and `0` when none is nonzero.
- `HashChain4([x_0, ..., x_n])` is `h = x_0`, then `h = Poseidon(h, g_0, g_1, g_2)` per group of three of `x_1..`, with the last group padded by zeros. `[a]` hashes to `a`. It hashes no length, so every statement that uses it has a fixed element count per key.
- `HashPrefix4(xs, n)` is `HashChain4` of the first `n` elements. A circuit selects `n` by a one-hot flag set over the key's range.

## Bytes to fields

- `PackBytesBE(b)` splits `b` into 31-byte chunks, each read as a big-endian integer. The last chunk is not padded, so its value sits in the low bytes. Rust names it `pack_be`.
- `hash_bytes(b) = HashChain(PackBytesBE(b))`. A value of one chunk is returned packed, without Poseidon. It hashes no length, so each use has one fixed input length.
- `right_align(x)` places `x` in the low bytes of a 32-byte big-endian field.
- `fe32(x)` is the canonical 32-byte big-endian encoding of the field element `x`. `u32be` and `u64be` are big-endian integers of 4 and 8 bytes.
- A 33-byte tagged key `0x04 || u` packs to `[BE(bytes[0..31]), BE(bytes[31..33])]`. A 32-byte value packs to `[BE(bytes[0..31]), bytes[31]]`.
- `pack_disclosure(b)` splits `b` into 31-byte chunks, each placed at byte 1 of a field and padded with zeros at the end. It differs from `PackBytesBE` only in a short last chunk.

## Identities

| Value | Encoding |
|---|---|
| Owner identity | `solana_owner_identity(key) = hash_bytes(0x53 \|\| key)`, for an Ed25519 key or a PDA |
| Nullifier key | `nullifier_pk = Poseidon(secret)`, the 31-byte secret read big endian |
| Owner hash | `Poseidon(owner_identity, nullifier_pk)` |
| Ring id | `hash_bytes(ring program id)` |
| Asset | `hash_bytes(mint)`, and `SOL_ASSET_FIELD = Poseidon(0, 0) = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864` for SOL |
| Owner member | `solana_owner_identity(key)` |
| Asset member | `hash_bytes(mint)`. The CLI names SOL by the zero address. |
| UTXO hash | `Poseidon(domain, tree_id, asset, amount, data_hash, Poseidon(ring_data_hash, ring_id), Poseidon(owner_hash, blinding))`, domains dummy `1`, address `2`, UTXO `3`, as zolana defines it |

## Blinding derivations

| Value | Encoding |
|---|---|
| Blinding seed of a ring transfer | `CRBS(tx_viewing_sk, salt) = Poseidon(CRBS, sk_0, sk_1, right_align(salt))`, with `(sk_0, sk_1) = PackBytesBE(tx_viewing_sk)` |
| Output seed | `TXOS(n0, seed) = Poseidon(TXOS, n0, seed)` |
| Output blinding | `TXOB(n0, output_seed, i) = Poseidon(TXOB, n0, output_seed, i)` |
| Private transaction blinding | `TXPB(n0, seed) = Poseidon(TXPB, n0, seed)` |
| Deposit blinding | `Poseidon(CRDB, blinding_secret)` |
| Merge output blinding | `TMOB(nullifier_secret, n0)`, as zolana defines it |

`n0` is the transfer's first nullifier. The audit proof pins each live output's blinding. SPP derives every output blinding and `private_tx_blinding` from one seed, so one live output fixes the seed to `CRBS(tx_viewing_sk, salt)`, and the auditor derives both from the sealed key.

## Slot secret and sender commitment

| Value | Encoding |
|---|---|
| Delivered slot secret | `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(0x04 \|\| u), right_align(salt), i, n0)`, `dh = X25519(tx_viewing_sk, u)`, 10 inputs |
| Sender commitment | `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)` |

The recipient rebuilds the slot secret from `X25519(u_sk, tx_viewing_u)`, the auditor from the sealed transaction viewing secret. The anonymous rail hashes no tag and no body. Its view tags and body keys are zolana's [View Tags](../../../zolana/docs/spec.md#view-tags) and [AES Key derivation](../../../zolana/docs/spec.md#aes-key-derivation).

## Member registry

| Value | Encoding |
|---|---|
| Member range | `1 <= member <= q - 2`, as big-endian bytes |
| Record | `Poseidon(member, next, right_align(lists as u64 BE), escrow_key, mint_policy, right_align(withdrawal_threshold as u64 BE), limits_0, limits_1, limits_2)` |
| Mint policy field | `threshold * 2^128 + cap * 2^64 + cosign_above`, each a u64 |
| Asset limit fields | `limits_0 = sender_cap * 2^128 + sender_window_slots * 2^64 + volume_cap`, `limits_1 = volume_window_slots * 2^128 + deposit_cap * 2^64 + deposit_window_slots`, `limits_2 = withdrawal_cap * 2^64 + withdrawal_window_slots`, each a u64 |
| Sentinel | `(0, q - 1, 0, 0, 0, 0, 0, 0, 0)` at leaf `0` |
| Escrow key | `Poseidon(nullifier_pk, hash_bytes(ciphertext))`, the 32-byte sealed secret |
| Tree node | `Poseidon(c_0, c_1, c_2, c_3)`, height 10, the leaf index as 20 bits |
| Queue entry | `Poseidon(CRQW, member, right_align(mask), right_align(value), escrow_key, mint_policy_write, right_align(withdrawal_threshold), limits_0, limits_1, limits_2)` |
| Mint policy write | `0` when the write keeps the mint settings, else `2^192 + mint policy field`. `withdrawal_threshold` and every asset limit field are `0` when the write keeps them. |
| Queue chain | `chain(-1) = 0`, `chain(p) = Poseidon(chain(p - 1), entry_p)` |

`policy_hash` is in [EncodedRuleTable](../../spec.md#encodedruletable).

## Domain tags

| Tag | Value | Use |
|---|---|---|
| `CRAU` | `0x43524155` | audit statement |
| `CRDS` | `0x43524453` | delivered slot secret |
| `CRBS` | `0x43524253` | ring blinding seed |
| `CRSC` | `0x43525343` | sender commitment |
| `CROD` | `0x43524f44` | disclosure pad |
| `CRPO` | `0x4352504f` | policy statement |
| `CRTB` | `0x43525442` | policy table hash |
| `CRPW` | `0x43525057` | withdrawal digest |
| `CRQW` | `0x43525157` | queue entry |
| `CRAP` | `0x43524150` | apply statement |
| `CRRG` | `0x43525247` | register key statement |
| `CRDP` | `0x43524450` | deposit statement |
| `CRDB` | `0x43524442` | deposit blinding |
| `CRWX` | `0x43525758` | withdrawal exemption statement |
| `CRMG` | `0x43524d47` | merge statement |
| `CRRU` | `0x43525255` | record update statement |
| `CRWG` | `0x43525747` | wallet grant record key |
| `CR_S` | `0x43525f53` | envelope shared secret |
| `CR_MD` | `0x43525f4d44` | merge disclosure pad |
| `TMOB` | `0x544d4f42` | zolana merge output blinding |
| `TXOS`, `TXOB`, `TXPB` | `0x54584f53`, `0x54584f42`, `0x54585042` | zolana output seed, output blinding, private transaction blinding |
| `TMSI`, `TMSK`, `TMSL`, `TMSN` | `0x544d5349`, `0x544d534b`, `0x544d534c`, `0x544d534e` | zolana key schedule silo, key halves and nonce |

Each tag is its ASCII bytes read as one big-endian integer and placed with `right_align`.
