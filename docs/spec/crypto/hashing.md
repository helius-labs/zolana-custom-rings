# Hashing

Every commitment and statement of a custom ring is a Poseidon hash over BN254. This file pins each encoding two implementations could choose differently. [Spec](../../spec.md)

## Poseidon

`Poseidon(x_1, ..., x_n)` is the zolana BN254 Poseidon of width `n + 1`, at most 12 inputs. `q` is the BN254 scalar field modulus. Every input is a canonical field element, a 32-byte big-endian value below `q`.

## Folds

- `HashChain([x_0, ..., x_n])` is the left fold `h = x_0`, then `h = Poseidon(h, x_i)`. An empty list hashes to `0`.
- `NonZeroHashChain(xs)` is `HashChain` over the nonzero elements of `xs`, and `0` when none is nonzero.
- `HashChain4([x_0, ..., x_n])` is `h = x_0`, then `h = Poseidon(h, g_0, g_1, g_2)` per group of three of `x_1..`, with the last group padded by zeros. `[a]` hashes to `a`. It hashes no length, so every use has a fixed element count per key or hashes the length beside the chain, as `digest` does.
- `HashPrefix4(xs, n)` is `HashChain4` of the first `n` elements. A circuit selects `n` by a one-hot flag set over the key's range.

## Bytes to fields

- `PackBytesBE(b)` splits `b` into 31-byte chunks, each read as a big-endian integer. The last chunk is not padded, so its value sits in the low bytes. Rust names it `pack_be`.
- `hash_bytes(b) = HashChain(PackBytesBE(b))`. A value of one chunk is returned packed, without Poseidon. It hashes no length, so each use has one fixed input length.
- `right_align(x)` places `x` in the low bytes of a 32-byte big-endian field.
- `fe32(x)` is the canonical 32-byte big-endian encoding of the field element `x`. `u32be` and `u64be` are big-endian integers of 4 and 8 bytes.
- A 33-byte tagged key `0x04 || u` packs to `[BE(bytes[0..31]), BE(bytes[31..33])]`. A 32-byte value packs to `[BE(bytes[0..31]), bytes[31]]`.
- `pack_left31(b)` splits `b` into 31-byte chunks, each placed at byte 1 of a field and padded with zeros at the end. It differs from `PackBytesBE` only in a short last chunk. Rust names it `pack_disclosure`, Go `PackDisclosure` and TypeScript `packDisclosure`.
- `digest(b) = Poseidon(u32 len(b), HashChain4(pack_left31(b)))`. The length closes the trailing zero ambiguity of `HashChain4`. The envelope ciphertext of a transfer uses it, because its length follows the input count. Rust names it `ciphertext_digest`.

## Identities

| Value | Encoding |
|---|---|
| Owner identity | `solana_owner_identity(key) = hash_bytes(0x53 \|\| key)`, for an Ed25519 key or a PDA |
| Nullifier key | `nullifier_pk = Poseidon(secret)`, the 31-byte secret read big endian |
| Owner hash | `Poseidon(owner_identity, nullifier_pk)` |
| Ring id | `hash_bytes(ring program id)` |
| Asset | `hash_bytes(mint)`, and `SOL_ASSET_FIELD = Poseidon(0, 0) = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864` for SOL |
| Zero nullifier key | `ZERO_NULLIFIER_PUBKEY = Poseidon(0) = 0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c`. No secret stands behind it, so no owner enrolls it. A ring output under it needs no tracking row for its key |
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
| Merge output blinding | `TMOB(seed, n0)`, as zolana defines it. `seed` is the owner's nullifier secret, and under the zero nullifier key the private merge seed |

`n0` is the transfer's first nullifier. The transfer proof derives `private_tx_blinding = TXPB(n0, CRBS(tx_viewing_sk, salt))` and reopens `private_tx_hash` over it. SPP derives every output blinding and `private_tx_blinding` from one seed, so the shared hash fixes that seed to `CRBS(tx_viewing_sk, salt)` and SPP holds every published output's blinding to it, a dummy's included. The auditor derives each output blinding from the sealed key. No frame field carries the output seed.

## Slot secret

| Value | Encoding |
|---|---|
| Slot secret | `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(0x04 \|\| u), right_align(salt), i, n0)`, `dh = X25519(tx_viewing_sk, u)`, 10 inputs |

The recipient rebuilds the slot secret from `X25519(u_sk, tx_viewing_u)`, the auditor from the sealed transaction viewing secret. A recipient body takes `i` as the slot. A reply takes the secret of its slot. The sender bundle takes `i = m`, past every body's index.

| Value | Encoding |
|---|---|
| Recipient tag | `Poseidon(CRRT, CRDS_i)`, `Poseidon(CRRT, s)` on a hidden dummy |
| Bundle tag | `Poseidon(CRST, CRDS_m)` |

Each tag is a canonical field element. `CRRT` and `CRST` sit below `2^32`, and a stream tag, a 9-byte label and one byte, sits above `2^72`. A tag and a [stream schedule](envelope.md#stream-schedule) therefore never share a first Poseidon input.

An exit's scheme 3 body keeps zolana's [AES Key derivation](../../../zolana/docs/spec.md#aes-key-derivation), with its output position as the HKDF slot. A deposit keeps zolana's [View Tags](../../../zolana/docs/spec.md#view-tags). The auditor message takes the auditor's `u` as its tag.

## Record tree

A policy registry holds one record per member.

| Value | Encoding |
|---|---|
| Member range | `1 <= member <= q - 2`, as big-endian bytes |
| Record | `Poseidon(member, next, right_align(lists as u64 BE), mint_policy, right_align(withdrawal_threshold as u64 BE), limits_0, limits_1, limits_2)`, 8 inputs |
| Mint policy field | `threshold * 2^128 + cap * 2^64 + cosign_above`, each a u64 |
| Asset limit fields | `limits_0 = sender_cap * 2^128 + sender_window_slots * 2^64 + volume_cap`, `limits_1 = volume_window_slots * 2^128 + deposit_cap * 2^64 + deposit_window_slots`, `limits_2 = withdrawal_cap * 2^64 + withdrawal_window_slots`, each a u64 |
| Sentinel | `(0, q - 1, 0, 0, 0, 0, 0, 0)` at leaf `0` |
| Tree node | `Poseidon(c_0, c_1, c_2, c_3)`, height 10, the leaf index as 20 bits |
| Record write | `Poseidon(CRQW, member, right_align(mask as u64 BE), right_align(value as u64 BE), mint_policy_write, right_align(withdrawal_threshold as u64 BE), limits_0, limits_1, limits_2)`, 9 inputs |
| Mint policy write | `0` when the write keeps the mint settings, else `2^192 + mint policy field`. `withdrawal_threshold` and every asset limit field are `0` when the write keeps them. |
| Write chain start | `chain_start(registry, revision) = HashChain4([CRAP, hash_bytes(registry address), right_align(revision as u64 BE)])` |
| Write chain | `chain(-1) = chain_start(registry, revision)`, `chain(p) = Poseidon(chain(p - 1), write_p)`, one chain per `Update` |

A write sets `lists' = (lists & !mask) | value`, and `value` must sit inside `mask`. It replaces the mint settings only when `mint_policy_write` is nonzero. The chain start names one registry at one revision, so an apply proof serves that registry at that revision only.

## Tracking tree

A tracking registry holds one leaf per enrolled owner.

| Value | Encoding |
|---|---|
| Member | `solana_owner_identity(owner)`, for a wallet or a PDA |
| List tag | `Poseidon(CRPT, list_salt)`. `RegisterKey` proves it, and it is final |
| Ciphertext hash | `ct_hash = hash_bytes(ciphertext)`, the 64-byte nullifier secret and list salt sealed to the auditor key |
| Tracking leaf | `Poseidon(CRTK, member, next, nullifier_pk, ct_hash, list_tag)`, 6 inputs |
| Sentinel | `member = 0`, `next = q - 1`, every other field `0`, at leaf `0` |
| Tree node | `Poseidon(c_0, c_1, c_2, c_3)`, height 16, the leaf index as 32 bits |
| Tracking entry | `Poseidon(CRTQ, member, nullifier_pk, ct_hash, list_tag)`, 5 inputs |
| Entry chain start | `HashChain4([CRTA, hash_bytes(registry address), right_align(revision as u64 BE)])` |
| Entry chain | `chain(-1) = chain_start`, `chain(p) = Poseidon(chain(p - 1), entry_p)` |

An unwritten leaf is `0`. The sentinel carries a zero `nullifier_pk`, and a query for an absent owner reads a zero key. The program computes every entry from the owner's tracking authorization, never from instruction data. No leaf holds a viewing key. The apply proof inserts each entry once, at the next index. Its member, nullifier key, ciphertext hash and list tag stay fixed. An insertion changes its predecessor's `next` and leaf hash. `test-vectors/registry/tracking-records.json` pins both hashes, the entry chain and the apply statement. A present owner opens by its leaf, and an absent one proves `member < owner < next` for a leaf under the frame's tracking root.

## Private list key

| Value | Encoding |
|---|---|
| Salted member | `Poseidon(CRPL, owner_identity, list_salt)` |

A private list entry is an ordinary record under the salted member. While the owner's tracking row is present, the transfer proof holds `list_salt` to open the row's `list_tag`, so the prover cannot choose the key. A private write's proof holds the written member to `Poseidon(CRPL, row.member, list_salt)`. It holds `Poseidon(CRPT, list_salt)` to the `list_tag` of a row under the tracking root, and that row's `nullifier_pk` to nonzero. The write must carry a private list bit in its mask.

## Policy table hash

```text
fields      = [CRTB, (list_id_i, registry_i) × 9, salted, rule_count, rule_j × 16]   // zero padded to 44
acc_0       = 0
acc_{c + 1} = Poseidon(acc_c, fields[11 c .. 11 c + 11])
policy_hash = acc_4
```

`salted` is the `u16` list bitmap of the private lists the table maps, bit `id - 1` for list `id`. `registry_i` is `0` for the ring's own records and `hash_bytes(address)` for a curator. Each `rule_j` is the 32-byte row `Rule::encoded` writes in `program-libs/policy/src/rule_table/mod.rs`, zero past `rule_count`.

## Approval totals digest

```text
fields  = [CRAO, blinder]
        ++ (asset, peak, charged_outflow)     per output slot of the key
        ++ (asset, peak, outflow, gross)      per public slot of the statement
digest  = HashChain4(fields)
```

Each amount is a u128 under `right_align`. An output slot reads the largest charged outflow of one owner of its asset as `peak` and the sum of charged outflows as `charged_outflow`. A public slot reads the largest debit as `peak` and the sum of debits as `outflow`, and `gross` is the slot's gross public withdrawal. A dummy or unused slot is all zero. The SDK draws `blinder` as a fresh random field element for each transaction, apart from `tx_viewing_sk`. No proof constrains it.

## Domain tags

| Tag | Value | Use |
|---|---|---|
| `CRTX` | `0x43525458` | transfer statement |
| `CRDS` | `0x43524453` | slot secret |
| `CRRT` | `0x43525254` | recipient and dummy tag |
| `CRST` | `0x43525354` | sender bundle tag |
| `CRBS` | `0x43524253` | ring blinding seed |
| `CRTB` | `0x43525442` | policy table hash |
| `CRPW` | `0x43525057` | withdrawal digest |
| `CRQW` | `0x43525157` | record write |
| `CRAP` | `0x43524150` | apply records statement and write chain start |
| `CRRG` | `0x43525247` | register key statement |
| `CRTK` | `0x4352544b` | tracking leaf |
| `CRTQ` | `0x43525451` | tracking entry |
| `CRTA` | `0x43525441` | apply enrollments statement and entry chain start |
| `CRPT` | `0x43525054` | list tag |
| `CRPL` | `0x4352504c` | salted member |
| `CRAO` | `0x4352414f` | approval totals digest |
| `CRMG` | `0x43524d47` | merge statement |
| `CRRU` | `0x43525255` | record update statement |
| `CRWG` | `0x43525747` | wallet grant record key |
| `CR_S` | `0x43525f53` | envelope shared secret |
| `TMOB` | `0x544d4f42` | zolana merge output blinding |
| `TXOS`, `TXOB`, `TXPB` | `0x54584f53`, `0x54584f42`, `0x54585042` | zolana output seed, output blinding, private transaction blinding |

Each tag is its ASCII bytes read as one big-endian integer and placed with `right_align`.
