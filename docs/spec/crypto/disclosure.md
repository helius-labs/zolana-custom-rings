# Disclosure

A ring transfer opens to the auditor through one AES-256-CTR stream, the auditor message. Its envelope seals the transaction viewing secret and the input map. Its records open every published output slot. Recipient bodies, tags, replies and the sender bundle stay outside every proof. [Spec](../../spec.md) [Envelope](envelope.md)

## Verified audit recovery

Every published slot of a transfer whose proof verifies opens for the auditor from its own record. The record is the guarantee, whatever the slot's recipient body contains.

- A ring output, an exit and a dummy each have one record. An exit's record opens the created default-ring note, its owner key included.
- A spent ring note has no record. The auditor links its nullifier from an opening it already holds and the owner's enrolled secret. A note the auditor never opened stays unlinked until its opening arrives, and it withholds no output slot.
- A spent default-ring note has an entry record in the envelope of an entry key. It names the owner, nullifier key, amount, mint and spent commitment, and discloses no blinding, data hash or secret.
- A wrong recipient body leaves the auditor's record unchanged. Ring RPC serves the owner its opening from that record, see [auditor fallback](../../design/audit-and-recovery.md#auditor-fallback).

## Discovery

Each published slot carries an owner tag. A non-exit slot's tag is an unproved hint. No proof constrains it, and SPP's external data hash binds only its bytes. A frame carries the low 8 bytes of a non-exit tag, and the program restores the 24 leading zero bytes before SPP reads it.

| Slot | Tag |
|---|---|
| Ring output, confidential frame | low 8 bytes of the recipient's `viewing_u` |
| Dummy, confidential frame | low 8 bytes of a fresh random key's `u` |
| Ring output, anonymous frame | low 8 bytes of `Poseidon(CRRT, CRDS_i)` |
| Change, anonymous frame | zero |
| Dummy, anonymous frame | low 8 bytes of `Poseidon(CRRT, s)`, `s` drawn uniform below `q` |
| Exit | SPP's 32-byte owner tag, which SPP's proof holds to the exit's owner |
| Sender bundle | `Poseidon(CRST, CRDS_m)`, 32 bytes |

`CRDS_i` is the [slot secret](hashing.md#slot-secret) that also keys slot `i`'s body. A wrong tag hides no decryptable note, because a full scan tries every body without a tag. [Wallet scanning](../../design/audit-and-recovery.md#wallet-scanning) states how a reader finds its notes.

## Auditor message

The auditor message is SPP's last message, under the auditor's `u` as its view tag. Its data is:

```text
0x04 || tx_viewing_u || envelope_ct || record_ct_0 .. record_ct_{m-1} || tail_ct_0 .. tail_ct_{m-1}
```

`tx_viewing_u` is SPP's `tx_viewing_pk` without its tag. The standard format has 105-byte record ciphertexts. The single-asset payout format has 73-byte records. Tails are present exactly when `has_data` is set, 64 bytes each.

`n` is the published input count, the frame's nullifier count. It is never the key capacity and never a private live count. The disclosure format, entry flag, `n`, `m` and `has_data` fix the auditor message's length. The frame's flags, shape and counts fix every other length, and the program refuses trailing bytes.

## Stream regions

The stream has one key, one nonce and one `CTREncrypt` call in the circuit over the capacity-sized plaintext. The table below describes the standard format. Each region is zero padded to a multiple of 16 bytes, so it starts on its own counter and no counter serves two regions. The key alone fixes every counter, so a reader decrypts slot `i` with no other slot. The frame carries only transmitted bytes, and padding and unpublished slots never leave the prover.

| Region | Start counter | Maximum blocks | Transmitted bytes |
|---|---|---|---|
| Envelope | `2` | `E` | `41`, or `49 + 136 n` on an entry key |
| Record of slot `i` | `R0 + 7 i`, `R0 = 2 + E` | `7` | `105` for `i < m` |
| Tail of slot `i` | `T0 + 4 i`, `T0 = R0 + 7 N` | `4` | `64` for `i < m` under `has_data` |

`E = ceil(41 / 16)` on a key without entry capacity, and `E = ceil((49 + 136 c) / 16)` on an entry key of input class `c`.

## Envelope plaintext

```text
tx_viewing_sk || u8(R) || u64be(A)                                                  key without entry capacity
tx_viewing_sk || u8(R) || u64be(A) || u64be(default_input_bits) || entry_record * n  entry key
entry_record = owner_key || fe32(nullifier_pk) || u64be(amount) || mint || fe32(input_commitment)
```

`R` counts the spent notes among the published inputs, and bit `k` of `A` is set exactly when input `k` is an address. Notes and addresses interleave in SPP's order, and dummies form the suffix. With `L = R + popcount(A)`:

- `1 <= n <= C <= 64`, `R <= n` and `L <= n`, with `C` the key's input capacity.
- No bit of `A` is set at or past `L`.
- Input `k < L` is an address when bit `k` of `A` is set and a spent note otherwise. Input `k >= L` is a dummy.

The circuit derives `R` and `A` from the same slot classes that open the inputs. It binds the nullifiers to `input_nullifier_chain`, so a reader takes no address for a spent note. The hidden rail holds input `0` to a note. Bit `k` of `default_input_bits` is set exactly when input `k` is a default-ring note, never an address or a dummy. `entry_record_k` names that note in 136 bytes and is all zero on every other input. `mint` is the 32-byte mint address, and the proof holds the input's asset to it. `input_commitment` is input `k`'s spent UTXO hash, the value `private_tx_hash` chains, and the proof holds the owner key, nullifier key, amount and mint to it.

## Spent notes

- A key without entry capacity refuses a default-ring input, since no evidence would open it.
- The auditor recomputes SPP's nullifier of a note from the opening it already read and the owner's secret from enrollment. Under the zero nullifier key the secret is zero. The auditor then matches SPP's published list. A match links the spend.
- No constraint binds a nullifier to an opening. A real nullifier with no match stays unresolved and never reads as padding.
- An entry record discloses its owner key, nullifier key, amount, mint and spent commitment, and no blinding, data hash or nullifier secret. The auditor reads the commitment and does not rebuild it. Each input carries its own owner and key, so one frame spends default-ring notes of several owners.

## Records

```text
record = u8(kind) || u64be(amount) || owner_key || mint || fe32(nullifier_pk)   105 bytes
tail   = fe32(data_hash) || fe32(ring_data_hash)                                 64 bytes
```

| `kind` | Slot | Plaintext |
|---|---|---|
| `0` | dummy | all zero |
| `1` | ring output | the slot's opening |
| `2` | exit | the slot's opening |

The proof derives `kind` from the domain and ring id the slot's hash commits, so no prover choice passes a note as a dummy. `owner_key` is the raw key whose `solana_owner_identity` the commitment hashes, and `mint` the raw mint whose `hash_bytes` is its asset. The auditor names an owner and an asset with no directory. The record omits the blinding, which the sealed key derives. A tail is zero on a dummy, and a clear `has_data` holds both data hashes of every slot to zero.

## Recipient body

The standard format seals each ring recipient body under `CRING/rcp` and its slot secret.

```text
base    = fe32(blinding) || u64be(amount) || mint                              72 bytes
payload = u8(has_ring_data) || ring_data_hash? || (data_hash || application_data)?
body    = base                                                              no data or padding
body    = base || u16be(payload_len) || payload || zero_padding              otherwise
```

`has_ring_data` is `0` or `1`. Its `1` form carries the 32-byte `ring_data_hash`. A nonzero `data_hash` adds that hash and its application data. The commitment covers both hashes. A padded body with no data has `payload_len = 0`. The decoder rejects nonzero bytes after the declared payload.

The SDKs use one body width for all ring recipient and dummy slots in a standard frame. The program rejects unequal recipient-body lengths. The width is the largest encoded ring body, at least 72 bytes, or 74 when any output carries data hashes. Each real body has zero padding before encryption. Each dummy has random bytes of the same width. Exits retain their separate scheme 3 encoding.

SPP output data carries scheme 10 followed by `u16le(body_len) || body || reply`. No proof constrains it. The reader rebuilds the commitment under its enrolled nullifier key, then under `ZERO_NULLIFIER_PUBKEY`. It accepts ownership only on a match. A slot in the bodiless bitmap carries no SPP data.

## Single-asset payout

`SingleAssetPayout = 1` selects a confidential published-owner shape with one real ring input and 16 real ring outputs of that same asset. It accepts no entry, exit, public leg, data hash, application data or reply. The frame extension uses bit 6. The audit layout uses bit 2.

```text
envelope = tx_viewing_sk || u8(1) || u64be(address_bits) || common_mint        73 bytes
record   = u8(1) || u64be(amount) || owner_key || fe32(nullifier_pk)            73 bytes
body     = fe32(blinding) || u64be(amount) || u64be(asset_id)                  48 bytes
```

The header occupies five AES blocks from counter 2. Record `i` starts at counter `7 + 5 i`, with an 80-byte padded stride. The frame transmits only 73 bytes per record and no tails. `address_bits` is zero because the sole input is a note. The common mint opens every record's asset without a registry read.

A recipient body uses scheme 11 with `u16le(48) || body` and the same `CRING/rcp` schedule. The reader selects the format from the scheme before decryption. Asset id 1 names SOL without a lookup, and id 0 is invalid. Other ids require an authenticated SPP mint-registry mapping before commitment verification. Unknown registry state cannot establish ownership. The authenticated registry may require RPC access.

## Reply metadata

A frame opts in with `REPLY_METADATA`, on an anonymous frame only. The reply follows its body inside the slot's scheme 10 data, under `CRING/rpl` and the same slot secret:

```text
viewing_u || owner_key || nullifier_pk || wincode(Data), zero padded to reply_len
```

`reply_len` is one length per frame, at least 97. Every slot with a recipient body carries one, and a slot with no reply or a dummy carries random bytes of that length. SPP's external data hash binds the bytes, and no proof reads their meaning. A reply is an unauthenticated claim about the sender. A reader never turns it into a verified sender identity.

## Sender bundle

Scheme 9 is the first SPP message of an anonymous frame, under `CRING/snd` and the slot secret at `i = m` of the sender's viewing key:

```text
output_seed || change_cell * b || recipient_u * (m - b)
change_cell = mint || u64be(amount)                                             40 bytes
```

`b` is the popcount of the frame's bodiless bitmap. The bundle has `32 + 40 b + 32 (m - b)` bytes and carries no count. Cell `k` belongs to the `k`th bodiless slot in ascending slot order, and `mint` is the 32-byte mint address. Key `k` belongs to the `k`th slot that carries a body. It is the viewing key the sender sealed that body to, and zero on an exit or a dummy. The reader rebuilds bodiless slot `i` from its cell, its own address and `TXOB(n0, output_seed, i)` at the slot's own index. It accepts a slot only when its commitment rebuilds. `test-vectors/audit/anonymous_bodies.json` pins a bundle with one change cell and three keys.

## Opening a transfer

1. The auditor computes `X25519(auditor_sk, tx_viewing_u)`, the salted [stream secret](envelope.md#shared-secret) and the stream, then recovers `tx_viewing_sk`, `R` and any entry records from the envelope.
2. It derives `seed_out = TXOS(n0, CRBS(tx_viewing_sk, salt))` and each blinding `TXOB(n0, seed_out, i)`. No frame field carries `seed_out`.
3. It decrypts the record of slot `i` at its counter, and its tail under `has_data`.
4. It rebuilds slot `i`'s commitment from the record, the tail, the blinding and the frame's tree id. The ring id enters on kind `1`, and zero on kind `2`. It accepts the slot only when that commitment equals the published hash at `i`. A kind `0` slot rebuilds as SPP's dummy hash under its blinding. A record moved to another slot rebuilds nothing.
5. It links the nullifier of each spent note that is not a default-ring input, see [spent notes](#spent-notes). A spent note is an input `k < L` whose bit of `A` is clear.

## Layout

| Bit value | Name | Set when |
|---|---|---|
| 1 | `has_data` | the frame carries one tail per published slot |
| 2 | `entry` | the frame selects a key with entry capacity |
| 4 | `single_asset_payout` | the frame selects the single-asset payout key |

The layout value is `has_data | entry << 1 | single_asset_payout << 2`. The circuit decomposes it into three bits. It binds entry and payout to the key and refuses `has_data` on a payout key.

## Merges

A merge seals one opening record of its output:

```text
opening_record = record || 7 zero bytes || fe32(secret)   144 bytes
```

The secret is the merge's seed. No envelope key derives the merged blinding, so the record seals what rebuilds it. The auditor rebuilds a merged note's blinding as `TMOB(seed, n0)`. A merge's ring proof opens no input, since SPP's merge proof ties every input to the output's owner, asset and sum. [Envelope uses](envelope.md#envelope-uses) states the keys and counters.
