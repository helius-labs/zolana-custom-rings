# Disclosure

A ring transfer opens through one proven record per output slot. Each record is sealed to the recipient key the sender supplies for its slot. One AES-256-CTR stream, the auditor stream, seals the transaction viewing secret, the note count and every slot's recipient key to the auditor. Payloads, non-exit tags, replies and the sender bundle stay outside every proof. [Spec](../../spec.md) [Envelope](envelope.md)

## Verified audit recovery

Every published slot of a transfer whose proof verifies has one record the auditor opens.

- A ring output, an exit and a dummy each have one record. An exit's record opens the created default-ring note, its owner key included.
- The auditor reads each slot's recipient key from its own stream. A key the sender chose wrongly changes what the recipient can open and leaves the auditor's reading unchanged.
- The record names the owner key, amount, mint, nullifier key and blinding. A note that commits a data hash rebuilds its commitment only with the hashes its payload carries. A malformed payload loses those hashes for the recipient and the auditor. The auditor still traces that note's spend from the published hash, the record's blinding and the owner's secret.
- A spent ring note has no record. The auditor links its nullifier from an opening it already holds and the owner's enrolled secret. A note the auditor never opened stays unlinked until its opening arrives, and it withholds no output slot.
- A spent default-ring note has an entry record in the envelope of an entry key. It names the owner, nullifier key, amount, mint and spent commitment, and discloses no blinding, data hash or secret.
- Ring RPC serves an owner its opening from the record, see [auditor fallback](../../design/audit-and-recovery.md#auditor-fallback).

## Discovery

Each published slot carries an owner tag. A non-exit slot's tag is an unproved hint. No proof constrains it, and SPP's external data hash binds only its bytes. A frame carries the low 8 bytes of a non-exit tag, and the program restores the 24 leading zero bytes before SPP reads it.

| Slot | Tag |
|---|---|
| Ring output, confidential frame | low 8 bytes of the recipient's `viewing_u` |
| Dummy, confidential frame | low 8 bytes of the slot's [dummy recipient key](hashing.md#slot-secret) |
| Ring output, anonymous frame | low 8 bytes of `Poseidon(CRRT, CRDS_i)` |
| Change, anonymous frame | zero |
| Dummy, anonymous frame | low 8 bytes of `Poseidon(CRRT, s)`, `s` drawn uniform below `q` |
| Exit | SPP's 32-byte owner tag, which SPP's proof holds to the exit's owner |
| Sender bundle | `Poseidon(CRST, CRDS_m)`, 32 bytes |

`CRDS_i` is the [slot secret](hashing.md#slot-secret) that also keys slot `i`'s record and payload. A wrong tag hides no decryptable note, because a full scan tries every body without a tag. [Wallet scanning](../../design/audit-and-recovery.md#wallet-scanning) states how a reader finds its notes.

## Auditor message

The auditor message is SPP's last message, under the auditor's `u` as its view tag. Its data is:

```text
0x04 || tx_viewing_u || envelope_ct || keys_ct || exit_record_ct of each exit in slot order
```

`tx_viewing_u` is SPP's `tx_viewing_pk` without its tag. `keys_ct` holds 32 bytes per published slot. Each exit record ciphertext is 137 bytes.

`n` is the published input count, the frame's nullifier count. It is never the key capacity and never a private live count. The entry flag, `n`, `m` and the exit bitmap fix the auditor message's length. The frame's flags, shape and counts fix every other length, and the program refuses trailing bytes.

## Stream regions

The stream has one key, one nonce and one `CTREncrypt` call in the circuit over the capacity-sized plaintext. Each region is zero padded to a multiple of 16 bytes, so it starts on its own counter and no counter serves two regions. The key alone fixes every counter, so a reader decrypts the key of slot `i` with no other slot. The frame carries only transmitted bytes, and padding and unpublished slots never leave the prover.

| Region | Start counter | Maximum blocks | Transmitted bytes |
|---|---|---|---|
| Envelope | `2` | `E` | `33`, or `41 + 136 n` on an entry key |
| Recipient key of slot `i` | `K0 + 2 i`, `K0 = 2 + E` | `2` | `32` for `i < m` |

`E = ceil(33 / 16) = 3` on a key without entry capacity, and `E = ceil((41 + 136 C) / 16)` on an entry key of input class `C`. The statement binds `envelope_digest = Poseidon(digest(envelope_ct), digest(keys_ct))`.

## Envelope plaintext

```text
tx_viewing_sk || u8(R)                                                             key without entry capacity
tx_viewing_sk || u8(R) || u64be(default_note_bits) || entry_record * n              entry key
entry_record = owner_key || fe32(nullifier_pk) || u64be(amount) || mint || fe32(input_commitment)
key_i        = V_i
```

`R` counts the spent notes among the published inputs, with `1 <= n <= C <= 64` and `R <= n`. The ring's input slots hold those notes in SPP's note order, then dummies, and no address enters a ring input slot. The circuit takes SPP's address chain as a private witness and checks it only through `private_tx_hash`. No statement element carries a nullifier but the first, so the proof names no note position among the published nullifiers. The hidden rail holds ring input `0` to a note.

Bit `k` of `default_note_bits` is set exactly when note `k` is a default-ring note. `entry_record_k` names that note in 136 bytes and is all zero otherwise, every `k >= R` included. Records follow note order, never the nullifier position. `mint` is the 32-byte mint address, and the proof holds the note's asset to it. `input_commitment` is the note's spent UTXO hash, the value `private_tx_hash` chains, and the proof holds the owner key, nullifier key, amount and mint to it.

## Spent notes

- A key without entry capacity refuses a default-ring input, since no evidence would open it.
- The auditor recomputes SPP's nullifier of a note from the opening it already read and the owner's secret from enrollment. Under the zero nullifier key the secret is zero. A match in SPP's published list links the spend.
- No constraint binds a nullifier to an opening. Ring RPC reads every published nullifier of a transfer as a spend until its note index resolves it. A nullifier no opened note owns stays unclassified, whether it is an unopened note, an address, a default-ring note or padding. It never reads as padding.
- `R` is the completeness check. The co-signer counts the linked notes and the entry records and refuses a frame whose count differs from `R`.
- An entry record discloses its owner key, nullifier key, amount, mint and spent commitment, and no blinding, data hash or nullifier secret. The auditor reads the commitment and does not rebuild it. Each record carries its own owner and key, so one frame spends default-ring notes of several owners.

## Records

```text
record = u8(kind) || u64be(amount) || owner_key || mint || fe32(nullifier_pk) || fe32(blinding)   137 bytes
```

| `kind` | Slot | Plaintext |
|---|---|---|
| `0` | dummy | all zero |
| `1` | ring output | the slot's opening |
| `2` | exit | the slot's opening |

The proof holds every slot `i < N` to the UTXO or the dummy domain, dummies last. A dummy's owner, asset, amount, data hash, ring data hash and ring id are zero, and SPP derives its blinding. No real output sits at or past `m`. The proof derives `kind` from the domain and ring id the slot's hash commits, so no prover choice passes a note as a dummy. `owner_key` is the raw key whose `solana_owner_identity` the commitment hashes, and `mint` the raw mint whose `hash_bytes` is its asset. The auditor names an owner and an asset with no directory. `blinding` is the slot's blinding, which `private_tx_hash` and SPP's derivation fix. The record holds no data hash, and the data hashes enter no ring constraint but the UTXO hash.

Each record is sealed from the transaction viewing secret to the slot's recipient key `V_i`:

```text
dh_i        = X25519(tx_viewing_sk, V_i)          V_i canonical, dh_i nonzero
record_ct_i = CRING/rcp stream under CRDS_i from counter 2, plaintext bytes 0 .. 137
```

| Slot | `V_i` |
|---|---|
| Ring output | the recipient's viewing `u`, the sender's own on change |
| Exit | any valid key, the SDKs supply the auditor's `u` |
| Dummy | the slot's [dummy recipient key](hashing.md#slot-secret) |
| Unpublished capacity slot | prover only, the SDKs supply the auditor's `u` |

No constraint ties `V_i` to the intended recipient. A record sealed to another key credits nobody, since a reader accepts a note only when the commitment rebuilds. The sender chooses `V_i`.

## Slot body

A non-exit slot's body is one `CRING/rcp` stream under `CRDS_i`. The payload continues the record's stream at plaintext byte 137.

```text
body    = record_ct || payload_ct                        payload_ct only under the frame's HAS_DATA
payload = u16be(len) || u8(has_ring_data) || ring_data_hash? || data || zero_padding
data    = empty, or data_hash || application_data
```

`len` counts the presence byte and everything after it up to the padding, so an empty payload is `u16be(1) || 0`. `has_ring_data` is `0` or `1`, and its `1` form carries the 32-byte `ring_data_hash`. A nonzero `data_hash` adds that hash and its application data. The commitment covers both hashes. The decoder refuses `len = 0` and nonzero bytes after the declared payload. No proof reads the payload.

Under `HAS_DATA` every non-exit payload in a frame has one width, and the program refuses unequal widths. Without it every non-exit body is the 137-byte record alone.

SPP output data of a non-exit slot is scheme 10, `u16le(body_len) || body || reply`. SPP's external data hash binds its bytes. An exit keeps SPP's scheme 3 body, and its record travels in the auditor message. A recipient accepts a note only when the record names its own owner key as a ring output and the commitment rebuilds from the record, the payload's data hashes and the frame's tree id. The record's nullifier key is taken as written, and the note spends only once that key is the owner's enrolled one.

## Reply metadata

A frame opts in with `REPLY_METADATA`, on an anonymous frame only. The reply follows its body inside the slot's scheme 10 data, under `CRING/rpl` and the same slot secret:

```text
viewing_u || owner_key || nullifier_pk || wincode(Data), zero padded to reply_len
```

`reply_len` is one length per frame, at least 97. Every non-exit slot carries one, and a slot with no reply or a dummy carries random bytes of that length. SPP's external data hash binds the bytes, and no proof reads their meaning. A reply is an unauthenticated claim about the sender. A reader never turns it into a verified sender identity.

## Sender bundle

Scheme 9 is the first SPP message of an anonymous frame, under `CRING/snd` and the slot secret at `i = m` of the sender's viewing key:

```text
output_seed || recipient_u * m                                                  32 + 32 m bytes
```

Key `k` is slot `k`'s `V_k`, the sender's own viewing `u` on change, and zero on an exit or a dummy. The bundle carries no count. The sender opens each slot whose key is its own at that slot's secret, and lists the other keys as its payments. `output_seed` is `TXOS(n0, CRBS(tx_viewing_sk, salt))`.

## Opening a transfer

1. The auditor computes `X25519(auditor_sk, tx_viewing_u)`, the salted [stream secret](envelope.md#shared-secret) and the stream. It recovers `tx_viewing_sk`, `R` and any entry records from the envelope, and `V_i` from each key region.
2. It derives `CRDS_i` from `tx_viewing_sk` and `V_i`, and decrypts slot `i`'s record from the slot's body. An exit's record comes from the auditor message.
3. It rebuilds slot `i`'s commitment from the record, the payload's data hashes when present and the frame's tree id. The ring id enters on kind `1`, and zero on kind `2`. It accepts the slot only when that commitment equals the published hash at `i`. A kind `0` slot rebuilds as SPP's dummy hash under `TXOB(n0, TXOS(n0, CRBS(tx_viewing_sk, salt)), i)`. A record moved to another slot rebuilds nothing.
4. It links the nullifier of each spent note, see [spent notes](#spent-notes).

## Layout

| Bit value | Name | Set when |
|---|---|---|
| 2 | `entry` | the frame selects a key with entry capacity |

The layout value is `entry << 1`. The circuit decomposes it, binds `entry` to the key and refuses every other bit. The frame's `HAS_DATA` flag sets no layout bit, and a data hash needs none.

## Merges

A merge seals one record of its output, followed by the seed, to the merged owner's viewing key `V` from a fresh `eph_sk`. An envelope seals `eph_sk` and `V` to the auditor.

```text
merge_envelope  = eph_sk || V                                    64 bytes, CRING/mrg under the shared secret to the auditor
merge_record    = record || fe32(seed)                           169 bytes, kind 1, blinding TMOB(seed, n0)
merge_record_ct = CRING/mro stream under the slot secret of eph_sk and V, salt zero, index 0, the merge's n0
```

The seed is the owner's nullifier secret off the zero key, and the private merge seed under it. The owner opens the record with its viewing secret, and the auditor opens the envelope first. Both ciphertexts travel in the ring instruction, since SPP's merge publishes no auditor message. A merge's ring proof opens no input, since SPP's merge proof ties every input to the output's owner, asset and sum. [Envelope uses](envelope.md#envelope-uses) states the keys and counters.
