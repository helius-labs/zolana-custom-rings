# Public inputs

Every ring proof has one public input. It is the fold of a statement its verifier rebuilds. The ring program rebuilds the transfer and merge statements, and the Storage program the apply and register key statements. A prover supplies none of the elements the verifier can derive. Element lists are in order. [Spec](../../spec.md) [Hashing](hashing.md)

| Statement | Fold | Elements | Verified by |
|---|---|---|---|
| Transfer | `HashChain4` | 49 | `Transfer`, `AuthorityTransfer` |
| Apply records | `HashChain4` | 9, or 11 on a private key | Storage `Update` |
| Apply enrollments | `HashChain4` | 8 | Storage `ApplyEnrollments` |
| Register key | `HashChain4` | 10 | Storage `Enroll`, first enrollment |
| Merge | `HashChain` | 12 | `Merge` |

## Transfer

Use [Proof composition](../../design/proof-composition.md) to review the constraint handoffs and program-derived fields.

One statement serves every rail. It covers the audit, the policy and the approval mask. No recipient body, tag, sender bundle or reply enters it. SPP's external data hash binds those bytes, see [Disclosure](disclosure.md).

`n` is the frame's nullifier count and `m` its published slots. `N` is the key's output capacity and `S` its signer slots. Per-slot chains are zero-filled to `N`, so `output_count` alone carries `m`.

```text
[ CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, envelope_digest, salt, layout,
  in_proof, hidden, delegate,
  approval_mask, approval_totals, signer_data_counts, no_spend,
  output_count, output_chain, record_chain, tail_chain,
  input_count, input_nullifier_chain, private_tx_hash, sender,
  party_0 .. party_6,
  signer_count, signer_chain,
  policy_hash, own_root, curator_root, tracking_root,
  (asset_k, net_k, gross_k) for k in 0..3,
  withdrawal_hash,
  49 ]                                the element count, itself included
```

The head has 10 elements:

| # | Element | Source |
|---|---|---|
| 0 | `CRTX` | constant |
| 1 | `n0` | the frame's first nullifier, SPP nullifier `0` |
| 2 | `ring_id` | `hash_bytes` of the executing program id |
| 3, 4 | `pack_be(0x04 \|\| tx_viewing_u)` | frame, SPP `tx_viewing_pk` |
| 5, 6 | `pack_be(auditor_pubkey)` | ring account |
| 7 | `digest(envelope_ct)` | frame |
| 8 | `right_align(salt)` | frame, SPP salt, 16 bytes |
| 9 | `right_align(has_data \| entry << 1 \| single_asset_payout << 2)` | frame header flags |

The auditor stream seals under `tx_viewing_sk`, so `txpk` is also the stream's ephemeral key and no separate ephemeral key enters the head. `entry` and `single_asset_payout` must match the key's shape. A payout key requires `has_data = 0`. A clear `has_data` holds every slot's data hashes to zero.

The rail bits:

| Rail | `in_proof` | `hidden` | `delegate` |
|---|---|---|---|
| Signer, confidential ring | 0 | 0 | 0 |
| In-proof owner, confidential ring | 1 | 0 | 0 |
| Delegate, confidential ring | 0 | 0 | 1 |
| Hidden sender, anonymous ring | 0 | 1 | 0 |
| Public owners, anonymous ring | 0 | 0 | 0 |
| Delegate, anonymous ring | 0 | 0 | 1 |

- `in_proof` is set by the frame's `OWNER_IN_PROOF` flag. `hidden` is set on an anonymous ring's `Transfer` without the frame's `PUBLIC_OWNERS` flag. `delegate` is set by the `AuthorityTransfer` tag alone, so a proof made with `delegate = 1` fails under `Transfer`.
- `approval_mask` is `right_align` of one byte, bit `1` `OUTFLOW` and bit `2` `WITHDRAWAL`. The proof sets `OUTFLOW` when some [charged outflow](../../spec.md#15-outflow-limits-per-transfer) `charged(o, a) > cosign_above(a)` with `cosign_above(a) != 0`, and `WITHDRAWAL` when some `gross(a) > withdrawal_threshold(a)` with `withdrawal_threshold(a) != 0`. The mask is zero while `own_root` is zero, and the program refuses a nonzero mask on a delegate frame. The program demands a co-signer for each set bit.
- `approval_totals` is `0` or the [approval totals digest](hashing.md#approval-totals-digest). The proof holds a nonzero value to the totals its outflow section computed.
- `signer_data_counts` is `right_align` of a `u64`. Entry `k` holds bits `5k .. 5k + 5`, the count of live output slots that the `k`th signer of `signer_chain` owns with a nonzero `data_hash`. It has 12 entries, and a bit above the last entry is refused. The frame carries it under `EXTENSIONS` only when nonzero, and the program supplies `0` when it is absent.
- `no_spend` is `1` when `R`, the sealed count of spent notes, is `0`. The proof sets it from `R`. The program then demands no owner signer and no `TRANSFERS` co-signer. An address input still needs SPP's authorization.
- `output_count` is `right_align(m)`, and `input_count` is `right_align(n)`.
- `input_nullifier_chain = HashChain4([right_align(n), nullifier_0 .. nullifier_{C-1}])`, over the nullifiers the program forwards to SPP, zero past `n`, `C` the key's input capacity. The circuit binds its private nullifiers to it and derives the address chain from them.
- `sender` is `solana_owner_identity` of the framed owner key on the in-proof rail, and `0` on every other rail.
- `party_0` is the payer. `party_1 .. party_5` are the co-signers, then each deposit leg funder not already named. `party_6` is the exit destination of a hidden sender. Each is `solana_owner_identity`, and `0` when absent. Every party is `0` off an anonymous ring. The circuit refuses a hidden owner equal to any nonzero party.
- `signer_count` is the number of distinct keys in the SPP owner signer run, deduplicated by first occurrence. `signer_chain` is `HashChain4` of their identities in that order, zero-filled to `S`, and `0` when the count is `0`. The delegate rails bind count `0` and chain `0`.
- `policy_hash` is the ring account's written hash on a policy ring, else `0`. `own_root` is the ring's own registry root at the frame's `own_revision` on a ring with own records, else `0`. `curator_root` is the curator root at the frame's `curator_revision` on a policy ring with a curator, else `0`. The delegate rails read no policy root, so all three are `0` there. `tracking_root` is the tracking registry root at the frame's `tracking_revision` on every rail. The program refuses a revision below the highest tracking floor of the salted sources the frame reads.
- A public slot holds SPP's asset field, the signed net and the gross public withdrawal of the asset. The net is `right_align(net)` when positive and `q - |net|` when negative. The gross is `right_align` of a `u128`, deposits excluded. Slots past the used ones are zeros.
- `withdrawal_hash` is the policy withdrawal hash below. The count closes the chain, so a statement of another length hashes apart.

The chains over the slots, each zero past `m`:

- `output_chain = HashChain4(hash_i)`, a hidden dummy's hash included.
- `record_chain = HashChain4(hash_bytes(record_i))`. `record_i` is the slot's record ciphertext, 105 bytes in the standard format or 73 bytes in the single-asset payout format.
- `tail_chain = HashChain4(hash_bytes(tail_i))` over the 64-byte data tails, and `0` when no slot carries a tail.

`withdrawal_hash = HashChain4([CRPW, right_align(count), (owner, asset, right_align(amount)) per withdrawal leg])`, in settlement order. A SOL leg's owner is `solana_owner_identity(recipient)`, and an SPL leg's owner is the identity of the token account's owner. The program reads both from the live settlement accounts. The list is empty on a ring without own records and on the delegate rails.

No zolana ciphertext enters the statement, an exit's scheme 3 body included. The circuit holds every spent UTXO to its rail's owner predicate and reopens SPP's `private_tx_hash` as `Poseidon(input_chain, output_chain, address_chain, private_tx_blinding)`. The address chain follows the address subsequence of the statement-bound nullifiers. `private_tx_blinding` stays private.

## Apply records

```text
[ CRAP, old_root, new_root, right_align(old_next_index), right_align(new_next_index),
  chain_start, chain_end, right_align(count), right_align(restrictive),
  right_align(private_writes), tracking_root ]   private key only past restrictive
```

The instruction data carries `restrictive`, and the proof holds it at `1` exactly when an active write meets a condition of [root history](../../design/records-and-roots.md#root-history). A zero bound reads as no bound, and an absent member's old fields read as zero. The Storage program retires every earlier root only when it is `1`.

The Storage program supplies `old_root` as the registry's newest root and `old_next_index`. It folds `chain_end` over the update's writes from [`chain_start(registry, revision)`](hashing.md#record-tree), one chain per `Update`, and supplies `count` as their number. It refuses a `revision` other than the registry's own. Of the roots and indices, only `new_root` and `new_next_index` come from the instruction data.

`private_writes` is a `u16` bitmap with bit `i` set for write `i` to a private list, except a write an asset entry exempts. The program derives it from the masks, and no caller flag sets it. When it is nonzero, the instruction names a `tracking_revision` and passes the tracking registry the registry pins. `tracking_root` is that registry's root at the revision, served under grace. The program refuses another tracking account and a registry that pins none. When it is zero, the update proves under the public key and its statement ends at `restrictive`. The instruction then names no revision and passes no tracking account.

## Apply enrollments

```text
[ CRTA, old_root, new_root, right_align(old_next_index), right_align(new_next_index),
  chain_start, chain_end, right_align(count) ]
```

The Storage program supplies `old_root` as the tracking registry's newest root, `old_next_index` and `chain_start = HashChain4([CRTA, hash_bytes(registry), right_align(revision)])`. It supplies `count` as the number of authorization accounts named. It computes each [tracking entry](hashing.md#tracking-tree) from its account and folds `chain = Poseidon(chain, entry)` from `chain_start` to `chain_end`. The applier chooses which accounts to name and never an entry's content. The program refuses a `revision` other than the registry's own. Of the roots and indices, only `new_root` and `new_next_index` come from the instruction data. Both indices are `u64`, and the program refuses a `new_next_index` past `TRACKING_CAPACITY = 2^32`.

## Register key

```text
[ CRRG, ring_id, member, nullifier_pk, list_tag,
  pack_be(auditor_pubkey), pack_be(0x04 || eph_u), hash_bytes(ciphertext) ]
```

The statement has 10 elements and no registry root. The Storage program takes `ring_id` and `auditor_pubkey` from the tracking registry, which pins both at creation, and computes `member = solana_owner_identity(owner)` from the signing owner. A proof for another ring, auditor or member fails. `nullifier_pk`, `list_tag`, `eph_u` and the 64-byte `ciphertext` come from the instruction data. The proof shows the ciphertext seals the nullifier secret behind `nullifier_pk` and the list salt behind `list_tag` to the auditor key. The program refuses `nullifier_pk = Poseidon(0)` ahead of the proof. A rotation carries no proof and no statement.

## Merge

```text
[ CRMG, output_utxo_hash, n0, ring_id,
  pack_be(auditor_pubkey), pack_be(eph_pk), hash_bytes(ciphertext),
  payer, published_owner, tracking_root ]
```

`output_utxo_hash` and `n0` come from the SPP merge data the program forwards. `ciphertext` is the 144-byte opening record of the output. `payer` is `solana_owner_identity` of the SPP payer, and the circuit holds a nonzero-key owner apart from it. Under a nonzero nullifier key, `published_owner` is `0` and `tracking_root` is the tracking root at the merge's `tracking_revision`, and the proof opens the owner's row. Under the zero key, `published_owner` is `solana_owner_identity` of the owner account SPP makes sign, and `tracking_root` is `0`. The statement holds no input. SPP's merge proof ties every input to the output's owner, asset and sum.
