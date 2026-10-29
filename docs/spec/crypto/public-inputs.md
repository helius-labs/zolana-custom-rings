# Public inputs

Every ring proof has one public input. It is the fold of a statement the program rebuilds from chain state and instruction data. A prover supplies none of the elements the program can derive. Element lists are in order. [Spec](../../spec.md) [Hashing](hashing.md)

| Statement | Fold | Elements | Verified by |
|---|---|---|---|
| Audit, delivered | `HashChain4` | 16 | `Transact`, `DelegateTransact` |
| Audit, anonymous | `HashChain4` | 19 | `Transact` |
| Policy, member key | `HashChain4` | 18 | `Transact` |
| Policy, delegate key | `HashChain4` | 17 | `DelegateTransact` |
| Apply | `HashChain4` | 8 | `ApplyRecords`, `AuthorityWriteRecords` |
| Register key | `HashChain4` | 8 | `RegisterKey` |
| Withdrawal exemption | `HashChain4` | 8 | `Transact` |
| Deposit | `HashChain` | 26 | `AuditedDeposit` |
| Merge | `HashChain` | 17 | `Merge` |

## Audit

The head has 12 elements:

| # | Element | Source |
|---|---|---|
| 0 | `CRAU` | constant |
| 1 | `n0` | the frame's first nullifier, SPP nullifier `0` |
| 2 | `ring_id` | the executing program id |
| 3, 4 | `pack_be(0x04 \|\| tx_viewing_u)` | frame, SPP `tx_viewing_pk` |
| 5, 6 | `pack_be(auditor_pubkey)` | config |
| 7, 8 | `pack_be(0x04 \|\| eph_u)` | frame |
| 9 | `hash_bytes(sealed)` | frame |
| 10 | `right_align(salt)` | frame, SPP salt |
| 11 | `right_align(layout)` | exits from the outputs, the other bits from the frame, bit value `4` clear |

Then by layout:

- Delivered: `HashChain4(output hashes)`, `HashChain4(body hash per slot)`, `HashChain4(disclosure)`, `HashChain4(pack_be(u) per slot)`. A body hash is `hash_bytes(body)`, and an exit contributes `0` and two zero key fields.
- Anonymous: `HashChain4(output hashes)`, `HashChain4(disclosure)`, `private_tx_hash`, `sender_commitment`, `party_0`, `party_1`, `party_2`. No tag and no body enters it.

The sender commitment comes from the frame, `0` without a policy. The party identities are `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, each `0` when absent.

The delivered statement carries no `private_tx_hash`. They bind the transfer through the first nullifier, the outputs, `tx_viewing_pk`, the salt and the auditor message. SPP's `external_data_hash` covers the outputs, `tx_viewing_pk`, the salt and the message, and the SPP proof binds the first nullifier as a public input.

## Policy

```text
[ CRPO, private_tx_hash, policy_hash, ring_id,
  anonymous,                  // member key only, 1 on the anonymous rail
  approval_required, key_escrow,
  own_root, curator_root, sender,
  asset_0, amount_0, asset_1, amount_1, asset_2, amount_2,
  3,                          // POLICY_STATEMENT_VERSION
  withdrawal_hash ]
```

- `policy_hash`, `own_root` and `curator_root` come from the registries by the frame's indexes. `curator_root` is `0` without a curator.
- `key_escrow` is `mode == ConfidentialEscrow`. The delegate key binds `approval_required = 0` and `key_escrow = 1`.
- `sender` is `solana_owner_identity` of the sole owner signer on the confidential rail, `sender_commitment` on the anonymous rail and `0` on the delegate rail.
- The public slots are SPP's per-asset nets in first-seen order. A slot holds the asset field, then `right_align(net)` for a positive net or `q - |net|` for a negative net. Slots past the used ones are zeros.
- `withdrawal_hash = HashChain4([CRPW, right_align(count), (owner, asset, right_align(amount)) per withdrawal leg])`, in settlement order. A SOL leg's owner is `solana_owner_identity(recipient)`, an SPL leg's owner is the identity of the token account's owner.

## Apply

```text
[ CRAP, old_root, new_root, right_align(old_next_index), right_align(new_next_index),
  chain_start, chain_end, right_align(count) ]
```

The program supplies `old_root` as the current root, `old_next_index`, `chain_start = queue.chain_head`, `chain_end = chain(tail - 1)` and `count = pending`. Only `new_root` and `new_next_index` come from the instruction.

## Register key

```text
[ CRRG, solana_owner_identity(member signer), nullifier_pk,
  pack_be(auditor_pubkey), pack_be(0x04 || eph_u), hash_bytes(ciphertext) ]
```

The statement has 8 elements and no registry root.

## Withdrawal exemption

```text
[ CRWX, own_root, asset_0, amount_0, asset_1, amount_1, asset_2, amount_2 ]
```

`own_root` is the own root at the proof's `root_index`. Each used slot holds `hash_bytes(mint)` of one withdrawn mint, in first-seen order of the withdrawal legs, and `right_align` of the gross sum of that mint's withdrawal legs. Deposit legs do not enter the sum. Slots past the withdrawn mints are zeros.

## Deposit

```text
context_hash = HashChain([ hash_bytes(program id), hash_bytes(tree),
                           right_align(len(spp_data) as u64), HashChain(right-aligned 31-byte chunks of spp_data) ])
statement    = HashChain([ CRDP, context_hash, right_align(count), right_align(anonymous),
                           (owner_utxo_hash_i, hash_bytes(capsule ciphertext_i)) × 8,
                           pack_be(auditor_pubkey), pack_be(eph_pk),
                           right_align(key_escrow), registry_root ])
```

`spp_data` is the forwarded SPP data from its tag byte `18`. Slots past `count` are zero. `anonymous` is `mode == Anonymous`. `key_escrow` is `mode == ConfidentialEscrow`, and then `registry_root` is the own root at the prefix's index, else `0`.

## Merge

```text
[ CRMG, private_tx_hash, output_utxo_hash, n0, ring_id,
  pack_be(auditor_pubkey), pack_be(eph_pk), hash_bytes(ciphertext), right_align(salt),
  HashChain4(disclosure fields),
  party_0, party_1, party_2, right_align(key_escrow), member_registry_root ]
```

The salt is the SPP merge output salt. The party identities are the payer, the signing co-signer and `0`. `key_escrow` is `mode == ConfidentialEscrow`, and then `member_registry_root` is the own root at `registry_root_index`, else `0`. SPP's merge proof binds the same `private_tx_hash` and nullifiers.
