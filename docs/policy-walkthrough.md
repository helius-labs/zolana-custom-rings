# Policy Walkthrough

A custom ring is a Solana program that governs its notes in the zolana shielded pool (SPP). SPP moves a ring note only when the ring program signs, and the ring program signs only after it verifies the ring's Groth16 proofs of the transfer. A policy ring adds a **policy proof** to every transfer. That proof shows that the transfer meets the ring's rules over the ring's member lists. [Spec](spec.md)

## Terms

### Policy

A **policy** is an `EncodedRuleTable`, a source map and `policy_hash`. The table holds the rules the policy proof enforces.

A **member record** is one leaf `Poseidon(member, next, lists, escrow_key, mint_policy, withdrawal_threshold, limits_0, limits_1)` per owner or asset. `member` is `solana_owner_identity(key)` for an owner and `hash_bytes(mint)` for an asset. `lists` has one bit per list. An asset's record also holds its **mint settings**: the per-asset guard `threshold`, the outflow `cap` and `cosign_above`, the co-signer's `withdrawal_threshold`, and the `limits` the Ring RPC co-signer enforces (`program-libs/policy/src/mint.rs:12`). Only the config authority writes them. [Mint settings](spec.md#mint-settings)

The policy lives in the ring's `RingPolicy` PDA at seed `[b"policy"]`, alongside:

- `records`: the ring's own `StorageRegistry`, fixed at creation
- `own_roots`, `curator_roots`: the mirrors of the records' and the curator's root history, see **Root freshness** below
- `policy_hash`: the commitment to the table and the source map
- `generation`: plus one at every table or source write, not hashed

The account stores the whole table. It stores no member record, only the mirrored roots of the record trees. The records reach clients through instruction data and the ring indexer. See `RingPolicy` in `program-libs/interface/src/accounts/state.rs:387`. [RingPolicy](spec.md#ringpolicy)

### Rule

A **Rule** is a list condition on one subject, with an optional amount guard (see **Evaluation**). See `Rule` in `program-libs/policy/src/rule_table/mod.rs:206`.

> Example: "Each output owner must be on the Allow list."

### Mode

A **Mode** is one of (`program-libs/policy/src/rule_table/mod.rs:185`):

- `Present`: the subject is on the list. Its record has the list bit set.
- `Absent`: the subject is off the list. Its record has the bit clear, or it has no record.

### Subject

A **subject** is the value a rule checks (`program-libs/policy/src/rule_table/mod.rs:175`, `prover/circuits/policy/subjects.go:26`).

A transfer runs on one of three rails. On the confidential rail the owner signs the transaction. On the anonymous rail the owner signs inside the SPP proof and stays hidden. On the delegate rail the ring's delegate moves an escrowed member's notes. [Rail](anonymity-walkthrough.md#rail)

A **live output** is a real output note, not a dummy slot. An **exit** is a live output to the default ring, the SPP notes outside every ring. A **withdrawal** is a public SOL or SPL transfer out of SPP inside the transfer.

| Subject | Value checked |
| --- | --- |
| `Sender` | The one sender of the transfer: the sole owner signer identity on the confidential rail, the hidden sender opened from the sender commitment on the anonymous rail, the source member on the delegate rail |
| `OutputOwner` | Every live output owner, including change and exits, and every withdrawal owner |
| `Asset` | Every live output asset and every withdrawn asset |

The **sender commitment** is `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`, a hash that hides the anonymous sender's identity. [Hashing](spec/crypto/hashing.md#slot-secret-and-sender-commitment)

The policy proof does not open the spent notes, so input assets are never screened. A sender rule takes no amount guard (`SenderGuard`, `program-libs/policy/src/rule_table/mod.rs:388`).

### Sources

**Sources** name the registry that serves each list (see **ListID**). A **curator** is a storage registry of any authority whose records a policy reads. For example, the Allow list might come from the ring's own registry, while the Block list comes from a curator.

Sources are configured **policy-wide**, not per rule, and they are positional: slot `i` serves list `i + 1` (`program-libs/policy/src/rule_table/mod.rs:34`). A zero registry names the ring's own registry. In instruction data, source `0` is the own registry and `1` the curator (`program-libs/interface/src/instructions/instruction.rs:207`).

A policy has at most one curator, `N_FOREIGN = 1` (`program-libs/policy/src/rule_table/mod.rs:13`, `:139`). The curator is a Storage Program `StorageRegistry` (`programs/custom-ring/src/instructions/accounts/loader.rs:113`). The ring program refuses its own records as a curator (`programs/custom-ring/src/instructions/verification/policy_binding.rs:68`).

### ListID

A **ListID** names one bit of a member record. Bit `id - 1` marks list `id` (`program-libs/policy/src/list.rs:49`). The config authority is the key that holds the ring config. `RegisterKey` is the instruction that seals a member's nullifier secret to the auditor.

| List | ID | Writer |
| --- | --- | --- |
| Allow | `1` | Config authority |
| Block | `2` | Config authority |
| Frozen | `3` | Config authority |
| RingViewing | `4` | Owner, own record |
| Recovery | `5` | Owner, own record |
| Reader | `6` | Config authority |
| Approval | `7` | Config authority |
| Escrow | `8` | `RegisterKey` only |

Rules read only the authority lists: Allow, Block, Frozen, Reader and Approval. A member therefore cannot admit itself. `EncodedRuleTable::validate` refuses any other (`MemberWrittenList`, `program-libs/policy/src/rule_table/mod.rs:631`). A curator source reads the same bit in the curator's records (`prover/circuits/policy/subjects.go:38`).

### Evaluation

**Evaluation** applies each active rule to each of its subjects. All rules must pass. The lists within a rule join with logical **OR**: a rule holds when the subject is on one of its present lists or off one of its absent lists (`prover/circuits/policy/rules.go:101`).

A **payment** is a live output or a withdrawal (`prover/circuits/policy/member.go:70`). The evaluation circuit computes three values per rule and payment (`prover/circuits/policy/rules.go:55`):

- **enabled**: the rule is active, it screens this kind of subject, and the payment is live. An owner rule also needs a nonzero owner.
- **refused**: no list of the rule admits the subject.
- **exempt**: the rule's amount guard covers the subject's payments.

The proof requires `exempt` wherever `enabled` and `refused` are both set (`prover/circuits/policy/rules.go:63`). A sender rule has no guard, so the sender must never be refused (`prover/circuits/policy/rules.go:24`).

The guards (`program-libs/policy/src/rule_table/mod.rs:192`, `prover/circuits/policy/rules.go:43`):

- `Always`: no exemption.
- `AboveAmount(t)`: an owner subject is exempt when its live payments sum to at most `t`, and every payment of the transfer then carries one asset. An asset subject is exempt when the payments of that asset sum to at most `t`.
- `AboveAmountByAsset`: output-owner rules only. The bound is the `threshold` of the payment asset's own record. An owner is exempt when its payments in the payment's asset sum to at most that threshold. A payment in a mint with a zero threshold fails the proof (`prover/circuits/policy/rules.go:58`).

Comparisons are inclusive. A deposit is no payment, so it never counts toward a guard total (`prover/circuits/policy/rules.go:77`).

### Opening

An **opening** proves one member's record against a registry root. The policy proof opens its records as one **record pool** per registry, and each subject resolves to one pool record (`prover/circuits/policy/record_pool.go:69`):

- A **present** member's pool record is its leaf `Poseidon(member, next, lists, escrow_key, mint_policy, withdrawal_threshold, limits_0, limits_1)`. Its `lists` bits answer every list, and its mint settings answer every bound of its asset.
- An **absent** member's pool record is the low record with `low < member < low.next`. Every list and every mint setting reads as `0`.

Every pool record's path folds to a shared canopy, the narrowest tree level at least as wide as the pool. The canopy hashes up to the root (`prover/circuits/registry/shared_path.go:46`). [Record pool](circuit-policy.md#record-pool)

Records sort by member through `next`, and an insert relinks its low record (`prover/circuits/registry/apply_records.go:128`). A present member therefore has no low record that brackets it. Every opening must fold to the bound root, so the prover cannot leave out the convicting record. [Member records](spec.md#member-records)

---

## Logic

The policy circuit proves no separate fact per list. Each subject resolves **one record per registry**: the own registry, plus the curator's when any list is foreign (`prover/circuits/policy/subjects.go:32`). That one opening answers every list, such as:

- Alice is allowlisted.
- Bob is not blocked.
- Alice is not frozen.

The proving key's output and withdrawal slot counts fix the entries. The sender takes one, each output and withdrawal slot an owner and an asset entry, and each public asset slot an own-registry entry (`prover/circuits/policy/policy.go:69`). The same counts fix each pool's capacity (`prover/circuits/policy/pooled_policy.go:61`). An asset entry resolves for every live payment, whatever the rules, because it carries the asset's mint settings (`prover/circuits/policy/subjects.go:47`). A public asset entry opens each nonzero public asset for the outflow bound (`prover/circuits/policy/outflow.go:45`).

Each rule, see `prover/circuits/policy/rules.go:22`, selects a subject: sender, output owner, or asset.

### Masks and alternatives

`mask`, `alternative` and `mode` belong to each rule row (`program-libs/policy/src/rule_table/mod.rs:215`):

- **mask**: a bitmask selecting lists for the rule's mode.
- **alternative**: a bitmask selecting absent lists beside a `Present` mask.

A rule with present lists stores them in `mask` with mode `Present` and its absent lists in `alternative`. A rule with absent lists only stores them in `mask` with mode `Absent` and `alternative = 0` (`program-libs/policy/src/rule_table/mod.rs:298`). `Rule::decode` refuses an `Absent` row with a nonzero `alternative` (`NonCanonicalAlternative`, `program-libs/policy/src/rule_table/mod.rs:349`). A rule therefore defines one requirement with several possible alternatives. [EncodedRuleTable](spec.md#encodedruletable)

### Example: a curator's blocklist with reviewed exceptions

A ring uses an external curator's Block list. The ring's config authority can review a flagged recipient and add them to the ring's own Approval list. This handles false positives without changing the curator's list. See `examples/curated-blocklist-approval-exception/ring.toml`.

The policy-wide Sources select:

| List | Source |
| --- | --- |
| Block | Curator's registry |
| Approval | Ring's own registry |

One rule checks each output owner:

```toml
[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]
```

It encodes as:

```
Subject:     OutputOwner (1)
Mode:        Present (1)
Mask:        0b01000000  → Approval
Alternative: 0b00000010  → Block
Guard:       Always (0)
```

<aside>

**Requirement:** approved by this ring **OR** not blocked by the curator.

</aside>

Approval is List ID `7`, so it uses bit `6`. Block is List ID `2`, so it uses bit `1`. This rule ignores all other lists.

For each output owner, the circuit opens the owner's own record and its curator record:

| Recipient | Opening that satisfies the rule |
| --- | --- |
| Bob is not blocked | Bob's curator opening reads bit `1` as `0`. Bob's record has the bit clear, or Bob is **Absent**. |
| Alice is blocked, but the ring approved her | Alice's own record has bit `6` set. |
| Mallory is blocked and has no approval | Both lists refuse Mallory and `Always` exempts nothing, so the proof fails. |

Different recipients can use different alternatives. Every live output owner must satisfy the rule, including owners of change outputs, exits and withdrawals.

### Adding an unconditional Frozen restriction

To make the ring's Frozen list an unconditional restriction, add a separate rule that forbids `OutputOwner` on Frozen:

```toml
[[policy.rules]]
subject = "output-owner"
forbid = "frozen"
```

It encodes with mode `Absent` (2), mask `0b00000100` and alternative `0`. Frozen reads the ring's own registry, since no source names it (`cli/src/commands/policy/grammar.rs:491`).

Alice now needs two facts:

1. **Present in Approval**, from Alice's own record
2. **Absent from Frozen**, from the same own record

Alice's curator record answers Block. Approval cannot override Frozen because both rules must pass. Each of Alice's output slots resolves to Alice's one record per registry, and that record answers both rules.

---

## What the circuit proves

The circuit binds three things (`prover/circuits/policy/member.go:56`):

1. **Subjects to the transaction**: outputs reopen `private_tx_hash`, SPP's blinded hash over the spent note hashes and the output hashes, which the SPP proof binds (`prover/circuits/policy/transaction.go:45`). Withdrawals hash to `withdrawal_hash`, which the program rebuilds from the settlement accounts (`prover/circuits/policy/withdrawals.go:35`, `programs/custom-ring/src/instructions/transact/verify.rs:66`). The sender is the statement's `sender`, which the program supplies: the sole owner signer identity, or on the anonymous rail the sender commitment the circuit opens to the hidden sender (`programs/custom-ring/src/instructions/transact/accounts.rs:118`, `prover/circuits/policy/member.go:84`). On the delegate rail the circuit takes it from the reopened inputs (`prover/circuits/policy/delegate.go:75`).
2. **Rules to the ring**: the table and the source map hash to the `policy_hash` the program reads from the ring policy (`prover/circuits/policy/table.go:60`, `program-libs/interface/src/instructions/transact.rs:842`).
3. **Openings to the registries**: every pool folds to `own_root` or `curator_root`, which the program reads by revision from the ring policy's mirrors (`program-libs/interface/src/instructions/transact.rs:843`, `program-libs/interface/src/accounts/state.rs:533`).

It then requires every enabled rule to pass and every outflow limit to hold. The program validates the table at write time, and the circuit trusts that validation (`program-libs/interface/src/accounts/state.rs:469`, `prover/circuits/policy/table.go:57`). The program then verifies the proof and only then CPIs SPP (`programs/custom-ring/src/instructions/transact/processor.rs:58`). [Transact](spec.md#20-transact)

<aside>

**Root freshness:** a statement names each root by its revision. `SyncRoots` copies a storage registry's roots into the ring policy's mirror. A mirrored root verifies while it is the newest one or its `expires_at` lies above the current slot. The Storage Program's `Update` sets a retired root's `expires_at` to the slot plus the registry's `grace_slots`, and `UpdateImmediate` clears every earlier root, so a block binds every transfer after the next `SyncRoots`. A root the registry dropped stays valid in the mirror until that sync.

`program-libs/interface/src/accounts/state.rs:430`, `:533`, `:538`, `root_at` in `program-libs/interface/src/accounts/storage.rs`

```text
root at revision r: nonzero, and r is the newest revision or slot < expires_at
Update:             expires_at = slot + grace_slots
UpdateImmediate:    every earlier root cleared
```

</aside>

---

## Code reading guide

1. **Rule structure**: `program-libs/policy/src/rule_table/mod.rs:206`
    - See how a rule chooses who or what to check, which lists can satisfy it, and whether an amount guard applies. `Rule::encoded` at `:298` writes the row, and `EncodedRuleTable::validate` at `:628` is the write-time check.
2. **Policy storage**: `program-libs/interface/src/accounts/state.rs:469`
    - Read `RingPolicy::set_policy` to see how the ring validates the table, stores the sources and repins `policy_hash`.
3. **Circuit entry point**: `prover/circuits/policy/member.go:56`
    - Follow how the circuit decodes the table under `policy_hash`, opens the outputs and withdrawals, resolves the sender, opens every subject's records, evaluates rules and outflow, and binds the statement. `prover/circuits/policy/policy.go:15` lists its properties.
4. **Record pool**: `prover/circuits/policy/record_pool.go:39`
    - Understand why a statement such as "Alice is not blocked" must be proven from the record tree. One pool per registry serves every subject, and `prover/circuits/registry/shared_path.go:46` folds the pool to the root.
5. **Rule evaluation**: `prover/circuits/policy/rules.go:16`
    - See how `enabled`, `refused` and `exempt` combine per payment, with the row split in `prover/circuits/policy/table.go:118` and the list bits in `prover/circuits/policy/subjects.go:38`. Every rule must pass.
6. **Outflow limits**: `prover/circuits/policy/outflow.go:18`
    - The bound runs once for each live output's asset and each nonzero public asset, with the `cap` and `cosign_above` of that asset's own record. `others` sums the asset over live outputs, except ring outputs to the sender. `net` is the asset's signed public net, a deposit positive and a withdrawal negative. See how `outflow = others - net` is bounded and how `approval_required` is set, the bit that makes the program demand a co-signer.
7. **On-chain verification**: `programs/custom-ring/src/instructions/transact/verify.rs:54`
    - The program supplies `policy_hash`, the roots, the sender and the withdrawals (`programs/custom-ring/src/instructions/transact/accounts.rs:56`), verifies the policy proof, and only then authorizes the SPP call that executes the transfer.

### Common misreadings

**"List entries are compressed UTXOs read by an existence proof."** No. A list is one bit of a member record. Records live in one 4-ary tree per ring, and the chain holds only its roots. The pool holds the member's record, or the low record that proves its absence (`prover/circuits/policy/record_pool.go:69`).

**"Rules screen input owners and input amounts."** No. The sender is one identity per transfer, and the policy proof of the confidential and anonymous rails does not open the inputs. The delegate key alone reopens inputs, and only to prove they share one source member (`prover/circuits/policy/delegate.go:75`).

**"A guard sums outputs plus public amounts."** No. A guard sums live outputs and withdrawals, by owner, by asset, or by owner and asset. Deposits never count (`prover/circuits/policy/rules.go:77`, `prover/circuits/policy/member.go:70`). Public nets enter only the outflow limit (`prover/circuits/policy/outflow.go:31`).

**"The table lists the limited mints."** No. The table holds rules only. Each asset's own record holds its threshold, cap and co-sign bound, and the proof resolves the record of every payment asset and every public asset (`prover/circuits/policy/subjects.go:47`, `prover/circuits/policy/outflow.go:45`). A mint without settings opens as absent and reads zeros.

**"A rule can fail a transfer above an amount."** Not a rule. A guard only exempts a refused subject at or below its threshold. To refuse a transfer above an amount, use an outflow limit `cap`. It bounds what leaves the sender, not the gross output (`prover/circuits/policy/outflow.go:18`).

**"A policy can bound the sum over 24 hours."** No. An outflow limit bounds one transfer, and no counter or window exists. [Limitation](spec.md#outflow-limits-bound-one-transfer)

**"A KYC rule on inputs needs a rule per input."** No. One `sender` rule screens the one sender:

```toml
[[policy.rules]]
subject = "sender"
require = "allow"

[[policy.rules]]
subject = "output-owner"
require = "allow"

[[policy.rules]]
subject = "output-owner"
forbid = "block"
```
