# Policy circuit

The policy circuit proves that one ring transfer meets the ring's rule table
and outflow limits. It reads the member records under the registry roots the
program binds. The `MemberPolicy` keys serve the confidential and anonymous
rails, and the `DelegatePolicy` keys serve the delegate rail. The rules and
their evaluation are in the [policy walkthrough](policy-walkthrough.md). The
checks are listed under [Transfer](spec.md#9-transfer).

## Statement

The one public input is `HashChain4` over the
[policy statement](spec/crypto/public-inputs.md#policy). The program rebuilds
every element from the frame, the registries and the settlement accounts. One
recipient per output slot follows `sender`. The statement version `4` follows
the public slots, then `withdrawal_hash`. A proof
for another statement version does not verify against the program's statement.
The rule table hash keeps its own version, `POLICY_TABLE_VERSION = 12`.

## Subjects

A payment is a live output or a withdrawal. The circuit screens these subjects:

- the one sender of the transfer
- the owner and the asset of every payment
- every nonzero public asset, for the outflow bound only

Every payment asset and every nonzero public asset resolves its own record,
whatever the rules, because that record holds the asset's mint settings.

## Record pool

Each key opens one own pool and, on a curator key, one curator pool. A pool
is a fixed set of records whose paths share one canopy.

1. Each record's path folds to a node of the canopy, the narrowest tree level
   at least as wide as the pool. The canopy hashes to `own_root` or
   `curator_root`. The curator pool folds only when some list is foreign.
2. A subject row names a member and a record index. The record is the member's
   own leaf, or the low record whose `member` and `next` bracket the member.
   A bracketed member reads every list and every mint setting as `0`.
3. The sender entry and each owner, asset and public asset entry names a
   subject row whose member equals the entry's value.

A member that several entries name takes one subject row. Absent members that
the same low record brackets share one record. With `o` outputs, `w`
withdrawal slots and `p` public asset slots, the pools hold:

```text
distinct = 1 + 2·o + w
own      = distinct + max(min(w, 3), p)
curator  = distinct + min(w, 3)
```

`p` is 3 on the member key and 0 on the delegate key. Withdrawals settle
through SPP's 3 public slots, so they add at most 3 distinct assets. Each pool
holds as many subject rows as records. `recordCapacity` in
[`pooled_policy.go`](../prover/circuits/policy/pooled_policy.go) and
`RingCircuit::record_pools` in
[`key_catalog.rs`](../program-libs/interface/src/proof/key_catalog.rs) compute
the same widths.

The SDKs collect the distinct members in first use order and read them with
the ring indexer's `getStorageRecordPool` under the root the transfer binds. They
check every path and every bracket against that root before they prove, and
fill the pool to its capacity by repeating its records.

## Withdrawals

A withdrawal is `(owner, asset, amount)`, with an active amount positive and
below `2^64`. Inactive slots are zero. The legs hash in settlement order to
`withdrawal_hash`. The program rebuilds it from the settlement accounts.

For SOL the screened owner is the recipient address. For SPL it is the token
account's owner. The frame carries one raw 32-byte owner per SPL withdrawal
after the interface transfers. The program checks the mint, the token program
and the owner of each token account before it verifies the proof. A stale or
fabricated owner fails.

Amount guards sum every payment, withdrawals included, and a deposit never
offsets a guard. A withdrawal enters neither `private_tx_hash` nor the key
escrow check. The outflow bound reads SPP's public nets, so a withdrawal counts
once.

## Keys

The member keys cover 2, 4, 8 and 16 outputs and 0, 1, 2, 4, 8, 16 and 32
withdrawal slots. The delegate keys cover the 2x2 and 4x4 ring authority
shapes. Every shape has an own key and a curator key:

```text
custom-ring-policy-member-v3-<outputs>-w<withdrawals>-<own|curator>
custom-ring-policy-delegate-v3-<inputs>x<outputs>-<own|curator>
```

The program takes the smallest withdrawal capacity at or above the withdrawal
count, and the own key when the policy has no curator. The own key requires
`curator_root = 0` and no foreign source.

## Rotating the keys

The setup is randomized, so a regeneration produces different keys. Prepare,
export and check the keys from the repository root:

```sh
just build-prover-server
python3 tools/prepare_ring_keys.py
cargo build --manifest-path zolana/Cargo.toml -p xtask
python3 tools/finalize_ring_keys.py --release https://github.com/helius-labs/zolana-custom-rings/releases/download/<tag>
cd prover
REQUIRE_RING_KEYS=1 ZOLANA_PROVER_KEYS_DIR="$PWD/../target/circuit-policy-keys" WRITE_RING_PROOF_VECTORS=1 go test ./ring -run TestCatalogRequestsProveWithTheInstalledKeys -timeout 60m
```

`finalize_ring_keys.py` writes the verifying keys, the lock and the
constraint counts, and removes verifiers of keys the catalog dropped. The
proving test writes `test-vectors/proof/ring-proofs.json`, a real proof per
key, and the Rust SDK verifies each one and refuses it under a changed
statement. Publish the files in `target/circuit-policy-keys` to the release
the lock names before the change merges. Deploy the program, the prover and
both SDKs together.

## Limits

A key's capacity does not promise that every transaction of its shape fits.
The 4,096-byte and 64-account transaction limits still apply.
