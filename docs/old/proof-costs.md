# Proof costs

Each proving key fixes a circuit family and its input and output width. A shape
such as 2x4 has two inputs and four outputs. The available ring keys are defined
by the [Go key catalog](../prover/ring/keys.go), mirrored by the
[Rust key catalog](../program-libs/interface/src/proof/key_catalog.rs), and pinned by
[proving-keys.lock](../prover/ring/proving-keys.lock). Use those files when
choosing a shape; a copied constraint count can become stale after a key
rotation.

## What each transaction proves

- A confidential transfer proves SPP's ring statement and one audit statement.
  A policy ring adds a member policy statement.
- An anonymous transfer proves SPP's anonymous statement and one anonymous
  audit statement. A policy ring adds a member policy statement.
- A delegate move proves SPP's ring authority statement, an audit statement
  and a delegate policy statement.
- An audited deposit proves a deposit statement; SPP's `ring_deposit` takes no
  separate proof.
- A merge proves SPP's ring merge statement and one merge disclosure
  statement, which opens the owner's escrow record under key escrow.
- Key registration and record application each prove their own statement.
- A withdrawal below configured thresholds can add a withdrawal exemption proof
  to waive withdrawal-scoped co-signing. Supplying the demanded co-signer needs
  no exemption proof.

## SPP statements

Input tree openings account for much of a transfer's work, so wider input
shapes cost more. The upstream [SPP fingerprint test](../zolana/prover/server/prover/fingerprint/fingerprint_test.go)
pins compiled constraints for representative shapes and rejects unplanned
changes.

## Audit statements

Delivered audit keys cover confidential and delegate outputs and prove that
each output body opens for its recipient. Anonymous audit keys disclose each
output's owner key, asset and amount, prove no body, and bind the hidden sender
and its input class. An entry key fully opens default-ring inputs. The [audit key tests](../prover/circuits/audit/keys_test.go)
pin the current compiled counts.

## Policy statements

A policy proof opens one record pool per registry. The pool holds the records
of the sender, each payment's owner and asset, and each nonzero public asset.
The key's output and withdrawal widths fix its capacity. Mint settings
reuse these asset records, so proof work depends on the shape rather than the
number of configured mints. A delegate policy proof also reopens spent notes.
[Policy circuit](circuit-policy.md#record-pool) gives the capacities. The
[policy key tests](../prover/circuits/policy/policy_test.go) enforce budgets
for the small output shapes, and transaction size limits the wider shapes.

## Registry, deposits and merge disclosures

Record application, key registration, audited deposits and merge
disclosures have separate keys. The [registry tests](../prover/circuits/registry/registry_test.go)
pin opening constraints. Verify the current cost of any other key by compiling
it with the [ring key tests](../prover/ring/keys_test.go).

## Representative counts

BN254 constraints of selected policy keys, from
[`constraints.json`](../prover/ringtest/ringkey/constraints.json):

| Policy key | Own | Curator |
| --- | ---: | ---: |
| Member, 2 outputs, no withdrawals | 38,889 | 56,778 |
| Member, 4 outputs, no withdrawals | 56,869 | 87,826 |
| Member, 8 outputs, no withdrawals | 92,416 | 149,124 |
| Member, 16 outputs, no withdrawals | 160,536 | 263,885 |
| Member, 2 outputs, 32 withdrawals | 175,233 | 300,205 |
| Member, 16 outputs, 32 withdrawals | 296,265 | 501,564 |
| Delegate, 2x2 | 30,640 | 48,530 |
| Delegate, 4x4 | 51,437 | 82,395 |

Apply 16 records takes 246,444, deposit 8 takes 223,264 and the withdrawal
exemption takes 12,318. Adding configured mints increases registry storage,
not these circuit sizes.
