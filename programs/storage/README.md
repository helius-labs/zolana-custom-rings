# Storage

Storage verifies registry updates and policy decisions for one authority and multiple readers. Start with [the instruction entry point](src/lib.rs).

The authority creates a registry at the PDA derived from `REGISTRY_SEED` and its address. The account layout and errors live in `custom_ring_interface::storage`. Initialization fixes the authority and grace period. The initial root contains only the tree sentinel.

Updates carry public record changes and an apply proof. The program checks the authority signature, validates the changes, and binds their ordered hash to the registry address and expected revision. The proof binds the old root and leaf index to their replacements. List contents and rule tables stay outside the account. Readers need access to the tree data to construct proofs.

A normal update gives the outgoing root a fixed expiry slot, saturating at `u64::MAX`, where the root never expires. Earlier expiry slots stay fixed. A normal update fails if it would replace an unexpired root. An immediate update clears all earlier roots. Both update modes advance the revision without wraparound.

Readers supply a revision, rule table, action hash, sender and policy proof. Verification reads the registry without changing it. All referenced lists come from the same registry. The proof uses the member policy circuit with confidential outputs, no withdrawals, no public asset flow and no key escrow. A proof can verify at another revision when the root bytes are equal.

The consumer authenticates the registry, rules, sender and action before it acts on a successful verification. It also enforces replay protection, required approval and settlement. A successful policy proof alone does not authorize a transfer. The authority controls policy records, including mint limits. Member recovery and escrow records cannot be written through the update instruction.

Build and run the lifecycle test from the workspace root.

```sh
just build-storage-program
cargo test --locked -p storage-program --test lifecycle
```

The test uses checked in proofs and needs no prover service. To replace the fixtures, install the pinned ring proving keys and run the generator from `prover/`. The generator uses the registry address in [proofs.json](tests/proofs.json).

```sh
POLICY_STORE_REGISTRY="$(jq -r .registry ../programs/storage/tests/proofs.json)" \
REQUIRE_RING_KEYS=1 go test ./ring -run '^TestPolicyStoreFixtures$' -count=1
```
