# Storage

Storage keeps record tree roots for one authority and any number of readers. Start with [the instruction entry point](src/lib.rs).

A creator makes a registry at the PDA `[b"storage", creator, registry_id]`. The creator and the payer both sign, and the creator becomes the first authority. Because the creator is in the seeds, no other signer can take its addresses. The account layout and `StorageError` live in `custom_ring_interface::storage`, and the instruction data in `custom_ring_interface::storage_instruction`. Initialization fixes the grace period. The initial root holds only the tree sentinel.

An update carries record writes and an apply proof. The program checks the authority signature, turns each write into its tree entry, and chains the entries in order from a start that binds the registry address and the expected revision. The proof binds the old root and leaf index to their replacements. A write changes lists, mint settings or both, or it is an escrow write and carries only its escrow key. Only an escrow write sets the escrow list. The program does not check an escrow key. The authority checks it before it writes. An escrow key fills once and no write removes it. List contents and rule tables stay outside the account, so readers need the tree data to build proofs.

A normal update gives the outgoing root a fixed expiry slot, saturating at `u64::MAX`, where the root never expires. Earlier expiry slots stay fixed. A normal update fails if it would replace an unexpired root. An immediate update clears all earlier roots. Both update modes advance the revision without wraparound. `StorageRegistry::root` is the one rule for which root a revision names at a slot.

The authority hands the registry to a new authority with `UpdateAuthority`. Both keys sign, so a typo cannot lock the registry. The old authority loses every right at once.

The program verifies no policy. A consumer reads a root and authenticates the registry, the rules and the action before it acts. The authority controls every record, including mint settings and escrow keys.

Build and run the lifecycle test from the workspace root.

```sh
just build-storage-program
cargo test --locked -p storage-program --test lifecycle
```

The test uses checked in proofs and needs no prover service. To replace the fixtures, install the pinned ring proving keys and run the generator from `prover/`. The proofs bind the registry address in [proofs.json](tests/proofs.json), and the test refuses a fixture made for another address.

```sh
STORAGE_REGISTRY="$(jq -r .registry ../programs/storage/tests/proofs.json)" \
REQUIRE_RING_KEYS=1 go test ./ring -run '^TestStorageFixtures$' -count=1
```

`ZOLANA_PROVER_KEYS_DIR` points the generator at another key directory.
