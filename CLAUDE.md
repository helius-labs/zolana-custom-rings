# Zolana Custom Rings Contributor Notes

@zolana/CLAUDE.md

The zolana notes above apply here, with their paths read under `zolana/`.

## Repository

- `zolana/` is the zolana submodule. Ring crates take zolana crates by path
  into it, so a zolana change and its ring change build together locally. Land
  the zolana side first, then move the pin with `just zolana-bump <commit>`.
- The layout mirrors zolana: `programs/custom-ring`, `program-libs/{interface,
  policy,member-registry}`, `sdk-libs/{client,indexer,keys,sdk,secret-file,
  transaction,ts}`,
  `program-tests/custom-ring`, `services/{ring-indexer,ring-rpc}`, `cli`, `xtask`.
- Large package implementations group by technical layer: protocol or codec,
  crypto or proof, RPC, state or storage, operations, and CLI UI. Keep a small
  package flat when each source file already has one clear purpose. Rust crate
  roots and TypeScript package entrypoints keep the public paths stable.
- Split crowded layers by their own purpose: commands by audience, protocol
  files by concept, and generated verifiers by circuit family and shape.
- Name a module for the work it owns, such as `output-rail`, `transfer-rails`,
  `ring-directory`, or `known_utxo_index`, rather than a broad noun that also
  describes another module. Integration cases live in behavior-named test
  modules; shared fixtures stay in one parent or helper module.
- The ring verifying keys are committed in `program-libs/interface/src/verifying_keys`, and
  `just check-custom-ring-keys` diffs them against the ring prover's export of
  the keys `prover/ring/proving-keys.lock` pins.
- The Go module `prover/` holds the ring circuits in `prover/circuits` and
  builds the ring prover, `just build-prover-server`. `prover/cmd/prover`
  imports `prover/ring` to register ring circuits alongside the SPP circuits.
  The justfile exports its `PROVER_BIN`.
- Shared vectors stay in `zolana/test-vectors`. Vectors only ring code reads
  live in `test-vectors/`.

## Ownership after the split

- Zolana owns wallet identity and key derivation, X25519 primitives, SPP circuits
  and programs, and generic prover/Photon extension hooks. Fix those upstream
  first, then update this repository's `zolana` pin to the merged commit.
- Custom rings owns ring circuits, policies, disclosures, the ring program,
  SDKs, CLI, indexer and auditor RPC. Ring integration failures belong here
  unless they reproduce in the underlying Zolana functionality.
- Examples consume `@heliuslabs/zolana-custom-rings` for ring operations and
  `@heliuslabs/spr` for core wallet functionality. Keep both dependencies on
  compatible revisions; the submodule identifies the tested core revision.
- Use `ed25519DerivationMessage(publicKey)` for browser-wallet signing. The
  signed off-chain message derives the existing identity; the bare payload does not.
- The ring key lockfile owns artifact names, sizes and hashes. Publish its exact
  prepared files to the pinned public release before merging a rotation;
  downloads must need no credentials.

## Ring proof review

Follow [Proof composition](docs/design/proof-composition.md) when changing ring circuits,
statement builders, or their program bindings. Trace each predicate from its trusted source
to its refusal test. Review shared output openings and gate derivation before capacity tuning.

## Common Commands

```bash
just check-all
just clippy
just test-hermetic
just test-custom-ring-validator
just check-custom-ring-keys
just zolana::build-programs
```
