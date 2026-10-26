# Circuit policy v2

The subsequent [mint-record transition](member-records.md#protocol-transition)
updates this deployment: the catalog now has 96 keys and mint settings live
in records. Counts and validation results below describe the earlier v2 baseline.

Implemented on `alex/circuit-policy`, based on PR 5 commit
`2bd20ae9c343ac5292c085e5c51a39828048dee7`.

## Guarantees and scope

The auditor still reconstructs committed owners, assets, amounts and transaction
relationships. Recipient encryption constraints remain: removing them would also
remove information the current auditor disclosure needs. Deliberate burns,
unusable keys and voluntary loss do not introduce new restrictions. Velocity
accounting is outside scope. Direct deposits and same-owner merges retain their
existing list behavior. Per-transfer amount guards, outflow caps and co-sign
thresholds remain enabled.

Anonymous transfer, entry and merge statements bind three identities, in order:
actual fee payer, configured co-signer, and public withdrawal owner. An absent
optional party is zero. Every nonzero party must differ from the hidden owner
proven by the circuit. Anonymous merges require the withdrawal identity to be
zero. The program derives these identities from its actual accounts and config;
the prover cannot substitute a different payer or hide a configured co-signer.

## Public withdrawal screening

Policy rules read private output owners/assets and public withdrawal owners/assets.
Amount guards aggregate gross payments, including split payments. Deposits cannot
offset a list threshold. Withdrawals do not enter the private transaction hash or
recipient key escrow checks. Outflow accounting keeps the existing public net
amounts so a withdrawal is not counted twice.

A withdrawal is `(owner_identity, asset_field, amount_u64)`. The digest is
`HashChain4(CRPW, count, owner_0, asset_0, amount_0, ...)`, where CRPW is
`0x43525057`. Only active legs enter the digest, in settlement order. Each active
amount is positive and bounded to u64; inactive witness slots are all zero.
The policy statement appends `2, withdrawal_digest` after its public net slots.
The rule table remains version 11.

For SOL, the screened owner is the recipient address. For SPL, it is the token
account's recorded owner. Policy frames store one raw 32-byte owner per SPL
withdrawal, immediately after the interface-transfer list. The program checks the
metadata count, token program, initialized account, mint and owner before proof
verification. A stale or fabricated owner fails. Shared SPL control is allowed by
the generic policy check; anonymous exits keep their additional identity rules.

Historical decoding exposes `screened_owner` in Rust and `screenedOwner` in
RPC/TypeScript from confirmed metadata, without reading the token account again.
Account closure or later ownership changes therefore cannot rewrite the screened
owner. Legacy frames and audit-only frames have no policy owner snapshot.

## Shapes and compatibility

Transfer tags are 43 (member) and 44 (delegate). The upgraded program refuses
legacy tags 3 and 25; historical decoders retain them. Stronger anonymous and
policy statements use distinct v2 circuit names, without legacy aliases.

Member policy keys cover 2/4/8/16 outputs and 0/1/2/4/8/16/32 withdrawal slots,
with separate own-registry-only and curator variants. The own-only circuit omits
curator paths and constrains every source registry and the curator root to zero.
The program chooses the variant from validated policy sources and the actual
withdrawal count. Delegates retain their existing no-public-settlement behavior.

Deposits use capacities 1/2/4/8 and registry writes use 1/2/4/8/16. SDKs select the
smallest supported capacity. Deposit statements retain all eight public slot
pairs, padding unavailable slots with constants. The catalog has 95 keys. The
4096-byte, 64-account transaction limits still apply; a circuit capacity does not
promise that every transaction of that capacity fits.

Proof JSON encodes withdrawal amounts as canonical 32-byte field hex, avoiding
JavaScript's JSON-number precision limit while the circuit enforces u64 bounds.

## Measured circuit costs

These are R1CS constraint counts, not wall-clock proving benchmarks. All catalog
counts are pinned in `prover/ringtest/ringkey/constraints.json` and checked against
fresh compilation. The policy comparison holds statement semantics and output
capacity fixed. Batch comparisons show the smaller shape selected for that count.

| Shape | General/largest key | Specialized key | Reduction |
| --- | ---: | ---: | ---: |
| Member policy, 2 outputs, no withdrawals | 49,039 | 30,923 | 36.9% |
| Member policy, 4 outputs, no withdrawals | 82,932 | 50,314 | 39.3% |
| Member policy, 8 outputs, no withdrawals | 150,837 | 89,266 | 40.8% |
| Member policy, 16 outputs, no withdrawals | 286,631 | 167,536 | 41.5% |
| Deposit, capacity 1 versus 8 | 148,936 | 52,680 | 64.6% |
| Deposit, capacity 2 versus 8 | 148,936 | 66,431 | 55.4% |
| Deposit, capacity 4 versus 8 | 148,936 | 93,932 | 36.9% |
| Registry batch, capacity 2 versus 16 | 232,892 | 30,033 | 87.1% |
| Registry batch, capacity 4 versus 16 | 232,892 | 59,081 | 74.6% |
| Registry batch, capacity 8 versus 16 | 232,892 | 117,018 | 49.8% |

Anonymous transfer/entry binding adds 309 constraints; anonymous merge binding
adds 733. Policy versioning with no withdrawals adds 584 to the general key.
An independent auditor disclosure design remains future work; see
[review-backlog.md](review-backlog.md).

## Proving-time benchmarks

Run from the repository root with the pinned release keys installed:

```sh
just bench-proofs
```

This regenerates [BENCHMARK.md](../BENCHMARK.md) and the raw samples in
`target/proof-benchmark.json` after a complete successful run. It measures
eleven endpoint shapes: minimum and maximum confidential audit outputs;
minimum anonymous audit, maximum anonymous inputs and maximum anonymous
outputs; and minimum outputs, maximum outputs without withdrawals, and maximum
outputs with maximum withdrawal capacity for both own-registry and curator
policy proofs. The shared shape list is
`prover/ring/proving-benchmarks.json`.

The default run takes five samples of three timed proofs each. Override with
`just bench-proofs --samples 3 --iterations 2`. Set `ZOLANA_PROVER_KEYS_DIR` or
pass `--keys-dir` to use another key directory. The default is
`zolana/prover/server/proving-keys`. The runner requires keys, checks their
sizes and SHA-256 digests against the release lock, and leaves the previous
report in place if proving or result validation fails. It does not download
or generate keys.

Each measurement uses the CPU `ExtensionProof.Prove` path: assignment
construction, witness encoding, constraint solving and Groth16 proving. Key
loading, fixture construction, JSON decoding, one warm-up proof and proof
verification are outside the timer. The warm-up and final proofs are verified.
The generated report records the Go version, hardware, actual `GOMAXPROCS`,
repository/submodule revisions and timing boundaries. Output and withdrawal
columns are compiled capacities; fixtures may include padding, and a compiled
shape does not guarantee that a transaction fits Solana's limits. The largest
anonymous input class is filled with 32 live inputs. SPP proofs, network
requests and transaction submission are excluded. No compute-unit profiling
or transaction-size measurements run. Use the same CPU allocation and an
otherwise idle machine for comparisons.

For a single circuit without regenerating the report, run from `prover/`:

```sh
REQUIRE_RING_KEYS=1 go test ./ring -run '^$' -bench '^BenchmarkRingProve$/custom-ring-audit-packed-2$' -benchtime=3x -count=5 -benchmem
```

## Key artifacts and release gate

Keys were generated locally with the pinned gnark setup tooling and exported to
the committed Rust verifiers. The lockfile and TypeScript pins identify the exact
artifacts. Setup is randomized: regenerating keys produces different artifacts.

The lockfile pins the public
[policy-v2 key release](https://github.com/helius-labs/zolana/releases/tag/custom-ring-keys-policy-v2).
Its files must match the prepared set in `target/circuit-policy-keys` byte for byte.
Publication of every pinned artifact is required before merging or deployment.
The installed-key CI job fails on missing keys and verifies every verifier export,
compiled circuit, generated proof and mutated public statement.

Local rotation and verification commands, from the repository root:

```sh
just build-prover-server
python3 tools/prepare_ring_keys.py
cargo build --manifest-path zolana/Cargo.toml -p xtask
python3 tools/finalize_ring_keys.py --release https://github.com/helius-labs/zolana/releases/download/custom-ring-keys-policy-v2
cd prover
REQUIRE_RING_KEYS=1 ZOLANA_PROVER_KEYS_DIR="$PWD/../target/circuit-policy-keys" WRITE_RING_PROOF_VECTORS=1 go test ./ring -run TestCatalogRequestsProveWithTheInstalledKeys -timeout 60m
```

`test-vectors/proof/ring-proofs.json` contains public statements and real proofs for all
95 keys. The Rust SDK verifies them with the same Solana verifier and committed
keys used by the program, including rejection under a changed statement.
Deploy the program, prover and both SDKs as one versioned change after publication.

## Validation

- The complete Go test suite and `go vet` pass. Installed-key checks separately
  compile-match, prove and verify all 95 catalog entries with missing keys fatal.
- `just check-custom-ring-keys` passes: all 95 committed verifiers match freshly
  exported pinned proving keys.
- All 95 public Go proof vectors pass the Rust SDK's Solana verifier; each rejects
  a changed public statement. The SDK suite passes 92 tests.
- The SBF program builds and all 106 LiteSVM/program tests pass, including rejection
  of legacy transfer tags and stale SPL ownership metadata.
- Interface, client, RPC and policy tests pass 417 tests (7 intentional skips).
- The TypeScript package passes format, lint, changelog, types, tests, build and
  distribution checks. Targeted historical tests include both legacy tags and
  confirmed withdrawal-owner snapshots.
- Workspace checks cover all targets. Clippy with warnings denied passes.
- Live integration covers anonymous deposits, inbox and pair payments, same-owner
  merges, auditor reconstruction, delegate moves and public withdrawal screening.
  Merge readiness requires the full CI suite on the final commit; local checks
  alone do not establish it.
