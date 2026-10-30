# Custom rings

A custom ring is a Solana program that governs the zolana shielded notes
tagged with its program id. The zolana shielded pool (SPP) moves a ring note
only on an instruction the ring program signs. Every transfer proves that the
ring's auditor can open it, and a policy ring also proves its rule table. A
confidential ring hides assets and amounts. An anonymous ring also hides
senders and recipients.

## Split with zolana

- SPP holds the notes, vaults, trees and nullifiers and verifies its own
  proofs. Its ring instructions require the ring's `ring_auth` PDA to sign.
- The ring program checks the ring proofs, signers and controls, then invokes
  SPP as `ring_auth`. It depends on zolana libraries, never on the SPP program.
- The ring prover is the zolana prover built from the Go module `prover/`,
  which holds the ring circuits.
- zolana's Photon has no ring code. `services/ring-indexer` indexes the ring
  state and forwards every other JSON-RPC call to Photon.
- `zolana/` pins zolana. A change to both lands in zolana first, then
  `just zolana-bump <commit>` moves the pin.

## Rings and rails

A ring may enforce a policy over member records or only require an audit proof.
The owner rail uses the note owner's signature, the anonymous rail proves the
owner's signature without publishing the owner, and the delegate rail lets an
authorized delegate move a member's notes. See the [spec](docs/spec.md),
[owner rails](docs/design/owner-rails.md) and [audit and key escrow](docs/design/audit-and-escrow.md).

## Roles

Four role keys govern a ring. The admin rotates the roles and appoints the
delegate, the policy authority sets the policy and the lists, the pauser pauses
the ring and the co-signer admin sets the co-signers. The auditor opens ring
activity, and members own notes and may write their own registry records. A curator supplies
lists to another ring's policy. A delegate can move notes only through the
ring's delegate checks; an authorized reader can query the ring RPC without
holding the auditor key. See [records and roots](docs/design/records-and-roots.md) and the
[ring RPC](services/ring-rpc/README.md).

## How a transfer settles

The wallet prepares the SPP settlement and the ring's required audit and policy
proofs. The ring program checks its authorization and proofs, then signs its
SPP call as `ring_auth`. SPP verifies its own proof and updates notes, trees and
nullifiers. [Public inputs](docs/spec/crypto/public-inputs.md) lists the statements by operation.

## Shapes

Each proving key fixes an input and output width; a shape such as 2x4 has two
inputs and four outputs. The available widths depend on the rail and proof
family. See the pinned
[key catalog](program-libs/interface/src/proof/key_catalog.rs).

## Threat

An auditor can open ring activity but cannot spend merely by holding the audit
key. A delegate's separate authority is checked by the ring program. The
upgrade authority can replace those checks; see [Limits](#limits) and
[trust assumptions](docs/spec.md#trust-assumptions).

## Setup

```bash
git clone --recursive https://github.com/helius-labs/zolana-custom-rings.git
just check-all && just test-hermetic
```

The build needs the Rust and Solana toolchains zolana pins, Go at the version
`prover/go.mod` names, and `just`. `just fetch-custom-ring-keys` downloads the
proving keys the lockfiles pin. The `test-custom-ring-*` suites start a local
validator, Photon, the ring indexer and the ring prover.

## Use

`zolana-ring new`, `deploy` and `init` create a ring, deploy its program and
fix its auditor key, tier and policy. Members pay with `zolana-ring transfer`
and `merge`, or through the Rust and TypeScript SDKs.

## Limits

- The upgrade authority can replace every check of the ring program.
- No instruction replaces the auditor key after `Initialize`.
- A paused ring, or one SPP governance has not activated, moves no note.
