# @heliuslabs/zolana-custom-rings

`@heliuslabs/zolana-custom-rings` is the TypeScript SDK for custom Rings on
Solana Privacy Rings. It builds on `@heliuslabs/zolana` and adds the Ring
program instructions and transactions, the auditor and key registry, and the
Ring RPC client.

## Install

```sh
npm install @heliuslabs/zolana-custom-rings@alpha @heliuslabs/zolana@alpha @solana/kit
```

`@heliuslabs/zolana` is a peer dependency pinned to one version. Install the
version `peerDependencies` names, the two share the protocol layouts.

## Client

`createCustomRingClient(config)` takes the `ZolanaClientConfig` of
`createZolanaClient` and returns a `CustomRingClient`. It is a `ZolanaClient`
that also proves the Ring circuits and reads the Ring projections of the
indexer, over the same attested prover session. `checkRingProvingKeys()`
compares the prover's Ring keys with the keys the package pins, run it before
the first Ring proof.

`syncRingWallet` runs `syncWallet`, then opens the confidential Ring notes and
Ring deposits it skips into the wallet. Keys that are also `RingKeys` open
delivered notes too. An audited Ring deposit opens through its capsule:

```ts
import { createCustomRingClient, syncRingWallet } from "@heliuslabs/zolana-custom-rings";

const client = await createCustomRingClient({ solanaRpcUrl });
await syncRingWallet({ client, wallet, keys });
```

Ring projection errors, such as a key registry the indexer has not caught up
with, are `RingError` codes. The flows retry the transient ones.

## Custom Rings

Besides the permissionless default Ring, regulated entities can create custom Rings.
Custom Rings are simple Solana programs for compliance and policy control. Each Ring deploys its own program. It has a program
upgrade authority, a protocol authority, and an auditor key. The default Ring does not have an auditor key.

The auditor key lives in a Ring RPC. The Ring authority grants view access.
Helius can host that RPC; the authority can host it itself. The forester is
shared with the default Ring.

A Ring is confidential or anonymous, and an anonymous Ring spends
through the Ring RPC relay. A Ring is audit-only or carries a
policy, a rule table over lists of members whose addresses the Ring claims in
its address tree. The tier is fixed when the Ring config is created.

Set a Ring up in this order.

1. `deployRingProgram` deploys or upgrades the Ring program from a
   `RingProgramBinary` and returns once the program is usable,
   `verifyRingProgram` checks the deployed bytes.
2. The records `StorageRegistry` exists in the storage program.
3. `initializeRingInstruction`, signed by the upgrade authority, stores the
   auditor key and the tier, binds the records, pins a policy Ring's rule table
   and registers the Ring with the pool.
4. On a permissioned pool the governance authority activates the Ring with
   `getSetRingActivationInstructionAsync` from `@heliuslabs/zolana/instructions`.
5. `AuthorityRecordUpdate` fills the lists through `RingRpc.submitRecordUpdate`.

A wallet spends through Ring RPC and reads no Merkle path and no record.
`prepareRingEntryRelay`, `prepareRingTransferRelay`, `prepareRingExitRelay`
and `prepareRingWithdrawalRelay` take the quote of `RingRpc.getRelayQuote`,
the nullifier key and the sender's signer, as `anonymous` on an anonymous Ring
and as `confidential` on any other, and `relay.send` hands the spend to Ring
RPC. On an anonymous Ring they also take the sender's `ViewingHistory`.
`PreparedRingDeposit.prepareRelay` relays a deposit, whose message the
depositor signs, and `prepareRingMergeRelay` relays a merge of the wallet's
smallest notes. `RingRpc` reads
decrypted Ring transactions for a granted reader.

Connect to a hosted Ring RPC with its service base URL and your API key:

```ts
import { RingRpc } from "@heliuslabs/zolana-custom-rings";

const ringRpc = new RingRpc("https://gateway.example/v1/zolana/ring", {
  apiKey: "YOUR_HELIUS_API_KEY",
});
const health = await ringRpc.health({ timeoutMs: 10_000 });
```

Use the gateway URL supplied by your operator. Pass the base URL once; calls
append `/health`, `/ringStatus`, or the other method name. A URL containing
`?api-key=...` also works, but supplying the key both ways is a
`RING_RPC_CONFIG` error. Keys must be nonempty, well-formed Unicode without
control characters and at most 4,096 UTF-16 code units. `ringRpc.url` omits
the API key, and transport errors omit credentials and response bodies.

For a local service, opt into HTTP explicitly:

```ts
const localRingRpc = new RingRpc("http://127.0.0.1:8785", {
  allowInsecureHttp: true,
});
```

Every call accepts a `RequestContext` with `signal` and `timeoutMs`. An API
key grants gateway access; reading decrypted transactions still requires a
granted reader's signature, and creating an auditor key requires the ring
authority's signature. A proxy must forward method paths and preserve the
JSON-RPC body; the server rejects a path/body mismatch with `-32601`.
See [server operation](../../services/ring-rpc/README.md#operation) for the HTTP
path and proxy requirements.

A deploy that fails after its buffer exists names the buffer in the
`RING_DEPLOY_PROGRAM` error details. Pass the same buffer keypair again to
resume, or reclaim its rent with `closeBufferInstruction`.

The deploy path is tested on Agave 4.0.2. The shipped Ring binaries are
SBPF v0 and do not load on Agave 4.1.2.

Passkey access to Ring audit traces uses `P256ReaderKey`.

The live ring controls test is described in
[test/e2e/RING-CONTROLS.md](test/e2e/RING-CONTROLS.md).

## Entry points

`@heliuslabs/zolana-custom-rings` exports the whole surface.
`@heliuslabs/zolana-custom-rings/client` narrows it to the Ring prover
requests, the client ports and `CustomRingClient`, and
`@heliuslabs/zolana-custom-rings/keypair` to the auditor envelope helpers.
