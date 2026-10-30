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
refuses a prover that does not serve a pinned Ring key or serves another
digest. Run it before the first Ring proof. A Helius mainnet or devnet RPC URL
selects the pinned Nitro Enclave prover of that cluster when `proverUrl` is
omitted.

`syncRingWallet` runs `syncWallet`, then opens the confidential Ring notes and
Ring deposits it skips into the wallet. Keys that are also `RingKeys` open
delivered notes too. An audited Ring deposit opens through its capsule:

```ts
import { createCustomRingClient, syncRingWallet } from "@heliuslabs/zolana-custom-rings";

const client = await createCustomRingClient({ solanaRpcUrl });
await syncRingWallet({ client, wallet, keys });
```

Ring projection errors, such as a storage registry the indexer has not caught
up with, are `RingError` codes. The flows retry the transient ones.

## Custom Rings

Besides the permissionless default Ring, regulated entities can create custom Rings.
Custom Rings are simple Solana programs for compliance and policy control. Each Ring deploys its own program. It has a program
upgrade authority, four role keys (admin, policy, pauser and co-signer admin), and an auditor key. The default Ring does not have an auditor key.

The auditor key lives in a Ring RPC. The Ring's policy authority grants view access.
Helius can host that RPC; the authority can host it itself. The forester is
shared with the default Ring.

A Ring is confidential or anonymous. A Ring is audit-only or carries a
policy, a rule table over the list bits of the member records in the Ring's
storage registry. The tier is fixed when the Ring account is created.

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

A wallet sends its operations through the Ring RPC relay by default, or
proves and sends them itself.

Through the relay the wallet reads no Merkle path and no record.
`prepareRingEntryRelay`, `prepareRingTransferRelay`, `prepareRingExitRelay`
and `prepareRingWithdrawalRelay` take the quote of `RingRpc.getRelayQuote`,
the nullifier key and the sender's signer, as `anonymous` on an anonymous Ring
and as `confidential` on any other, and `relay.send` hands the spend to Ring
RPC. On an anonymous Ring they also take the sender's `ViewingHistory`.
`PreparedRingDeposit.prepareRelay` relays a deposit, whose message the
depositor signs, and `prepareRingMergeRelay` relays a merge of the wallet's
smallest notes. `RingRpc` reads
decrypted Ring transactions for a granted reader.

Without Ring RPC the `CustomRingClient` reads the records and Merkle paths
from the indexer and proves, and the wallet signs and sends from a fee payer
it chooses. `createRingTransferSubmission`, `createRingExitSubmission`,
`createRingEntrySubmission`, `createRingWithdrawalSubmission`,
`createRingDepositSubmission`, `createRingMergeSubmission` and
`createRingDelegateSubmission` return a `RingTransactionSubmission`, and its
`send` takes the transport of `createKitRingSubmissionTransport`. A rejected
proof whose root left its registry proves again under the live root. A spend
with `inProofOwner` signs inside the proof, spends ring notes only, and only
the fee payer and a demanded co-signer sign the transaction. Without it each
input owner signs. A withdrawal creates its recipient's missing associated
token account in the same transaction. On an anonymous Ring a spend
takes `anonymous`, the hidden owner's signer and `ViewingHistory`, and the
wallet stores `viewingHistory` before `send`. The fee payer and any co-signer
must differ from the hidden owner. On every Ring they must also differ from the
owner of a merge. `CustomRingClient` proves SPP's anonymous rail, the rail of
an anonymous spend and of a spend with `inProofOwner`.
The `build*Transaction` functions return one unsigned transaction. A spend or
deposit on an anonymous Ring goes through its submission, which returns the
viewing history.

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

The deploy path is tested on Agave 4.2. The shipped Ring binaries are
SBPF v0 and do not load on Agave 4.1.2.

Passkey access to Ring audit traces uses `P256ReaderKey`.

## Entry points

`@heliuslabs/zolana-custom-rings` exports the wallet and operator surface, and
`@heliuslabs/zolana-custom-rings/advanced` adds the codecs, statements and
registry proofs the Ring circuits bind.
`@heliuslabs/zolana-custom-rings/client` narrows it to the Ring prover
requests, the client ports and `CustomRingClient`, and
`@heliuslabs/zolana-custom-rings/keypair` to the auditor envelope helpers.
