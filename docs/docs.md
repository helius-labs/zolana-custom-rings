# Custom rings

A custom ring is a Solana program that governs the zolana shielded notes tagged with its program id. The zolana shielded pool (SPP) holds the notes and moves one only when the ring program signs. The ring program signs after it verifies the ring's proofs of the move. [The spec](spec.md) defines every account, instruction and proof. The [policy walkthrough](policy-walkthrough.md) and the [anonymity walkthrough](anonymity-walkthrough.md) explain the policy proof and the anonymous rail, and [Reading the code](code-reading.md) gives an auditor a route through the source.

Each ring fixes three things when it is created: its auditor key, its tier, and whether it is confidential or anonymous. The auditor reads every transfer. A policy ring also screens every transfer against a rule table over its member lists. A confidential ring hides amounts and assets, and an anonymous ring also hides senders and recipients.

The operator runs the `zolana-ring` CLI from a `ring.toml`. Members pay through the CLI or the Rust and TypeScript SDKs. Two services run beside Photon, the zolana SPP indexer: the ring indexer serves member records, and Ring RPC holds the auditor key and serves readers.

## Development of a custom ring

1. **Configure the ring**
   1. Run `zolana-ring new` to write `ring.toml` and a program keypair.
   2. Choose the mode, confidential or anonymous. It is fixed once the config exists.
   3. Add a `[policy]` table for a policy ring, or leave it out for an audit-only ring.
2. **Deploy and initialize**
   1. `zolana-ring deploy` deploys the program under the upgrade authority.
   2. `zolana-ring init` fixes the auditor key, creates the config, the records and the policy, and registers the ring with SPP.
   3. SPP governance activates the ring unless its protocol config activates rings on creation.
3. **Operate**
   1. Write authority lists with `list add`, and point a list at a curator with `list set-source <list> --curator <id>`.
   2. Grant readers, set the co-signers, pause and resume.
   3. On a confidential policy ring, set a delegate to turn on key escrow.
4. **Build clients**
   1. Deposit into the ring with an audited deposit.
   2. Register the member's key on a key-escrow ring.
   3. Prove and submit transfers, exits, withdrawals and merges.
   4. Sync the wallet to find received notes.
5. **Audit**
   1. Ring RPC opens every transfer with the auditor key.
   2. Readers read audited history with a signed request.

## Glossary

| # | Term | Definition |
| --- | --- | --- |
| 1 | Ring program | The Solana program of one ring. Verifies its proofs and invokes SPP as its `ring_auth` PDA. |
| 2 | Ring note | An SPP note tagged with the ring's program id. Only the ring program moves it. |
| 3 | Default ring | The SPP notes of no ring. A transfer exits a ring by paying the default ring. |
| 4 | Tier | Audit-only or policy. Fixed when the config is created. |
| 5 | Mode | `Confidential`, `ConfidentialEscrow` or `Anonymous`. `ConfidentialEscrow` is `Confidential` with key escrow and a delegate. |
| 6 | Audit proof | Proves that the auditor key opens every output. Every transfer carries one. |
| 7 | Policy proof | Proves the rule table and outflow limits. Every transfer of a policy ring carries one. |
| 8 | Records | The ring's member records in its storage registry: one per owner or asset, with list bits, an escrow key and, for an asset, its mint settings. The chain holds the last 32 roots. |
| 9 | List | A record bit. The config authority writes allow, block, frozen, reader and approval. A member writes ring-viewing and recovery. |
| 10 | Rule | A list condition on the sender, every output owner or every output asset. |
| 11 | Outflow limit | A per-transfer cap and a co-signer threshold for one mint, stored in the mint's record. |
| 12 | Curator | A storage registry a policy reads for one or more lists. |
| 13 | Upgrade authority | The program's Loader v3 upgrade authority. Creates the config. |
| 14 | Config authority | Holds the config after `init`. Sets the policy, lists, readers, co-signers, pause and delegate. |
| 15 | Co-signer | A key with its own record and scope. One co-signer whose scope covers every class an operation demands signs it. A transfer that needs approval and demands no class takes any co-signer. A withdrawal below the mint's withdrawal threshold can skip it with an exemption proof. |
| 16 | Delegate | Moves escrowed members' notes inside a key-escrow ring without their signature. |
| 17 | Auditor key | The X25519 key every transfer's audit proof seals to. Ring RPC or a local file holds it. |
| 18 | Reader | An Ed25519 key or a P-256 passkey with a grant on the `reader` list of its record. Reads audited history from Ring RPC. |
| 19 | Ring address | An anonymous-ring payment address, the recipient's shielded address and the ring. A `zolana:` payment request adds the recipient's request tag. |
| 20 | Ring indexer | Serves member records and forwards every other call to Photon. |
| 21 | Ring RPC | Holds the auditor key and serves readers. |
| 22 | Hidden owner | The sender on an anonymous ring. It signs inside the SPP proof, so its key stays off chain. |
| 23 | Relayer | A key that pays and submits an anonymous transfer for the hidden owner. |

## Configuration

`ring.toml` names the ring, its program id, its authority keys and one URL set per cluster. `zolana-ring new` writes it. `mode` defaults to confidential and accepts `anonymous`.

```toml
name = "own-blocklist"
target = "localnet"
program_id = "71xpmf2e94nEd9T1S32trTQnhY39xfSUeNW7GH4quTw6"
authority_keypair = "~/.config/solana/id.json"

[localnet]
rpc = "http://127.0.0.1:8899"
indexer = "http://127.0.0.1:8784"
prover = "http://127.0.0.1:3001"
ring_rpc = "http://127.0.0.1:8785"

[devnet]
rpc = "https://api.devnet.solana.com"
indexer = "https://d2xah7tnhdhcom.cloudfront.net"
prover = "https://d55y5ksdsm1vw.cloudfront.net"
ring_rpc = "https://d24brah9h1i4q9.cloudfront.net"
ring_rpc_pubkey = "C8TeRCdueRdXj3y4uFDtNywYThc3qeiH2ZGfcbYZzVSs"

[policy]

# each output owner must not be on the block list
[[policy.rules]]
subject = "output-owner"
forbid = "block"
```

- `authority_keypair` signs for both authorities. `upgrade_authority_keypair` and `config_authority_keypair` split them.
- Both cluster tables are required. `indexer` names the ring indexer, which forwards Photon calls.
- `ring_rpc_pubkey` pins the Ring RPC service key per cluster. A pin always wins. Without one, `init` accepts a Ring RPC key only with `--trust-ring-rpc`.
- The presence of `[policy]` selects the policy tier. An empty `[policy]` is a policy ring with an empty table, and every transfer still proves it.
- `[cosigner]` holds `key`, `scope` and `thresholds` for `cosigner set` without flags. The thresholds go to the mints' records.
- A `.env` beside `ring.toml` fills `${NAME}` in the URL keys.

Readers and the delegate have no `ring.toml` key. They live on chain and change through CLI commands.

## Policy

A rule names a `subject` and exactly one of `require`, `forbid` or `any`:

- `output-owner` screens every output owner: payments, change, exits to the default ring and withdrawal owners.
- `sender` screens the transfer's single sender.
- `asset` screens every output's asset and every withdrawn asset. Input assets are never screened.

`require = "allow"` admits a subject on the list. `forbid = "block"` admits a subject off the list. `any` admits a subject that one of its parts admits. Rules join with AND. A rule reads only authority lists, so a member cannot admit itself.

```toml
# each output owner must be on the approval list or must not be on the block list
[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]

[policy.sources.localnet]
# the block list reads the records of the named curator ring
block = "Gy3wjbn1MpGvJNrjinhWuSzLsp7HLazpmbQynmmMd91Z"
```

A guard exempts small amounts. `above = <amount>` on an output-owner or asset rule exempts a subject whose payments in the transfer sum to at most the amount. On an output-owner rule it also requires every output of the transfer to carry one mint. `limits = [{ asset, above }]` on an output-owner rule sets that bound per mint in the mint's record, and a transfer that pays any other mint fails.

```toml
# each output owner must be allowed above the limit for that output's mint
[[policy.rules]]
subject = "output-owner"
require = "allow"
limits = [
  { asset = "11111111111111111111111111111111", above = 1000000000 },
  { asset = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", above = 1000000 },
]
```

Outflow limits bound what one transfer sends away from its sender in one mint. A transfer fails above `cap`, and needs a co-signer above `cosign_above`. Zero turns either off. The zero address names SOL. The table holds rules only. The CLI writes every mint's threshold, `cap` and `cosign_above` into that mint's record in the ring's own registry, so the number of mints has no table limit.

```toml
[policy]
limits = [
  { asset = "11111111111111111111111111111111", cap = 5000000000, cosign_above = 1000000000 },
]
```

Change to the sender's own ring identity is not outflow. A deposit leg in the same transfer offsets it, and a deposit larger than the outflow of a limited mint fails. The limit holds per transfer and per signing key, and keeps no window.

`zolana-ring policy check` compares `ring.toml` with the pinned table and the mint records on the target cluster. `new --policy-from` compiles a table for both clusters. `policy set --yes` repins it, which makes every proof over the old table fail, and then sends the changed mint records to Ring RPC in one record update. It keeps each mint's withdrawal threshold.

## Operator CLI

The CLI runs from the directory of `ring.toml`. Every command names its target cluster through `target` or `--target`.

```bash
zolana-ring new my-ring --policy-from examples/own-blocklist/ring.toml
cd my-ring
zolana-ring localnet
zolana-ring deploy
zolana-ring init
zolana-ring list add block --owner <ADDRESS>
zolana-ring reader grant <SOLANA_KEY>
zolana-ring cosigner set --signer <KEY> --scope transfers,withdrawals --threshold sol=1000000000
```

- `localnet` loads the storage program at `STORAGE_PROGRAM_ID` at genesis, from the release or from the workspace build.
- `deploy` deploys the released program of the embedded release lock, or `--program-so`. It refuses a binary whose verifying key markers do not cover every pinned proving key, and an existing program under another upgrade authority.
- `deploy` does not deploy the storage program. No keypair exists for `STORAGE_PROGRAM_ID`, and only a validator that loads it at genesis has it.
- `init` skips every step the chain already agrees with. The upgrade authority signs `Initialize` and, when the two keys differ, hands the config to the config authority with `UpdateAuthority` in the next transaction.
- `init` takes the auditor key from Ring RPC when no config and no `keys/auditor.key.pub` exist, and checks the service signature. With a hosted Ring RPC, `--local-auditor` pins `keys/auditor.key.pub` instead.
- `cosigner set` creates or rescopes the signer's co-signer record, then writes its withdrawal thresholds into the mints' records and clears the others. `cosigner clear` closes the signer's record and keeps the mint records.
- `list add` and `list clear` write authority lists, and `list join` and `list leave` write the member's own lists, each through a record update Ring RPC applies.
- `reader grant` and `reader revoke` set and clear the `reader` list of the reader's own record.
- `delegate set --delegate-keypair <FILE>` turns a confidential policy ring into a key-escrow ring for good. SPP governance must enable the ring's authority rail, the SPP rail a delegate move runs on, before `delegate move` runs.
- `authority transfer` moves the upgrade authority without the new key's signature. `authority transfer-config` moves the config authority, and both keys sign.
- `--fee-payer-keypair` pays member operations of an anonymous ring. The CLI refuses it when it equals the hidden owner.

## Client

1. Read the ring config and check that SPP activated the ring.
2. Deposit: the SDK seals each new note to the auditor and proves the deposit, or the Ring RPC relay proves it.
3. On a key-escrow ring, register the member's key and wait for the record update to apply.
4. Transfer: the SDK reads the policy and the records, proves the SPP, audit and policy proofs together, and builds one instruction. When only the withdrawal class demands a co-signer and every withdrawn mint stays within its withdrawal threshold, it adds a withdrawal exemption proof, and no co-signer signs. A relayed transfer sends its proof inputs to Ring RPC, which reads the records, proves and sends.
5. Submit: the SDK re-proves when a root or the policy moved before the transfer landed. A relayed transfer that misses its blockhash fails.
6. Sync: the wallet finds received notes by its tags and opens them.

### TypeScript

`@heliuslabs/zolana-custom-rings` pins its `@heliuslabs/zolana` peer to one version. A wallet deposits, transfers and merges through Ring RPC and reads no Merkle path and no record. `requiredEnv`, `signSendAndConfirm`, `sendInstruction`, `currentSlot` and `ringReadTarget` are test helpers, and `sender`, `member`, `recipient` and `actor` are test wallets with `signer`, `keypair`, `wallet` and `keys`.

```ts
const client = await createCustomRingClient({
  solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
  indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
  proverUrl: requiredEnv("ZOLANA_PROVER_URL"),
  tree: address(requiredEnv("ZOLANA_TREE")),
});
const config = await fetchRingProgramConfig(client, ringProgramId);
const ringRpc = new RingRpc(requiredEnv("RING_RPC_URL"), { allowInsecureHttp: true });
```

Deposit. Ring RPC proves the deposit with its audit proof and returns the message the depositor signs.

```ts
const deposit = await PreparedRingDeposit.prepareRelay({
  client,
  ringProgramId,
  depositor: sender.signer,
  recipient: { kind: "confidential", address: sender.keypair.shieldedAddress() },
  amount: DEPOSIT,
  quote: await ringRpc.getRelayQuote({ ring: ringProgramId, operation: "deposit" }),
});
const sent = await deposit.relay.send(ringRpc);
if (sent.step === "signMessage") await sent.sign(ringRpc, sender.signer);
```

Register the member's nullifier key on a key-escrow ring through a record update. `target` is the `RecordUpdateTarget` of the ring's records:

```ts
const nullifierKey = member.keypair.nullifierKey();
const escrow = new NullifierKeyEscrow(nullifierKey, client);
try {
  const entry = await new KeyRegistration({
    ringProgramId,
    member: member.keypair.shieldedAddress(),
    authority: escrow,
  }).prove(client);
  const update = await new WalletRecordUpdate({ ...target, wallet: member.signer.address })
    .withEscrow(entry)
    .sign(member.signer);
  await ringRpc.submitRecordUpdate(update);
} finally {
  escrow.destroy();
  nullifierKey.destroy();
}
```

Transfer on a confidential ring. The sender signs the message hash inside the proof, and Ring RPC pays, co-signs and sends.

```ts
const transfer = await prepareRingTransferRelay({
  client,
  ringProgramId,
  wallet: sender.wallet,
  keys: sender.keys,
  recipient: recipient.keypair.shieldedAddress(),
  amount: PAYMENT,
  confidential: {
    quote: await ringRpc.getRelayQuote({ ring: ringProgramId, operation: "confidential" }),
    nullifierKey: sender.keypair.nullifierKey(),
    signer: messageSignerSpendSigner(sender.signer),
  },
});
const relayId = submittedRelay(await transfer.relay.send(ringRpc));
```

`prepareRingExitRelay` pays the default ring and `prepareRingWithdrawalRelay` withdraws to a Solana account. `RingRpc.getRelayStatus(relayId)` follows the relay. `prepareRingMergeRelay` merges the sender's notes.

Sync confidential ring notes into the wallet:

```ts
await syncRingWallet({
  client,
  wallet: actor.wallet,
  keys: ringWalletKeys(actor.keys, LocalRingKeys.fromKeypair(actor.keypair)),
  config: { requireSlot: await currentSlot(client) },
});
```

Read audited history from Ring RPC after an `AuthorityRecordUpdate` puts the reader on the `reader` list:

```ts
const target = await ringReadTarget(ringRpc, ringProgramId);
const ringView = await ringRpc.getDecryptedTransactions({
  target,
  signer: messageSignerReader(authoritySigner),
});
```

`target.service` is the service key. Take it from a pin, not from the service's own `health` answer, in production.

### Rust

`custom-ring-sdk` drives the same flows through one pipeline with three rails. Every call is async and takes a `RingClient`. The examples come from `program-tests/custom-ring`, where `env.run` blocks on a future, `env.client` is the CLI's `Zolana` client, `land` signs and settles a submission, and `env.member_record` reads a record through `MemberRecords`.

```rust
let native = RingClient::new(
    AsyncZolanaClient::new(
        AsyncSolanaRpc::new(env.rpc_url.clone()),
        AsyncZolanaIndexer::new(env.indexer_url.clone()),
        AsyncProverClient::local(),
    ),
    AsyncProverClient::local(),
);
```

Deposit:

```rust
let deposit = RingDeposit {
    ring,
    payer: &deposit_source,
    recipient: DepositRecipient::Confidential(sender_address),
    tree: env.tree,
    asset: DepositAsset::Sol,
    amount,
    cosigner: None,
};
let RingDepositReceipt { utxo, .. } =
    env.run(deposit.send_with_fee_payer(env.client.ring_client(), sender))?;
```

Register a key through a record update, `target` the `RecordUpdateTarget` of the ring's records:

```rust
let registration = env.run(
    KeyRegistration {
        ring,
        member: member.shielded_address()?,
        authority: member,
    }
    .prove(env.client.ring_client()),
)?;
let update = WalletRecordUpdate::new(target, member.pubkey())?
    .with_escrow(registration)?
    .sign(member)?;
```

`RecordUpdateService::submit_record_update` sends the signed update to Ring RPC.

Transfer on a confidential ring:

```rust
let mut prepared =
    ConfidentialTransaction::new_with_ring(inputs, sender.pubkey(), ring_program)?;
prepared.transfer_sol(
    &env.recipient.keypair.shielded_address()?,
    RING_TRANSFER_AMOUNT,
)?;
let transfer = CustomRingTransfer::new(CustomRingTransferInput {
    ring,
    sender,
    nullifier_key: Some(&sender.nullifier_key),
    transaction: prepared,
});
let proven = env.run(transfer.prove(env.client.ring_client()))?;
```

`proven.instruction()` builds the instruction, and `RingSubmission::new(op).send_until_settled` signs, sends and re-proves on a stale root. The zolana `ConfidentialTransaction` builds the outputs: `transfer_with_ring(.., None)` pays the default ring, `withdraw` and `withdraw_sol` add a public leg, and `with_interface_transfer_accounts` names its settlement accounts.

Transfer on an anonymous ring. The recipient shares its ring address or a payment request, and `first_contact` picks the bootstrap tag or the request tag until the pair is known ([Anonymity walkthrough](anonymity-walkthrough.md#first-payment)). The transaction names the relayer as payer:

```rust
let transaction = ConfidentialTransaction::new_with_ring(
    self.inputs,
    self.payer.pubkey(),
    self.ring.program_id(),
)?;
CustomRingTransfer::new(CustomRingTransferInput {
    ring: self.ring,
    sender: self.sender,
    nullifier_key: Some(&self.sender.nullifier_key),
    transaction,
})
.with_anonymous_signer(&self.sender.signing_key, self.history)
.with_payment(custom_ring_sdk::AnonymousPayment {
    to: self.to,
    first_contact: self.first_contact,
    asset: Mint::SOL,
    amount: self.amount,
})?
.with_shape(shape)?
```

`transfer.viewing_history()` is the sender's history past the transfer's tags, stored before the transfer is sent. `AnonymousSync::new(keys, &assets).fetch(indexer, &history)` finds received notes and returns the raised history.

Merge on any ring. On a key-escrow ring the owner's record must escrow the nullifier key:

```rust
let prepared = CustomRingMerge::new(ring, merged_inputs.clone(), None)?
    .with_output_tree_id(tree_id)
    .encrypt(&env.recipient.keypair)?;
let merge = RingMergeOperation::new(
    prepared,
    MergeProofInput {
        nullifier_key: env.recipient.keypair.nullifier_key.clone(),
        input_tree: env.tree,
        output_tree: env.tree,
        co_signer: None,
    },
);
```

Delegate move on a key-escrow ring. The auditor opens the member's escrowed nullifier secret, and the delegate signs:

```rust
let escrowed = read
    .escrowed(&member_address.nullifier_pubkey)?
    .context("the record escrows the member's nullifier key")?;
let nullifier_key = escrowed.sealed.open(&auditor)?;
let proven = DelegateTransfer::new(DelegateTransferInput {
    ring,
    delegate: delegate.pubkey(),
    payer: env.payer.pubkey(),
    source: member_address,
    source_nullifier_key: &nullifier_key,
    inputs: vec![moved],
    outputs: vec![DelegateOutput {
        recipient: member_address,
        asset: SOL_MINT,
        amount: SEND,
    }],
})
.with_assets(&env.assets);
let proven = env.run(proven.prove(env.client.ring_client()))?;
```

`RingScan::new(program_id, auditor_pk).audit(&auditor, indexer, origin, &assets)` opens audit pages with a local auditor key. `RingRecovery::new(program_id, &auditor).for_member(SourceMember { address, nullifier_key }).run(indexer, rpc, &assets)` rebuilds a member's notes.

## Services

The ring indexer projects storage registries from Solana and forwards every other call to Photon. Point clients and the prover at it, so ring and Photon calls go to one URL. `indexer` in `ring.toml` names the ring indexer, and the ring indexer names Photon with `--photon-url`. The example runs them on two ports.

```bash
ring-indexer --db-url 'sqlite://ring-indexer.db?mode=rwc' --rpc-url http://127.0.0.1:8899 \
  --photon-url http://127.0.0.1:8784 --port 8786 --start-slot latest
```

- `--start-slot` is required on an empty index. A registry created before it is never indexed.
- The indexer trusts its Solana RPC for blocks and accounts. Clients check every opening against a root they read from the chain.
- It binds all interfaces without authentication. Put it behind the deployment's access control.

Ring RPC holds the auditor key. It runs with one key for one ring, or derives one key per ring from a root secret. The service key, the storage authority, the co-signer, the grant rows key and the fee payer each have their own key file.

```bash
ring-rpc keygen --out keys/auditor.key
ring-rpc keygen --kind service --out keys/service.key
ring-rpc serve --port 8785 --indexer-url <ring indexer> --rpc-url <solana> \
  --auditor-key-file keys/auditor.key --service-key-file keys/service.key --ring-program-id <id>
```

- `--indexer-url` must be the ring indexer. Ring RPC calls its record methods for key escrow and merge audits.
- A key file holds exactly 64 lowercase hex characters, owner-only. `keygen` writes it that way.
- `serve` refuses to start when two roles share one key, or when a feature it turns on has no key file.
- The service binds loopback unless `--insecure-public-bind` is set. Passkey readers need `--allow-origin` and `--webauthn-rp-id`.
- Nonces and rate windows live in memory. Run one process per key.

## Limitations

1. **Confidential rings name their parties:** the sender signs and each ring output publishes the recipient's viewing key, which the zolana user registry maps to its Solana key. Use an anonymous ring to hide them.
2. **Anonymity needs a relayer and request tags:** the payer and fee payer must not link to the owner, and a first payment under the bootstrap tag publishes the recipient's viewing key. A default-ring spend, an exit or a withdrawal to a linked key ends the anonymity of that transfer.
3. **Outflow limits bound one transfer:** the proven `cap` and `cosign_above` count no other transfer. Only the Ring RPC co-signer counts windowed caps from the mint's `AssetLimits`, on transactions that demand its signature.
4. **Deposits screen assets only and merges screen nothing:** rules screen the sender and the outputs of each transfer, a deposit only its assets. A key-escrow ring refuses a deposit to or a merge of an owner without an escrowed key.
5. **Key escrow and the delegate are permanent:** a registered key cannot change, and nothing removes a delegate.
6. **Records are public:** every list write names its member. On an anonymous ring a member's own list write publishes its Solana key.
7. **The auditor reads everything:** a reader grant has no scope or expiry.
8. **TypeScript anonymous spends go through Ring RPC:** the pinned TypeScript prover has no anonymous spend proof, so the TypeScript SDK spends an anonymous ring through the Ring RPC relay, which receives the nullifier key and proves the spend. Use the Rust SDK or the CLI to prove locally.
9. **Single-party setup:** the ring's proving keys come from one gnark setup. Trust the key generator as you trust the upgrade authority.
