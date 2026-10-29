# Ring RPC

Ring RPC holds an auditor viewing key and opens custom ring transfer outputs. It reads ring transactions from Photon and checks reader grants in the ring's storage tree or in its own database.

## Keys

Local mode serves one ring with one auditor key file. Generate the key before ring config creation.

```bash
cargo run -p zolana-ring-rpc -- keygen --out keys/auditor.key
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --auditor-key-file keys/auditor.key \
  --ring-program-id <program-id>
```

The command writes the secret with owner access only. It writes the X25519 public key to `keys/auditor.key.pub`.

Derived mode serves a stable key for each ring and cluster, for as many rings as ask. Generate a root secret with `keygen --kind root`. Protect one root as carefully as all keys derived from it. The key comes from the root, the cluster genesis hash and the ring program id, so a new ring needs no configuration, no restart, and nothing stored. Repointing the service at another cluster changes every derived key and orphans every ring already registered.

A relay pays fees with its own Ed25519 key, apart from the auditor and service keys. Generate it with `keygen --kind fee-payer`, fund it, and pass it with `--fee-payer-key-file`, a `--store-url` for the relay records and the ring prover's `--prover-url`. The service refuses a fee payer key equal to its service key.

A ring must take its auditor key from the service before it creates its config. The config fixes the auditor for the life of the ring, so a ring registered with any other key can never be read here, whatever the service derives for it. `ringStatus` reports which of the three cases a ring is in.

`createAuditorKey` answers only a request signed by the authority the ring's config names, or, while no config exists, by the program's Loader v3 upgrade authority. The signature binds the cluster genesis hash, the ring, a Unix timestamp and a random nonce. The service reads the authority from the chain on every request and accepts a nonce once. `ringStatus` and `health` never return the key the service holds, only the key the config already publishes. The response carries a service signature over the cluster, the ring, the auditor key and the request nonce. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode and service public key |
| `createAuditorKey` | Ring program ID and authority authorization | Auditor key and service attestation |
| `ringStatus` | Ring program ID | Whether the ring's config names the key held here (`served`), another one (`foreignAuditor`), or does not exist yet (`uninitialized`), with the config's key when it exists |
| `ringDeposits` | Ring program ID, examined signature limit, and page cursor | The deposits found, the next cursor, and the oldest slot examined |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |
| `getAuditedMerges` | Ring, page, and read authorization | Hash-checked merge openings and unresolved outputs |
| `getAuditedUtxos` | Ring, 1 to 100 UTXO hashes, and read authorization | `utxos`, in request order, the opening of each hash the service opened, `null` for any other |
| `setReaderGrant` | Ring, optional wallet, reader, `grant` or `revoke`, timestamp, nonce, and the signature of the wallet or, without one, of the config authority | The action the service holds for the grant |

`ringDeposits` walks ring history backwards from the newest signature. A deposit publishes its asset and amount, so the method needs no auditor key and no read authorization. Its `limit` counts signatures examined rather than deposits found, so a page can hold no deposits and still have history behind it. The default limit is 50 and the service clamps it to 200.

The response `cursor` is opaque and goes back in the next request. It is present while older ring history remains and absent at the end, so a client pages until it is absent. `oldestSlot` reports the slot of the oldest signature the page examined, absent when the page examined nothing. A client that merges deposits with another paginated stream needs `oldestSlot` to know how far back an empty page reached.

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the method, cluster, service key, ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

The authority authorization contains the authority address, the cluster genesis hash, Unix timestamp, random nonce, and a raw Ed25519 signature over the attestation bytes. Both authorizations share the timestamp skew and the per-ring nonce set.

The onchain auditor public key must match the auditor key held by Ring RPC.

## Reader grants

`--reader-grants` selects the one store the service reads grants from, `tree` by default or `database`.

In `tree` mode a reader holds its grant in the ring's own storage tree, the `StorageRegistry` its ring policy names. The service opens the reader's records through the indexer and checks each opening against the newest root the policy mirrors. A ring-wide grant is the `Reader` list on the reader's own record. That record belongs to the owner identity of an Ed25519 reader, or to the `hash_bytes` of a passkey's tagged key. A wallet grant is the `Reader` list on the record `Member::wallet_grant(wallet, reader)`. The config authority has no implicit access. A ring with no policy, or whose policy mirrors no root of its own registry, refuses every read with `-32130`. In this mode `setReaderGrant` answers `-32131`.

A read that names a `wallet` returns only the rows where that wallet is the sender, a signer or an output owner, the merges it owns and the notes it owns, and no skipped rows. A ring-wide grant covers every wallet, a wallet grant only its own wallet. The wallet joins the signed attestation as a last `wallet:` line, and a read without one signs no such line.

In `database` mode, which needs `--store-url`, the service keeps both grants in its own database and never reads the storage tree for a grant, so a ring whose policy mirrors no root still serves its readers. `setReaderGrant` writes a wallet grant under the wallet's raw Ed25519 signature, and a ring-wide grant, which names no wallet, under the signature of the authority the ring config names. The signature covers `zolana/ring-rpc-reader-grant/v1`, the cluster, service, ring, the wallet when named, reader, action, timestamp and nonce, under the skew and nonce set of a read. Each accepted call appends one row, sealed with AES-256-GCM under a key HKDF-SHA256 derives with `zolana/ring-rpc-grant-rows/v1` from the auditor key in local mode or the root secret in derived mode. Beside its insert id, a row keeps in plaintext only the HMAC-SHA256 of the reader key under the same derivation, also the associated data. The row with the latest signed timestamp holds, the later write on a tie. A ring-wide row holds for every wallet. The record writer refuses an update that writes or awaits a `reader` list with `-32230`, because no read checks it. Write access to the database can drop a revocation row, so protect it like the service key.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

Accepted nonces are held in process memory for the timestamp window. Run one process for each service key. Multiple replicas need a shared nonce store before they can use the same key.

## Relay, record updates and merge settings

`zolana_ring_client::rpc` defines these methods and the TypeScript SDK mirrors them in `protocol/ring-rpc`. The service answers the record update methods through its [record writer](#record-writer), the four relay methods and `prepareAuthorityTransfer` when it runs with a fee payer key, and `setMergeSettings` with a store.

| Method | Request | Result |
| --- | --- | --- |
| `getRelayQuote` | Ring and relay operation | `feePayer` and `validUntilSlot` |
| `prepareRelay` | Ring, the quote, and the `intent` with the rail's proof inputs | A `RelayStep`, `submitted` or `signMessage` with the v1 message to sign |
| `submitRelay` | `relayId`, signer and its signature over that message | `RelayStatus` |
| `getRelayStatus` | `relayId` | `RelayStatus`, one of `awaitingSignature`, `sent`, `confirmed` or `failed` |
| `submitRecordUpdate` | Storage registry, the update, signer and signature | `updateId` |
| `getRecordUpdateStatus` | `updateId` | One of `awaitingAuthority`, `queued`, `submitted`, `applied` with the new revision, or `refused` |
| `getPendingEnrolments` | Ring, an optional `cursor` and the config authority's authorization | One page of the enrolments that await the config authority, oldest first, after `cursor`, with `nextCursor` on every page but the last |
| `refuseEnrolment` | Ring, `updateId` and the config authority's authorization | The `refused` status |
| `createRecordsRegistry` | Ring and the config or upgrade authority's authorization | The ring's records `registry` and the writer's `storageAuthority` |
| `setMergeSettings` | Ring, owner, the settings, timestamp, nonce and signature | The stored settings |
| `prepareAuthorityTransfer` | Ring, delegate, the transfer, timestamp, nonce and signature | A `RelayStep`, `signMessage` until the delegate signs |

The relay operation is `anonymous`, `confidential`, `delegate`, `deposit` or `merge`. The quote names the fee payer the relay signs with and the last slot it takes the request, at most 150 slots ahead. On the anonymous and confidential rails the intent carries the owner's Ed25519 signature over `SppProofInputs::message_hash`, and the service refuses a request it does not verify before it proves. On the anonymous rail that signature authorizes the spend inside the proof and `prepareRelay` answers `submitted`. The ring program checks a confidential owner as a transaction signer, so on the confidential rail, as on the delegate rail, it answers `signMessage` and each owner or the delegate signs the returned message for `submitRelay`. The service sends once the message carries every signature, the co-signer's included. On the deposit rail it answers `signMessage` and the depositor signs the returned message to fund its SOL or SPL transfer. It refuses a depositor that is the relay fee payer. On the merge rail it answers `submitted`, no wallet signs the merge. A transfer intent may name `tokenAccountSetup`, each entry the owner and mint of an associated token account a withdrawal pays. The service puts an idempotent create, funded by its fee payer, ahead of the transfer, and refuses an entry no withdrawal of its mint pays or an entry that repeats one. The proof inputs carry no Merkle path and no record opening, the service reads those. `relayId` is the SHA-256 of the domain `zolana/ring-rpc-relay/v1` and the request's JSON as the service serializes it, so a retried request names the same relay.

A relay record keeps the message, the collected signatures and the status, never the proof inputs. A repeated `prepareRelay` returns the stored step and proves nothing again. A tracker moves every pending relay on every two seconds, so a restart between send and confirmation resumes. A relay that has not landed by the last valid block height of its blockhash fails, and the co-signer frees what it reserved for it. Relay errors take codes `-32100` to `-32113`, in order: ring not relayed, quote fee payer, quote expired, quote window, invalid proof inputs, ring mismatch, rail mismatch, owner signature, refused transfer, co-signer refusal, unknown relay, unexpected signer, signer signature and cluster refusal. `-32200` refuses a token account setup and `-32201` a depositor that is the fee payer.

`proofInputs` is the base64 of one `RelayProofInputs` in wincode, enum tags and vector lengths in one byte and byte strings with a two byte length. It holds the sealed transfer: the rail, the ring program id, the sender's shielded address, its nullifier secret, the transaction viewing secret, the ephemeral secret that sealed the auditor message, every input opening, the outputs, the external data with its auditor message, the blinding seed and the output tree id. An anonymous rail adds its view tag plan and an optional exit token owner, a delegate rail the delegate. An input opening is a spend of the sender, a dummy or compact padding, and the service derives every input hash and nullifier from it. Each interface transfer is a withdrawal, an SPL one names its token program. The service is trusted with these secrets, it proves with them and keeps none past the relay. `test-vectors/rpc/relay_proof_inputs.json` pins the bytes.

A deposit's `proofInputs` is one `RelayDepositInputs`: the ring, the tree, the depositor, the recipient's shielded address, the SOL or SPL settlement, the amount, the view tag, the encrypted deposit data with the auditor capsule, the blinding secret and the capsule's ephemeral secret. The service derives the owner commitment from the blinding secret and checks the ephemeral secret against the capsule. A merge's `proofInputs` is one `RelayMergeInputs`: the ring, the owner's shielded address, its nullifier secret and the notes as spend openings with their leaf indexes. The service derives the merged note from the nullifier secret.

A record update names the cluster genesis hash, a ring, its entries, `validUntilSlot` and, for an enrolment, `awaitedLists`. An entry is a `write` of masked lists with optional mint settings, an `escrow` registration with its register key proof, or a `walletGrant` that sets or clears the reader list of the record `Poseidon(CRWG, wallet, reader)`, with the `wallet` and `reader` identities and `access` of `granted` or `revoked`. The signer signs the 32 bytes of `Poseidon(CRRU, hash_bytes(genesisHash), hash_bytes(ring), hash_bytes(registry), entries_hash, validUntilSlot)`, where `entries_hash` folds `queue_chain` over the entries from a zero start. An enrolment appends `awaitedLists` as a seventh element. That hash is the `updateId`.

Merge settings name a mint, a target note count and a minimum average amount. The owner signs them under `zolana/ring-rpc-merge-settings/v1` with the cluster, service, ring, timestamp and nonce of a read authorization.

## Authority transfer

The ring delegate moves a wallet's notes to recipients in the same ring without the wallet. The transfer names the source's shielded address, a mint and its payments, each a recipient shielded address and an amount, all addresses as base58 text. The delegate signs it under `zolana/ring-rpc-authority-transfer/v1` with the cluster, service, ring, delegate, source, mint, one `payment:` line per payment in order, timestamp and nonce, under the skew and nonce set of a read.

The service checks the signature under the named delegate, that the ring config names that key its delegate, and that the config is `ConfidentialEscrow` under the auditor key held here. It opens the source's escrowed nullifier secret with the auditor key and checks it against the source address's nullifier key. The notes it opened for the source under that key and mint, with no data and no nullifier the ring history published, fund the move. The ring SDK picks the fewest notes of one tree, returns the change to the source, encrypts the outputs to their owners and the auditor, and seals the move for the relay's delegate rail. The seal names no co-signer, so a ring that demands one refuses the move. The relay proves it with its policy and escrow checks and stores it under `relayId`, the SHA-256 of the relay domain and the request's JSON, so a repeated request returns the stored step. The delegate signs the returned message through `submitRelay`, and the relay pays, sends and tracks it. The backfill indexes the spent inputs and the new outputs. The secret stays in memory for the request, and the service never logs, stores or serves it.

Errors are `-32220` the signer is not the ring delegate, `-32221` the ring escrows no key to the service, `-32222` the source escrows no nullifier key, `-32223` the source address names another nullifier key, and `-32224` the service runs no relay.

## Record writer

`--store-url` turns the record writer on. The store takes a `postgres://` or `sqlite://` URL. The writer proves every storage update, so the service refuses to start with a store and no `--prover-url`, or with a prover and no store. The prover must serve the ring apply keys.

The writer signs and pays for every storage update with its storage authority key. The key derives from the auditor key file or the root secret under its own domain, apart from the service key, and the service logs its address at start. Fund it before the first ring. A registry the writer serves names the key as its authority, and the ring policy account names the registry as its records.

`createRecordsRegistry` creates a ring's records, the `StorageRegistry` of the storage authority under the ring program id, and pays for them. The ring's config authority signs the request, or the program's upgrade authority while no config exists, over `zolana/ring-rpc-enrolment/v1` with the `action:` line `create records`. A repeated request returns the same registry. The service answers once the creation confirms and fails with `-32260` when it does not land. `zolana-ring init` binds these records at `Initialize` with the storage authority the answer names.

`submitRecordUpdate` checks the genesis hash against the service's cluster, the signature over the update statement, `validUntilSlot` against the current slot, and the registry against the ring. A wallet writes the `ring-viewing` and `recovery` lists of its own record, its own escrow registration and its own wallet grants. The ring config authority writes the `allow`, `block`, `frozen`, `reader` and `approval` lists and the mint settings of any record. An escrow registration names the signer's owner identity. The writer verifies its register key proof with the committed `RegisterKey` verifying key, over the register key statement it builds with the auditor key of the ring config. An anonymous ring takes no escrow registration. The writer refuses an escrow key for a member whose record holds one under the newest root the policy mirrors, or whose awaiting, queued or submitted update carries one. An escrow registration on a ring whose policy mirrors no own root fails with `-32130`. An update refused at submit is never stored. A resubmitted update returns its first `updateId`.

An enrolment is a wallet's update with nonzero `awaitedLists`, the record bits of the `allow`, `reader` or `approval` lists it needs. The writer refuses an enrolment from the config authority or one that awaits a list the ring policy does not read from its own records. It stores the enrolment as `awaitingAuthority`, and its escrow entry waits with it while it still counts toward the one escrow key a member holds. The config authority lists enrolments with `getPendingEnrolments`, at most `PENDING_ENROLMENTS_PAGE_LIMIT` a page, and passes the `nextCursor` of a page as the `cursor` of the next. It approves one by submitting its normal record update that sets every awaited list on the wallet's owner identity. That update queues with the enrolments it approves joined to it, and they go out in one batch, the enrolment writes first, or share its refusal. An approval that would carry more than 16 writes with its enrolments is refused at submit. `refuseEnrolment` turns an awaiting enrolment `refused`. Both methods take the config authority's raw Ed25519 signature over `zolana/ring-rpc-enrolment/v1`, the cluster, service, ring, authority, an `action:` line of `list`, `list after <cursor>` or `refuse <updateId>`, timestamp and nonce, under the skew and nonce set of a read. An enrolment still awaiting after its `validUntilSlot` turns `refused`, so a wallet gives it a window that leaves the authority time to act. The writer refuses an enrolment whose `validUntilSlot` lies more than `MAX_ENROLMENT_WINDOW_SLOTS` past the current slot. It holds any number of awaiting enrolments, and [rate limiting](#rate-limiting) bounds how fast a client or a key submits them. A submit reads only the awaiting enrolments of the members it writes.

Updates queue in submit order for each registry. One `Update` carries at most 16 writes and never splits an update. An urgent update sets `block` or `frozen`, clears `allow` or `approval`, or writes mint settings. Only the config authority writes these. Urgent and graced updates never share a batch. An urgent batch goes out at once and passes queued graced updates, unless one of them writes the same record. It goes out as `UpdateImmediate` and retires every earlier root when it revokes, else as a graced `Update`. A mint settings write revokes when it restricts, where a zero cap or co-sign bound is off. A graced batch goes out once it is full, its oldest update waited `BATCH_WINDOW_SLOTS`, or an urgent update waits behind it. A reader grant revocation, ring-wide or wallet, is graced, since the service checks grants against the newest mirrored root. A graced `Update` waits while the oldest retired root is unexpired. Each transaction also carries `SyncRoots` for every ring in the batch, so each ring policy account mirrors the new root in the same transaction.

The apply proof starts at the registry's current root from `getStorageApplyProofInputs`. The writer drops inputs at another revision or root, or for other writes, and retries on its next pass. It stores the batch and its signature before it sends the transaction, and one registry has at most one open batch. A restart settles that batch by its signature. A confirmed batch is applied, a failed one queues again, and an unknown one queues again once its blockhash can no longer land. An update turns `refused` after `MAX_BATCH_ATTEMPTS` batches that did not apply, or when it is still queued after `validUntilSlot`. Run one writer for each storage authority key.

On every pass the writer also reads each registry it applied a batch to and each `--watch-registry` curator registry. It finds every ring the shielded pool registered whose policy names that registry as a source, and sends `SyncRoots` to each whose curator mirror differs from the registry's roots. A curator update reaches a subscriber's transfers only after that sync.

The leaf commits only the hash of an escrow envelope. The ephemeral key and ciphertext stay in the stored request.

| Code | Refusal |
| --- | --- |
| -32140 | The service runs no record writer |
| -32141 | The update carries no entry or more than 16 |
| -32142 | An entry does not encode |
| -32143 | The signature does not verify |
| -32144 | The current slot is past `validUntilSlot` |
| -32145 | The ring has no config |
| -32146 | The registry is not the ring records under the writer authority |
| -32147 | The signer may not write an entry |
| -32148 | An escrow registration proof does not verify |
| -32149 | `getRecordUpdateStatus` names no stored update |
| -32190 | The genesis hash is not the service's cluster |
| -32191 | An escrow registration names an anonymous ring |
| -32192 | The member already holds or awaits an escrow key |
| -32193 | The update rode in `MAX_BATCH_ATTEMPTS` batches that did not apply, reported only as its status reason |
| -32240 | An enrolment comes from the config authority or awaits a list outside `allow`, `reader` and `approval` that the ring's own records serve |
| -32241 | The enrolment request signer is not the ring config authority |
| -32242 | An approval and its enrolments exceed one `Update` |
| -32243 | The config authority refused the enrolment, reported only as its status reason |
| -32244 | `refuseEnrolment` names no awaiting enrolment of the ring |
| -32245 | An enrolment's `validUntilSlot` lies past `MAX_ENROLMENT_WINDOW_SLOTS` |
| -32260 | The records creation did not land |

## Co-signer limits

`LimitedCoSigner` implements the `CoSignPolicy` trait the relay calls before it submits a transaction that demands the co-signer. It reads each asset's `AssetLimits` from the asset's record in the ring's own storage registry, checks the opening against the newest own root the ring policy mirrors, and signs only when every limit holds. With `--store-url`, `serve` gives it to the relay, and a host that spawns `ManagedMerge` takes it from `Hub::co_signer`. Without a store `Hub::co_signer` refuses every co-signature. [Co-signer limits](../../docs/spec.md#co-signer-limits) in the spec gives each limit and its window.

A signature reserves its flows in the `cosign_usage` table, keyed by the co-signature and the asset. `settle` keeps a confirmed reservation and deletes a failed or expired one, and a repeat of either changes nothing. The relay passes the co-signature to `settle`, since it names the transaction before the fee payer signs. A reservation the relay never settles counts until its window passes. The reservation lock lives in process memory, so run one co-signer process for each store.

The co-signer key derives from the auditor key or the root secret, as the service key does, under its own HKDF domain. `serve` logs its public key for the ring's `CoSigner` record.

Co-signer errors are `-32160` disabled, `-32161` over a limit, `-32162` an asset named twice and `-32163` unreadable limits.

## Managed merge

`setMergeSettings` keeps one row for each ring, owner and mint in the service store that `--store-url` opens. Without a store it fails with `-32170`. The Ed25519 signature must verify under the request's `owner`, within the timestamp skew, with a fresh nonce. A request replaces the row only when its timestamp is later, else it fails with `-32171`. A target note count of zero revokes the settings. The zero row stays, so an older request cannot restore them.

With a fee payer key, a store and a prover, `serve` spawns `ManagedMerge::run` beside `Hub::run_utxo_backfill`, whose notes and escrow records it reads, and sends each merge through the relay's fee payer. Its merges name no co-signer, so a ring that demands one refuses them. On each ring whose `ConfidentialEscrow` config names the service's auditor key, it reads every wallet with a nonzero target. It opens the wallet's escrowed nullifier secret with the auditor key and checks it against the registered nullifier key. The secret stays in memory for one merge build, and the service never logs or serves it.

A note is a candidate when the service opened it for that owner, mint and escrowed nullifier key, it has a nonzero amount and no data, and the ring history has not published its nullifier. The wallet keeps at most its target count and, under a nonzero minimum average amount, at most its total divided by that amount, never less than one note. When the candidates exceed that count, one merge joins the smallest notes of the tree that holds the most of them, no more than the count needs and at most `MAX_RING_MERGE_INPUTS`.

The merge needs the fee payer, the co-signer signature when the config scope covers transfers, and the nullifier secret. It needs no owner signature. `RingSdkMergeBuilder` proves it through the ring SDK, and the worker sends it through `RelaySubmit`. The inputs of a sent merge stay out of later merges until the process restarts.

## Audit result

`outputs` lists every slot whose opening rebuilds its published UTXO hash. Each carries its tree context and, unless its `kind` is `dummy`, the UTXO. A confidential or delegate ring output also carries the recipient key, and an anonymous ring output carries its view tag instead. `payloadErrors` names every other slot and why. `frame` is a delivered slot without a body of its layout. `disclosure` is a slot whose disclosure bytes do not parse under the layout. `recipientKey` is a delivered recipient key with no X25519 agreement. `commitment` is an opening that hashes to another UTXO hash. `escrowUnknown` is an owner whose escrowed nullifier key the background backfill has not read from the registry. An asset the registry does not know keeps its opening without a mint.

The audit proof binds every disclosure field to the settled notes. The recipient ciphertext of a 2 or 4 output transfer stays outside it. An anonymous disclosure also reveals the sender, the spent notes and the recipients to the auditor. A malformed disclosure is reported as a skipped transaction with a reason. It cannot be presented as a successfully opened payment.

An anonymous transfer that spends no default-ring note names its first spent note by its UTXO hash. It names every later one by the first 16 bytes of its hash. The service keeps every note it opened in process memory and opens such an input from there. It finds a later input among the ring notes of the first note's owner that carry its prefix. When more of the owner's ring notes carry one prefix than inputs name it, each such input lists them as `candidates` and carries no opening. A background backfill reads the ring history from where it stopped and opens every transfer, audited deposit and merge, so a later page finds the notes they created. A deposit's capsule names the owner hash and no nullifier key, so a deposited note carries none, and neither does the sender of a transfer whose first spent note was deposited. A transfer whose spent note the service has not opened yet appears in `skipped` as `unseenInput`. A restart rebuilds the notes from the ring history.

`getAuditedUtxos` serves the same notes from memory. Its read authorization binds the cluster, the service key, the ring, the timestamp, the nonce and the SHA-256 digest of the hashes in request order.

A transaction that carries the auditor view tag but did not run under this ring is not reported. It reaches neither the audited items nor the skipped rows, and the page cursor still advances past it, so an empty page is not the end of the history.

Photon supplies transaction discovery. Ring RPC fetches each candidate from Solana RPC and requires successful execution with the ring as SPP's direct caller. It reconstructs the exact SPP event and checks the indexed UTXO hashes, ciphertext, viewing metadata, nullifiers and output positions against it. Recovery applies the same check to deposits, merges and spend-query responses. Transfer proofs are enforced by the confirmed on-chain execution.

Clients of Ring RPC trust the configured service to perform these checks. Rebuilding the UTXO hashes of the returned openings alone does not independently authenticate chain history.

The chain RPC remains trusted for confirmed contents. Photon remains trusted for complete history. These checks detect changed contents, but cannot prove that an indexer omitted no transaction. Rows that fail event binding or disclosure checks appear in `skipped`. A failed chain lookup returns an error.

`getAuditedMerges` checks each confirmed merge against the chain and tries auditor keys from authenticated storage record pages. It stops searching once every output on the history page has a hash-checked opening. Each request is limited to 100 registry pages and 100,000 key and output attempts. If either limit is reached before the scan is complete, the method returns `audit scan exceeded its per-request work budget`. It does not return a partial page. A direct Rust `MergeAudit` scan has no default key-attempt limit and can search the full registry. Photon history rows must advance strictly past the requested cursor, so a repeated event cannot be counted on a later signed page.

## Operation

The server accepts loopback binds only, put a TLS proxy in front of it for remote clients. `--insecure-public-bind` lifts that for a test deployment and serves the decrypted audit data over plain HTTP. Keep the proxy request body limit at or below the service limit.

The TypeScript SDK and `zolana-ring` CLI take a service base URL and append the JSON-RPC method, preserving its query parameters. For example, `https://ring-rpc.example?api-key=KEY` becomes `POST /ringStatus?api-key=KEY`. In `ring.toml`, use `ring_rpc = "https://ring-rpc.example?api-key=${RING_RPC_API_KEY}"` to load the key from the environment.

A call posted to any path but `/` runs only when its JSON-RPC body is one call naming the path's last segment: `/ringStatus` and `/v1/zolana/ring/ringStatus` run `ringStatus` and refuse every other method with HTTP 400 and JSON-RPC error `-32601`. A gateway that routes and prices by path therefore prices the method that runs and does not bill these refusals as successful calls. `/` remains available to existing self-hosted JSON-RPC clients. Proxies must preserve the method path; rewriting it to `/` removes the path check.

The check runs before RPC execution, nonce consumption and metering, so a gateway forwards the body without inspecting it. Disable automatic proxy retries of signed POST requests: a 5xx or lost response does not prove that the call's nonce was unused, so the caller handles the outcome rather than a transparent resend.

A successful `ringDeposits` answers `x-helius-metering-units` with one unit for every 50 signatures it asked to examine, rounded up, so a 200-signature page bills four times a default one. Other methods answer a bounded page or one lookup and report none, which a gateway bills as one unit.

`GET /health` reports the service identity. `GET /ready` checks Photon and Solana RPC. In local mode it also checks that the ring config still names the auditor key held here. In derived mode it re-reads the cluster genesis hash and fails when it differs from the one captured at boot, because that hash binds every derived key. A failed probe names the check in the response body.

Four lanes admit every JSON RPC method but `health`, and each lane has its own one-second request window. `ringStatus` takes the public lane, the one lane without a concurrency cap. `ringDeposits` takes the deposit lane and counts as one request plus one for each signature it may examine. `createAuditorKey` and `getAuditedUtxos` take an authentication slot, since they verify a signature and read the chain. `getDecryptedTransactions` and `getAuditedMerges` release the authentication slot after the read authorization and hold a read slot for the page. A reader runs one read request at a time on each ring. `GET /ready` takes no lane, runs one upstream probe at a time and answers from its last result for one second. In local mode `ringDeposits` answers for the served ring only, like `ringStatus`. Key files must have owner access only unless the operator selects the shared file option.

## Rate limiting

Every JSON RPC call spends a token from its client's bucket before it runs, one bucket for each client and method class. Public reads are `health`, `ringStatus`, `ringDeposits`, `getRecordUpdateStatus`, `getRelayQuote` and `getRelayStatus`, and a `ringDeposits` page spends one token per metering unit, at most its burst. Signed reads are `createAuditorKey`, `getDecryptedTransactions`, `getAuditedMerges`, `getAuditedUtxos` and `getPendingEnrolments`. Every other method is a signed write, record updates and enrolments included. A bucket refills at its per-minute rate up to its burst. The lanes above still bound the whole service.

A signed write also needs a token from the bucket of the key it names as signer, at the signed write rate, so one key cannot pass its rate through many addresses. Only a successful call spends that token, so a request with a forged signature never spends the budget of the key it names.

The client is the TCP peer address, and an IPv6 peer is its /64. Every /64 of one IPv6 /48 also spends from a shared bucket of the /48 with 16 times the client rate and burst. A peer named with `--trusted-proxy` names the client in `x-forwarded-for`. The service reads that header from the right and takes the first address that is not a trusted proxy. It ignores the header from every other peer. A hop takes an optional port, an IPv6 hop with a port in brackets. A malformed hop, or a header that names only trusted proxies, leaves the peer as the client. A listed proxy must append the peer it sees, or a client names itself. A TLS proxy on loopback must be listed, or all of its clients share one bucket.

With `--api-key-sha256` set, a request that carries an `x-api-key` header, or else an `api-key` query value, takes that key as its client. The service holds only the SHA-256 of each key, over the value as sent, and refuses an unlisted key with HTTP 401 and `-32254`. Leave the digests unset behind a gateway that keys calls with its own `api-key` query value, or the service refuses every call.

The bucket table has a fixed size. A bucket that has refilled to its burst is the same as a new one and leaves the table first. When the table is at its size, the bucket nearest to its burst leaves next. Rates and bursts come from `--public-reads-per-minute`, `--public-read-burst` and their signed read and signed write twins, each with a `RING_RPC_` variable. A refusal answers HTTP 429 with `Retry-After` in seconds, and its JSON RPC error carries `retryAfterMs` in `data`.

| Code | Meaning |
|---|---|
| -32250 | The client is past its public read rate |
| -32251 | The client is past its signed read rate |
| -32252 | The client is past its signed write rate |
| -32253 | The key the write names as signer is past its signed write rate |
| -32254 | The request names an API key whose digest is not configured |
