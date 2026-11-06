# Ring RPC

Ring RPC holds an auditor viewing key and opens custom ring transfer outputs. It reads ring transactions from Photon and checks reader grants in the ring's storage tree or in its own database.

## Keys

Local mode serves one ring with one auditor key file. Generate the key before `Initialize` creates the ring account.

```bash
cargo run -p zolana-ring-rpc -- keygen --out keys/auditor.key
cargo run -p zolana-ring-rpc -- keygen --kind service --out keys/service.key
cargo run -p zolana-ring-rpc -- serve \
  --indexer-url http://127.0.0.1:8784 \
  --rpc-url http://127.0.0.1:8899 \
  --auditor-key-file keys/auditor.key \
  --service-key-file keys/service.key \
  --ring-program-id <program-id>
```

The command writes the secret with owner access only. It writes the X25519 public key to `keys/auditor.key.pub`.

Derived mode serves a stable key for each ring and cluster, for as many rings as ask. Generate a root secret with `keygen --kind root`. Protect one root as carefully as all keys derived from it. The root yields auditor keys and no other key. The key comes from the root, the cluster genesis hash and the ring program id, so a new ring needs no configuration, no restart, and nothing stored. Repointing the service at another cluster changes every derived key and orphans every ring already registered.

Every other role reads its own secret file, and `keygen --kind <role>` writes each one. The service key of `--service-key-file` signs the `createAuditorKey` answers, and every read and grant signature binds its public key. Every `serve` needs it. The storage authority of `--storage-authority-key-file` signs and pays for every records write, and `--store-url` needs it. The co-signer of `--co-signer-key-file` turns co-signing on and needs `--store-url`. The 32-byte secret of `--grant-rows-key-file` keys the reader grant rows, and `--reader-grants database` needs it. A missing file stops `serve` with an error that names its flag.

A relay pays fees with its own Ed25519 key, apart from the auditor and service keys. Generate it with `keygen --kind fee-payer`, fund it, and pass it with `--fee-payer-key-file`, a `--store-url` for the relay records and the ring prover's `--prover-url`.

Relay enrollment and token account creates stay off until the operator funds them. An enrollment and a token account the relay creates spend the fee payer's lamports, and the relay budget bounds them. `--relay-budget-lamports` caps the lamports reserved and spent over the store's life, and `--relay-signer-budget-lamports` caps what one signer holds outstanding at once. Both default to zero. While either is zero, `serve` logs that relay enrollment and token account creates are off and `prepareRelay` refuses each of them with `-32210`. To turn them on, set both and fund the fee payer with at least the total. A landed enrollment keeps its signature fees and the tree 0 forester fee cap in the total for good. Raise the total to fund more. Any other relay pays only its fee and needs no budget.

`serve` refuses to start when two role files hold the same secret, the auditor key file and the root secret included. It compares the secrets in constant time.

A ring must take its auditor key from the service before `Initialize` creates its ring account. The ring account fixes the auditor for the life of the ring, so a ring registered with any other key can never be read here, whatever the service derives for it. `ringStatus` reports which of the three cases a ring is in.

`createAuditorKey` answers only a request signed by the policy authority the ring policy names, or, before `Initialize` creates it, by the program's Loader v3 upgrade authority. The signature binds the cluster genesis hash, the ring, a Unix timestamp and a random nonce. The service reads the authority from the chain on every request and accepts a nonce once. `ringStatus` and `health` never return the key the service holds, only the key the ring policy already publishes. The response carries a service signature over the cluster, the ring, the auditor key and the request nonce. The current ring program does not verify the service signature. Operators must verify and pin the service public key through a separate trusted channel.

## JSON RPC

All wire fields use camel case.

| Method | Request | Result |
| --- | --- | --- |
| `health` | none | Service mode and service public key |
| `createAuditorKey` | Ring program ID and authority authorization | Auditor key and service attestation |
| `ringStatus` | Ring program ID | Whether the ring account names the key held here (`served`), another one (`foreignAuditor`), or does not exist yet (`uninitialized`), with the ring account's key when it exists |
| `getDecryptedTransactions` | Ring, page, and read authorization | Decrypted transaction page |
| `getWalletActivity` | Ring, wallet, page, and read authorization | The wallet's own part of each transaction it is a party to |
| `getAuditedMerges` | Ring, page, and read authorization | The merges the backfill opened and the next cursor |
| `getAuditedUtxos` | Ring, 1 to 100 UTXO hashes, and read authorization | `utxos`, in request order, the opening of each hash the service opened, `null` for any other |
| `getWalletStatus` | Ring, wallet, an optional cursor, and read authorization | `historyThrough`, `enrollment`, `balances`, `notes`, `cursor` and optional `snapshotExpiresAt`. See [Balance status](#balance-status) |
| `getSpendCoverage` | Ring, authority, optional cursor, timestamp, nonce, and the authority's signature | `positionSlot`, absent inside a paged read, `historyThrough`, optional `totals`, `unresolvedReal`, `unreadable`, `integrityFaults` and optional `cursor`. See [Balance status](#balance-status) |
| `getDelegateNotes` | Ring, delegate, owner, an optional cursor, timestamp, nonce and the delegate's signature | The owner's `nullifierSecret`, absent unless the service holds the owner's credential, and its wallet status |
| `releaseWalletSnapshot` | Wallet-status request with a cursor and release-domain authorization | `true` |
| `releaseDelegateSnapshot` | Delegate-notes request with a cursor and release-domain signature | `true` |
| `getListSalt` | Ring, writer, owner, timestamp, nonce and the writer's signature | The owner's `listSalt`, absent while the service holds no credential for the owner, refused while its credential scan is incomplete |
| `setReaderGrant` | Ring, optional wallet, reader, `grant` or `revoke`, timestamp, nonce, and the signature of the wallet or, without one, of the policy authority | The action the service holds for the grant |

The read authorization contains a canonical reader key, Unix timestamp, random nonce, and signature. The signature binds the method, cluster, service key, ring, timestamp, nonce, cursor, and limit. Ed25519 readers sign the attestation bytes. P256 readers use WebAuthn with user verification.

The authority authorization contains the authority address, the cluster genesis hash, Unix timestamp, random nonce, and a raw Ed25519 signature over the attestation bytes. Both authorizations share the timestamp skew and the per-ring nonce set.

The onchain auditor public key must match the auditor key held by Ring RPC.

## Reader grants

`--reader-grants` selects the one store the service reads grants from, `tree` by default or `database`.

In `tree` mode a reader holds its grant in the ring's own storage tree, the `StorageRegistry` its ring policy names. The service opens the reader's records through the indexer and checks each opening against the newest root of that registry. A ring-wide grant is the `Reader` list on the reader's own record. That record belongs to the owner identity of an Ed25519 reader, or to the `hash_bytes` of a passkey's tagged key. A wallet grant is the `Reader` list on the record `Member::wallet_grant(wallet, reader)`. The policy authority has no implicit access. A ring with no policy, or whose records address holds no storage registry, refuses every read with `-32130`. In this mode `setReaderGrant` answers `-32131`.

`getWalletActivity` names a `wallet` and returns one `WalletActivity` for each transaction that wallet is a party to, and no skipped rows. The sender of an anonymous transfer sees its inputs, every output, the payload errors and the withdrawals. A confidential spender is an owner signer or the owner the SPP proof verifies. It sees every output, the payload errors and the withdrawals. An owner the SPP proof verifies also sees its inputs. The owner of an output sees only its own outputs and the withdrawals it receives. A fee payer or co-signer outside the owner signers is no party. A delegate transfer has no spender. `getAuditedMerges` and `getAuditedUtxos` with a `wallet` return the merges and notes it owns. `getDecryptedTransactions` serves whole transactions to a ring-wide read only, and a granted read whose method and wallet disagree fails with `-32270`. A ring-wide grant covers every wallet, a wallet grant only its own wallet. The wallet joins the signed attestation as a last `wallet:` line, and a read without one signs no such line.

`database` mode needs `--store-url`. The service keeps both grants in its own database and never reads the storage tree for a grant, so a ring without a records registry still serves its readers. `setReaderGrant` writes a wallet grant under the wallet's raw Ed25519 signature, and a ring-wide grant with no wallet under the signature of the policy authority the ring policy names. The signature covers `zolana/ring-rpc-reader-grant`, the cluster, service, ring, the wallet when named, reader, action, timestamp and nonce, under the skew and nonce set of a read. Each accepted call appends one row, sealed with AES-256-GCM under a key HKDF-SHA256 derives with `zolana/ring-rpc-grant-rows` from the secret of `--grant-rows-key-file`. Beside its insert id, a row keeps in plaintext only the HMAC-SHA256 of the reader key under the same derivation, also the associated data. The row with the latest signed timestamp holds, the later write on a tie. A ring-wide row holds for every wallet. The record writer refuses an update that writes or awaits a `reader` list with `-32230`, because no read checks it. Write access to the database can drop a revocation row, so protect it like the service key.

Allowed WebAuthn origins need an explicit RP ID. The RP ID can be the origin host or a valid parent domain. Cross origin assertions are rejected.

With `--store-url` an accepted nonce is spent in the store and stays spent across a restart. Without a store the nonces stay in process memory. Replicas need a shared store and the same service, auditor and co-signer keys. Without a shared store, run one process per ring. Projection writes require the ring lease. Run one record writer per storage authority.

## Relay, record updates and merge settings

`zolana_ring_client::rpc` defines these methods and the TypeScript SDK mirrors them in `protocol/ring-rpc`. The service answers the record update methods through its [record writer](#record-writer), the four relay methods and `prepareAuthorityTransfer` when it runs with a fee payer key, and `setMergeSettings` with a store.

| Method | Request | Result |
| --- | --- | --- |
| `getRelayQuote` | Ring and relay operation | `feePayer` and `validUntilSlot` |
| `prepareRelay` | Ring, the quote, and the `intent` with the rail's proof inputs | A `RelayStep`, `submitted` or `signMessage` with the v1 message to sign |
| `submitRelay` | `relayId`, signer and its signature over that message | `RelayStatus` |
| `getRelayStatus` | `relayId` | `RelayStatus`, one of `awaitingSignature`, `sent`, `confirmed` or `failed` |
| `submitRecordUpdate` | Storage registry, the update, signer and signature | `updateId` |
| `getRecordUpdateStatus` | `updateId` | One of `pendingListApproval`, `queued`, `submitted`, `applied` with the new revision, or `refused` |
| `getPendingListApprovals` | Ring, an optional `cursor` and the policy authority's authorization | One page of the updates pending list approval, oldest first, after `cursor`, with `nextCursor` on every page but the last |
| `refuseListApproval` | Ring, `updateId` and the policy authority's authorization | The `refused` status |
| `createRecordsRegistry` | Ring and the policy or upgrade authority's authorization | The ring's records `registry` and the writer's `storageAuthority` |
| `setMergeSettings` | Ring, owner, the settings, timestamp, nonce and signature | The stored settings |
| `prepareAuthorityTransfer` | Ring, delegate, the transfer, timestamp, nonce and signature | A `RelayStep`, `signMessage` until the delegate signs |

The relay operation is `anonymous`, `confidential`, `delegate`, `deposit`, `merge` or `enroll`. The quote names the fee payer the relay signs with and the last slot it takes the request, at most 150 slots ahead. On the anonymous and confidential rails the intent carries the owner's Ed25519 signature over `SppProofInputs::message_hash`, and the service refuses a request it does not verify before it proves. On the anonymous and confidential rails that signature authorizes the spend inside the proof and `prepareRelay` answers `submitted`. On the delegate rail it answers `signMessage` and the delegate signs the returned message for `submitRelay`. The service sends once the message carries every signature, the co-signer's included. On the deposit rail the intent carries the depositor's Ed25519 signature over `SHA-256(zolana/ring-rpc-relay-deposit || proofInputs)`, the service refuses a request it does not verify before it proves, it answers `signMessage` and the depositor signs the returned message to fund its SOL or SPL transfer. It refuses a depositor that is the relay fee payer. On the merge rail the intent carries the owner's signature over `SHA-256(zolana/ring-rpc-relay-merge || proofInputs)` under the same refusal, and it answers `submitted`. On the enroll rail the intent carries the owner's signature over the enrollment request under the same refusal. The service refuses an enrollment whose proof fails or whose credential address nullifier already exists before it reserves any budget, then simulates the message without signatures. A passing simulation authorizes nothing. The service answers `signMessage` and sends only once the owner signs the message, and a transaction that fails on state that changed after the simulation settles as a failed relay that keeps its fee. An enrollment holds its reservation from its funding to the settlement or the proven expiry of its message. A transfer intent may name `tokenAccountSetup`, each entry the owner and mint of an associated token account a withdrawal pays. For an account still missing when the service compiles the message, it puts an idempotent create, funded by its fee payer, ahead of the transfer. It omits the create of an account that exists then, and refuses an entry no withdrawal of its mint pays or an entry that repeats one. The proof inputs carry no Merkle path and no record opening, the service reads those. `relayId` is the SHA-256 of the domain `zolana/ring-rpc-relay` and the request's JSON as the service serializes it, so a retried request names the same relay.

A relay record keeps the message, the collected signatures and the status, never the proof inputs. A repeated `prepareRelay` returns the stored step and proves nothing again. The fee payer signs once the message carries every other signature, and the record stores that signed transaction before its first send. A tracker moves every pending relay on every two seconds and sends its stored transaction again, so a send lost to a restart still reaches the cluster under the same signature. A relay awaiting a signature fails after finalized blockhash expiry. A sent relay stays pending until finalized success, finalized failure, or finalized expiry without a recorded outcome. A preflight refusal alone releases no allowance. Finalized failure or expiry releases the reservation. Status lookups search the ledger history, so `--rpc-url` must serve transaction history. Relay errors take codes `-32100` to `-32113`, in order: ring not relayed, quote fee payer, quote expired, quote window, invalid proof inputs, ring mismatch, rail mismatch, owner signature, refused transfer, co-signer refusal, unknown relay, unexpected signer, signer signature and cluster refusal. `-32200` refuses a token account setup and `-32201` a depositor that is the fee payer. `-32202` to `-32210` are, in order: invalid enrollment, relay budget, signer budget, enrollment signature, delegate signature, spent allowance, an earlier relay of the request that can still land, depositor signature, and a relay budget the operator left unset. `-32213` to `-32215` refuse a relayed enrollment, in order: an owner whose credential address an enrollment already reserves, a RegisterKey proof that does not verify for the credential the program rebuilds, and an enrollment the chain refuses in simulation before any signature. `-32211` and `-32212` refuse a sealed transfer whose stream the records move, the owner seals again under the narrow or the wide row. `-32216` refuses a message past one v1 transaction, 4,096 bytes or 64 accounts with its setup, before any charge.

`proofInputs` is the base64 of one `RelayProofInputs` in wincode, enum tags and vector lengths in one byte and byte strings with a two byte length. It holds the sealed transfer: the rail, the ring program id, the sender's shielded address, its nullifier secret, the transaction viewing secret, the ephemeral secret that sealed the auditor message, every input opening, the outputs, the external data with its auditor message, the blinding seed and the output tree id. An anonymous rail adds its view tag plan and an optional exit token owner, a delegate rail the delegate. An input opening is a spend of the sender, a dummy or compact padding, and the service derives every input hash and nullifier from it. Each interface transfer is a withdrawal, an SPL one names its token program. The service is trusted with these secrets, it proves with them and keeps none past the relay. `test-vectors/rpc/relay_proof_inputs.json` pins the bytes.

A deposit's `proofInputs` is one `RelayDepositInputs`: the ring, the tree, the depositor, the recipient's shielded address, the SOL or SPL settlement, the amount, the view tag, the encrypted deposit data with the auditor capsule, the blinding secret and the capsule's ephemeral secret. The service derives the owner commitment from the blinding secret and checks the ephemeral secret against the capsule. A merge's `proofInputs` is one `RelayMergeInputs`: the ring, the owner's shielded address, its nullifier secret and the notes as spend openings with their leaf indexes. The service derives the merged note from the nullifier secret.

A record update names the cluster genesis hash, a ring, its entries, `validUntilSlot` and, for an update pending list approval, `awaitedLists`. An entry is a `write` of masked lists with optional mint settings or a `walletGrant` that sets or clears the reader list of the record `Poseidon(CRWG, wallet, reader)`, with the `wallet` and `reader` identities and `access` of `granted` or `revoked`. The signer signs the 32 bytes of `Poseidon(CRRU, hash_bytes(genesisHash), hash_bytes(ring), hash_bytes(registry), entries_hash, validUntilSlot)`, where `entries_hash` folds `queue_chain` over the entries from a zero start. An update pending list approval appends `awaitedLists` as a seventh element. That hash is the `updateId`.

Merge settings name a mint, a target note count and a minimum average amount. The owner signs them under `zolana/ring-rpc-merge-settings` with the cluster, service, ring, timestamp and nonce of a read authorization.

## Authority transfer

`prepareAuthorityTransfer` requires `sources`, `payments`, `exits` and `withdrawals`. Empty leg arrays remain present. Payments and exits name a shielded recipient, mint and amount. Withdrawals name a recipient, mint, amount and optional `tokenProgram`. A SOL recipient is the destination account. An SPL recipient is the token-account owner, and the service derives its associated token account. The mint account authenticates the token program. A conflicting supplied program returns `-32229`.

The authority-transfer signature binds each exit as `exit: <shielded-recipient> <mint> <amount>` after the payment lines. Withdrawal lines follow as `withdrawal: <recipient> <mint> <amount> <tokenProgram or ->`. The delegate SDK validates these legs, permits change only to requested sources, and refuses deposits, extra legs or data before signing.

The ring delegate moves members' notes without their signatures. All request addresses use base58 text. The delegate signs under `zolana/ring-rpc-authority-transfer`. The message binds the cluster, service, ring, delegate, ordered source, payment, exit and withdrawal lines, timestamp and nonce. It uses the skew and nonce set of a read.

The service checks the signature under the named delegate, that the ring policy names that key its delegate, and that the ring policy names the auditor key held here. It opens each source's nullifier secret from its audit credential, rebuilt from finalized `Enroll` history, with the auditor key and checks it against the source address's nullifier key, and a source under the zero key moves under the public secret. The move spends opened notes of the requested sources, keys and mints. It excludes notes with data or a nullifier already published in ring history. The SDK selects notes within the delegate rail's input and tree limits. Each mint's change returns to the owner of its last selected input. The SDK encrypts the outputs to their owners and the auditor, then seals the delegate transfer. The delegate rail demands no co-signer and bypasses policy checks. The relay proves the sealed move and stores it under `relayId`. The id hashes the relay domain and request JSON with SHA-256. A repeated request returns the stored step. The delegate signs the returned message through `submitRelay`, and the relay pays, sends and tracks it. The backfill indexes the spent inputs and the new outputs. The secret stays in memory for the request, and the service never logs or stores it.

`getDelegateNotes` hands the ring's delegate one owner's secret and notes. `getListSalt` hands the policy authority or the authority of a salted list's registry one owner's list salt, and never its nullifier secret.

Errors are `-32220` the signer is not the ring delegate, `-32221` the ring seals its keys to another auditor, `-32222` the source has no enrolled nullifier key, `-32223` the source address names another nullifier key, `-32224` the service runs no relay, `-32225` a transaction key that is no clamped X25519 secret, and `-32226` a signer that writes no salted list of the ring.

## Record writer

`--store-url` turns the record writer on. The store takes a `postgres://` or `sqlite://` URL. The writer proves every storage update, so the service refuses to start with a store and no `--prover-url`, or with a prover and no store. The prover must serve the ring apply keys.

The writer signs and pays for every storage update with the storage authority key of `--storage-authority-key-file`. `keygen --kind storage-authority` prints its address, and the service logs it at start. Fund it before the first ring. A registry the writer serves names the key as its authority, and the ring policy account names the registry as its records.

`createRecordsRegistry` creates a ring's records, the `StorageRegistry` of the storage authority under the ring program id, and pays for them. The ring's policy authority signs the request, or the program's upgrade authority before `Initialize`, over `zolana/ring-rpc-policy-authority` with the `action:` line `create records`. A repeated request returns the same registry. The service answers once the creation confirms and fails with `-32260` when it does not land. `zolana-ring init` binds these records at `Initialize` with the storage authority the answer names.

`submitRecordUpdate` checks the genesis hash against the service's cluster, the signature over the update statement, `validUntilSlot` against the current slot, and the registry against the ring. A wallet writes the `ring-viewing` list of its own record and its own wallet grants. The ring's policy authority writes the `allow`, `block`, `frozen`, `private-allow`, `private-block`, `reader` and `approval` lists and the mint settings of any record. An update for a ring whose records address holds no storage registry fails with `-32146`. An update refused at submit is never stored. A resubmitted update returns its first `updateId`.

A wallet's update with nonzero `awaitedLists` asks for list approval, the record bits of the `allow`, `reader` or `approval` lists it needs. List approval is the policy authority's off chain decision, a KYC check for one, and the writer only holds the update for it. It is not an enrollment and registers no secret. The writer refuses `awaitedLists` from the policy authority or a list the ring policy does not read from its own records. It stores the update as `pendingListApproval`, one state of the writer's lifecycle, and sends none of its writes while it waits. The policy authority lists these updates with `getPendingListApprovals`, at most `PENDING_LIST_APPROVALS_PAGE_LIMIT` a page, and passes the `nextCursor` of a page as the `cursor` of the next. It approves one by submitting its normal record update that sets every awaited list on the wallet's owner identity. That update queues with the updates it approves joined to it, and they go out in one batch, the approved writes first, or share its refusal. An approval that would carry more than 16 writes with the updates it approves is refused at submit. `refuseListApproval` turns a pending update `refused`. Both methods take the policy authority's raw Ed25519 signature under `zolana/ring-rpc-policy-authority`. It binds the cluster, service, ring, authority, action, timestamp and nonce, under the skew and nonce set of a read. The action is `list <registry>`, `list <registry> after <cursor>` or `refuse <registry> <updateId>`. Both requests require `registry`, which the signature binds. The current policy authority can list or refuse pending requests for an older registry after the ring changes records. An update still pending after its `validUntilSlot` turns `refused`, so a wallet gives it a window that leaves the authority time to act. The writer refuses one whose `validUntilSlot` lies more than `MAX_LIST_APPROVAL_WINDOW_SLOTS` past the current slot. It holds any number of pending updates, and [rate limiting](#rate-limiting) bounds how fast a client or a key submits them. A submit reads only the pending updates of the members it writes. Nothing obliges the authority to answer, and a write the storage authority signs directly skips the wait.

Updates queue in submit order for each registry. One `Update` carries at most 16 writes and never splits an update. An authority update carries an entry only the policy authority writes, an authority list or mint settings. Authority and wallet updates never share a batch. An authority batch goes out at the next pass and passes queued wallet updates, unless one of them writes the same record. The Storage program decides retirement from the batch's proven restrictive bit, see `docs/design/records-and-roots.md#root-history`. A restrictive batch retires every earlier root. Any other batch keeps the outgoing root for the grace period and evicts the oldest kept root from a full history. Reader list writes never revoke. A wallet batch goes out once it is full, its oldest update waited `BATCH_WINDOW_SLOTS`, or an authority update waits behind it. A reader grant revocation, ring-wide or wallet, is graced, since the service checks grants against the registry's newest root.

The apply proof starts at the registry's current root from `getStorageApplyProofInputs`. The writer drops inputs at another revision or root, or for other writes, and retries on its next pass. It stores the batch and its signature before it sends the transaction, and one registry has at most one open batch. A restart settles that batch by its signature. A confirmed batch is applied, a failed one queues again, and an unknown one queues again only when its signature is still not found once the block height is past the last valid block height of its blockhash. An update turns `refused` after `MAX_BATCH_ATTEMPTS` batches that did not apply, or when it is still queued after `validUntilSlot`. After proving, the writer reads the current policy roles and slot before signing. An expired update or an authority update whose signer lost the role turns `refused`. If the authority lost its role, an update it approved turns `pendingListApproval` again. A refused or deferred member prevents submission of the batch. Later expiry or role rotation does not revoke an already signed transaction. Run one writer for each storage authority key.

The ring program reads every root from the live registry account a transfer or merge passes. A curator update reaches every subscriber ring's transfers as soon as storage applies it, and a restrictive update fails the next transfer under an older root.

| Code | Refusal |
| --- | --- |
| -32140 | The service runs no record writer |
| -32141 | The update carries no entry or more than 16 |
| -32142 | An entry does not encode |
| -32143 | The signature does not verify |
| -32144 | The current slot is past `validUntilSlot` |
| -32145 | The ring has no ring account |
| -32146 | The registry is not the ring records under the writer authority |
| -32147 | The signer may not write an entry |
| -32149 | `getRecordUpdateStatus` names no stored update |
| -32190 | The genesis hash is not the service's cluster |
| -32193 | The update rode in `MAX_BATCH_ATTEMPTS` batches that did not apply, reported only as its status reason |
| -32240 | `awaitedLists` comes from the policy authority or names a list outside `allow`, `reader` and `approval` that the ring's own records serve |
| -32241 | The policy authority request signer is not the ring policy authority |
| -32242 | An approval and the updates it approves exceed one `Update` |
| -32243 | The policy authority refused the list approval, reported only as its status reason |
| -32244 | `refuseListApproval` names no update of the ring pending list approval |
| -32245 | The `validUntilSlot` of an update pending list approval lies past `MAX_LIST_APPROVAL_WINDOW_SLOTS` |
| -32260 | The records creation did not land |
| -32275 | The signer of a queued authority update no longer holds the policy role, reported only as its status reason |
| -32276 | Mint limits pair a cap with no window or a window with no cap, or a window exceeds `MAX_LIMIT_WINDOW_SLOTS` |
| -32277 | Mint limits name an asset with no record under the newest root of the ring's records registry |

## Co-signer limits

`LimitedCoSigner` implements the `CoSignPolicy` trait the relay calls before it submits a transaction that demands the co-signer. It reads each asset's `AssetLimits` from the asset's record in the ring's own storage registry, checks the opening against the newest root of that registry, and signs only when every limit holds. Window limits are optional service policy and never a ring limit. They bind only a transaction that needs Ring RPC's signature, and the ring program checks only the co-signature. They bind every operation of a class, such as Transfers, only when Ring RPC is the one co-signer that covers that class. Otherwise a transfer below the co-sign bound, or one another co-signer signs, can pass uncounted. The co-sign bound and the withdrawal threshold cap nothing. Above one a transfer needs an approver's signature, and any co-signer whose scope covers that approval can give it. No proof carries a window limit. A proof of one would need authenticated usage state that every transaction updates. With `--co-signer-key-file`, `serve` gives it to the relay, and a host that spawns `ManagedMerge` takes it from `Hub::co_signer`. Without a co-signer key `Hub::co_signer` refuses every co-signature, and a hub with a co-signer key and no store refuses to build. [Co-signing](../../docs/design/co-signing.md#window-limits-in-ring-rpc) gives each limit and its window.

A transfer's flows come from the frame the co-signer signs, opened with the auditor key. The message must be version 1, so a lookup table refuses. It must hold exactly one instruction that names the ring or SPP program, as its program or as an account, and that instruction must be the transfer. Any other message refuses with `-32164`, and an input the service has not opened refuses with `-32163`. A signature reserves each owner and asset once. Window totals use an indexed sum. Finalized success confirms the reservation, and finalized failure or expiry releases its totals. A released signature cannot reserve again. Repeating settlement changes nothing. Replicas using the same co-signer key must share one store. Different signing keys cannot share one message allowance. The relay passes the co-signature to `settle`, since it names the transaction before the fee payer signs. A reservation the relay never settles counts until its window passes. A decision first writes the `cosign_admission` row of its ring and each asset, and holds the write locks until its transaction ends. Concurrent decisions therefore grant each allowance once. The decision reads its slot after the asset locks and before the window totals. A backward slot or a changed slot at the final read rolls back admission. The final read precedes commit. Commit delay and transaction landing do not move the reservation's slot.

`keygen --kind co-signer` prints the co-signer public key for the ring's `CoSigner` record, and `serve` logs it at start.

Co-signer errors are `-32160` disabled, `-32161` over a limit, `-32162` an asset named twice, `-32163` unreadable limits, `-32164` a message with anything but one readable ring transfer, `-32165` no approved class the operation demands, `-32166` a released reservation and `-32296` an asset with no record.

## Managed merge

`setMergeSettings` keeps one row for each ring, owner and mint in the service store that `--store-url` opens. Without a store it fails with `-32170`. The Ed25519 signature must verify under the request's `owner`, within the timestamp skew, with a fresh nonce. A request replaces the row only when its timestamp is later, else it fails with `-32171`. A target note count of zero revokes the settings. The zero row stays, so an older request cannot restore them.

With a fee payer key, a store and a prover, `serve` spawns `ManagedMerge::run` beside `Hub::run_utxo_backfill`, whose notes and held credential keys it reads, and sends each merge through the relay's fee payer. A merge demands no co-signer. On each ring whose ring policy names the service's auditor key, it reads every wallet with a nonzero target. It opens the wallet's nullifier secret from its audit credential, rebuilt from finalized `Enroll` history, with the auditor key. The secret stays in memory for one merge build, and the service never logs or serves it.

A note is a candidate when the service opened it for that owner, mint and credential nullifier key, it has a nonzero amount and no data, and the ring history has not published its nullifier. The wallet keeps at most its target count and, under a nonzero minimum average amount, at most its total divided by that amount, never less than one note. When the candidates exceed that count, one merge joins the smallest notes of the tree that holds the most of them, no more than the count needs and at most `MAX_RING_MERGE_INPUTS`.

The merge needs the fee payer and the nullifier secret. It needs no owner signature. `RingSdkMergeBuilder` proves it through the ring SDK. The worker stores the merge as a relay with its input nullifiers, then sends it. The relay tracker confirms or expires it and resumes it after a restart. Its inputs stay out of later merges until the relay fails or expires, or until it confirms and the ring history publishes their nullifiers.

## Audit result

`outputs` lists every slot whose opening rebuilds its published UTXO hash. Each carries its tree context and, unless its `kind` is `dummy`, the UTXO. A ring output also carries its published owner tag as `tag`. `payloadErrors` names every other slot and why. `disclosure` is a slot whose record holds a value outside the field. `commitment` is an opening that hashes to another UTXO hash. An asset the registry does not know keeps its opening without a mint. The service reads the registry at most once per `ASSET_REFRESH_INTERVAL`, and a later read names the mint once the registry holds it.

The audit proof binds every disclosure field to the settled notes. A recipient body stays outside it. A disclosure reveals the real input count, each default-ring input's opening and every output's owner to the auditor. A malformed disclosure is reported as a skipped transaction with a reason. It cannot be presented as a successfully opened payment.

A frame names each real input by its published nullifier alone, and an entry frame also opens each default-ring input in full. The service derives the nullifier of a note it opened once the owner's secret reads, from its audit credential, rebuilt from finalized `Enroll` history, or the zero key, and its note index names the note a real input spent. A background backfill reads the ring history from where it stopped and opens every transfer and merge, so a later page finds the notes they created. With a store the notes and spend rows commit with each page and a restart resumes from that position. Without one a restart reads the ring history again.

A real input the note index cannot name stays `unresolvedReal` in `getSpendCoverage`, the outputs stay open, and the spend stays unresolved until the note or its secret opens. `getWalletActivity` reads such an input as another party's.

`getAuditedUtxos` serves the same notes from the service's projection. With a store, memory keeps a bounded cache of it and the store answers every other note. A held output reads `null` until it opens, and the response context can already be past its slot. Its read authorization binds the cluster, the service key, the ring, the timestamp, the nonce and the SHA-256 digest of the hashes in request order.

A transaction that carries the auditor view tag but did not run under this ring is not reported. It reaches neither the audited items nor the skipped rows, and the page cursor still advances past it, so an empty page is not the end of the history.

Ring RPC enumerates finalized ring signatures from an archival Solana RPC. It requires each expected SPP event exactly once in Photon and binds the indexed fields to the canonical transaction. Missing, repeated or altered events stop the page before coverage advances. The service requires successful execution with the ring as SPP's direct caller.

Clients trust the configured service and archival RPC for complete chain history. Rebuilding returned UTXO commitments alone does not authenticate that history. Initial signature discovery reads and stores the requested history range. The service reuses the snapshot during pagination and appends newer finalized signatures on the next scan.

Disclosure errors leave unresolved history. Only a finalized event marks a note spent.

`getAuditedMerges` lists each finalized merge the backfill opened. The service opens the merge's sealed record and accepts it only when the record and its seed rebuild the published output. The result is an audit record of the output's owner, asset, mint and amount and the real input nullifiers. A merge the backfill has not opened stays out of the page.

## Balance status

`getWalletStatus` lists one wallet's unspent notes as of `historyThrough`, the finalized slot the service verified. Only an unreadable frame holds `historyThrough` back, and an unresolved spend never does. A note created past `historyThrough` stays out, so a spent input and its change never both count. A spent note leaves the list once its spend slot is at or before `historyThrough`. Until then it reads `unspent`. The first page's `balances` sums all unspent notes in that snapshot. Later pages return an empty `balances` list.

With a store, the service reads each wallet from an index of the owner's notes. Owner and note are keyed tags, and each row is sealed under the auditor key. The page commit that records a spend marks the note's row with the spend slot. The next commit deletes the row once its history slot covers that spend, so a read never meets a settled spend. A read of a slot older than the spend still finds the note. `cursor` binds the ring, wallet and retained snapshot. Later projection changes do not alter its captured notes. Each page checks current authorization and the same reader principal. The same contract applies to delegate note pages. `snapshotExpiresAt` gives the fixed Unix expiry on every retained page, including the final page. It is absent when one page needs no retained snapshot. The default lifetime is 300 seconds, with at most 1,024 retained snapshots per store and two per ring, principal and wallet. An expired or released cursor returns `-32172`. Restart without a cursor and discard the earlier pages. Capacity exhaustion returns `-32173`.

`releaseWalletSnapshot` takes a wallet-status request with a required cursor, signed under `zolana/ring-rpc-wallet-snapshot-release`. `releaseDelegateSnapshot` takes a delegate-notes request with a required cursor, signed under `zolana/ring-rpc-delegate-snapshot-release`. Both return `true`, check current authorization and release that session. Cleanup removes captured rows in bounded batches. Clients retain a page cursor until release, even after the final response omits its next cursor.

The cursor is base64 of `u8(2) || ring[32] || wallet[32] || snapshot[32] || after[32]`. Each session has its own snapshot id. A note with no readable secret reads `unknown` and never counts, and a zero key note of an Ed25519 owner reads `exposedIfSpent` outside the balance. Activity after `historyThrough` can spend a listed note. `enrollment` reports the owner's authorization state as `notEnrolled`, `pending`, `pendingPastCapacity` or `applied`. A pending authorization grants no tracking membership.

`getSpendCoverage` is the one read that lists unresolved spends by nullifier. Only the ring authority signs it, and a reader grant never reaches it. It pages unresolved rows, unreadable frames and repeated nullifiers in `integrityFaults`, with at most 100 entries per stream. The first page includes `totals` with `observed`, `padding`, `address`, `external` and `resolved` counts. Responses to continuation cursors omit `totals`. Its optional base64 cursor resumes each stream independently. The signed message adds `cursor: <base64>`, or an empty value on the first page. A completed stream stays empty. The response omits its cursor only when all three streams finish. With a store, each page reads one database snapshot. Later pages read current state and require the current authority. No snapshot is retained between pages.

The first database page aggregates totals in `O(H)`, where `H` is the ring's retained spend history. Database continuation pages skip that aggregate and use bounded indexed detail reads plus metadata queries. Without a store, each detail page scans the retained collections.

A deployment uses fresh registries, indexer records and RPC operation state. Relay completion, record application and blockhash expiry require finalized state.

## Operation

The server accepts loopback binds only, put a TLS proxy in front of it for remote clients. `--insecure-public-bind` lifts that for a test deployment and serves the decrypted audit data over plain HTTP. Keep the proxy request body limit at or below the service limit.

The TypeScript SDK and `zolana-ring` CLI take a service base URL and append the JSON-RPC method, preserving its query parameters. For example, `https://ring-rpc.example?api-key=KEY` becomes `POST /ringStatus?api-key=KEY`. In `ring.toml`, use `ring_rpc = "https://ring-rpc.example?api-key=${RING_RPC_API_KEY}"` to load the key from the environment.

A call posted to any path but `/` runs only when its JSON-RPC body is one call naming the path's last segment: `/ringStatus` and `/v1/zolana/ring/ringStatus` run `ringStatus` and refuse every other method with HTTP 400 and JSON-RPC error `-32601`. A gateway that routes and prices by path therefore prices the method that runs and does not bill these refusals as successful calls. `/` remains available to existing self-hosted JSON-RPC clients. Proxies must preserve the method path; rewriting it to `/` removes the path check.

The check runs before RPC execution and nonce consumption, so a gateway forwards the body without inspecting it. Disable automatic proxy retries of signed POST requests: a 5xx or lost response does not prove that the call's nonce was unused, so the caller handles the outcome rather than a transparent resend.

`GET /health` reports the service identity. `GET /ready` checks Photon and Solana RPC. In local mode it also checks that the ring policy still names the auditor key held here. In derived mode it re-reads the cluster genesis hash and fails when it differs from the one captured at boot, because that hash binds every derived key. A failed probe names the check in the response body.

Three lanes admit every JSON RPC method but `health`, and each lane has its own one-second request window. `ringStatus` takes the public lane, the one lane without a concurrency cap. `createAuditorKey` and `getAuditedUtxos` take an authentication slot, since they verify a signature and read the chain. `getDecryptedTransactions`, `getWalletActivity` and `getAuditedMerges` release the authentication slot after the read authorization and hold a read slot for the page. A reader runs one read request at a time on each ring. `GET /ready` takes no lane, runs one upstream probe at a time and answers from its last result for one second. Key files must have owner access only unless the operator selects the shared file option.

## Rate limiting

Every JSON RPC call spends a token from its client's bucket before it runs, one bucket for each client and method class. Public reads are `health`, `ringStatus`, `getRecordUpdateStatus`, `getRelayQuote` and `getRelayStatus`. Signed reads are `createAuditorKey`, `getDecryptedTransactions`, `getWalletActivity`, `getAuditedMerges`, `getAuditedUtxos` and `getPendingListApprovals`. Every other method is a signed write, record updates and list approval refusals included. A bucket refills at its per-minute rate up to its burst. The lanes above still bound the whole service.

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
