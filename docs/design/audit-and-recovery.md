# Audit and recovery

The auditor holds one viewing key for the ring's life. Every operation proves a record that key opens. Recipient delivery stays outside every proof. [Spec](../spec.md)

## Transfers

- The sender draws a transaction viewing key. The transfer proof seals its secret to the auditor in one AES-256-CTR stream.
- The key schedule binds the auditor key, the transaction key and a salt. A resend repeats the key, and a fresh salt gives a different keystream.
- The stream contains an envelope, one record per published slot and, under `has_data`, one data tail per slot.
- A record contains the kind, amount, owner key and nullifier key. The standard format carries its mint in each record. A single-asset payout carries the common mint in its envelope. A dummy's record is all zero, so the auditor skips it by its kind byte.
- The proof holds every published blinding to a derivation from the sealed key, the salt, the first nullifier and the slot index.
- The auditor rebuilds each commitment from its record and that blinding. It needs no other slot, no history and no mint registry.
- A record of another slot rebuilds no published hash, so the reader refuses it.
- The program builds the ring statement from the frame it forwards to SPP, so the proof binds the transfer that settles.

## Spent notes

- A ring input takes no record. The envelope seals `R`, the count of spent notes, and `A`, the bitmap of address positions.
- Notes and addresses interleave in SPP's order before the dummy suffix. Let `L = R + popcount(A)`. Input `k < L` is an address when bit `k` of `A` is set and a spent note otherwise. Input `k >= L` is padding, see [envelope plaintext](../spec/crypto/disclosure.md#envelope-plaintext).
- The auditor recomputes a nullifier from an opening it already read and the owner's sealed secret. It then matches SPP's published list, and a match links the spend.
- No constraint binds a nullifier to a record. A note the auditor never opened stays unlinked until the opening arrives.
- A default-ring input has no earlier record. An entry key therefore names it in the stream, with its owner key, nullifier key, amount, mint and spent commitment.
- An entry record discloses no blinding, data hash or secret, and one frame can carry default-ring inputs of several owners.

## Exits and withdrawals

- An exit's record has its own kind and opens the created default-ring note for the auditor.
- An exit's recipient body is SPP's confidential output form, in the same layout as a default-ring transfer. No ring proof binds it.
- A withdrawal adds no stream bytes, since SPP publishes its asset, amount and destination.

## Nullifier secrets

- A wallet has one nullifier secret. Enrollment seals it to the ring's auditor key beside the wallet's list salt, and the program verifies the seal proof, see [tracking](records-and-roots.md#tracking).
- The tracking authorization keeps the ciphertext in an account. A restarted auditor checks each row the ring indexer serves against the tracking root and each seal against the row's `ct_hash`, then opens the seal.
- A tracking scan that has not reached the root's next index is no evidence that an owner is unenrolled.
- With a secret the auditor derives the nullifier of any note whose hash and blinding it knows. The derivation reaches every ring and the default pool.
- One leaked secret therefore exposes that wallet's spends across every ring it enrolled on. A wallet that wants separation uses another keypair per ring.
- A note under the zero nullifier key carries no secret. Its sender and the auditor both compute its nullifier, see [zero-key notes](owner-rails.md#zero-key-notes).

## Recipient delivery

- Recipient encryption and discovery tags stay outside the circuit. The proof constrains no body, tag, reply or sender bundle.
- SPP's external data hash binds the bytes a frame submits. A replaced byte fails SPP's verification, and a correct proof says nothing about what those bytes contain.
- A transaction with a correct proof can therefore carry a body or a tag its recipient cannot use. Nothing promises delivery.
- A full scan repairs a bad discovery tag. It never repairs a wrongly encrypted body, since no held key rebuilds that note's commitment.
- Auditor recovery is a separate authorized fallback. It depends on Ring RPC, and an owner with no Ring RPC cannot open a note under a bad body.

A standard recipient body contains the blinding, amount and mint. A compact payout body replaces the mint with its authenticated asset id. A note that commits a ring data hash or application data carries them after those fields. The cipher has no authentication, so the commitment a reader rebuilds under its own keys is the only proof of ownership.

The sender's SDK resolves a nonzero-key recipient through its tracking row under a root it verified, and seals to the viewing key of the owner's authorization account. It refuses an owner with no applied row. It also refuses a row whose nullifier key differs from the address, or whose list tag the address's salt does not open. That check protects an honest sender and binds nobody else.

## Auditor fallback

- `getWalletStatus` returns each of the wallet's notes with its opening, read from the proven record. The nullifier key stays absent on a deposit whose owner the service has not resolved. A wallet under an unusable body rebuilds its note from that opening.
- A wallet authorizes the read with its signature. A program cannot sign off chain, so it writes an `OwnerGrant` account through CPI that names a reader key.
- The fallback covers notes the service opened.

## Wallet scanning

- `AnonymousSync` reads the history of each ring the wallet's `ViewingHistory` names, then tests each slot and bundle tag for each held key.
- The key holder runs one agreement per candidate per key and returns a slot secret on a match. Raw agreements stay inside the holder.
- A deposit is found through its tag stream. A nonzero-key merge is found from its nullifiers, and a zero-key merge from the owner tag SPP publishes.
- Full recovery reads a ring from its first row and tries every output and message without a tag. Rust uses `AnonymousSync::new(keys, assets).with_full_scan(ring).fetch_wallet(indexer, wallet)`. TypeScript uses `fullScanWallet(client, wallet, ring)`.
- A body a full scan leaves unopened stays in `auditor_recovery.unopened`, foreign notes and dummies among them.
- A wallet tries its enrolled key and the zero key on every body, so a note received before enrollment stays recoverable.
- A zero-key note enters the wallet as exposed if spent. No automatic path selects it.
- Only a final page's `context.slot` becomes a stored position. A failed page moves nothing, and a key added later is its own query.
- `AnonymousWallet` contains notes, pending notes, spends, reply claims and positions in one document. `absorb` takes a scan's results together, so a position is never saved without what it covers.
- A standard body under an unknown mint can stay pending until mint resolution. A compact body establishes no ownership until authenticated asset resolution rebuilds its commitment.
- `RotatingRingKeys` contains one identity's current and retired viewing keys, so a note sealed to any of them opens.
- The CLI refuses a wallet store that contains no entry of the wallet's viewing key.

Durable recovery fixes its target slot and stores its continuation with the wallet. `Paused` means coverage is incomplete. Absorb each returned scan, then repeat the same durable call and scan scope. Rust full scans keep `with_full_scan(ring)`. TypeScript full scans repeat `fullScanWallet` with the same ring.

An unspent note whose nullifier check has not reached the target reads `PendingSpendCheck` in Rust or `pendingSpendCheck` in TypeScript. Wallet balances and exposed-note lists omit it. Rust `funding_notes` also omits it. `notes` remains the full inventory. Rust `require_complete` refuses an unfinished session.

TypeScript compact SPL recovery requires `withCompactAssetClient` and a durable wallet call. A missing client returns `RING_SYNC_INCOMPLETE`. Lookup budget exhaustion or transient source errors pause the session.

TypeScript sets its target at or above the saved recovery floor, ring and tag positions, core checkpoints, private-transaction slots and configured `requireSlot`. The recovery floor retains the highest committed target or authenticated note observation. Imported notes without publication slots supply no additional floor.

History-only calls do not preserve a wallet recovery session. A paused Rust `fetch` or `full_scan` result must be absorbed and resumed through `fetch_wallet`. TypeScript `fetch` and `fullScan` refuse compact SPL recovery with `RING_SYNC_INCOMPLETE`. Use `fetchWallet` or `fullScanWallet` for that format.

## Deposits and merges

- A deposit is a transfer that spends no note, and its outputs open through the auditor stream.
- A merge seals one opening record of the output, followed by the seed. The auditor rebuilds the published hash from that record and the first nullifier.
- SPP's proof ties every merge input to that owner, asset and sum. The ring proof therefore opens no inputs, and one ring key serves every width.
- SPP's merge publishes no auditor message, and no external data hash covers the record. The auditor reads the ciphertext from the ring instruction, and the statement alone binds those bytes.
- The merge's seed also classifies its padding nullifiers. Its real nullifiers mark inputs through the note index.

## Reading through Ring RPC

- Ring RPC enumerates finalized signatures and binds each indexed event to the canonical transaction.
- Missing or altered indexed events stop the page before coverage advances.
- Each published nullifier takes one state. A position at or past `L` is padding, and an address position spends no note. A default-ring position is external, and a note index hit resolves the rest.
- A real nullifier with no hit stays unresolved. It never reads as padding or unspent, and a later opening resolves it.
- One database transaction per finalized page commits the rows, the notes and the position.
- `getWalletStatus` derives each note's status from that note's own nullifier. An unresolved spend elsewhere never changes it, and the response names no other transaction.
- Only an unreadable stream stops `history_through` for every wallet. The balance sums `Unspent` notes, and `Unknown` and `ExposedIfSpent` stay out of it.
- `getSpendCoverage` is the one read that names an unresolved spend, and it serves the ring authority alone.
- `getDelegateNotes` hands the owner's openings and nullifier secret to the ring's configured delegate alone. No other read returns a nullifier secret.
- A co-signer reads debits from the frame and the note index. A real input with no note index hit is refused with `LimitsUnavailable`.

Member recovery returns a bounded sample of unmatched input nullifiers and their total count. The sample does not establish complete spend coverage.
