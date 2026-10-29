# Anonymous rings

An anonymous ring is a custom ring whose config holds `RingMode::Anonymous`. A
transfer of ring notes inside it hides the sender and the recipient, amount
and asset of each ring output from a chain observer. The ring auditor reads all
of them. Each ring output carries a view tag and an encrypted body. The audit
proof opens each ring output's owner key and each output's asset and amount to
the auditor, and it checks neither the tag nor the body.

The tags, the body encryption and the sync follow zolana's
[View Tags](../zolana/docs/spec.md#view-tags),
[AES Key derivation](../zolana/docs/spec.md#aes-key-derivation) and
[First Time Sync Wallet](../zolana/docs/spec.md#first-time-sync-wallet). The
ring SDKs take the view tag derivations and the scheme numbers from zolana and
encode the plaintexts with their own codecs. The byte layouts are in
[Ring Address](../sdk-libs/keys/src/ring_address.rs),
[anonymous plaintexts](../sdk-libs/transaction/src/anonymous_plaintext.rs),
[ring deposits](../sdk-libs/transaction/src/ring_deposit.rs) and
[Transact](spec.md#20-transact).

## Roles

A **sender** spends ring notes, and a **recipient** holds the keys behind an
address. The **hidden owner** is the sender of an anonymous spend. Its Ed25519
key signs the spend inside the SPP proof.

A recipient learns the asset, the amount and the blinding of each note it
receives. The body also names the viewing key of its sender, and no proof
checks that key.

The **auditor** opens every transfer. It reads the hidden owner's key, every
spent note, every recipient's owner key, every amount and every asset. See
[What the auditor reads](auditing.md#what-the-auditor-reads).

The **payer** is the SPP payer account, and it signs the transaction. Among
the SPP accounts the ring program accepts no other signer. Nothing on chain
checks the transaction's Solana fee payer against the hidden owner. The
TypeScript builders make the SPP payer the Solana fee payer, and Rust's
`RingSubmission` refuses a fee payer that is the hidden owner.

The **indexer** serves outputs by exact tag, spends by nullifier and Merkle
paths by leaf. It sees which tags, nullifiers and leaves a wallet asks for, and
a sync asks for the tags of one stream together. A wallet trusts it to return
every match. A paged read fails when the indexer repeats a cursor. A wallet
that needs unlinkability runs its own indexer.

A **chain observer** sees the ring, the shape, the payer, the Solana fee payer
and the co-signer. It sees the Solana slot, every tag, the length of every
body, and every public deposit and withdrawal. A bootstrap tag
shows it the recipient's viewing key. A transfer that spends default-ring notes
publishes the hidden owner's key. An exit publishes its owner. No other output
names its recipient to the observer.

## Creating an anonymous ring

Anonymity is fixed when the config is created. With the CLI, set
`mode = "anonymous"` in `ring.toml`, or select it in `zolana-ring new`, before
the first `init`. An anonymous ring can be a policy ring or audit-only. It
refuses key registration and so key escrow, because its auditor already holds
every opening. It refuses a delegate, because a delegate signs for an owner
the ring hides.

## Addresses

A **ring address** names one recipient inside one ring by its shielded address
and the ring program id. See [Ring Address](../sdk-libs/keys/src/ring_address.rs).
Every holder of the address learns the recipient's signing key and viewing key.

A **payment request** is the `zolana:` form of an address with a request view
tag and an optional amount, mint and label. The recipient mints each request
from its request counter with `ViewingHistory::request_tag` and stores the
advanced history before it shares the request, so no two requests share a tag.
The checksum covers the address alone, so a sender treats the rest of the
request as a suggestion. `zolana-ring address` mints the next request of the
CLI's sender keypair and prints it.

## View tags

Every anonymous ring output publishes a 32-byte view tag as its owner tag. The
wallet takes it by [View Tag Selection](../zolana/docs/spec.md#view-tag-selection)
over the counters of its viewing history.

1. Output 0, the first change output, takes the transfer's sender tag, the
   next `get_sender_view_tag(tx_count)`. A second change output takes a dummy
   tag and opens from the sender bundle. A deposit to the wallet's own note
   takes the next sender tag too.
2. A payment to a known recipient takes the pair's next shared tag.
3. A first payment takes the recipient's request tag or its bootstrap tag, the
   recipient's `u`. The caller picks one per recipient with
   `FirstContact::Request` or `FirstContact::Bootstrap`, and the SDK never
   falls back from one to the other.
4. A dummy takes `0x00` and 31 random bytes, laid out as a derived tag.

A first transfer payment makes the recipient known to the sender's history,
and the recipient learns the sender from the body. Both then use the pair's
shared tags.

## Sending

Each payment names its recipient by a ring address and its first-payment tag.
In Rust `with_payment` takes an `AnonymousPayment`, and `AnonymousMove` takes a
`RingPayment` from `RingPayment::bootstrap` or `RingPayment::to_request`. A ring
output to another owner without a payment fails before proving, and so does a
recipient key that admits no X25519 agreement.

The counters advance when the wallet builds the transfer.
`AnonymousTransfer::viewing_history` returns the history past the transfer's
tags. Store it before the transfer is sent, or a later transfer reuses the
tags. Every proving attempt of one transfer takes the same tags.

## What the proof covers

For every output the audit proof shows that

1. a ring output's owner is the identity of the owner key the disclosure opens,
2. every live output's amount lies below `2^64`, and the disclosure opens its
   asset and amount,
3. every blinding is SPP's output blinding under the seed the transaction key
   and the salt fix, and
4. no live output carries a data hash or ring data.

For the spend it shows that every spent note is the hidden owner's, that
`private_tx_hash` reopens over the same notes, and that each party identity
differs from the hidden owner. On a policy ring the sender commitment opens to
the hidden owner.

The proof derives no view tag and opens no body. A wrong tag or a body sealed
to the wrong key costs the recipient the note, as a payment to a wrong address
does. It gains the sender nothing, because the sender's inputs are already
spent, and the auditor still opens the output. The ring program keeps the ring
data hash of a deposit and a merge output on an anonymous ring zero, and
refuses the delegate rail there.

## Output layout

Every output slot of an anonymous transfer is published, so the slot count
shows only the shape. The bodies are the scheme 1 recipient and scheme 2
sender bundle plaintexts. An exit is a default-ring output under its owner's
tag.

1. Output 0 is the sender's change, a zero-amount note when nothing returns.
   SPL change leads SOL change. A change output carries its tag and no body.
2. The sender bundle, scheme 2, is the first SPP message, under the sender's
   tag and sealed to the sender's own viewing key at the output count. It holds
   the change amounts and mint, the seed every change blinding derives from,
   and one recipient viewing key per output after the change, in output order.
   An exit or a dummy takes the dummy key `0x04 || 0^32`. The zolana sender
   bundle lists recipients only, so the dummy key is a custom-ring extension,
   and a sync never adds it to the known recipients.
3. A payment carries a scheme 1 body sealed to its recipient at its output
   position, with the owner key, the mint, the amount, the sender's viewing
   key, the blinding and the data.
4. A dummy carries random bytes of a payment body's length.

A reader keeps a note only when its rebuilt hash equals the published output
hash. The change takes at most one SPL and one SOL output, and a zero change
only alone, because a zero amount reads back as no output.

The program checks only that the sender bundle is not empty. An empty body
marks a change output, so an observer tells change from payments and dummies.
A second change output takes a dummy tag, and its empty body still marks it as
change.

## The anonymous SPP rail

An anonymous ring settles a member transfer on SPP's `AnonymousRingEddsa`
rail. The hidden owner signs the
[ring spend message](../program-libs/interface/src/proof/statement.rs). The circuit
verifies the signature and checks that the ring program id the owner signs is
the transfer's ring.

Three parties are public, and the circuit proves each one distinct from the
hidden owner:

1. The SPP payer.
2. The ring's co-signer, or the zero address when the ring has none.
3. The key every withdrawal names, or zero without a withdrawal.

A transfer can spend the hidden owner's default-ring notes in place of ring
notes. It then publishes the owner's key as its default owner tag, and one
transfer cannot spend both kinds. Such a transfer proves under the anonymous
entry audit key and opens every spent note to the auditor. The SDKs select ring
notes alone unless the sender allows default-ring notes. Rust's `AnonymousMove`
allows them with `EntrySpend::Allow`, and the CLI with
`transfer --funding held --entry-spend allow`. A TypeScript transfer allows
them with `inputs` of `"ring-or-default"` or `"default"`, and
`createRingEntrySubmission` spends them alone.

`AnonymousSpendSigner` produces the signature, so the hidden owner's key can
stay outside the process that proves. In Rust `spr_keypair::SigningKey` and
`ed25519_dalek::SigningKey` implement it, and a hardware or remote signer
implements it itself.

The SDKs refuse a payer or a co-signer equal to the hidden owner before they
prove. They also refuse a withdrawal destination that names the hidden owner
or its associated token account. The sender names the owner of a token account
the transaction creates, with `with_exit_token_owner` in Rust or
`exitTokenOwner` in TypeScript. The SDK accepts that account only as the named
owner's associated token account.

## Deposits and merges

A deposit into an anonymous ring discloses its owner key to the auditor. See
[Deposits](auditing.md#deposits). A deposit to the depositor's own note takes
its next sender tag, and a deposit to another member takes a tag by the
selection above. In Rust `DepositRecipient::Anonymous` and
`DepositRecipient::AnonymousPayment` name the two, and
`RingDeposit::viewing_history` returns the history to store before the deposit
is sent. In TypeScript `PreparedRingDeposit.viewingHistory` returns it, and
`buildRingDepositTransaction` refuses an anonymous recipient. A deposit body
names no sender, so a deposit pairs neither side, and the next payment to that
recipient takes a first-payment tag again. The ring sync opens the scheme 8
deposit body with Rust `DepositOpener` or TypeScript `openRingDeposit`. It
keeps the note only when the note rebuilds the published hash.

A merge consolidates notes of one owner without the owner's signature. See
[Merges](auditing.md#merges).

## Policies

An anonymous policy ring runs the same rule table as a confidential one. The
sender is the hidden owner. The audit proof and the policy proof both bind one
blinded hash of the hidden owner's key, so the policy screens the owner who
spends. Every spent note belongs to that owner, and the rules read the
records of the owner, of every output owner and of every output asset.

## Wallet sync

A wallet keeps one `ViewingHistory` and stores it as key material between
syncs, because its counterparties link the wallet's payments. It holds one
entry per retained viewing key, oldest first, with the fields
[First Time Sync Wallet](../zolana/docs/spec.md#first-time-sync-wallet) lists.
Each stream counter also keeps a watermark, the index the next sync resumes
from. `AnonymousSync` runs the anonymous-ring steps of that section for every
entry whose viewing key the wallet holds.

1. Each round reads the sender stream, the request stream and the shared
   stream of every known counterparty, all their tags batched into indexer
   requests of `TAGS_PER_REQUEST`. The first round also reads the bootstrap
   tag. A stream's first round reads from its watermark to `TAG_GAP` indices
   past its next index, each later round reads on with the gap doubled up to
   `TAGS_PER_REQUEST`, and the stream stops after a round that finds nothing.
2. Each matched recipient body opens at its output position and gives a note
   and the viewing key of its sender. A matched sender bundle opens at the
   output count and gives the wallet's change, and its recipients when the
   wallet's own transaction key derives the published one. A matched deposit
   gives its note. Each new key joins the known senders or the known
   recipients.
3. A counterparty learned in a round joins the next one.
4. The spends of every found or held ring note mark it spent and find the ring
   merges among them.

A note counts only when it rebuilds the published hash under the mint its
plaintext names. A body that fails to decode, names another owner or rebuilds
no note is skipped and never fails the sync. `unmatched` lists the outputs whose
body decoded as the wallet's and rebuilt no note.

An index a sync passes unseen below the highest one it saw stays pending while
it lies within `PENDING_RETENTION` of the watermark, and every later sync asks
for it again. A transfer that lands after a later one is therefore still found.
`with_full_rescan` reads every stream from index 0, for a wallet that keeps no
notes between syncs.

A sync that opens the wallet's change at output 0 also opens each listed payment
with the transaction viewing key and reports it in `sent`. A payment is
`SentCheck::Verified` when an address passed to `with_recipient_addresses`
names its owner and viewing key and rebuilds the published hash. Otherwise it
is `SentCheck::Unverified`, and its owner, amount and recipient are what the
wallet's own body claims.

A restore starts a new `ViewingHistory`, whose watermarks start at 0. The change
bodies list every recipient the wallet paid and the recipient bodies name every
sender, so its first sync rebuilds both maps. `ViewingHistory::from_json`
refuses a stored history of another version. `with_rotated_key` appends a newer
viewing key, a transfer runs from the current key only, and a sync still reads
every earlier key the wallet holds.

A wallet whose viewing secret is kept in a remote key holder syncs the same way.
`RingKeys::view_tags` derives the sender and request tags,
`RingKeys::shared_view_tags` returns one pair domain per counterparty, and
`ShieldedKeys` decrypts the bodies and derives the viewing keys of the wallet's
own transactions. The viewing secret never leaves the key holder.

## Integration

### Rust wallet

1. Start the wallet's `ViewingHistory` from `zolana-ring-client` with
   `ViewingHistory::new(viewing_pubkey, created_at)`, and store it with
   `to_json` after every change.
2. To receive, share the `RingAddress`, or a `RingPaymentRequest` with a tag
   from `request_tag` once the history it returns is stored.
3. To sync, build `AnonymousSync::new(keys, assets)`. Pass the wallet's notes
   to `with_held_notes` and the addresses it pays to
   `with_recipient_addresses`. Call `fetch(indexer, history)` and store the
   history the scan returns.
4. To pay, build a `CustomRingTransfer`, call `with_anonymous_signer` with the
   hidden owner's signer and the history, and add one `with_payment` per
   recipient. `AnonymousMove` selects the notes and the shape for a list of
   `RingPayment`s. Store `viewing_history()` and submit through
   `RingSubmission`.

### TypeScript wallet

1. Start the wallet's `ViewingHistory` from `@heliuslabs/zolana-custom-rings`
   with `ViewingHistory.create(viewingPublicKey, createdAt)`, and store
   `toJson()` after every change. The keys implement `RingKeys`, and
   `LocalRingKeys` does.
2. To receive, share the `RingAddress`, or a `RingPaymentRequest` with a tag
   from `requestTag` once the history it returns is stored. Both come from
   `@heliuslabs/zolana-custom-rings/keypair`.
3. To sync, build `AnonymousSync.create(keys, assets)`, pass the wallet's notes
   to `withHeldNotes` and the addresses it pays to `withRecipientAddresses`.
   Call `fetch(indexer, history)` and store the scan's `history`.
4. To pay, call `createRingTransferSubmission` with `anonymous` holding the
   hidden owner's signer and the history. A `RingPaymentRequest` recipient
   takes its request tag, and a bare `RingAddress` needs
   `anonymous.firstContact`. Store the submission's `viewingHistory` before
   the first `send`. Exits, entries and withdrawals go through
   `createRingExitSubmission`, `createRingEntrySubmission` and
   `createRingWithdrawalSubmission`. The plain `buildRing*Transaction`
   builders return no history and refuse an anonymous ring with
   `RING_ANONYMOUS_SUBMISSION_REQUIRED`.

## Limits

Owners are Ed25519 keys. A ring output carries no data. An anonymous transfer
carries no SPP address slot, because its audit proof rebuilds
`private_tx_hash` with an empty address chain. The Rust SDK refuses such a slot
before signing.

The anonymous commitment keys serve 2 and 4 outputs up to 16 spent notes and 8
outputs up to 8, and the entry key serves up to 8 default-ring notes at 2, 4
and 8 outputs. See [the shapes](../README.md#shapes). Through a relayer, an
8-output transfer that spends more than 5 notes, or any 8-output transfer on a
policy ring with a co-signer, exceeds the transaction size limit and fails
assembly with `TransactionTooLarge`. `every_transfer_shape_takes_its_pinned_transaction_size`
pins the size of every shape.

A first payment under the bootstrap tag publishes the recipient's viewing key.
See [the limitation](spec.md#a-bootstrap-payment-names-its-recipients-viewing-key).

Scan cost grows with the counterparties of each viewing key and the wallet's
own spends. Each known counterparty that sends nothing adds `TAG_GAP` tags to
every sync, and no limit applies to the counterparties a viewing key learns.
Ring traffic does not add to it.

A merge spends at most 24 notes.
