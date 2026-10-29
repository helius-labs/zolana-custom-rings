# Anonymity Walkthrough

A custom ring is a Solana program that governs its notes in the zolana shielded pool (SPP). SPP moves a ring note only when the ring program signs, and the ring program signs only after it verifies the ring's proofs. Every transfer carries an audit proof that the ring's auditor key opens it. An anonymous ring also hides the sender and the recipient of each transfer from chain observers. The auditor still opens every transfer. [Spec](spec.md)

## Terms

### Mode

A **mode** fixes the rail of every transfer on a ring. `Initialize` sets `Anonymous` for the `Anonymous` and `AnonymousPolicy` ring kinds and `Confidential` for the `AuditOnly` and `Policy` kinds (`programs/custom-ring/src/instructions/configuration/setup/initialize.rs:67`).
- `Confidential`: owners sign in public, and each ring output publishes its recipient's viewing key.
- `ConfidentialEscrow`: `Confidential` with key escrow and a delegate. Each output owner's nullifier secret is sealed to the auditor, and the delegate can move escrowed notes.
- `Anonymous`: the sender and the recipient are hidden from chain observers.

### Rail

A **rail** is the signing form of a transfer. The instruction tag and the mode select it, never the frame, the transfer's compact instruction data (`RingRail::of`). The payer is SPP account `0` and pays rent and fees. A co-signer is an optional key with its own `CoSigner` record. The program demands its signature when its scope or an outflow limit names the operation.

| Rail | Mode | Who signs | SPP circuit |
| --- | --- | --- | --- |
| Confidential | `Confidential`, `ConfidentialEscrow` | Each owner signer, the payer and a demanded co-signer | `ConfidentialRingEddsa` |
| Anonymous | `Anonymous` | The SPP payer and a demanded co-signer. The hidden owner signs inside the SPP proof. | `AnonymousRingEddsa` |

A third rail, the delegate rail, runs `AuthorityTransfer` in `ConfidentialEscrow` mode only.

### Hidden owner

The **hidden owner** is the sender on the anonymous rail. Its Ed25519 signature verifies inside SPP's proof, so its key never reaches the chain. Every spent note belongs to it.

### Ring address

A **ring address** is the recipient's shielded address and the ring program id. The shielded address carries the recipient's signing key, nullifier key and viewing key `u`. `u` is an X25519 public key, and only the recipient holds its secret. A **payment request** adds a request view tag the recipient minted. Both are shared off chain.

### View tag

A **view tag** is the 32-byte owner tag SPP publishes for each output. On a confidential ring it is the recipient's `u`. On an anonymous ring it is one of zolana's [view tags](../zolana/docs/spec.md#view-tags), and a recipient finds its notes by asking the indexer for the tags it derives.
- The **sender tag** `get_sender_view_tag(tx_count)` derives from the sender's own viewing secret. Output 0, the first change output, takes it. A second change output takes a dummy tag and opens from the sender bundle.
- The **request tag** `get_recipient_request_view_tag(request_count)` derives from the recipient's viewing secret. The recipient puts it in a payment request.
- The **bootstrap tag** is the recipient's `u`. Anyone who holds the address derives it.
- A **shared tag** derives from the X25519 agreement of the sender's and the recipient's viewing keys and an index. Only the two holders derive it.

### First payment

A **first payment** is a payment to a recipient the sender's viewing history does not hold. It takes the recipient's request tag or its bootstrap tag, as the caller chooses. Its body names the sender's viewing key as `sender_pubkey`, so the recipient learns the pair, and both sides take the shared tags afterwards. No proof checks `sender_pubkey`.

### Party identities

The **party identities** are `solana_owner_identity` of three public keys, `0` when absent: the payer, the signing co-signer, and the one withdrawal destination key. `solana_owner_identity(key)` is `hash_bytes(0x53 || key)`, the owner identity zolana stores in a note. The Solana fee payer of the outer transaction is no party identity, and the program does not check it.

### Entry spend

An **entry spend** spends default-ring notes, the SPP notes outside every ring. It publishes the hidden owner's identity as `default_owner_tag`, so it names its sender. It cannot also spend ring notes.

## Logic

**The sender stays hidden.** The program refuses every SPP signer but the payer. The hidden owner signs inside SPP's proof. The audit proof shows the hidden owner differs from each party identity.

**The recipient stays hidden.** A request tag and a shared tag derive from viewing secrets an observer does not hold. Each body is sealed from the transaction viewing key to the recipient's viewing key at its output position, and no proof covers it. The auditor reads every output's owner key, asset and amount from the proven disclosure.

**A first payment turns into shared tags.** The recipient's sync opens the first payment, adds `sender_pubkey` to its known senders and reads that pair's shared tags from then on. The sender bundle lists the recipient's viewing key, so the sender recovers the pair from its own transfers.

### Example: Alice pays Bob twice

Bob mints a payment request and gives it to Alice. Alice pays from Alice's ring notes. A relayer, a third party that submits and pays for the transaction, is the payer.

```
Payment 1:  output 0, Alice's change   get_sender_view_tag(t) of Alice
            output 1, Bob              Bob's request tag
Payment 2:  output 0, Alice's change   get_sender_view_tag(t + 1) of Alice
            output 1, Bob              get_send_shared_view_tag(Bob, 0) of Alice
```

<aside>

**Requirement:** the relayer and the Solana fee payer do not link to Alice **AND** Alice pays the request tag, not Bob's bootstrap tag.

</aside>

| Observer | Payment 1 (request tag) | Payment 2 (shared tag) |
| --- | --- | --- |
| Chain observer | The relayer, every tag, every body's scheme and length, and the output hashes. Not Alice, not Bob. | The same. No tag links it to payment 1. |
| Any holder of Bob's ring address | Bob's signing key and `u`. The request tag does not derive from them, so the holder cannot find payment 1. Under the bootstrap tag every observer would read Bob's `u` from the output. | Nothing. The shared tag needs Alice's or Bob's viewing secret. |
| Bob | Finds the request tag, opens the body and reads Alice's viewing key as `sender_pubkey`. | Derives the shared tags of Alice's key and finds payment 2. |
| Auditor or Ring RPC reader (Ring RPC holds the auditor key and serves openings to granted readers) | Alice as sender, Bob's owner key, the asset, the amount and Alice's spent notes. | The same. |

### Adding an exit, a withdrawal or a default-ring spend

An exit pays a default-ring note, and its owner is public. A withdrawal pays SOL or a token to a public account.

| Leg | Public | Checked |
| --- | --- | --- |
| Exit to key `K` | `K` as the exit's owner | SPP's proof refuses `K` equal to Alice's key on a ring spend. |
| Withdrawal to `D` | `D`, the mint and the amount | All withdrawals of the transfer name one `D`, and the audit proof shows `D` differs from Alice. |
| Default-ring spend | Alice's identity as `default_owner_tag` | The auditor gets full openings of every spent note. |

Each leg puts one more key on chain. No check finds a `K` or a `D` that belongs to Alice under another key. Alice stays hidden only when no one links `K` and `D` to Alice and Alice spends no default-ring note.

## What the circuit proves

The program rebuilds the anonymous audit statement, the public values the proof binds, from the frame and the accounts. The circuit binds three things:

1. **The sender to the spent notes**: every spent note is the hidden owner's and reopens SPP's `private_tx_hash`, the blinded hash over the spent note hashes and the output hashes that SPP's proof binds. The hidden owner differs from the payer, the signing co-signer and the withdrawal destination.
2. **Each output to the disclosure**: a ring output's owner is the identity of the owner key the disclosure opens, every live output's asset and amount are disclosed, every blinding derives from the sealed key, and no output carries data.
3. **The auditor message to the transfer**: it seals `tx_viewing_sk` to the auditor, opens every output, and names every spent note by hash and 16-byte prefixes, or by full openings on an entry spend.

Not proven: no layer checks an exit owner or a withdrawal destination for a link to the hidden owner. No proof derives a view tag or opens a body, and none checks `sender_pubkey`. A wrong tag or a body sealed to the wrong key costs the recipient the note and gains the sender nothing, and the auditor still opens the output. A tag can repeat across transfers.

See [Anonymity breaks when its conditions fail](spec.md#anonymity-breaks-when-its-conditions-fail), [Repeated view tags link outputs](spec.md#repeated-view-tags-link-outputs), [A bootstrap payment names its recipient's viewing key](spec.md#a-bootstrap-payment-names-its-recipients-viewing-key), [The sender key in a body is unauthenticated](spec.md#the-sender-key-in-a-body-is-unauthenticated) and [Disclosure](spec/crypto/disclosure.md).

<aside>

**Important:** the payer and the Solana fee payer must not link to the hidden owner. Only the SPP payer is checked on chain, by the signer check and by its party identity. A payment under the bootstrap tag publishes its recipient's viewing key.

</aside>

## Code reading guide

1. **Rail selection**: `program-libs/interface/src/instructions/transact.rs:93`
    - `RingRail::of` maps the tag and the mode to a rail, and `AuthorityTransfer` on `Anonymous` fails.
2. **Payer-only signer**: `programs/custom-ring/src/instructions/transfer/accounts.rs:124`
    - Any other SPP signer fails with `InvalidAnonymousSigner`. Line 197 builds the party identities.
3. **Withdrawal destination**: `program-libs/interface/src/instructions/anonymous_exit.rs:122`
    - Every withdrawal names one key. `identities` at line 175 hashes the three parties.
4. **Tag selection**: `sdk-libs/client/src/state/viewing_history.rs:221`
    - `select` takes a known recipient's next shared tag or the caller's first-payment tag. `TransferTagging::plan` at line 380 takes the sender tag.
5. **Anonymous audit**: `prover/circuits/audit/anonymous.go:89`
    - `openSlot` at line 136 opens each output's owner key, asset and amount, and `spend` at line 150 binds the spent notes. No line derives a tag or opens a body.
6. **Delivery**: `prover/circuits/audit/delivery.go:53`
    - On the delivered rails the body opens for `u`. Line 76 binds the owner to the disclosed owner key, and nothing binds `u` to it.
7. **Parties**: `prover/circuits/shared/parties.go:7`
    - Each nonzero party identity differs from the hidden owner.
8. **Output layout**: `sdk-libs/transaction/src/anonymous_rail.rs:76`
    - `slots` gives output 0 the sender tag and a later change output a dummy tag, and refuses a transfer without change. `lead_change` at line 152 moves the change to the front. `AnonymousSeal::body` at line 194 seals each body at its output position. `sender_bundle` at line 230 lists one recipient key per output after the change and seals the bundle at the output count. An exit or a dummy takes the dummy key `0x04 || 0^32`.
9. **Wallet sync**: `sdk-libs/client/src/operations/anonymous.rs:284`
    - `entry` runs both phases, `stream` at line 317 resumes from the watermark, and `record_sent` at line 604 opens the wallet's sent payments.
10. **Ring address**: `sdk-libs/keys/src/ring_address.rs:38`
    - `RingPaymentRequest` at line 118 carries the request tag.
11. **SPP hidden owner**: `zolana/prover/server/circuits/spp_transaction/custom/anonymous_eddsa.go:198` at `ff04c625c`
    - `ed25519.Verify` checks the owner's signature. In `AssertDefaultHiddenOwner` at `zolana/prover/server/circuits/spp_transaction/shared/signers.go:107`, line 126 publishes `default_owner_tag`, line 128 refuses an entry spend that also spends ring notes, and line 130 refuses an exit to the hidden owner on a ring spend.

### Notes

**Conditions anonymity rests on**

1. The payer and the Solana fee payer do not link to the hidden owner.
2. The transfer spends ring notes only.
3. No exit or withdrawal pays a key linked to the owner.
4. A first payment takes a request tag. A bootstrap payment publishes the recipient's viewing key.
5. The wallet runs its own indexer or trusts it, and the prover runs locally or in an attested TEE.
6. The rules admit many owners. An allow rule bounds every sender and recipient to the public allow list.
7. Public leg amounts and timing do not single out a spend.

[Anonymity breaks when its conditions fail](spec.md#anonymity-breaks-when-its-conditions-fail) gives each condition.

**What each observer learns**

1. Photon, the zolana SPP indexer: the tags of one stream of one viewing key per request, and the nullifiers of the wallet's ring notes (`sdk-libs/client/src/operations/anonymous.rs:317`, `sdk-libs/client/src/rpc/tags.rs:87`, `sdk-libs/client/src/operations/anonymous.rs:797`).
2. Ring indexer: every call it forwards to Photon, and on a policy ring the members a client opens (`services/ring-indexer/src/rpc/server/mod.rs:43`, `services/ring-indexer/src/rpc/api.rs:164`).
3. Prover: the full witness, the hidden owner and every opening included (`prover/circuits/audit/anonymous.go:43`).
4. Ring RPC reader: what the auditor opens, once granted (`services/ring-rpc/src/operations/audit.rs:284`).
