# The record writer

Ring RPC is the one writer of a ring's records. It turns signed record updates into storage updates, and its checks are the only gate on who writes what. [Spec](../spec.md)

## A record update

- The signer signs one hash over the cluster, the ring, the tree, every entry, an expiry slot and, for an enrolment, the awaited lists. That hash is the update id.
- Each entry hashes as the tree entry the update proof chains, so the signature binds every write that reaches the tree.
- A wallet writes its own viewing and recovery flags, its escrow entry and its wallet grants.
- The policy authority writes the allow, block, frozen, reader and approval lists and the mint settings of any record.

## Checks before an update queues

- The cluster, the signature, the expiry, and the signer's right to each entry.
- An escrow entry's proof shows its ciphertext seals the secret of its nullifier key to the ring's auditor key.
- An anonymous ring refuses an escrow entry. A member that holds or awaits an escrow key gets no second one.
- Mint settings set each cap with its window and each window within a bound, for an asset that has a record.

## Batches

- One storage update carries at most 16 writes and never splits a record update.
- An authority batch passes queued wallet updates unless one of them writes the same record.
- A batch revokes when, under the ring's current rule table, it clears a list a rule accepts on, sets a list a rule accepts off, or restricts mint settings. It then goes out as an immediate update.
- A wallet batch also goes out early when an authority batch waits behind it.
- A grant revocation goes graced. A wallet that could force an immediate update would void every member's proof in flight.
- A reader list clear goes graced even when a rule reads the reader list.
- When the writer refuses an authority update whose signer lost the policy role, an enrolment that update approved waits again.

## Enrolment

- A wallet's update can await the allow, reader or approval lists the policy reads from the ring's own records.
- It waits until the policy authority's own update sets every awaited list on the wallet. Both then go out in one batch, the wallet's writes first.
- The policy authority can refuse it. An enrolment still waiting after its expiry slot is refused, and the expiry has an upper bound.
- No cap limits pending enrolments. Per-client and per-key rate limits bound how fast they arrive.

## Durability

- The writer stores each batch and its signature before it sends the batch, and one tree has at most one open batch.
- A restart settles the open batch by its signature.
- An update that rides in a bounded number of failed batches, or outlives its expiry, is refused. Nothing sends it again, so its signer must check that each revocation landed.
- Run one writer for each storage authority key. Ring RPC does not enforce this.

## What the writer does not cover

- A write the storage authority signs directly skips every check above, and the tree accepts it.
- The Storage program checks the tree update, not who asked for it.
