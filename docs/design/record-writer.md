# The record writer

Ring RPC writes a ring's policy records when it holds the storage authority key. It turns signed record updates into storage updates, and its checks gate only the writes it sends. Tracking enrollment takes no part in these writes, apart from the tracking row a private owner write proves. [Spec](../spec.md)

## A record update

- The signer signs one hash over the cluster, the ring, the registry, every entry, an expiry slot and the awaited lists. That hash is the update id.
- Each entry hashes as the tree entry the update proof chains, so the signature binds every write that reaches the tree.
- A wallet writes its own member lists and its wallet grants.
- The policy authority writes the authority lists and the mint settings of any record.

## Checks before an update queues

- The writer checks the cluster, the signature, the expiry, the registry and the signer's right to each entry.
- Mint settings must pair each cap with its window and bound each window. They must also name an asset that has a record.
- A service that keeps reader grants in its database refuses a tree reader write.

## Batches

- One storage update carries at most `APPLY_BATCH` writes and never splits a record update.
- An authority batch passes queued wallet updates unless one of them writes the same record.
- A wallet batch goes out when it is full, when it has aged a window, or when an authority batch waits behind it.
- The apply proof decides the grace from the writes, see [root history](records-and-roots.md#root-history). A wallet's writes stay graced, so no wallet can void every member's proof in flight.
- A graced batch over a full history evicts the oldest kept root and never waits.
- When the writer refuses an authority update whose signer lost the policy role, an update that approval joined turns pending list approval again.
- After proving, the writer checks each update's expiry and authority again before signing. A refused or deferred member prevents submission of the batch.

## List approval

- List approval is the policy authority's off chain decision on a wallet's request for a list, a KYC check for one. The writer holds the request as one state of its lifecycle, pending list approval, and keeps no other record of it.
- A wallet's update can await the reader list, or the allow or approval lists the policy reads from the ring's own records.
- It waits until the policy authority's own update sets every awaited list on the wallet. Both then go out in one batch, or neither does.
- The policy authority can refuse it. An update that still waits after its expiry slot is refused, and the expiry has an upper bound.
- Nothing obliges the authority to answer, and the writer checks no process behind an approval.
- No cap limits pending updates. Per-client and per-key rate limits bound how fast they arrive.
- List approval grants lists and differs from [tracking enrollment](records-and-roots.md#tracking), a secret the wallet registers outside the authority's control.
- A private owner write proves the owner's applied row under one tracking root, and Storage raises the source's tracking floor to that root's revision. A batch whose salted owner has no applied row fails before the proof.

## Durability

- The writer stores each batch and its signature before it sends the batch, and one registry has at most one open batch.
- A restart settles the open batch by its signature.
- An update that rides in a bounded number of failed batches, or outlives its expiry, is refused. Nothing sends it again, so its signer must check that each revocation landed.
- Run one writer for each storage authority key. Ring RPC does not enforce this.

## What the writer does not cover

- A write the storage authority signs directly skips every check above, and the tree accepts it.
- The Storage program checks the tree update and the authority's signature, not who asked for the write.
- Expiry or role rotation after signing does not revoke an in-flight transaction.
- A salted owner write under a wrong salt fails its proof, because the salt must open the owner's row tag.
