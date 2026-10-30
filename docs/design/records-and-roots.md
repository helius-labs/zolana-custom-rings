# Records and live roots

A ring's lists, escrow keys, mint settings and tree grants are records in a Storage program tree. [Spec](../spec.md)

## Records

- A record holds one member's list bits, its escrow key and, for an asset, its mint settings.
- A member is an owner identity, a passkey reader, an asset, or the grant key of one wallet and one reader.
- Each record points to the next member in sort order. The records are the leaves of a 4-ary tree in insert order.
- A proof opens a present member by its leaf and an absent member by the record that brackets it. A prover cannot leave out the record that convicts its subject.
- A records tree has a fixed number of leaves, each member keeps its leaf permanently, and a full tree takes no new member.
- A curator serves list membership only. Mint settings and escrow keys always come from the ring's own records.
- Rules read authority lists only, so no owner admits itself. The viewing and recovery flags a wallet writes are for off-chain use.
- Every write publishes its member and its values in instruction data, and the ring indexer serves each record with its path.

## Root history

- A storage registry keeps its newest roots, each with a revision.
- A graced update keeps the outgoing root valid for the registry's grace period, so a proof in flight under it still lands.
- An immediate update retires every earlier root at once, and every proof under them fails.
- A graced update waits while the oldest kept root is still valid, so it never drops a valid root.

## Live roots

- The program reads each root live from the registry account the transaction passes, after it checks the account against the address the ring account binds.
- A proof names a root by its revision, and the program reads that root. The prover picks the revision, never the root.
- A direct sender that meets a retired root reads the newest root and proves again. Ring RPC never proves a relay again, so a relay that meets a retired root fails and the wallet sends a new request.

## How fast a change binds

- A graced write is in the newest root at once. A new proof can still name the old root for the grace period.
- Ring RPC checks reader grants against the newest root, so a graced grant revocation stops reads once its batch lands.

## Why live roots

- Every root the program reads is the registry's current state, so no copy can lag a revocation.
- A forged root needs a forged registry.
- An operation that reads a root passes one or two registry accounts beside the ring account.
