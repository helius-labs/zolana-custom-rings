# Records and live roots

A ring reads two kinds of tree, each in a Storage program account with its own root and its own write path. A policy registry contains lists, mint settings and reader grants. A tracking registry contains enrollments. [Spec](../spec.md)

## Why two trees

- A storage update names a revision, and a proof made against another revision fails. One tree would make enrollment and revocation race on that revision.
- `ApplyEnrollments` touches only the tracking root, and an authority write touches only a policy root. Enrollment traffic therefore cannot fail or delay a restrictive update.
- An authority cannot gate enrollment. Policy admission stays a separate list write.

## Records

- A policy record contains one member's list bits and, for an asset, its mint settings.
- A member is an owner's public key `ListKey(owner, 0)`, an owner's salted key, a reader key or an asset. It can also be the grant key of one wallet and one reader.
- Each record points to the next member in sort order. The records are the leaves of a 4-ary tree in insert order.
- A proof opens a present member by its leaf and an absent member by the record that brackets it. A prover cannot leave out the record that convicts its subject.
- A tree has a fixed number of leaves, each member keeps its leaf permanently, and a full tree takes no new member.
- Every write publishes its member and its values in instruction data, and the ring indexer serves each record with its path.

## Lists and rules

- A rule reads a list by presence or by absence. The grant lists are read by presence and the deny lists by absence.
- Presence on any grant list a rule names satisfies that rule. Absence from a deny list satisfies its rule, and rules join with AND.
- Each denial is a separate rule. The program refuses a row that reads several lists by absence, inverts a list's polarity or mixes presence with absence.
- An accepted policy can still restrict nothing.
- No rule reads the reader list or the wallet-written `ring-viewing` list. An owner therefore admits itself to nothing, and a reader grant moves no funds.
- A curator serves list bits only. Mint settings always come from the ring's own records.

## Private lists

- `PrivateAllow`, `PrivateBlock` and `PrivateFrozen` are always salted. A private entry is an ordinary record under `Poseidon(CRPL, owner, list_salt)`, written through the same apply path.
- The tracking row contains `list_tag = Poseidon(CRPT, list_salt)`, proven at enrollment and final.
- While a subject has a tracking row, the circuit forces its salt to open that tag, so it forces the key too. A proven absent row is the one skip.
- A subject proven absent reads no salted list. A deny rule on a salted list passes, and an allow rule on one fails.
- To list an unenrolled identity, a curator uses a public list keyed by owner. Later enrollment leaves that entry in force.
- A public and a private block are two rules. One rule over both would admit a publicly blocked owner with no private entry.
- The wallet derives its salt per ring from its viewing key, so an auditor that holds the nullifier secret cannot derive another ring's salt.
- Private lists serve one ring. A source of a salted list must pin the ring's tracking registry, so a curator that serves several rings keeps one registry per ring.
- A list writer reads an enrolled owner's salt through `getListSalt`, which checks the salt against the row's tag and never returns the nullifier secret.
- A private write proves the owner's applied row. A write for an owner whose enrollment is still pending fails before the proof. A write that names an asset whose mint hashes to its member needs no row.

## Tracking

- A tracking leaf binds its member, successor, nullifier key, ciphertext hash and list tag. Only its successor changes when a new member follows it.
- The tree has 16 levels of four, taller than a policy tree. Anyone can pay to fill it, and no tree replaces a full one. Its next index is a `u64`, and an apply past `TRACKING_CAPACITY` leaves fails.
- `Enroll` needs the owner's signature, and a program signs its PDA through CPI. Any payer may fund it, and Ring RPC can relay it for a wallet with no SOL.
- A first enrollment carries a proof. It shows the ciphertext seals the secret of that nullifier key and the salt of that tag to the auditor key.
- The program supplies the ring id, the member and the auditor key from the signer and the registry. A proof for another ring, member or auditor fails.
- The program verifies that proof in the same instruction, and refuses the zero nullifier key.
- `Enroll` only reads the registry, so enrollment traffic takes no write lock on it.
- `ApplyEnrollments` is permissionless. An applier names the authorization accounts in any order, and the program computes each entry from the account, so no applier can alter one. An applied account refuses a second apply.
- An enrollment is complete only when its leaf sits under an accepted tracking root. A pending account grants nothing, because every check reads the root. The owner's notes under its key spend from that root on.
- Ring RPC applies the pending enrollments of the rings its operator names. Any other party can apply the same accounts.
- A full tree leaves a first enrollment pending.
- A ring creates its tracking registry at `Initialize` and pins its address. A forged registry with a matching ring id fails that address check.

## Viewing keys

- The owner's authorization account holds its current viewing key for one ring. No other ring reads it, and no tracking leaf holds it.
- A rotation is a later `Enroll` with no proof. It moves only the viewing key in the account. The nullifier key, the list tag and the ciphertext are final. A rotation moves no root, marks nothing pending and leaves no tracking work.
- A sender's SDK proves presence, nullifier key and list tag through the verified tracking row, then reads the viewing key from the authorization account at `confirmed`. It checks the account's program owner, registry and owner. An address that names an older viewing key resolves to the current one.
- A rotation that lands after the read leaves the payment sealed to the key read. No program check reads a viewing key.
- A wallet keeps every replaced viewing key in its viewing history, so notes sealed to an older key still open.

## Root history

A policy batch is restrictive when one of its writes does any of these:

- clears an allow, approval or private-allow bit
- sets a block, frozen, private-block or private-frozen bit
- writes a private list
- lowers a guard threshold
- sets or lowers a cap, co-sign or withdrawal bound, where zero means no bound
- changes an asset limit

The apply proof binds that restrictive bit, reading an absent member's old fields as zero.

- A registry keeps its newest roots, each with a revision.
- A restrictive update retires every earlier root at once, and every proof under them fails and proves again.
- Any other update keeps the outgoing root valid for the grace period, so a proof in flight under it still lands. Over a full history it evicts the oldest kept root, and that root's proofs prove again.
- A kept root reads no policy field more permissively than the newest root. Rules are monotone in those fields, so a kept root admits no transfer the newest refuses.
- A tracking apply retires the outgoing root under a program constant, and every retired tracking root serves its whole grace. An apply that would evict an unexpired root fails with `RootHistoryRetained`, and its accounts stay pending until the oldest root expires.
- The limit is enrollment availability. New owners can fill the kept roots, and a one entry apply spends a root as a full batch does, so enrollment waits under sustained load while enrolled owners keep their tracking witnesses.

## Tracking floor

- A private write proves its owners' rows under one tracking root, named by its revision. The Storage program raises the registry's `tracking_floor` to that revision with the new policy root, in one instruction.
- A frame that reads salted lists names a tracking revision at or above the highest floor of the sources it reads them through. A lower revision fails with `TrackingRootBelowFloor`.
- Rows never leave the tracking tree. Every accepted root therefore holds each owner with a private entry, and no such owner proves absence.
- An owner with no applied row has no private entry, so its proven absence hides none.
- A public write leaves the floor unchanged, and the floor never falls.
- The floor is the one exception to tracking grace.

## Live roots

- The program checks each registry account against the address the ring account binds, then reads its root live.
- A proof names a root by its revision, and the program reads that root. The prover picks the revision, never the root.
- A direct sender that meets a retired root reads the newest root and proves again. Ring RPC never proves a relay again, so a relay that meets a retired root fails and the wallet sends a new request.
- A delegate transfer and a merge read no policy root, so a policy update cannot fail them. Every transfer and deposit reads the tracking root.
- An owner-signed merge reads no tracking root, and a merge under a nonzero key reads one.
- An audit-only ring with no records reads the tracking root alone.

## How fast a change binds

- A graced write is in the newest root at once. A new proof can still name the old root for the grace period.
- Ring RPC checks reader grants against the newest root, so a graced grant revocation stops reads once its batch lands.
- A curator's restrictive write stops a subscriber ring at once, since the ring reads the curator's roots at transaction time.
