# Member records

A ring keeps its lists in member records, and a registered owner's record binds
its escrowed nullifier key. The records form a 4-ary indexed Merkle tree in the
ring's own `StorageRegistry`, the records `Initialize` binds. The storage
program keeps the tree's recent roots on chain, and the ring indexer stores the
records. Owners and the config authority sign record updates, and the Ring RPC
writer applies them in a storage update with its apply proof. The same
transaction sends `SyncRoots`, so the ring policy mirrors the new root at once.
A policy proof opens records under a root the mirror holds and reveals no
record it opened. The records themselves are public. The queue entry, the
chain and the apply statement are in
[Member registry](../program-libs/interface/src/accounts/member_registry.rs),
and the storage layouts are in [Storage program](spec.md#storage-program).

## Members and lists

A **member** is an owner or an asset. See
[Member registry](../program-libs/interface/src/accounts/member_registry.rs) for its value. One list
holds both kinds, and an owner key and a mint with equal bytes stay distinct
members.

A record holds the member, the next member in sort order, a bitmap of lists
an escrow key and the mint settings. Eight lists exist, and each list has one writer:

- The config authority writes `Allow`, `Block`, `Frozen`, `Reader` and
  `Approval`.
- The member itself writes `RingViewing` and `Recovery`.
- Only an escrow write sets `Escrow`, and it also fills the escrow key.

The Ring RPC writer enforces the writer of each list. The storage program
accepts every list but `Escrow` from the registry authority.
[The policy guide](ring-policy.md#rules) says which of these lists
a rule reads.

The tree starts with a sentinel record at leaf 0. Every member lies strictly
between the sentinel and the largest field element, so every absent member has
a present low record that brackets it. A proof of absence opens that low
record. An absent member reads as an empty bitmap, no escrow key and zero mint settings.

## Writes

Every write is masked. It changes the list bits inside its mask to the bits of
its value and keeps every other bit. A write over an absent member inserts a
record at the next free leaf, unless the new record would be empty. A record
is never removed. A cleared record stays in the tree with an empty bitmap.

A member signs a record update for its own record. The writer derives the
record from the signer's Solana key, so no member writes another member's
record, and the mask names only `RingViewing` and `Recovery`.

A member escrows its nullifier key with an escrow entry. Its register key proof
shows that a 32-byte ciphertext seals the member's nullifier secret to the ring
auditor, and that the secret matches the published nullifier key. The writer
verifies the proof, and the update carries an escrow write that sets `Escrow`
and the escrow key over the nullifier key and the ciphertext. The escrow key
fills once. The writer refuses a second escrow key for a member, and an
anonymous ring refuses the escrow entry. See
[Creating an anonymous ring](anonymous-rings.md#creating-an-anonymous-ring).

The config authority signs record updates over authority lists and mint
settings of any record. [Record updates](spec.md#record-updates) gives the
batching, and which updates retire every earlier root at once.

## Mint settings

Each asset record stores `threshold`, `cap`, `cosign_above`,
`withdrawal_threshold` and the eight `AssetLimits` values of the Ring RPC
co-signer, all unsigned 64-bit integers. The first three pack into
one 192-bit field; the withdrawal threshold occupies another field, and the
limits pack three to a field into three more. [Mint settings](spec.md#mint-settings)
gives the leaf and the queue entry hash.
Bit 192 of `mint_policy_write` distinguishes an explicit replacement from a
list/key write that preserves every setting. An explicit all-zero value
clears settings while preserving lists and the escrow key. Member writes and
escrow writes cannot change mint settings.

Use Rust `AuthorityRecordUpdate::with_mint_policy` or TypeScript
`AuthorityRecordUpdate`. Settings use the ring's own records even
when a curator supplies lists. There is no per-policy mint count. The record
tree's capacity and write batch sizes apply. Audit-only rings hold records too,
so their mint settings configure withdrawal exemptions without a list policy.

The CLI keeps `limits` in policy TOML and writes the resulting records.
`cosigner set` replaces withdrawal thresholds while preserving the other
settings. `cosigner clear` closes the signer's record but retains the mint records. A later
`cosigner set` replaces those retained withdrawal thresholds.

## Applying writes

The writer proves each batch from `getStorageApplyProofInputs` at the
registry's current root. The proof binds the old root, the new root, the next
free leaf before and after, and the hash chain of exactly the batch's writes
from a start that binds the registry and its revision. A submitter therefore
cannot drop, reorder or invent a write.

The tree holds `2^20` leaves, the sentinel included, so a registry holds at
most `2^20 - 1` member records. One storage update covers at most `APPLY_BATCH`
writes.

## Roots and curators

The registry keeps the last `ROOT_HISTORY` roots, each with its revision. A
graced `Update` keeps the outgoing root readable for the registry's
`grace_slots`, and `UpdateImmediate` retires every earlier root at once. A
policy transfer names the revision of each root its proof binds and reads the
root from the ring policy's mirror. A merge on a confidential ring and an
audited deposit under key escrow do the same.

A ring that reads a list from a curator's registry reads the curator root from
its curator mirror. A curator update reaches a subscriber at the next
`SyncRoots` of that subscriber's curator mirror.

## Indexing

The ring indexer reads every storage update from its instruction and replays it
over its copy of the tree. It compares the resulting root and next leaf with
the instruction's values. A mismatch stops the registry's projection, and the
ring indexer then refuses the registry's record reads. Clients check every
opening against a root the ring policy mirrors before they prove.

## With the CLI and the SDKs

`zolana-ring list add|clear <list> --owner <address>` or `--asset <mint>`
signs a config authority record update. `list join|leave ring-viewing|recovery`
signs the member update of `keys/sender-keypair.json`. `key register` escrows
the sender's key, and `status` prints the newest root of each mirror.

In Rust, `WalletRecordUpdate::new(target, wallet)` takes `with_lists`,
`with_escrow` and `with_wallet_grant`, and `AuthorityRecordUpdate::new(target,
authority)` takes one `with_write(member, write)` or `with_mint_policy` per
record. `sign` returns the request a `RecordUpdateService` submits.
`KeyRegistration` proves an escrow entry, and `MemberRecords` reads openings it
checks against the mirrored root.

## Pitfalls

A transfer that binds an old root fails once later updates move it out of the
mirror or its grace window passes. The Rust SDK proves again when a bound root
leaves the mirror.

## Protocol transition

This layout is incompatible with earlier four-field leaves, five-field queue
hashes and the inline mint arrays. The rule-table hash uses version 12. The
config is 112 bytes. `SetCoSigner` carries only signer and scope. A record
write adds a 97-byte optional mint-setting replacement. Transfers may append a
200-byte withdrawal exemption proof with its own revision.

Deploy the matching program, SDK, indexer and pinned keys together for fresh
rings. Existing rings require an explicit account/tree migration before an
upgrade. Reindexing old instructions under the new leaf format does not
preserve old on-chain roots and is not a migration.
