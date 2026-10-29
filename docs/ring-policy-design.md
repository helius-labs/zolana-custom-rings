# The Ring Policy Construction

The ring adds admission and spend controls to SPP settlement. SPP proves value
conservation and tree membership, and ownership outside the delegate rail. The
ring proves its rules over the same transaction and supplies the required
authorization. List facts stay private.

The config authority pins admission rules as data in the ring policy. A
transferring wallet must prove every rule satisfied against list state it does
not control. A **curator** is a storage registry whose lists many rings read by
reference.

A list membership is one bit of a member record, a leaf of an indexed Merkle
tree that belongs to the ring. A policy is a proof obligation over the records
of the transfer's subjects. The proof opens them under a root the ring policy
mirrors and binds them to the transfer through `private_tx_hash`.

The running example is a blocklist ring. Its pinned table holds one rule,
forbid `output-owner` on `Block`. A curator ring serves the `Block` list. The
curator bans Mr. Evil. Mr. Crazy transfers.

## The member record

A **member** is the field element a UTXO opening carries for an owner or an
asset, defined in [Member registry](../program-libs/interface/src/accounts/member_registry.rs). One member space
therefore serves every rule subject. One list holds owners and assets side by
side, and an owner key and a mint with equal bytes stay distinct members.

A record holds a member, the next member above it, a list bitmap, an escrow
key and the mint settings. One opening answers every list for its member. The links order the
records by member, and leaf 0 holds a sentinel whose link spans the field.
Every member lies strictly inside that link, so an absent member always has a
present low record whose link brackets it. A proof of absence opens that low
record, and an absent member reads as on no list.
[Member registry](../program-libs/interface/src/accounts/member_registry.rs) fixes the layouts and the tree.

A record is never removed. A write that clears every bit leaves an empty
bitmap in place, so removal is an ordinary write and absence keeps one
provable shape. The records are public. Every write names its member and its
bits on chain, and the ring indexer replays the writes into its copy of the tree.

## Writers and the apply proof

[Members and lists](member-records.md#members-and-lists)
names the writer of each list. The Ring RPC writer derives a member's own
record from the update's signer. The circuit proves membership, never who
wrote it, so authorization stays outside the circuit.

Every write is masked. It sets the bits inside its mask to its value and keeps
the others. A member signs a record update and takes no proof. The writer
checks the signer and the mask and batches the write into a storage update.
The update chains its writes with Poseidon from a start that binds the
registry and its revision. Its apply proof moves the tree from its newest root
to the next. The statement binds both roots, the next free leaf before and
after, and both ends of the chain over exactly the update's writes. An update
therefore cannot drop, reorder or invent a write, and the storage program
never hashes the tree itself.

The config authority's revoking writes go out as `UpdateImmediate`, which
retires every earlier root. [Roots and revocation](#roots-and-revocation)
shows how a ban binds every later transfer.

## The table, the source map, and one hash

The rule table arrives as instruction data and lives in the ring policy.
`Initialize` and `UpdatePolicy` carry the rule rows and source specs.
Mint thresholds and outflow limits are authority writes to asset records. The program encodes and validates them,
and an illegal table fails the instruction and never reaches the account. The
CLI builds the same table from `ring.toml` through `RuleTableBuilder::try_build`
first and names the refused row. The builder refuses duplicate rules by
signature, subject plus both list sets, guard excluded. The pair
`require(output-owner, Allow)` and the same rule guarded above a threshold
reads as a working exemption. The unguarded rule subsumes it, so the builder
refuses the pair.

[Ring policy](ring-policy.md#rules) states when a rule holds. A rule packs its
subject, mode, list mask, guard, threshold and alternative mask into one field
element at fixed byte positions. The hash covers only the packed element. The
circuit witnesses the components, range-checks each and re-derives the packed
value. Without the range checks a prover could borrow across byte boundaries
and read a pinned rule as a different one. The form is canonical. A rule with a
present set is `Present` primary, and a rule with absent lists only is `Absent`
primary with an empty alternative. `Rule::decode` refuses every other encoding,
so one rule has one row and one hash.

A rule reads only the lists the config authority writes. The program refuses a
table with a rule over `RingViewing`, `Recovery` or `Escrow`. Members write the
first two, and an escrow write sets `Escrow`.

The **source map** decides which registry serves each list. It is eight
positional slots, and slot `i` is empty or serves list `i + 1`. An occupied
slot names the ring's own registry or a curator's registry. Positional layout
gives each list one slot and needs no ordering check in the circuit. The
sources name exactly the lists the rules read. Every curator slot names the
same registry, because the circuit opens one curator tree beside the ring's own
tree.

One hash binds the table and the map, over the fields
[Policy proof](../program-libs/policy/src/rule_table/mod.rs) lists. `POLICY_TABLE_VERSION` moves with
any change of the preimage. All eight source slots enter, empty slots as
zeros. Hashing only the referenced slots would let a slot for an unused list
change without moving the hash. The counts enter beside the rows, so a
truncated table cannot alias a longer one. A referenced list with no source
fails the policy write before any hash is stored.

## The on-chain binding

The upgrade authority pins the first table with `Initialize`, which refuses a
table on an audit-only ring and a ring that already has a policy. The config
authority signs every later write. `UpdatePolicy` replaces the table and the
map, re-points one list, or rebinds the records. Each table write validates the
table against the new map and stores both in the ring policy. It re-hashes them
and counts one more `generation` at the current slot. A changed hash binds
every later transfer, and a proof built against the old table fails. Generation
itself is not hashed, so an identical re-pin preserves the proof statement.

Curatorship is permissionless. A curator source names a `StorageRegistry` of
any authority, and the program checks only that the storage program owns it. There
is no curator registry. The trust decision is the operator's choice of account.
The ring opens records in the curator's own tree, never through the curator's
sources. A curator re-pointing its own lists therefore moves nothing
downstream, and a curator of a curator never chains. A subscriber trusts its
curator's writes wholly. A curator source bounds who writes, never what they
write.

## Three proofs per transfer

A policy ring transfer carries three proofs. SPP's proof settles the
transaction, the audit proof shows what the auditor reads, and the policy proof
shows the rules hold. Each ring proof binds the same `private_tx_hash` the SPP
proof binds. Its one public input is the hash of a statement the program
rebuilds from its accounts and the transfer's data. The program reads the
policy hash from the ring policy and resolves each root from a revision the
transfer carries. It derives the key escrow bit and SPP's public slots itself,
and on the confidential rail the sender from the owner signer or the frame's
in-proof owner key. The approval bit
comes from the transfer, and the policy proof shows it is exact. A wallet
cannot satisfy the audit statement while it skips the policy statement, because
the program verifies both against the one transaction.

An audit-only ring carries the SPP and audit proofs alone. The tier is the
config's `has_policy` flag, fixed by the kind `Initialize` takes. A policy
ring therefore cannot present the audit statement alone to skip its rules. The
audit proof is the same on both tiers, so the auditor reads every transfer.

## The policy circuit

The policy circuit decodes the table under `policy_hash`. It reopens every
output and recomputes `private_tx_hash` from the outputs, the input chain and
the transaction's address chain and blinding. The recompute is the
subject-integrity binding. Without the recompute, a wallet paying a blocked
member could witness the outputs of an innocent transaction. Those outputs
meet every rule while SPP settles the real hash. The recompute forces the
screened owners, assets and amounts to be the preimage of the hash SPP settles.

A policy transfer has one sender. On the confidential rail it is the one owner
signer or the in-proof owner, and the program derives its identity from that key. On the anonymous
rail the statement carries `sender_commitment`. The anonymous audit proof binds
the same value and shows that every spent note belongs to the hidden sender.
The policy proof opens the owner that `sender_commitment` hides. On the
delegate rail the circuit reopens the spent notes and proves one owner for all
of them. The member key takes the input chain as given. SPP's single owner
signer or the anonymous audit proof already binds every input to the sender.

The circuit opens the record of the sender, of every output's owner and, under
an asset rule, of every output's asset. Each opening sits under `own_root`, and
also under `curator_root` when a list reads from the curator. A list takes its
bit from the registry its source names. Every rule must hold for each of its
subjects. An owner rule reads every UTXO output that names an owner, the
sender's change and every output that leaves the ring included. An asset rule
reads every output's asset. A transfer whose inputs exactly cover its payments
has no change, so its sender never appears as an output owner. Sender rules
cover that case.

An amount guard exempts a subject whose total stays at or below the threshold.
An owner rule sums each owner's outputs and an asset rule each asset's outputs,
so a payment split across slots does not escape the guard. A per-asset guard
groups gross payments by owner and mint and reads each mint's threshold from
its authenticated record in the ring's own registry. A wallet paying a blocked member cannot omit the convicting record.
Every subject demands an opening under a root the program accepts, and an
absent member opens only through a low record that brackets it.

Public withdrawals also satisfy owner and asset list rules; deposits never
offset their amount guards. The program binds public withdrawal owners and
amounts from settlement accounts. Separately, net public amounts feed the
outflow calculation. Every nonzero public asset opens its own mint settings,
even when no private output carries that asset.

## Roots and revocation

Each registry keeps its last `ROOT_HISTORY` roots, each with its revision, and
the ring policy mirrors them. A transfer names the revision of each root its
proof binds, and the program reads the root from the mirror. A revision the
mirror does not hold, or a retired root past its expiry, fails with
`MirrorRootExpired`, and the wallet proves again.

Inclusion and absence both read one root, so an old root can show a revoked
member as clean. A graced `Update` keeps the outgoing root readable for the
registry's `grace_slots`. A revoking update goes out as `UpdateImmediate` and
retires every earlier root, so after the `SyncRoots` in its transaction no
transfer of the ring binds a root without the ban. Member writes and escrow
writes go out graced, and no rule reads the lists they write.

A curator root follows the same rule in the curator's registry, read from the
subscriber's curator mirror. In the example, the curator's write that bans
Mr. Evil goes out as `UpdateImmediate`. A proof Mr. Crazy built a moment
before still lands until the subscriber's curator mirror syncs. After the
sync, every proof that pays Mr. Evil must open his record under a root that
holds the ban, and the rule fails.

## The wallet cycle

1. The wallet reads the ring policy and trusts the stored table and
   sources only after they reproduce `policy_hash`.
2. It collects its members, the sender, the owner and the asset of every
   output and withdrawal, and every nonzero public asset.
3. It reads them as one record pool per registry with `getStorageRecordPool`,
   under the newest own root and, with a curator, the newest curator root. It
   checks every record and every bracket against the root before it uses it.
   A lying indexer stalls proving but cannot steer the answer.
4. It evaluates the table against the openings. A rule that fails for one
   subject refuses client-side with `PolicyRuleUnsatisfied`, before any proof
   request. The chain never learns of the refused transfer.
5. It builds the SPP witness, yielding `private_tx_hash`, then proves the SPP
   statement, the audit statement and the policy statement.
6. It sends the transfer with the proofs and the revision of each root.
   Rust's `RingSubmission` proves again when a bound root leaves the mirror.

## Co-signing, delegation and outflow limits

Co-signing is a program check. Delegation and the outflow limits live in the
ring statements, the delegate rail under its own keys.

**Actors.** The upgrade authority creates the config. The config authority sets
the delegate, writes the policy and the authority lists and re-points
sources. It grants and revokes readers, sets the co-signers and pauses the
ring. A member writes its own `RingViewing` and `Recovery` bits
and registers its key. The auditor holds the X25519 key fixed at `Initialize`
and decrypts transfers, and that key cannot authorize an ownership transfer or
a withdrawal. SPP governance activates the ring and enables the authority rail
through `set_ring_activation`, and nothing in the ring program can. No
instruction changes the tier or the auditor, and the program stays upgradeable.

**Co-signing** is a signer check. The ring stores one record per co-signer,
each with a scope over transfers, deposits and withdrawals. Withdrawal thresholds live in mint
records, including on audit-only rings. An optional withdrawal exemption proof
opens the actual withdrawn mints under a mirrored own root and bounds each gross total by its threshold. Missing or zero thresholds
never exempt positive withdrawals; deposits cannot reduce these totals. This
proof waives only withdrawal-scoped co-signing, never transfers, deposits or
the approval bit. Every transact and merge
is a transfer, and a public leg adds its class, so a shielded transfer cannot
hide behind a small deposit. The proof-bound approval bit demands a co-signer
whatever the scope. A transfer refuses a co-signer that is one of its
owner signers or its delegate.

**Delegation** exposes the SPP authority rail behind a delegate. The config
authority and the delegate both sign `SetDelegate`, once, and no instruction
replaces it. `SetDelegate` needs a policy ring with a ring policy and
refuses an anonymous ring, which hides the owner a delegate would sign for. A
delegate move carries an audit proof and a delegate policy proof, which applies
the list rules and amount guards. The inputs' owner is the screened sender. The
key exempts the move from the outflow limits and binds the approval bit to
zero, and the scoped co-signer still applies. The program refuses a public leg
on the rail, and SPP's authority circuit keeps every real UTXO inside the ring.
A delegate therefore cannot withdraw or exit.

**Key escrow** keeps every note the delegate may later move spendable by the
delegate. `SetDelegate` moves the config to `ConfidentialEscrow` mode, and no instruction
leaves it. The statement then binds `key_escrow = 1`. The record of every UTXO
output's owner under `own_root` must hold an escrow key over that output's
nullifier key. The escrow key also covers the ciphertext that seals the
nullifier secret to the auditor. Recovery needs the auditor secret, and
authorization needs the delegate's signature. The CLI expects one operator to
hold the keys. See the [README](../README.md#roles).
A plain deposit is refused in every mode, and the audited deposit binds each
owner's escrow record under a named root. Every merge proves its disclosure
to the auditor, and on a key escrow ring it also binds the owner's escrow
record.

**Outflow limits** bound a sender's outflow per mint in one transfer. The
policy proof opens the settings of every real output asset and nonzero public
asset, then bounds the total outflow by its authenticated
[MintPolicy](../program-libs/policy/src/mint.rs). A zero cap or threshold leaves that bound
off. The ring keeps no counter, so a sender may move up to the cap in every
transfer. The program demands a co-signer when the transfer sets
the approval bit.

## Rejected designs

**Lists as notes in SPP's state trees.** It reuses SPP's trees, forester and
indexer. A private read of a fresh note needs a proof that its nullifier is
still absent. The alternative is a spend that publishes a nullifier anyone can
link. Every list fact would pay that per subject. A ring-owned record tree
answers every list of a member with one opening.

**One combined audit and policy proof.** It buys one verification. The audit
statement would enter every policy key, and the member policy keys would miss
their constraint budget.

**Revocation at the next application.** It buys one write path for everyone.
A ban would bind only after an application lands, and the banned member could
still transfer until then. Revoking writes go out at once as
`UpdateImmediate` instead.

**Encrypted records.** It buys list privacy. Every prover opens foreign
records to build its proof. Encryption would restrict proving to key holders,
and the operator would co-prove every transfer. The table names its lists and
the writes are public, so the secrecy would be hollow.

**Members as raw addresses.** It buys human-readable lists. The circuit sees
an owner only as the opening's `owner_proof_input_hash`. A raw address costs
an extra in-circuit preimage per subject.

## Limits

- The builder rejects any table carrying `ExitDestination`. Public withdrawal
  destinations stay outside the list rules.
- [Ring policy](ring-policy.md#limits) and
  [Member records](member-records.md#applying-writes)
  state the table and registry limits.
