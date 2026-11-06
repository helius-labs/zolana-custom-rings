# Custom rings

A custom ring enforces your own compliance rules on private transfers in the Solana Privacy Program (SPP). The ring program moves a ring note only after it verifies the proofs and approvals its settings demand. Ring RPC proves, co-signs, pays for and sends wallet operations, and a wallet can also prove and send its own. This document describes each control, who can change it, what each party is trusted with, and the decisions behind them.

The docs form one ladder from this overview down to the code. Each rung says only what the rung above cannot.

1. This spec: the controls, components, roles, trust, flows and decisions.
2. Design notes, one short file for each concept that is hard to see from here: [records and roots](design/records-and-roots.md), [owner rails](design/owner-rails.md), [the record writer](design/record-writer.md), [co-signing](design/co-signing.md), [privacy](design/privacy.md), [audit and recovery](design/audit-and-recovery.md), and [proof composition](design/proof-composition.md).
3. Exact sub-specs: [hashing](spec/crypto/hashing.md), [envelope](spec/crypto/envelope.md), [disclosure](spec/crypto/disclosure.md) and [public inputs](spec/crypto/public-inputs.md).
4. Component READMEs, the interface contracts and operator setup: [repository](../README.md), [Storage program](../programs/storage/README.md), [Ring RPC](../services/ring-rpc/README.md) and [TypeScript SDK](../sdk-libs/ts/README.md).
5. Code comments, the invariant at each check.

## Compliance Rules

1. ZK Policy
   1. Allowlist
   2. Blocklist
   3. Frozen list
   4. Asset allowlist
   5. Outflow limits per transfer
   6. Auditor
2. Ring account controls
   1. Pause
   2. Permanent delegate
   3. Co-signer approval
3. Ring RPC
   1. Readers
   2. Co-signer limits

## 1. ZK Policy

The policy defines which checks a transfer must prove. `Initialize` pins the first rule table, and the policy authority then sets the rule table and signs the list entries. A rule screens the sender, every output owner or every asset, and rules join with AND. A rule is a grant, met by presence on any of its grant lists, or a denial, met by absence from its one deny list. The program refuses three rule forms. A rule that reads several lists by absence fails with `MultiListAbsenceRule`. A rule that reads a grant list by absence or a deny list by presence fails with `InvertedListPolarity`. A rule that mixes presence with absence fails with `MixedPolarityRule`. Each denied list therefore takes its own rule. A list has no effect until a rule reads it. A new rule table binds at once, and every proof made under the old one fails. A ring created without a rule table never gets one. [Records and roots](design/records-and-roots.md)

### 1.1. Allowlist

An allowlist is a list of approved identities. A rule can require the sender, every recipient, or both, to be on it. A recipient rule screens every output, the sender's change and each exit included, and the owner of each withdrawal. A guard can exempt payments at or below a threshold, so only recipients above it must be listed. The threshold is one value for the rule, compared with each owner's total of each asset, or one value per asset in the asset's record. Change that the sender's own ring notes fund adds no receipt.

### 1.2. Blocklist

A blocklist is a list of identities or assets the ring refuses. A sender rule over it stops every transfer of a blocked identity. Its notes stay in the ring, it can still merge them, and the delegate can still move them. A blocklist refuses known members only. A fresh key passes it.

### 1.3. Frozen list

The frozen list is a second authority list, kept apart from the blocklist. A sender rule over it stops every transfer of a frozen identity. A merge and a delegate move read no rule. The private frozen list is its salted counterpart. It holds enrolled owners under salted keys, and a rule reads it as its own deny list.

### 1.4. Asset allowlist

An asset rule over the allowlist admits only listed assets to deposits and transfers. A guard on that rule can admit small amounts of other assets. A deposit runs the owner and asset rules on each recipient and asset, and no sender rule, because a depositor spends no note.

### 1.5. Outflow limits per transfer

An asset's record can hold a cap and a co-sign bound. The transfer proof keeps each owner's charged outflow of the asset at or below the cap. It sets the `OUTFLOW` approval bit when a charged outflow passes the co-sign bound. An asset with no record has neither, and a ring with no own records bounds no outflow. An owner's net outflow is its actual decrease, `debit`. Its charged outflow adds `charge`, a share of what leaves the ring beyond every owner's debit. The two differ only when an owner's spend returns to it while something else leaves in the same transaction.

Per asset `a`, over the sender rows `j` in ascending owner identity order:

```text
held_j     = row j's live inputs of a, default-ring notes included
returned_j = row j's live ring outputs of a
leaving    = every exit of a, whoever receives it, + the gross public withdrawal of a
debit_j    = max(held_j - returned_j, 0)               net outflow
kept_j     = held_j - debit_j
H = sum held_j, T = sum debit_j, K = sum kept_j
D          = min(leaving, H) - min(leaving, T)
R_j        = kept_0 + ... + kept_j
share_j    = floor(D * R_j / K), D on the last row, share_-1 = 0
charge_j   = share_j - share_(j-1)
charged_j  = debit_j + charge_j                        charged outflow
```

`D` is at most `K`, and `K = 0` forces every charge to zero. Each charge is `floor(D * kept_j / K)` or one more, the charges sum to `D` exactly, and no charge passes `kept_j`. The row order alone places a rounding unit, and no prover input picks a share. The gross public withdrawal subtracts no deposit. An asset with no live ring output is bound over its debits, since no row keeps it.

`leaving` names no payer. A transaction that composes independent payments can therefore charge an owner for an exit or a withdrawal another party funds. The charge stays within what that owner kept. Payments in separate transactions never charge each other. The SDKs report each owner's charge before signing, so a caller can split such payments.

As an example, A spends 100 of an asset and receives 100 back in a ring output. B deposits 100, and the transaction withdraws 100 in public. A's net outflow is 0 and its charged outflow is 100. A cap of 100 proves and a cap of 99 refuses. The charge is intended.

Limits over time are Ring RPC's, see 3.2. Differs from the PR 15 draft: per-transfer outflow limits live in the transfer proof. [Co-signing](design/co-signing.md)

### 1.6. Auditor

The auditor holds the ring's viewing key. It reads the tokens, amounts and owners of every transfer, deposit and merge, and on an anonymous ring the hidden sender. Every operation carries a proof that the auditor can open it. The auditor can't move funds. [Audit and recovery](design/audit-and-recovery.md)

## 2. Ring account controls

Differs from the PR 15 draft: the ring account holds the keys of these controls, not a separate program config. SPP's ring config holds the pause flag.

### 2.1. Pause

Pausing stops all activity in the ring until it's resumed: deposits, transfers, withdrawals, merges and delegate moves. Funds stay where they are. Record updates, policy changes and other controls still run.

### 2.2. Permanent delegate

A permanent delegate is a key that can move any note of the ring without its owner's signature. The admin and the delegate set it once, on any ring kind. A delegate move transfers within the ring, withdraws and exits, and takes no deposit leg. It reads no rule, guard, cap or approval, so a blocked or frozen member's funds move. Its nonzero-key inputs still match their owners' tracking rows, its outputs still meet the output key rule, and its records still open to the auditor. On an anonymous ring the delegate is public, and the source and the recipients stay hidden. SPP governance must enable the ring's authority rail before the first move.

### 2.3. Co-signer approval

A co-signer is a key that the co-signer admin designates to approve selected operations. Each co-signer has its own account and scope. A transaction carries a co-signer for each demanded class, and one co-signer may cover several classes. The program refuses a co-signer that covers no class still uncovered, and a hidden sender cannot approve itself. The co-signer on its own cannot move funds. Differs from the PR 15 draft: co-signer approval is enforced by the ring program, and only its limits live in Ring RPC.

#### Operations that can require approval

- **`TRANSFERS`**: a transfer that spends a note. A frame with `no_spend` set, a merge and a delegate move never demand it.
- **`DEPOSITS`**: a deposit, and a transfer with a deposit leg.
- **`WITHDRAWALS`**: a transfer with a public withdrawal.
- **`APPROVE_OUTFLOW`**: an owner's charged outflow of an asset above the asset's co-sign bound, see 1.5.
- **`APPROVE_WITHDRAWAL`**: the gross withdrawn of an asset, with no deposit subtracted, above the asset's withdrawal threshold. It reads no owner and limits what a transaction withdraws in public, whoever funds it.

The first three demand a co-signer only when the ring configured a co-signer of that class. The proof sets the two approval bits in `approval_mask`. A set bit demands its approver whether or not the ring configured one, so it fails closed without one. A delegate move sets no bit.

## 3. Ring RPC

### 3.1. Readers

A reader accesses decrypted activity through Ring RPC without holding the auditor key. The policy authority grants access across the ring. A wallet grants access to its own activity, and its own key reads nothing without that grant. A deployment keeps every grant in one store, the ring's storage tree or Ring RPC's encrypted database. Differs from the PR 15 draft: one store per deployment, never both.

### 3.2. Co-signer limits

Ring RPC co-signs only within limits the policy authority writes to each asset's record:

1. **Sender limit:** what one sender outputs to another owner or another ring and withdraws of the asset within a window. A deposit does not lower it.
2. **Volume limit:** what the ring transfers, takes in and pays out of the asset within a window.
3. **Deposit and withdrawal limits:** what the ring takes in and pays out in public deposits and withdrawals, each with its own window.

These limits bind only the operations the ring requires co-signing for. Ring RPC enforces them when it decides whether to co-sign, and the ring program checks only that the co-signer signed. Ring RPC refuses to co-sign an operation that moves an asset with no record. Enforcement at co-signing follows the PR 15 draft's Flow 9 and trust assumption 3. A limit binds every operation of a class, for example Transfers, only when Ring RPC is the one co-signer that covers that class. Otherwise a transfer below the co-sign bound, or one that another co-signer signs, can pass uncounted. The per-transfer cap and co-sign bound of 1.5 hold either way. Differs from the PR 15 draft: limits are set per asset, not per co-signer (open question 1).

## Components and ownership

1. **Ring program:** one deployment per ring. Verifies the ring proofs and controls, then calls SPP signed by its ring PDA.
2. **Storage program:** one shared deployment. Keeps the root history of policy record trees, each under one authority, and of each ring's tracking tree. It verifies the proof of each tree update and of each first enrollment. It checks no policy.
3. **Ring RPC:** our hosted service. Holds the auditor key, writes policy records, applies enrollments, relays and pays for wallet operations, co-signs under limits, merges enrolled owners' notes and serves readers. It opens every enrolled owner's sealed secret from the ring's tracking rows.
4. **Ring indexer:** projects every policy and tracking tree from confirmed blocks and lists pending enrollments. It serves record and tracking openings, and forwards every other call to Photon.
5. **Ring prover:** the zolana prover with the ring circuits added.
6. **SDKs and CLI:** the Rust and TypeScript SDKs build ring operations. A wallet sends them through Ring RPC by default, or reads the records and Merkle paths from the ring indexer, proves and sends them itself. The operator CLI creates, deploys and governs rings.

Zolana owns SPP: its programs, its circuits and its rails. Those circuits are audited, and this repository never refactors them. The ring imports zolana gadgets unchanged and keeps its own copy of any gadget it must change. A new SPP circuit enters zolana as new files only.

The ring uses these SPP rails:

1. **Confidential signer rail:** each input owner signs the Solana transaction.
2. **Confidential in-proof rail:** the owner signs inside the proof of SPP's anonymous rail, and public co-owners can sign the transaction beside it. SPP hides the owner, and the ring statement publishes it as the sender.
3. **Anonymous rail:** a hidden owner signs inside the SPP proof, with optional public co-owners who sign the transaction. Under the frame's `PUBLIC_OWNERS` flag no hidden owner exists, every live owner is a published signer, and SPP's confidential rail settles the frame.
4. **Authority rail:** the ring PDA moves notes with no owner signature, for the delegate, on a confidential and on an anonymous ring. A delegate exit settles on SPP's `ring_authority_exit` selector.
5. **Ring merge.** A deposit is a transfer on the signer rail, or under `PUBLIC_OWNERS` on an anonymous ring, that spends no note.

An in-proof owner on ring transfers lets Ring RPC pay for and send a confidential transfer from one wallet signature. Zolana's own in-proof circuit serves default-ring transfers only, so the confidential in-proof rail proves on SPP's anonymous rail. Both confidential owner rails stay. [Owner rails](design/owner-rails.md)

## Accounts

1. **Ring account:** one per ring. Holds the roles, the mode, the auditor key, the delegate, the co-signer counts and the policy. It binds the addresses of the ring's tracking registry, of its records tree and of its one curator tree. A ring without a policy, anonymous included, may bind no records tree.
2. **Co-signer account:** one per co-signer, holding its key and its scope.
3. **Storage registry:** one per policy record tree, owned by the Storage program. Holds the authority, the grace period, the next leaf, the immutable ring id, the immutable tracking registry pin, the tracking floor and the root history. Record contents live in instruction data and the ring indexer. A nonzero ring id makes the tree that ring's own records. A zero ring id makes it a curator only. Any registry can serve as a curator, the ring's own records included. A nonzero pin names the one tracking registry whose enrolled owners the registry can hold salted entries for. `Initialize` and `UpdatePolicy` refuse a salted source that pins no tracking registry or another one before they store a policy. A refused write changes nothing. A frame that reads a salted list refuses such a source again.
4. **SPP ring config:** owned by SPP at the ring PDA. Holds the activation, pause and authority-rail flags.
5. **Tracking registry:** one per ring, owned by the Storage program and created by `Initialize`. Holds the immutable ring id, the immutable auditor key, the next leaf as a `u64` and the root history of the ring's enrollments. Its tree has `TRACKING_QUAD_HEIGHT = 16` levels of four, so it holds `TRACKING_CAPACITY = 2^32` leaves. [Tracking](design/records-and-roots.md#tracking)
6. **Tracking authorization:** one per owner per tracking registry, owned by the Storage program. Holds the owner's nullifier key, list tag, viewing key and ephemeral key, and whether an apply inserted the owner's row. Its ciphertext seals the nullifier secret and the list salt to the auditor. The tracking leaf holds the member, the next member, the nullifier key, the ciphertext hash and the list tag, and no viewing key.
7. **Owner grant:** one per owner, tracking registry and reader, owned by the Storage program. Holds whether a program owner grants that reader access to its activity.

A transfer or deposit passes the ring account and the tracking registry. It adds the records registry when it reads the policy or the thresholds, and the curator registry when the policy uses a curator source. It adds a co-signer account for each co-signer the demanded classes need. The program checks each registry against the address the ring account binds and reads its roots live. Differs from the PR 15 draft: the config and the policy are one account, and no roots are synced into it. A storage tree is a root history over an indexed tree, not account compression. [Records and roots](design/records-and-roots.md)

## Authorities

Five on-chain roles govern a ring. Every role key is nonzero once set, and no key holds two roles.

1. **Admin:** hands the admin, policy, pauser or co-signer admin role to a new key, which also signs. It appoints the delegate once.
2. **Policy authority:** sets the policy and signs the authority record updates: authority lists, mint settings and limits, ring-wide reader grants and list approvals.
3. **Pauser:** pauses and resumes the ring.
4. **Co-signer admin:** creates, rescopes and closes co-signer accounts.
5. **Delegate:** moves any note of the ring outside the rules. Set once, never rotated.

The upgrade authority deploys the program. Among ring instructions it signs only `Initialize`, which names the four role keys. Before that it can request the auditor key and the records tree from Ring RPC. Differs from the PR 15 draft: its single Config Authority splits into these roles.

Ring RPC keeps one key file per role. The auditor key opens ring activity. The service key signs auditor key releases, and every signed read and grant binds it. The storage authority signs record tree updates. The co-signer signs co-signatures. The fee payer pays for relayed transactions. The grant rows key seals database reader grants. Each key does one job. Ring RPC refuses to start when two role files hold the same secret, and its root secret yields auditor keys only.

## Trust Assumptions

1. **Storage authority:** trusted for every policy record. The tree proof verifies the update, not the record. A write the authority signs directly skips every Ring RPC check, the wallet's signature included. No authority writes a tracking tree, so none can delay, change or clear an enrollment.
2. **Policy authority:** trusted to set policy rules, lists, limits and ring-wide grants, and to bind the records. Each other role is trusted for its own control.
3. **Ring RPC:** trusted to protect the auditor key and every proof input a wallet hands it. It is trusted to enforce reader grants and co-signer limits, and to write records as signed. A depositor or the delegate signs the message Ring RPC builds. The ring SDKs sign it only when the quoted fee payer pays and the one instruction is the ring operation the request asked for. With derived keys Ring RPC relays and pays only for a ring whose config names an auditor key it derives, and its rate limits bound what it pays. Replicas share the store and the same service, auditor and co-signer keys. One projection lease owns each ring, and one writer serves each storage authority. Ring RPC holds the auditor key, so it opens the nullifier secret of every enrolled owner and links that owner's spends. Only a note under the zero nullifier key carries no secret, and its sender and the auditor both compute its nullifier.
4. **Curator:** a ring trusts the authority of its one curator tree.
5. **Delegate:** trusted with every member's funds. It moves, withdraws and exits any note of the ring outside the rules, guards, caps and approvals.
6. **Upgrade authority:** trusted to create the ring and to deploy upgrades that keep the program's guarantees. An upgrade can replace every check. Only the operator tools refuse an upgrade over a ring account the new release cannot read.
7. **Key generator:** the ring proving keys come from a single-party setup. Whoever ran it could forge every ring proof.
8. **Revocation timing:** a restrictive update binds on chain the moment the Storage program applies it. A transaction that passed Ring RPC or a relayer before then fails on chain. The apply proof marks an update restrictive when it tightens a list, guard or bound, writes a private list or changes an asset limit. A curator's revocation binds as fast as its authority writes it.
9. **Limits:** Ring RPC enforces co-signer limits only on what it co-signs. A co-signer outside Ring RPC enforces none.
10. **Photon, ring indexer and chain RPC:** Photon and the ring indexer that forwards to it are trusted for complete history, the chain RPC for confirmed contents. A balance read observes the service's verified finalized history. No authoritative balance or limit decision reads it, see [reading through Ring RPC](design/audit-and-recovery.md#reading-through-ring-rpc). Ring RPC verifies each record opening under the newest root. While the ring indexer lags that root, Ring RPC's tree-mode reader grant checks, its limit updates and its co-signatures on a deposit, transfer or withdrawal fail.
11. **SPP governance:** trusted to activate the ring when SPP does not activate it at creation, and to enable its authority rail.
12. **Delegate message:** before the delegate signs, the ring SDKs open the message's auditor records and check the move against the request. Each requested payment or exit must match its output kind, owner key, nullifier key, mint and amount. Each withdrawal must match its recipient, mint, amount and token program. Every other ring output must return to a requested source. The message carries no deposit, extra leg or data. Each spent note position must carry a nullifier of a note the delegate opened for exactly the requested sources. The SDKs do not choose which of those notes the move spends.

## Glossary

| # | Term | Type | Definition |
| --- | --- | --- | --- |
| 1 | **Ring note** | UTXO | An SPP note tagged with the ring's id. Only a transaction the ring program signs moves it. |
| 2 | **Default ring** | Note set | SPP notes outside every ring. An exit pays into it. |
| 3 | **Ring account** | Account | The one account that holds a ring's roles, settings, policy and the addresses of its record trees. |
| 4 | **Mode** | Ring setting | A `RingKind`: `AuditOnly`, `Policy`, `Anonymous` or `AnonymousPolicy`. Fixed at creation. Setting a delegate changes no mode. |
| 5 | **Policy ring** | Ring setting | A ring with a rule table. Every transfer proves it inside its one ring proof. An audit-only ring proves the same statement with the policy section switched off. |
| 6 | **Member record** | Tree leaf | One member's list bits and, for an asset, mint settings, in a policy registry. |
| 7 | **Mint settings** | Record fields | An asset's guard threshold, cap, co-sign bound, withdrawal threshold and window limits. |
| 8 | **Records** | Storage tree | The ring's own record tree. |
| 9 | **Curator** | Storage tree | A record tree of any authority that serves some of a ring's lists. A ring has at most one. |
| 10 | **Revision** | Root number | The sequence number of a storage root. A proof names its root by revision, and the program reads that root live from the registry. |
| 11 | **Rail** | Transfer form | How SPP authorizes a spend: owner signer, in-proof owner, hidden owner or delegate. |
| 12 | **Exit** | Output | An output paid to the default ring. Its owner is public. |
| 13 | **Public leg** | Transfer part | A SOL or SPL deposit or withdrawal inside a transfer. Its account, asset and amount are public. |
| 14 | **Enrollment** | Tracking row | An owner's fixed nullifier key, list tag and ciphertext hash in the tracking tree. The authorization account holds its current viewing key and sealed secret and salt. `RegisterKey` proves the seal. It lets the auditor link that owner's spends and lets Ring RPC merge its notes and serve the delegate. |
| 15 | **Record update** | Signed request | A signed list of record writes that Ring RPC queues and applies. |
| 16 | **List approval** | Record update | A wallet's policy record update that waits for the policy authority to set the lists it needs. It is separate from enrollment. |
| 17 | **Relay** | Ring RPC operation | Ring RPC proves, co-signs, pays for and sends an operation the wallet requested. |
| 18 | **Shape** | Proof width | The input and output counts of a transfer. SPP has one proving key per shape, and a ring key serves every shape up to its input class. |
| 19 | **Wallet** | User | Holds spending keys and authorizes transfers of its ring notes. |
| 20 | **Reader** | User | Uses granted read access to query decrypted ring activity through Ring RPC. |
| 21 | **Auditor** | Authority | Holds the auditor key and decrypts ring transfers, deposits and merges. It also decrypts each enrolled owner's sealed nullifier secret and list salt. |
| 22 | **Co-signer** | Authority | Signs operations when the ring's co-signer scopes or outflow bounds demand it. |
| 23 | **Delegate** | Authority | Moves any note of the ring with no owner signature and outside the rules. |
| 24 | **Policy authority** | Authority | Sets the ring's rules, lists, mint settings and ring-wide grants. |
| 25 | **Storage authority** | Authority | Signs the updates of one record tree. Ring RPC holds it for the ring's records. |
| 26 | **Upgrade authority** | Authority | Deploys and upgrades the ring program and signs `Initialize`. |
| 27 | **Auditor stream** | Ciphertext | One AES-256-CTR stream per transfer, sealed to the auditor key and proven. It carries the transaction viewing secret, the input map and the entry openings on an entry key. It also carries one record per published slot and, under `has_data`, one data tail per slot. |
| 28 | **Recipient body** | Ciphertext | A ring output's blinding, amount and mint, encrypted to its recipient's viewing key. No proof constrains it. |
| 29 | **Change** | Output | An anonymous output to the sender, published with no recipient body. The sender bundle rebuilds it. |
| 30 | **Sender bundle** | Ciphertext | One per anonymous transfer, encrypted to the sender's viewing key. It holds the change cells, the output seed and each recipient's viewing key. No proof constrains it. |
| 31 | **Reply metadata** | Ciphertext | An optional unauthenticated claim about the sender, one fixed length per frame. |
| 32 | **Published slot** | Output position | An output position below the frame's count `m`. A compact frame omits every later position. |
| 33 | **Tracking registry** | Storage tree | One ring's tree of enrollments. Any applier moves pending enrollments into it, and no authority writes it. |
| 34 | **Tracking floor** | Registry field | The highest tracking revision a private write proved a row under. A frame that reads a salted list through the registry names no lower tracking revision. |
| 35 | **Input map** | Envelope field | The sealed note count `R` and address bitmap `A` that class each published input as a note, an address or a dummy. |

## Flows

1. Enrollment and list approval
2. Record updates
3. Deposit
4. Transfer (anonymous, confidential, exit to the default ring, withdrawal)
5. User merge
6. Managed merge
7. Authority transfer
8. Reader access grants and revocation
9. Co-signer limits configuration

## 1. Enrollment and list approval

Every owner that receives or spends a ring note under a nonzero nullifier key enrolls on the ring's tracking registry, on every ring kind. A note under the zero nullifier key needs no row for its key. A wallet has one nullifier secret, so enrollment discloses it to each ring's auditor it enrolls with. An owner's nullifier key, list tag and ciphertext are final on one registry after the first enrollment.

1. **Owner:** signs Storage `Enroll` with its nullifier key, its list tag, its viewing key, an ephemeral key and a ciphertext. The ciphertext seals its nullifier secret and list salt to the ring's auditor key, and a `RegisterKey` proof shows the seal. A wallet signs directly, and a program signs its PDA through CPI. The payer funds the account and authorizes nothing. Ring RPC relays it for a wallet with no SOL when its operator funds a relay budget.
2. **Storage program:** verifies the proof against the ring id and the auditor key the tracking registry pins and the member of the signing owner. It refuses the zero nullifier key and stores the tracking authorization. `Enroll` moves no root.
3. **Any applier:** sends `ApplyEnrollments` with a proof over the authorization accounts it names. The program computes each entry from its account and marks the account applied, so no applier can alter or repeat one. Ring RPC applies the rings its operator names, under a key none of its other jobs uses.
4. **Ring indexer:** lists pending authorizations, projects the tracking tree and serves its openings.

An enrollment grants nothing until an apply places its row under a tracking root. A recipient becomes usable at the first root that holds its row. Before then the SDKs refuse to pay the owner under a nonzero key, and a salted owner write for it fails. Any party can apply, so no single applier holds an enrollment back. No authority writes the tracking tree, so no authority can gate an enrollment. [Tracking](design/records-and-roots.md#tracking)

A wallet rotates its viewing key per ring. It signs `Enroll` again on that ring's tracking registry with the new viewing key and every other field unchanged. The rotation carries no proof, and the program refuses a change to any other field. The rotation moves only the authorization's viewing key and waits on no apply. A sender verifies the owner's row under a tracking root and reads the viewing key from the owner's authorization at `confirmed`. An address that carries an older viewing key therefore seals to the current one.

List approval admits a wallet to lists, and it is separate from enrollment:

1. **Wallet:**
   1. Signs a record update for its own lists.
   2. Names the reader list, or the allow or approval list its ring's rules read from its own records, when it awaits one.
2. **Ring RPC:**
   1. Checks the cluster, the signature, the expiry, and that the wallet writes only its own record and its own grant records.
   2. Holds an update pending list approval until the **Policy authority** approves it or refuses it, or its window ends.
3. **Policy authority:** approves a pending update with its own update that sets every awaited list, and both reach the tree in one root.
4. **Ring RPC:** queues the update, proves the tree update, submits it to the **Storage Program**, and pays fees.
5. **Ring indexer:** projects the applied records and serves their openings.

## 2. Record updates

The **Wallet** writes its own viewing flag and its wallet grants. The **Policy authority** writes the authority lists, the mint settings and ring-wide grants.

1. **Wallet or Policy authority:** signs an update for one cluster, ring and tree, valid until a slot, and sends it to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the signer may write each entry.
   2. Queues wallet and authority updates in separate batches. An update its list approval joined rides first in its approver's batch.
   3. Sends an authority batch at its next pass, and a wallet batch when it is full, aged or ahead of a queued authority update.
   4. Leaves the grace to the **Storage program**. The apply proof marks a batch [restrictive](design/records-and-roots.md#root-history) when it tightens a list, guard or bound, writes a private list or changes an asset limit. Such a batch retires every earlier root. Any other batch keeps the outgoing root for the grace period, and over a full history it evicts the oldest kept root.
   5. Proves a batch with salted owner writes under the private apply key. The proof opens each such owner's applied row under one root of the pinned tracking registry. It holds the written key to the owner's salted member under a salt that opens the row's list tag. A wrong salt fails the proof. The update names that root's revision. The Storage program reads the root and raises the registry's tracking floor to the revision in the same instruction. A batch whose salted owner has no applied row fails before the proof.
   6. Refuses a queued authority update once its signer no longer holds the policy role.
   7. Proves each batch and submits it, paying fees.

[The record writer](design/record-writer.md)

## 3. Deposit

A deposit moves SOL or tokens from a wallet's public balance into up to 8 ring notes. The token and amounts are public. It is a transfer that spends no note, every SPP input a dummy, funded by a deposit leg.

**Limit:** one deposit carries at most 3 distinct tokens, the public slots of a transfer key. The SDKs refuse a wider deposit before proving, and the wallet splits it.

1. **Wallet:**
   1. Chooses the token, amount and recipient.
   2. Prepares the deposit notes and seals their openings to the **Auditor**.
   3. Sends the deposit request to **Ring RPC** on the deposit relay rail. The funder signs `deposit_request_digest`, the SHA-256 of `"zolana/ring-rpc-relay-deposit"` and the proof input bytes. No owner signs.
2. **Ring RPC:**
   1. Checks that the ring is active. Refuses a frame with a real input, with two funders, with the fee payer as funder, or with a signature the funder did not make.
   2. Generates the transfer proof. It shows the owner and asset rules hold for each recipient and asset. It also shows that each nonzero nullifier key matches its owner's tracking row. Under a salted payee read it shows that each zero-key owner has no row.
   3. Returns the transaction to the **Wallet** for signing.
3. **Wallet:** the funder signs the transaction to authorize the SOL or SPL token transfer.
4. **Ring RPC:**
   1. Co-signs when deposits demand approval.
   2. Pays fees and submits the deposit to the **Ring Program**.
   3. Follows the deposit to confirmation. The recipient's **Wallet** finds its notes by view tag.

Without Ring RPC the **Wallet** reads the records itself, generates the transfer proof, and pays for and submits the deposit.

On every ring the sealed opening names each note's owner key, and the transfer proof binds that key to the note's owner commitment. No ring instruction signs SPP's proofless ring deposit.

## 4. Transfer

A unified flow for anonymous and confidential transfers, exits and withdrawals. On every rail the transfer proof holds each live input to the rail's owner rule. It holds each live ring input under a nonzero key to its owner's tracking row. The sealed input map classes each published input as a note, an address or a dummy. The proof derives it from the nullifiers the program forwards to SPP. The auditor links each published nullifier of a note to a note it opened.

**Variants:**

1. **Anonymous:** a hidden owner signs inside the SPP proof, and public co-owners can sign beside it. The sender and recipients stay hidden from chain observers. No proof constrains a recipient body, a tag or the sender bundle, and SPP's external data hash binds their bytes. The discovery guarantee is [Discovery](spec/crypto/disclosure.md#discovery). A sender can attach reply metadata, and a recipient reads it as an unauthenticated claim.
2. **Confidential:** the policy screens the sender and recipients as public inputs. The wallet signs inside the proof, and the signer rail serves one or more owners who send their own transaction.
3. **Exit to the default ring:** some outputs leave the ring to a public owner.
4. **Public withdrawal:** SOL or SPL transfers to one or more accounts, optionally alongside other outputs. On the anonymous rail every withdrawal pays one key. Ring RPC can create the missing token account of an SPL withdrawal.

**Steps:**

1. **Wallet:** takes a quote that names the fee payer and builds the transfer from its own notes. It seals the **Auditor** stream, signs the SPP message hash and sends the proof inputs to **Ring RPC**. It reads no Merkle path and no record.
2. **Ring RPC:**
   1. Verifies the owner's signature.
   2. Reads the required member records and Merkle paths.
   3. Generates the SPP proof and the ring proof.
   4. Co-signs within the limits when the transfer demands a co-signer.
   5. Pays fees, submits the transaction to Solana and follows it to confirmation.

A recipient wallet finds an anonymous note by scanning ring history, see [wallet scanning](design/audit-and-recovery.md#wallet-scanning). Without Ring RPC the **Wallet** does step 2 itself and pays from a fee payer it chooses. A demanded co-signer still signs. On the anonymous rail that payer and any co-signer must differ from the hidden owner, and the ring program accepts any such payer.

A frame publishes `m` output slots up to the key's capacity, and omits the rest as a suffix. A ring output publishes no owner identity, and an exit's owner is public. Every ring program transaction is one inline v1 transaction, with no frame buffer and no lookup table. The SDKs refuse before proving a frame whose transaction passes 4,096 bytes or 64 addresses, or whose SPP CPI data passes 10 KiB. The key catalog in `program-libs/interface/src/proof/key_catalog.rs` fixes each key's input class. The SDKs refuse a wider shape as unkeyed, and the sender merges first. A relayed transfer carries withdrawals only, and a relayed deposit takes the deposit relay rail of [Deposit](#3-deposit). A transfer that spends a note beside a deposit leg goes out in the owner's own transaction, and on an anonymous ring its payer funds the leg.

The table names construction paths, subject to policy, key capacity and frame fit. Direct SDK paths build their own proofs. Hosted paths ask Ring RPC to prove and submit. Public co-owners still sign the transaction. A missing proving key refuses every path.

| Transfer combination | Direct Rust | Direct TypeScript | Hosted Ring RPC | Proof and program boundary |
|---|---|---|---|---|
| Confidential signer, ring or default-ring inputs, optional public co-owners | Yes | Yes | No signer path | SPP verifies public owner signatures. Default-ring inputs select an entry key. |
| Confidential in-proof owner, ring inputs, optional public co-owners | Yes | Yes | Yes | SPP verifies the owner's proof signature and each public co-owner's transaction signature. |
| Confidential in-proof owner with a default-ring input | Refused | Refused | Refused | The ring entry proof permits the input, but the SDK paths refuse it. |
| Anonymous hidden owner, ring inputs, optional public co-owners | Yes | Yes | Yes | Input zero belongs to the hidden owner. Its key is nonzero. Public co-owners sign. |
| Anonymous entry, one owner, default-ring inputs only, no input data | Yes | Yes | Yes | SPP publishes the default-ring owner's identity. An entry key opens those inputs to the auditor. |
| Anonymous entry with public co-owners or input data | Yes | Yes | Yes | The hidden owner cannot mix its own ring and default-ring notes. Public co-owners sign. |
| Anonymous owner mixing its own ring and default-ring inputs | Refused | Refused | Refused | SPP refuses the mixture. Use the public-owner path. |
| Anonymous public owners, ring or default-ring inputs | Yes | Yes | No public-owner path | Every spending owner signs. Default-ring inputs select an entry key. Recipients remain hidden. |
| Delegate, ring inputs, payments, exits or withdrawals | Yes | Yes | Yes | The delegate signs. Policy checks and co-signer demand are bypassed. |
| Delegate with default-ring inputs | Refused | Refused | Refused | The authority proof and key selector require ring inputs. |
| Confidential single-asset payout | Yes | Yes | Refused | One public owner, one ring input and 16 real ring outputs of one asset. No entry, public legs, data or replies. |

The capacity profiles below use one input, a separate payer, one co-signer and one curator, with no application data or replies.

| Rail | Output capacity | Conditions |
|---|---|---|
| Confidential published owner | 16 delivered recipients | Single-asset payout format, one asset, exact funding, no change, exits or public legs |
| Anonymous hidden owner | 8 total slots | Change consumes a slot, leaving at most 7 recipient payments when change is present |

The confidential in-proof SDK rail does not accept default-ring inputs. Other combinations require their own frame-fit check. A missing proving key refuses the operation. A supported encoding does not establish that its production key is available.

The SDKs select the largest eligible notes first within the rail's input and tree limits. Selection can refuse a payment even when another note subset fits. The sender can merge notes before another attempt.

## 5. User merge

A merge combines notes of the same wallet, token and ring into one note with their total value, up to 24 at once.

1. **Wallet:** selects the notes and sends them with its nullifier secret to **Ring RPC**. Under a nonzero key it signs nothing, because the merge proves the nullifier secret. Under the zero key it signs the transaction as the published owner.
2. **Ring RPC:**
   1. Checks that the notes are unspent and belong to the same wallet, token, ring and tree.
   2. Generates SPP's merge proof and the ring merge proof. The ring proof seals one opening record of the output and its seed to the **Auditor**. Under a nonzero key it also opens the owner's tracking row. It opens no input.
   3. Pays fees and submits the merge to the **Ring Program**.
   4. Indexes the result.

An owner never pays its own merge, on any ring mode, because the merge proof holds the owner apart from the payer. A wallet merges in one of two ways:

- Through a second funded key, with the **Wallet** generating both proofs.
- Through **Ring RPC**, which receives the wallet's nullifier secret.

A confidential wallet with only its owner key can spend its notes through a signer rail transfer. An anonymous wallet can spend them through a public-owner rail transfer. A demanded co-signer still signs.

A merge runs no policy rule and demands no co-signer. The **Auditor** rebuilds the output from the merge record and the first nullifier, and marks the inputs spent through their nullifiers.

## 6. Managed merge

Managed merge is initiated by **Ring RPC** on every ring it audits, in either mode, for a wallet whose tracking enrollment it holds. It combines one wallet's notes of one token toward the wallet's settings.

1. **Wallet:** signs its merge settings for a token: a target note count and a minimum average amount. A zero target revokes them.
2. **Ring RPC:**
   1. When the wallet holds more notes than its settings allow, selects its smallest notes in the tree that holds most of them, up to 24 so that the merge fits one transaction.
   2. Opens the wallet's nullifier secret from its tracking seal with the auditor key and prepares the merged note.
   3. Generates SPP's merge proof and the ring merge proof.
   4. Pays fees and submits the merge through its relay.
   5. Indexes the result.

Ring RPC stores merge settings on any ring, and gives no error where it cannot merge.

## 7. Authority transfer

An authority transfer moves a wallet's funds to recipients within the same ring, to withdrawals or to exits, authorized by the permanent **Delegate**.

1. **Delegate:** signs a request naming the source wallets, ring payments, exits and withdrawals, including each mint, recipient and amount. SPL withdrawals also bind their token program when supplied.
2. **Ring RPC:**
   1. Checks that the signer is the ring's delegate and that the ring's config names the auditor key Ring RPC holds.
   2. Opens the source's nullifier secret from its tracking seal, or takes zero under the zero key, and checks it against the source's nullifier key.
   3. Funds the payments from the source's notes and returns the change to the source.
   4. Generates the SPP proof and the ring proof, the inputs' tracking rows and the outputs' key rule included.
3. **Delegate:** checks the message against its request, see trust assumption 12, then signs the transaction.
4. **Ring RPC:** pays fees, submits the transfer to the **Ring Program** and indexes the result. The delegate rail demands no co-signer.

A **Delegate** can generate the proofs and send the move without Ring RPC. It reads the source's nullifier secret and openings through `getDelegateNotes`, which Ring RPC answers only to the ring's configured delegate.

## 8. Reader access grants and revocation

The **Policy authority** grants and revokes **Reader** access across the ring. A **Wallet** grants and revokes access to its own activity.

1. **Policy authority or Wallet:** signs a grant or revocation and sends it to **Ring RPC**. It names the ring, the **Reader**'s key and, for a wallet grant, the wallet.
2. **Ring RPC:**
   1. In tree mode, writes it as a record update, see Flow 2.
   2. In database mode, verifies the signature and stores the grant sealed under its grant rows key. The grant with the newest signed timestamp holds.
3. **Reader:** signs a read request with its wallet key or passkey.
4. **Ring RPC:** verifies the signature and an active grant, then returns the permitted activity.
   1. A ring-wide grant covers every wallet.
   2. Wallet scope admits the sender of an anonymous transfer, a confidential spender and the owner of an output, and returns only that wallet's view.
   3. A confidential spender is an owner signer or the in-proof owner, and it sees every output, payload error and withdrawal of its transfer.
   4. Signing or paying the fee alone admits no wallet.

A revoked reader keeps what it already read.

## 9. Co-signer limits configuration

The **Policy authority** configures the limits applied by the **Co-signer** that Ring RPC runs.

1. **Policy authority:** sets, updates or removes each asset's sender, volume, deposit and withdrawal caps and their windows, in a record update.
2. **Ring RPC:**
   1. Refuses a cap without its window, a window without its cap, a window past its bound, and limits for an asset with no record. Limits for a new asset go in an update submitted after the one that creates its record lands.
   2. Applies the update as Flow 2 does.
3. **Ring RPC**, before each co-signature:
   1. Reads the limits under the records' newest root.
   2. Reserves the operation's flows and signs only when every limit holds.
   3. Keeps the reservation at confirmation and frees it on failure or expiry.
   4. Refuses to co-sign when it cannot read the limits.

The **Ring Program** checks only the required co-signer signature, never the limits. A limit binds only the operations the ring requires co-signing for. [Co-signing](design/co-signing.md)

## Instructions

### Ring Program

1. `Initialize`: creates the ring account with the four role keys and the auditor key. It creates the ring's tracking registry through the Storage program, binds the records, and on a policy ring pins the rule table. It registers the ring with SPP. It refuses a records registry whose ring id is not this ring's. The upgrade authority signs.
2. `UpdatePolicy`: replaces the rule table, repoints one list's source, or rebinds the records to a registry of this ring. Its trailing accounts are the registries the write names, then every other registry a private list of the resulting account reads, matched by address. It refuses a salted source of another ring and stores nothing on a refusal. The policy authority signs.
3. `UpdateAuthority`: hands one role to a new key. The admin and the new key sign. Differs from the PR 15 draft: it names the role.
4. `SetPaused`: pauses or resumes the ring in SPP. The pauser signs.
5. `SetCoSigner`: creates a co-signer account or changes its scope. The co-signer admin signs.
6. `ClearCoSigner`: closes a co-signer account to a rent recipient. The co-signer admin signs.
7. `SetDelegate`: sets the delegate once. It changes no mode and needs no policy. The admin and the delegate sign.
8. Tag 58 is unassigned. A deposit is a `Transfer` that spends no note.
9. `Transfer`: verifies the one ring proof before SPP CPI. Its statement carries the audit, the tracking root and the policy section under the ring's written policy hash. It also carries `approval_mask` under the thresholds of the ring's own records. The payer signs. On the signer rail each input owner also signs. On the in-proof rail the owner the frame names signs inside the SPP proof, and each other owner of the run signs the transaction. The proof holds every input to one of them. On the anonymous rail each public co-owner signs. Each co-signer the demanded classes need and each deposit leg's funder also sign.
10. `AuthorityTransfer`: as `Transfer` on the authority rail, on a confidential or an anonymous ring. It reads no policy root, sets no approval bit, demands no co-signer and takes no deposit leg. The delegate and the payer sign.
11. `Merge`: verifies the ring merge proof before SPP CPI. Its statement carries the output hash, the first nullifier, the ring id, the auditor and ephemeral keys and the sealed record. It also carries the payer, the published owner and the tracking root. The payer signs, and under the zero key the published owner. No co-signer signs.

### Storage Program

1. `Initialize`: creates a policy registry at an address only its creator can take, with the empty root. Its grace, ring id and tracking registry pin are final. The creator becomes the authority.
2. `Update`: applies 1 to 16 writes with a proof of the tree update. The proof binds whether the batch is restrictive, and a restrictive batch retires every earlier root. Any other batch keeps the earlier root valid for the grace period and evicts the oldest kept root from a full history. A write to a private list is a private write, unless it names an asset whose mint hashes to its member. A batch with a private write proves under the private apply key. That proof opens each private write's owner row under the pinned tracking registry's root at the revision the update names. It holds the written key to `Poseidon(CRPL, member, list_salt)` for a salt whose `Poseidon(CRPT, list_salt)` is the row's list tag. The program refuses a private write on a registry with no tracking pin. It raises the tracking floor to that revision with the new root. The authority signs.
3. `UpdateAuthority`: hands the registry to a new authority. Both keys sign.
4. `Enroll`: creates an owner's tracking authorization with a `RegisterKey` proof the program verifies, or rotates its viewing key with no proof. The owner and the payer sign.
5. `ApplyEnrollments`: applies 1 to 16 named authorizations to the tracking tree with a proof of the tree update. The program computes each entry from its account. Every retired root keeps its full grace, and an apply over a full history of unexpired roots fails with `RootHistoryRetained`. No authority signs.
6. `OwnerGrant`: grants or revokes one reader's access to a program owner's activity. The owner signs, a program through CPI, and the payer funds the account.
7. `InitializeTracking`: creates a tracking registry under a signing creator, with its final ring id and auditor key. Ring `Initialize` creates the ring's own through CPI signed by its ring PDA, and binds its address.

## Design decisions

1. Records live in Storage program trees, and the ring account binds their addresses. Every root reader takes the registry accounts and reads their roots live, so a revocation binds on chain the moment storage applies it. Differs from the PR 15 draft, whose question 3.1 syncs roots into the policy account for one account per transfer (open question 11).
2. The Storage program verifies each tree update and each first enrollment's `RegisterKey` proof on chain. Ring RPC checks the signatures of policy record updates off chain. Update proofs stay small, as the draft's notes 5 and 6 ask, and no false seal reaches a tracking row.
3. Each tracking authorization keeps the owner, the nullifier key, the list tag and the sealed secret and salt in an account. The auditor and Ring RPC recover every enrolled secret from the ring's tracking rows after a restart.
4. An enrolled nullifier key, ciphertext and list tag are final, and a later `Enroll` moves only the viewing key. No later write can redirect an owner's seal, and a viewing key rotation touches one ring.
5. The program retires every earlier root only for a batch whose apply proof marks it restrictive, and keeps the others within grace. A block binds at once. An allowlist addition or a wallet write keeps the outgoing root valid for the grace period. A kept root reads no policy field more permissively than the newest root, so it admits no transfer the newest refuses.
6. Authority and wallet writes never share a batch, except an update its list approval joined. After proving, the writer checks each update's expiry and any required policy role before signing. An invalid member prevents submission of the batch. Later expiry or role rotation does not revoke an already signed transaction.
7. An update pending list approval waits within a bounded window under rate limits, with no cap on pending updates. A cap would let spam lock list approval out.
8. The config and the policy are one ring account. A transfer loads fewer accounts.
9. Five on-chain roles replace the single Config Authority. A stolen key other than the admin key reaches one control.
10. Ring RPC reads one key file per role. A leaked file exposes one job.
11. Each co-signer has its own account. A transaction carries a co-signer for each demanded class, and one co-signer may cover several. A ring can then keep separate outflow and withdrawal approvers. The hot path loads each co-signer account by owner and discriminator, as the draft's note 2 asks.
12. Co-signer limits live per asset in the asset record, each cap with its own window. The tree already serves per-asset data under a root the program reads.
13. Co-signing fails closed when Ring RPC cannot read the limits or the asset has no record. Either would otherwise read as no limits.
14. Ring RPC relays and pays for every wallet operation except a transfer that spends a note beside a deposit leg, or an operation that needs an outside co-signer. A deposit relays on its own rail, where the funder signs the deposit request and no owner signs. A relayed wallet never fetches a Merkle path, as the draft's note 4 asks.
15. The confidential in-proof rail proves on SPP's anonymous rail, and admits signing co-owners beside the in-proof owner, as SPP does. The transfer proof holds every input to the in-proof owner or an owner of the signed run. It follows the maintainer's suggestion and keeps no new SPP circuit.
16. Both confidential owner rails stay. The program admits an entry key on every rail but the delegate's. The SDKs refuse a default-ring input on the in-proof rail, and a hidden owner's ring notes beside its own default-ring note.
17. This repository never refactors zolana circuits. They are audited, and a source change reopens the audit.
18. The transfer statement holds no recipient key, body or tag. Recipient delivery stays outside every proof, and the audit stays provable on every transfer.
19. A deposit proves on a transfer key and opens the curator root. Curator asset lists then admit deposits.
20. The SDKs refuse a merge whose payer is the owner, on every ring. The merge circuit already refuses it, and the SDKs fail before proving.
21. Every ring merge proves one opening record of its output and the seed, sealed to the auditor. SPP's proof ties every input to that owner, asset and sum, so the ring proof opens no input and one ring key serves every width.
22. A deployment keeps reader grants in one store. Every read checks one source of truth.
23. A passkey reader's record is keyed by a hash of its tagged key. Ed25519 and passkey readers share one record space.
24. Wallet scope admits the anonymous sender, a confidential spender and the owner of an output. A key that only signs or pays is no party to the transfer.
25. Replicas with the same co-signer key share one store. Asset locks serialize admission, and each signature reserves once. Different signing keys have separate reservations and cannot share one message allowance. Projection writes require the ring lease. Record writers remain single per storage authority.
26. No instruction migrates an older ring layout. Rings are created fresh, and the repository forbids compatibility shims. A change to the `RegisterKey` seal needs a fresh deployment. An enrolled owner's nullifier key, ciphertext and list tag are final in its ring's one tracking registry.
27. `Initialize` creates the ring account, binds the records and registers the ring with SPP in one instruction. No half-created ring exists.
28. Ring RPC creates the ring's records tree under its storage authority, and `Initialize` binds it. The program accepts any storage registry of this ring as the records, so whoever binds them picks the records writer. A tree written outside Ring RPC skips its checks.
29. One Poseidon schedule under a 9-byte label keys every ring stream, the merge record included.
30. Every published slot has one record in the auditor stream, and the statement chains the records and the data tails. The transfer circuit expands one AES key for the auditor stream, and no counter serves two regions.
31. The key catalog fixes one input class per family and output count. A wider class costs a key, so no class grows without a verdict behind it.
32. A nullifier key enters a tracking row only through an owner-signed `Enroll`, never through instruction data of another party. A wallet and a PDA share one path, and no authority can delay or change an enrollment. `ApplyEnrollments` computes every entry from an authorization, so a row under a root proves a verified enrollment.
33. Enrollment lives in a tracking tree apart from the policy registry, because one tree would make enrollment and revocation race on one revision. A curator source reads list bits only, so any registry other than the ring's records can serve as a curator.
34. Reply metadata is optional and off by default. The mandatory body names neither sender nor memo, and a reply stays an unauthenticated claim.
35. A transfer's co-signer derives each owner's debit from the frame it signs with the auditor key. Client-sent openings would widen what the co-signer learns.
36. A note under the zero nullifier key needs no tracking row for its key, so a program-owned note needs no enrollment. The proof accepts a zero-key output to an enrolled owner only while no salted payee read is active. Under a salted payee read the payee's row must be absent, a requirement of its own since the salted read opens a payee's row by owner identity whatever the key. The SDKs accept that zero-key recipient and read its current viewing key from its authorization account. Readers mark a zero-key note `exposed_if_spent`, and automatic selection leaves it out.
37. A slot's discovery tag is a hint no proof constrains. One every-site scan reads no tag, so a wrong tag cannot hide a note its recipient can decrypt.
38. A salted owner write proves the owner's row under one tracking root. In the same instruction it raises the source's tracking floor to that root's revision. Rows never leave the tracking tree, so every root a salted read accepts holds each owner with a private entry. No such owner proves absence. An owner with no applied row has no private entry, so its proven absence hides none.
39. The input map is part of the sealed envelope and the proof derives it from the forwarded nullifiers. Notes and addresses interleave in SPP's order before the dummy suffix, and a reader never takes an address for a spent note.

## Notes

1. Anonymity holds only under the conditions in [privacy](design/privacy.md). A confidential ring publishes its sender and each recipient's viewing key.
2. An anonymous transfer cannot create an address.
3. A delegate is permanent for the deployed program. An enrolled nullifier key, ciphertext and list tag are final.
4. A paused ring, or one SPP governance has not activated, moves no note.
5. A tracking registry keeps `ROOT_HISTORY = 32` roots, and every retired root serves its full `TRACKING_GRACE_SLOTS = 750` slots. An apply that would evict an unexpired root fails with `RootHistoryRetained` (9037), and its accounts stay pending until the oldest root expires. A rotation writes only the authorization and moves no root. A proof under a served tracking root therefore stays valid for the grace, and enrollment waits under sustained apply load.

## Open questions for the maintainer

1. Should co-signer limits be set per co-signer, as the draft's Flow 9 names, or per asset as built?
2. Ring RPC pays fees and token account rent with no charge. Which fees does the policy authority set, and who charges the relay fee?
3. SPP reads an output's encryption scheme byte as its exit marker. Should SPP carry an explicit exit marker in the output data instead?
5. Does this scope fit the two-week audit, and what moves out if it does not?
7. A ring reads lists from one curator. Is one enough?
8. Third-party ZK programs settle through plain SPP transfers and cannot touch ring notes. Should the ring program offer a hook for allowlisted programs?
10. An enrolled nullifier key cannot change once its tracking row exists. Should a wallet be able to rotate it?
11. Roots are read live from the storage registries, so a policy transfer passes the ring account plus one or two registry accounts. Do you accept this over your question 3.1, which syncs roots into the policy account?
