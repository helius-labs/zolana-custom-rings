# Custom rings

A custom ring enforces your own compliance rules on private transfers in the Solana Privacy Program (SPP). The ring program moves a ring note only after it verifies the proofs and approvals its settings demand. Ring RPC proves, co-signs, pays for and sends wallet operations, and a wallet can also prove and send its own. This document describes each control, who can change it, what each party is trusted with, and the decisions behind them.

The docs form one ladder from this overview down to the code. Each rung says only what the rung above cannot.

1. This spec: the controls, components, roles, trust, flows and decisions.
2. Design notes, one short file for each concept that is hard to see from here: [records and roots](design/records-and-roots.md), [owner rails](design/owner-rails.md), [the record writer](design/record-writer.md), [co-signing](design/co-signing.md), [privacy](design/privacy.md), and [audit and key escrow](design/audit-and-escrow.md).
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

The policy defines which checks a transfer must prove. `Initialize` pins the first rule table, and the policy authority then sets the rule table and writes the list entries. A rule screens the sender, every output owner or every asset, and rules join with AND. Within one rule the lists join with OR, so a rule that forbids several lists refuses only a subject on all of them. A list has no effect until a rule reads it. A new rule table binds at once, and every proof made under the old one fails. A ring created without a rule table never gets one. [Records and roots](design/records-and-roots.md)

### 1.1. Allowlist

An allowlist is a list of approved identities. A rule can require the sender, every recipient, or both, to be on it. A recipient rule screens every output, the sender's change and each exit included, and the owner of each withdrawal. A guard can exempt payments at or below a threshold, so only recipients above it must be listed. The threshold is one value for the rule, which limits each transfer to one asset, or one value per asset in the asset's record.

### 1.2. Blocklist

A blocklist is a list of identities or assets the ring refuses. A sender rule over it stops every transfer and delegate move of a blocked identity. Its notes stay in the ring, and it can still merge them. A blocklist refuses known members only. A fresh key passes it.

### 1.3. Frozen list

The frozen list is a second authority list, kept apart from the blocklist. A sender rule over it stops every transfer and delegate move of a frozen identity.

### 1.4. Asset allowlist

An asset rule over the allowlist admits only listed assets to deposits and transfers. A guard on that rule can admit small amounts of other assets. A deposit runs the asset rules and no owner rule.

### 1.5. Outflow limits per transfer

An asset's record can hold a cap and a co-sign bound. The policy proof keeps one transfer's outflow of the asset at or below the cap, and demands a co-signer above the bound. An asset with no record has neither. The outflow is the asset's outputs to another owner or another ring plus its withdrawals, less its deposits. Limits over time are Ring RPC's, see 3.2. Differs from the PR 15 draft: per-transfer outflow limits live in the policy proof. [Co-signing](design/co-signing.md)

### 1.6. Auditor

The auditor holds the ring's viewing key. It reads the tokens, amounts and owners of every transfer, deposit and merge, and on an anonymous ring the hidden sender. Every operation carries a proof that the auditor can open it. The auditor can't move funds. [Audit and key escrow](design/audit-and-escrow.md)

## 2. Ring account controls

Differs from the PR 15 draft: the ring account holds the keys of these controls, not a separate program config. SPP's ring config holds the pause flag.

### 2.1. Pause

Pausing stops all activity in the ring until it's resumed: deposits, transfers, withdrawals, merges and delegate moves. Funds stay where they are. Record updates, policy changes and other controls still run.

### 2.2. Permanent delegate

A permanent delegate is a key that can move an escrowed member's funds to another escrowed member within the ring. The admin and the delegate set it once, on a confidential policy ring. From then on, the owner of every new note must escrow its key, the owner of an exit included (open question 12). A member's public withdrawal pays any owner the rules admit. The delegate cannot pay out of the ring. SPP governance must enable the ring's authority rail before the first move. The rules still screen the moved member as the sender, so a blocked or frozen member's funds do not move (open question 6).

### 2.3. Co-signer approval

A co-signer is a key that the co-signer admin designates to approve selected operations. Each co-signer has its own account and scope. One co-signer whose scope covers every demanded class signs. The co-signer on its own cannot move funds. Differs from the PR 15 draft: co-signer approval is enforced by the ring program, and only its limits live in Ring RPC.

#### Operations that can require approval

- **Transfers**, delegate moves and merges
- **Deposits**, and transfers with a deposit leg
- **Withdrawals**, unless an exemption proof shows the total withdrawn of each asset at or below the asset's withdrawal threshold
- **Outflow above the co-sign bound** of an asset, see 1.5

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
2. **Storage program:** one shared deployment. Keeps the root history of record trees, each under one authority, and verifies the proof of each tree update. It checks no policy.
3. **Ring RPC:** our hosted service. Holds the auditor key, writes records, relays and pays for wallet operations, co-signs under limits, merges escrowed notes and serves readers.
4. **Ring indexer:** projects every storage tree from confirmed blocks, serves record openings, and forwards every other call to Photon.
5. **Ring prover:** the zolana prover with the ring circuits added.
6. **SDKs and CLI:** the Rust and TypeScript SDKs build ring operations. A wallet sends them through Ring RPC by default, or reads the records and Merkle paths from the ring indexer, proves and sends them itself. The operator CLI creates, deploys and governs rings.

Zolana owns SPP: its programs, its circuits and its rails. Those circuits are audited, and this repository never refactors them. The ring imports zolana gadgets unchanged and keeps its own copy of any gadget it must change. A new SPP circuit enters zolana as new files only.

The ring uses these SPP rails:

1. **Confidential signer rail:** each input owner signs the Solana transaction.
2. **Confidential in-proof rail:** the owner signs inside the SPP proof, and SPP publishes the owner's key.
3. **Anonymous rail:** a hidden owner signs inside the SPP proof.
4. **Authority rail:** the ring PDA moves notes with no owner signature, for the delegate.
5. **Ring deposit and ring merge.**

The ring needs zolana's in-proof owner rail on ring transfers so that Ring RPC can pay for and send a confidential transfer from one wallet signature. Zolana's own in-proof circuit serves default-ring transfers only. Both confidential owner rails stay. [Owner rails](design/owner-rails.md)

## Accounts

1. **Ring account:** one per ring. Holds the roles, the mode, the auditor key, the delegate, the co-signer counts and the policy. It binds the addresses of the ring's records tree and of its one curator tree.
2. **Co-signer account:** one per co-signer, holding its key and its scope.
3. **Storage registry:** one per record tree, owned by the Storage program. Holds the authority, the grace period, the next leaf and the root history. Record contents live in instruction data and the ring indexer.
4. **SPP ring config:** owned by SPP at the ring PDA. Holds the activation, pause and authority-rail flags.

An operation that proves against records passes the ring account and the records registry. It adds the curator registry when the policy uses a curator source, and a co-signer account when it demands one. The program checks each registry against the address the ring account binds and reads its roots live. Differs from the PR 15 draft: the config and the policy are one account, and no roots are synced into it. A storage tree is a root history over an indexed tree, not account compression. [Records and roots](design/records-and-roots.md)

## Authorities

Five on-chain roles govern a ring. Every role key is nonzero once set, and no key holds two roles.

1. **Admin:** hands the admin, policy, pauser or co-signer admin role to a new key, which also signs. It appoints the delegate once.
2. **Policy authority:** sets the policy and signs the authority record updates: authority lists, mint settings and limits, ring-wide reader grants and enrolment approvals.
3. **Pauser:** pauses and resumes the ring.
4. **Co-signer admin:** creates, rescopes and closes co-signer accounts.
5. **Delegate:** moves escrowed members' notes. Set once, never rotated.

The upgrade authority deploys the program. Among ring instructions it signs only `Initialize`, which names the four role keys. Before that it can request the auditor key and the records tree from Ring RPC. Differs from the PR 15 draft: its single Config Authority splits into these roles.

Ring RPC keeps one key file per role. The auditor key opens ring activity. The service key signs auditor key releases, and every signed read and grant binds it. The storage authority signs record tree updates. The co-signer signs co-signatures. The fee payer pays for relayed transactions. The grant rows key seals database reader grants. Each key does one job. Ring RPC refuses to start when two role files hold the same secret, and its root secret yields auditor keys only.

## Trust Assumptions

1. **Storage authority:** trusted for every record. The tree proof verifies the update, not the record. A write the authority signs directly skips every Ring RPC check, the wallet's signature and the escrow proof included.
2. **Policy authority:** trusted to set policy rules, lists, limits and ring-wide grants, and to bind the records. Each other role is trusted for its own control.
3. **Ring RPC:** trusted to protect the auditor key and every proof input a wallet hands it. It is trusted to enforce reader grants and co-signer limits, and to write records as signed. A depositor or the delegate signs the message Ring RPC builds. The ring SDKs sign it only when the quoted fee payer pays and the one instruction is the ring operation the request asked for. With derived keys Ring RPC relays and pays only for a ring whose config names an auditor key it derives, and its rate limits bound what it pays. No two Ring RPC processes serve one ring. A relayed transfer or merge hands Ring RPC the owner's nullifier secret, and with it Ring RPC links that owner's spends. A wallet keeps the secret from Ring RPC only when it escrows no key and proves and sends every spend itself.
4. **Curator:** a ring trusts the authority of its one curator tree.
5. **Delegate:** trusted to move escrowed members' funds within the ring under the configured controls.
6. **Upgrade authority:** trusted to create the ring and to deploy upgrades that keep the program's guarantees. An upgrade can replace every check. Only the operator tools refuse an upgrade over a ring account the new release cannot read.
7. **Key generator:** the ring proving keys come from a single-party setup. Whoever ran it could forge every ring proof.
8. **Revocation timing:** an immediate revocation binds on chain the moment its storage update applies, and a transaction that passed Ring RPC or a relayer before then fails on chain. Ring RPC sends the revocations [the record writer](design/record-writer.md) names as immediate updates. Any other revocation goes graced, so a proof under the earlier root still lands within the grace period. A curator's revocation binds as fast as its authority writes it.
9. **Limits:** Ring RPC enforces co-signer limits only on what it co-signs. A co-signer outside Ring RPC enforces none.
10. **Photon, ring indexer and chain RPC:** Photon and the ring indexer that forwards to it are trusted for complete history, the chain RPC for confirmed contents. Ring RPC verifies each record opening under the newest root. While the ring indexer lags that root, Ring RPC's tree-mode reader grant checks, its escrow and limit updates and its co-signatures on a deposit, transfer or withdrawal fail.
11. **SPP governance:** trusted to activate the ring when SPP does not activate it at creation, and to enable its authority rail.
12. **Delegate message:** the ring SDKs bind the leading output owners of the delegate's message to the payees in payment order, and each other owner to the source or zero. They do not bind whose notes it spends, the mint or the amount each payee gets.

## Glossary

| # | Term | Type | Definition |
| --- | --- | --- | --- |
| 1 | **Ring note** | UTXO | An SPP note tagged with the ring's id. Only a transaction the ring program signs moves it. |
| 2 | **Default ring** | Note set | SPP notes outside every ring. An exit pays into it. |
| 3 | **Ring account** | Account | The one account that holds a ring's roles, settings, policy and the addresses of its record trees. |
| 4 | **Mode** | Ring setting | Confidential, confidential with key escrow, or anonymous. Fixed at creation, except that setting a delegate adds key escrow. |
| 5 | **Policy ring** | Ring setting | A ring with a rule table. Every transfer proves it. An audit-only ring proves only the audit. |
| 6 | **Member record** | Tree leaf | One member's list bits, escrow key and, for an asset, mint settings. |
| 7 | **Mint settings** | Record fields | An asset's guard threshold, cap, co-sign bound, withdrawal threshold and window limits. |
| 8 | **Records** | Storage tree | The ring's own record tree. |
| 9 | **Curator** | Storage tree | A record tree of any authority that serves some of a ring's lists. A ring has at most one. |
| 10 | **Revision** | Root number | The sequence number of a storage root. A proof names its root by revision, and the program reads that root live from the registry. |
| 11 | **Rail** | Transfer form | How SPP authorizes a spend: owner signer, in-proof owner, hidden owner or delegate. |
| 12 | **Exit** | Output | An output paid to the default ring. Its owner is public. |
| 13 | **Public leg** | Transfer part | A SOL or SPL deposit or withdrawal inside a transfer. Its account, asset and amount are public. |
| 14 | **Key escrow** | Record field | A member's nullifier secret sealed to the auditor. It lets the auditor link that member's spends and lets Ring RPC move and merge its notes. |
| 15 | **Record update** | Signed request | A signed list of record writes that Ring RPC queues and applies. |
| 16 | **Enrolment** | Record update | A wallet's update that waits for the policy authority to set the lists it needs. |
| 17 | **Relay** | Ring RPC operation | Ring RPC proves, co-signs, pays for and sends an operation the wallet requested. |
| 18 | **Shape** | Proof width | The input and output counts of a transfer. Each shape has its own proving keys. |
| 19 | **Wallet** | User | Holds spending keys and authorizes transfers of its ring notes. |
| 20 | **Reader** | User | Uses granted read access to query decrypted ring activity through Ring RPC. |
| 21 | **Auditor** | Authority | Holds the auditor key and decrypts ring transfers, deposits and merges, and each escrowed key whose escrow proof Ring RPC checked. |
| 22 | **Co-signer** | Authority | Signs operations when the ring's co-signer scopes or outflow bounds demand it. |
| 23 | **Delegate** | Authority | Moves escrowed members' notes within a ring that escrows keys. |
| 24 | **Policy authority** | Authority | Sets the ring's rules, lists, mint settings and ring-wide grants. |
| 25 | **Storage authority** | Authority | Signs the updates of one record tree. Ring RPC holds it for the ring's records. |
| 26 | **Upgrade authority** | Authority | Deploys and upgrades the ring program and signs `Initialize`. |

## Flows

1. Enrolment and key escrow
2. Record updates
3. Deposit
4. Transfer (anonymous, confidential, exit to the default ring, withdrawal)
5. User merge
6. Managed merge
7. Authority transfer
8. Reader access grants and revocation
9. Co-signer limits configuration

## 1. Enrolment and key escrow

Enrolment depends on the ring's policy. Key escrow is required on a ring with a delegate, optional on other confidential rings, and refused on anonymous rings.

1. **Wallet:**
   1. Signs a record update for its own lists.
   2. To escrow its key, adds its nullifier secret sealed to the **Auditor** with a proof of the seal.
   3. On a ring whose rules read the allow, reader or approval list from its own records, names the lists it awaits.
2. **Ring RPC:**
   1. Checks the cluster, the signature, the expiry, and that the wallet writes only its own record and its own grant records.
   2. Verifies the escrow proof and refuses a second escrow key for the member.
   3. Holds an awaiting enrolment until the **Policy authority** approves it or refuses it, or its window ends.
3. **Policy authority:** approves an enrolment with its own update that sets every awaited list, and both reach the tree in one root.
4. **Ring RPC:** queues the update, proves the tree update, submits it to the **Storage Program**, and pays fees.
5. **Ring indexer:** projects the applied records and serves their openings.

## 2. Record updates

The **Wallet** writes its own viewing and recovery flags, its escrow and its wallet grants. The **Policy authority** writes the authority lists, the mint settings and ring-wide grants.

1. **Wallet or Policy authority:** signs an update for one cluster, ring and tree, valid until a slot, and sends it to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the signer may write each entry.
   2. Queues wallet and authority updates in separate batches. An approved enrolment rides first in its approver's batch.
   3. Sends a revoking batch as an immediate update, which retires every earlier root.
   4. Sends an authority batch at its next pass, and a wallet batch when it is full or aged.
   5. Sends a grant revocation graced, so no wallet can clear the root history.
   6. Refuses a queued authority update once its signer no longer holds the policy role.
   7. Proves each batch and submits it, paying fees.

[The record writer](design/record-writer.md)

## 3. Deposit

A deposit moves SOL or tokens from a wallet's public balance into up to 8 ring notes. The token and amounts are public.

1. **Wallet:**
   1. Chooses the token, amount and recipient.
   2. Prepares the deposit notes and seals their openings to the **Auditor**.
   3. Sends the deposit request with its proof inputs to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the ring is active.
   2. Generates the deposit proof. It shows the asset rules hold and, on a ring with a delegate, that each recipient escrows its key.
   3. Returns the transaction to the **Wallet** for signing.
3. **Wallet:** signs to authorize the SOL or SPL token transfer.
4. **Ring RPC:**
   1. Co-signs when deposits demand approval.
   2. Pays fees and submits the deposit to the **Ring Program**.
   3. Follows the deposit to confirmation. The recipient's **Wallet** finds its notes by view tag.

Without Ring RPC the **Wallet** reads the records itself, generates the deposit proof, and pays for and submits the deposit.

On every ring the sealed opening names each note's owner key, and the deposit proof binds that key to the note's owner commitment.

## 4. Transfer

A unified flow for anonymous and confidential transfers, exits and withdrawals.

**Variants:**

1. **Anonymous:** a hidden owner signs inside the SPP proof. The sender and recipients stay hidden from chain observers.
2. **Confidential:** the policy screens the sender and recipients as public inputs. The wallet signs inside the proof, and the signer rail serves owners who send their own transaction.
3. **Exit to the default ring:** some outputs leave the ring to a public owner.
4. **Public withdrawal:** SOL or SPL transfers to one or more accounts, optionally alongside other outputs. On the anonymous rail every withdrawal pays one key. Ring RPC can create the missing token account of an SPL withdrawal.

**Steps:**

1. **Wallet:** takes a quote that names the fee payer and builds the transfer from its own notes. It seals the **Auditor** message, signs the SPP message hash and sends the proof inputs to **Ring RPC**. It reads no Merkle path and no record.
2. **Ring RPC:**
   1. Verifies the owner's signature.
   2. Reads the required member records and Merkle paths.
   3. Generates the SPP, audit and policy proofs.
   4. Co-signs within the limits when the transfer demands a co-signer.
   5. Pays fees, submits the transaction to Solana and follows it to confirmation.

Without Ring RPC the **Wallet** does step 2 itself and pays from a fee payer it chooses. A demanded co-signer still signs. On the anonymous rail that payer and any co-signer must differ from the hidden owner, and the ring program accepts any such payer.

The SDKs refuse a shape that does not fit one transaction. A relayed wide confidential policy payout does not fit, so the sender splits it or merges first. A relayed transfer carries withdrawals only. A transfer with a deposit leg goes out in the owner's own transaction, and on an anonymous ring its payer funds the leg. The SDKs fund a transfer from one tree, so one payment moves at most what the wallet holds in one tree.

## 5. User merge

A merge combines notes of the same wallet, token and ring into one note with their total value, up to 24 at once.

1. **Wallet:** selects the notes and sends them with its nullifier secret to **Ring RPC**. It signs nothing, because the merge proves the nullifier secret.
2. **Ring RPC:**
   1. Checks that the notes are unspent and belong to the same wallet, token, ring and tree.
   2. Generates the merge proof and its disclosure to the **Auditor**. On a ring with a delegate the proof also opens the owner's escrow record.
   3. Co-signs when a co-signer's scope covers transfers.
   4. Pays fees and submits the merge to the **Ring Program**.
   5. Indexes the result.

The payer and the co-signer must differ from the owner on every ring. Without Ring RPC the **Wallet** generates both proofs and pays from a key other than its own. A merge runs no policy rule.

## 6. Managed merge

Managed merge is initiated by **Ring RPC** on a ring with a delegate. It combines one wallet's notes of one token toward the wallet's settings.

1. **Wallet:** signs its merge settings for a token: a target note count and a minimum average amount. A zero target revokes them.
2. **Ring RPC:**
   1. When the wallet holds more notes than its settings allow, selects its smallest notes in the tree that holds most of them.
   2. Opens the wallet's escrowed nullifier secret with the auditor key and prepares the merged note.
   3. Generates the merge proof and its disclosure.
   4. Pays fees and submits the merge through its relay.
   5. Indexes the result.

Ring RPC stores merge settings on any ring, and gives no error where it cannot merge.

## 7. Authority transfer

An authority transfer moves a wallet's funds to recipients within the same ring, authorized by the permanent **Delegate**.

1. **Delegate:** signs a request naming the source wallet, the token, and each recipient and amount, and sends it to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the signer is the ring's delegate and that the ring escrows keys to its auditor key.
   2. Opens the source's escrowed nullifier secret and checks it against the source's nullifier key.
   3. Funds the payments from the source's notes and returns the change to the source.
   4. Generates the delegate-rail proofs, including the recipients' key-escrow checks.
3. **Delegate:** signs the transaction.
4. **Ring RPC:** co-signs when the move demands a co-signer, pays fees, submits the transfer to the **Ring Program** and indexes the result.

A **Delegate** that holds the source's nullifier secret can generate the proofs and send the move without Ring RPC.

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

1. `Initialize`: creates the ring account with the four role keys and the auditor key, binds the records, and on a policy ring pins the rule table. It registers the ring with SPP. The upgrade authority signs.
2. `UpdatePolicy`: replaces the rule table, repoints one list's source, or rebinds the records. The policy authority signs.
3. `UpdateAuthority`: hands one role to a new key. The admin and the new key sign. Differs from the PR 15 draft: it names the role.
4. `SetPaused`: pauses or resumes the ring in SPP. The pauser signs.
5. `SetCoSigner`: creates a co-signer account or changes its scope. The co-signer admin signs.
6. `ClearCoSigner`: closes a co-signer account to a rent recipient. The co-signer admin signs.
7. `SetDelegate`: sets the delegate once and turns on key escrow. The admin and the delegate sign.
8. `Deposit`: verifies the deposit proof before SPP CPI. The depositor signs, and a co-signer when the ring demands one.
9. `Transfer`: verifies the audit proof, on a policy ring the policy proof, and an optional withdrawal exemption proof before SPP CPI. The payer signs. On the signer rail each input owner also signs. A demanded co-signer and each deposit leg's funder also sign.
10. `AuthorityTransfer`: as `Transfer` on the authority rail. The delegate and the payer sign.
11. `Merge`: verifies the merge disclosure proof before SPP CPI. The payer signs, and a co-signer when the ring demands one. No owner signs.

### Storage Program

1. `Initialize`: creates a registry at an address only its creator can take, with the empty root. The creator becomes the authority.
2. `Update`: applies up to 16 writes with a proof of the tree update, and keeps the earlier root valid for the grace period.
3. `UpdateImmediate`: applies writes as `Update` does and retires every earlier root.
4. `UpdateAuthority`: hands the registry to a new authority. Both keys sign.

## Design decisions

1. Records live in Storage program trees, and the ring account binds their addresses. Every root reader takes the registry accounts and reads their roots live, so a revocation binds on chain the moment storage applies it. Differs from the PR 15 draft, whose question 3.1 syncs roots into the policy account for one account per transfer (open question 11).
2. The Storage program verifies the tree update only, and Ring RPC checks signatures and escrow proofs off chain. Update proofs stay small, as the draft's notes 5 and 6 ask.
3. An escrow write publishes the owner key, the nullifier key and the sealed secret beside the record. The auditor and Ring RPC recover an escrowed secret from chain data.
4. An escrow key fills once. No later write can redirect a member's escrow.
5. Revoking list writes go as immediate updates, and grant revocations go graced. A block binds at once, and no wallet can void every member's pending proofs.
6. Authority and wallet writes never share a batch, except an approved enrolment, and a queued authority write needs its signer to still hold the policy role. A rotated-out key loses its pending writes.
7. An enrolment waits within a bounded window under rate limits, with no cap on pending enrolments. A cap would let spam lock enrolment out.
8. The config and the policy are one ring account. A transfer loads fewer accounts.
9. Five on-chain roles replace the single Config Authority. A stolen key other than the admin key reaches one control.
10. Ring RPC reads one key file per role. A leaked file exposes one job.
11. Each co-signer has its own account, and one co-signer covering every demanded class signs. The hot path loads one co-signer account by owner and discriminator, as the draft's note 2 asks.
12. Co-signer limits live per asset in the asset record, each cap with its own window. The tree already serves per-asset data under a root the program reads.
13. Co-signing fails closed when Ring RPC cannot read the limits or the asset has no record. Either would otherwise read as no limits.
14. Ring RPC relays and pays for every wallet operation except a transfer with a deposit leg or an operation that needs an outside co-signer. A relayed wallet never fetches a Merkle path, as the draft's note 4 asks.
15. The ring's in-proof owner rail enters zolana as new files, and the ring program refuses owner signers on it. Every input then belongs to the owner the policy reads as the sender.
16. Both confidential owner rails stay. The signer rail needs no SPP feature build.
17. This repository never refactors zolana circuits. They are audited, and a source change reopens the audit.
18. The audit statement keeps the recipient viewing key, and the SDKs refuse shapes over one transaction. The audit stays provable on every transfer, and relayed wide payouts split.
19. The deposit proof also opens the curator root. Curator asset lists then admit deposits.
20. The SDKs refuse a merge whose payer or co-signer is the owner, on every ring. The merge circuit already refuses it, and the SDKs fail before proving.
21. Every ring merge carries a disclosure proof. The auditor opens every merge.
22. A deployment keeps reader grants in one store. Every read checks one source of truth.
23. A passkey reader's record is keyed by a hash of its tagged key. Ed25519 and passkey readers share one record space.
24. Wallet scope admits the anonymous sender, a confidential spender and the owner of an output. A key that only signs or pays is no party to the transfer.
25. One Ring RPC process serves a ring. Its store serializes co-sign admission and keeps spent replay nonces across a restart, so no allowance is granted twice and no nonce is accepted twice.
26. No instruction migrates an older ring layout. Rings are created fresh, and the repository forbids compatibility shims.
27. `Initialize` creates the ring account, binds the records and registers the ring with SPP in one instruction. No half-created ring exists.
28. Ring RPC creates the ring's records tree under its storage authority, and `Initialize` binds it. The program accepts any storage registry as the records, so whoever binds them picks the records writer, and a tree written outside Ring RPC skips its checks.

## Notes

1. Anonymity holds only under the conditions in [privacy](design/privacy.md). A confidential ring publishes its sender and each recipient's viewing key.
2. An anonymous transfer cannot create an address.
3. A key escrow and a delegate are permanent for the deployed program.
4. A paused ring, or one SPP governance has not activated, moves no note.

## Open questions for the maintainer

1. Should co-signer limits be set per co-signer, as the draft's Flow 9 names, or per asset as built?
2. Ring RPC pays fees and token account rent with no charge. Which fees does the policy authority set, and who charges the relay fee?
3. SPP reads an output's encryption scheme byte as its exit marker. Should SPP carry an explicit exit marker in the output data instead?
4. Today one co-signer must cover every demanded class. Should co-signers with split scopes approve one operation together?
5. Does this scope fit the two-week audit, and what moves out if it does not?
6. Should the delegate move a blocked or frozen member's funds?
7. A ring reads lists from one curator. Is one enough?
8. Third-party ZK programs settle through plain SPP transfers and cannot touch ring notes. Should the ring program offer a hook for allowlisted programs?
9. Do you need relayed 16-way confidential payouts in one transaction? A relayed one needs SPP to publish less per output.
10. An escrow key cannot change once set. Should a wallet be able to rotate it?
11. Roots are read live from the storage registries, so a policy transfer passes the ring account plus one or two registry accounts. Do you accept this over your question 3.1, which syncs roots into the policy account?
12. On a ring with a delegate an exit pays only an escrowed owner, though neither the delegate nor a managed merge moves default-ring notes. Should an exit pay any owner the rules admit, as a public withdrawal does?
