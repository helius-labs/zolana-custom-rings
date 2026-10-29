# Custom rings

A custom ring is a Solana program that governs its notes in the zolana shielded pool (SPP). SPP moves a ring note only under the ring program's `ring_auth` signature. The ring program signs after it verifies an audit proof of the move. On a policy ring it also verifies a policy proof over the rule table and the member registry. Owners fund the ring by audited deposits and pay each other inside it. They leave it by an exit to the default ring or by a public withdrawal, while SPP has the ring activated and not paused. Owners keep their spending keys and sign every transfer, except a delegate move on a `ConfidentialEscrow` ring. The upgrade authority deploys and creates the ring, and an upgrade can replace every check. The config authority sets the policy, the lists, the controls and the delegate. The auditor reads every transfer. An optional co-signer approves the operations its scope or an outflow limit names. A `Confidential` or `ConfidentialEscrow` ring is confidential. Amounts, assets and blindings are private, but the sender and the recipient's viewing key are public. An `Anonymous` ring also hides the sender and the recipient from chain observers. That holds only under the conditions of [Anonymity breaks when its conditions fail](#anonymity-breaks-when-its-conditions-fail). The first three are that the payer does not link to the sender, the transfer spends no default-ring note, and no exit or withdrawal pays a key linked to the sender.

## Glossary

| Term | Type | Definition |
|---|---|---|
| Notation | Functions | `Poseidon`, `hash_bytes`, `solana_owner_identity`, `pack_be`, `right_align` and the field modulus `q` as [Hashing](spec/crypto/hashing.md) defines them. |
| Ring program | Solana program | One deployment per ring. Parses each transfer, verifies the ring proofs, builds the SPP instruction and signs the SPP CPI as `ring_auth`. |
| `ring_auth` | PDA | `[b"ring_auth"]` under the ring program. Holds the SPP `RingConfig` of the ring. Only the ring program signs for it. |
| Ring id | Hash | `hash_bytes(ring program id)`. SPP binds it as `ring_program_id`, and every ring note carries it. |
| Ring note | UTXO | An SPP UTXO with the ring's ring id. Only a transfer the ring program signs spends it. |
| Default ring | Note set | SPP notes with ring id `0`, outside every ring. Their owners spend them with a plain SPP transfer. |
| Entry spend | Transfer | An anonymous-ring transfer that spends default-ring notes. Its audit proof opens every spent note to the auditor. |
| Live output | Output | A transfer output that is a UTXO, not a dummy. A ring output has the ring id, an exit has ring id `0`. |
| Exit | Output | A live output to the default ring. Its owner is public. |
| Public leg | SPP interface transfer | A deposit or withdrawal of SOL or an SPL token inside a transfer. Its account, mint and amount are public. Its settlement accounts follow the SPP account list. |
| Frame | Instruction data | The compact byte string of `Transact` and `DelegateTransact`. The program expands it to the SPP transfer. |
| Salt | 16 bytes | Drawn by the sender per transfer attempt and published in the SPP data. It enters every output blinding and the disclosure pad. |
| First nullifier `n0` | Field element | The nullifier of input `0`. SPP accepts it once, so every value derived from it is unique to one spend. |
| Private transaction hash | Hash | `private_tx_hash`, the SPP Poseidon hash over the spent note chain, the output note chain, the address nullifier chain and a secret blinding. The SPP proof, the policy proof and the anonymous audit proof bind it. |
| Ring kind | Config value | `AuditOnly`, `Policy`, `Anonymous` or `AnonymousPolicy`, fixed by `CreateConfig`. Sets the tier and the first mode. |
| Tier | Config value | Audit-only or policy (`has_policy`). A policy ring verifies a policy proof on every transfer. |
| Mode | Config value | `Confidential`, `ConfidentialEscrow` or `Anonymous`. Selects the transfer rail. `ConfidentialEscrow` is `Confidential` with key escrow and a delegate. |
| Rail | Transfer form | Confidential (each owner signs the transaction), anonymous (a hidden owner signs inside the SPP proof) or delegate (the delegate signs). |
| Authority rail | SPP rail | SPP `RING_AUTHORITY_TRANSACT`. It moves ring notes under the `ring_auth` signature with no owner signature. SPP governance enables it per ring. The delegate rail runs on it. |
| Shape | `n_in × n_out` | The input and output slot counts of an SPP transfer, one of `SPP_SUPPORTED_SHAPES`. |
| Member | Field element | A value in `[1, q - 2]` that names an owner, `solana_owner_identity(key)`, or an asset, `hash_bytes(mint)`. |
| List | Record bit | One of 8 named bits of a record. A list has no effect beyond the rules that read it. |
| Record | Tree leaf | `Poseidon(member, next, lists, escrow_key, mint_policy, withdrawal_threshold, limits_0, limits_1)`. One per member, sorted by member through `next`. |
| Mint settings | Record fields | `threshold`, `cap`, `cosign_above`, `withdrawal_threshold` and the six asset limits, each a u64, in the record of an asset member. Only the config authority writes them. [Mint settings](#mint-settings) gives the effect of each value, zero included. |
| Member registry | Account and tree | The `MemberRegistry` account holds the last 32 roots the record queue instructions apply. No transfer, deposit or merge reads them. |
| Storage registry | Account | A Storage Program `StorageRegistry`, the root history of one record tree under one authority. Each root carries a revision, and a retired root an expiry. Record contents live in instruction data and the ring indexer. |
| Records | Storage registry | The ring's own storage registry, bound by `CreatePolicy` for the ring's life. |
| Ring policy | Account | The `RingPolicy` account holds the policy, the records address and a mirror of the root history of the records and of the curator. |
| Own root, curator root | Root | A root of the records or of the curator, named by its revision and read from the ring policy's mirror. |
| Record queue | Account | The `RecordQueue` account holds pending record writes as a hash chain. An apply proof moves them into the tree. |
| Floor | Queue position | The queue tail after the last authority write. An own root below it is refused. |
| Policy | Rule table, source map and hash | Stored in the ring policy. The policy proof binds `policy_hash`. |
| Rule | Table row | A list condition on one subject: the sender, every output owner, or every output asset. A guard exempts amounts at or below a threshold. |
| Outflow limit | Mint settings | The `cap` and `cosign_above` of an asset's record. Bounds the outflow of that asset in one transfer and names when the co-signer must sign. |
| Curator | Storage registry | A storage registry of any authority whose records serve a ring's foreign lists. A ring has at most one. |
| Transaction viewing key | X25519 key pair | `tx_viewing_sk` and `tx_viewing_pk = 0x04 \|\| tx_viewing_u`, drawn by the sender per transfer. The secret seeds every output blinding and the disclosure pad. |
| Viewing key `u` | X25519 key | A recipient's 32-byte X25519 public key, the `u` of its zolana viewing key. Its secret opens the notes sent to it. |
| Owner tag | 32 bytes | The tag SPP publishes with each output. A recipient finds its notes by it. A confidential ring output carries the recipient's `u`, an anonymous one a view tag, and an exit its owner's Solana key. |
| Auditor message | SPP message | The one message the program builds per transfer, `0x04 \|\| eph_u \|\| sealed \|\| disclosure`. Its view tag is the auditor's `u`, by which the auditor finds every transfer. `sealed` is `tx_viewing_sk` sealed to the auditor from the ephemeral key `eph_u`. |
| Disclosure | Field list | The openings of the outputs, each field masked by a pad. On the anonymous rail it also names each spent note by hash or prefix, or opens it. |
| Audit proof | Groth16 proof | Proves the auditor message opens every output of the transfer. Verified on every transfer, under the key of its rail and shape. On the anonymous rail a commitment key (`AnonymousAudit`) serves a spend of ring notes and an entry key (`AnonymousEntryAudit`) serves an entry spend. |
| Policy proof | Groth16 proof | Proves the rules and the outflow limits over record openings. Verified on every transfer of a policy ring. |
| Withdrawal exemption proof | Groth16 proof | Proves that the gross withdrawal of each withdrawn mint is at or below the `withdrawal_threshold` of the mint's record under an own root. A transfer on any ring with a ring policy can carry one. It waives only the withdrawal class of the co-signer. |
| Nullifier secret | Field element | An owner's 31-byte secret, with public key `nullifier_pk = Poseidon(secret)`. A note's nullifier needs the secret, so its holder can link the owner's spends. |
| Key escrow | Record field | A record's nullifier secret sealed to the auditor by `RegisterKey`. A `ConfidentialEscrow` ring requires it of every output owner. |
| Ring address | Payment address | The recipient's shielded address and the ring program id, shared off chain. A `zolana:` payment request adds a request view tag. |
| View tag | 32 bytes | The owner tag of an anonymous ring output, a zolana [view tag](../zolana/docs/spec.md#view-tags) or a random tag on a dummy. No proof derives it. |
| First payment | Ring output | A payment to a recipient the sender holds no shared tags with. It takes the recipient's request tag or bootstrap tag, as the caller chooses. |
| Upgrade authority | Key | The Loader v3 upgrade authority of the ring program. Signs `CreateConfig`. |
| Config authority | Key | `RingProgramConfig.authority`. Sets the policy, authority lists, mint settings, readers, co-signer, insert fee, pause and delegate. Receives the insert fee. |
| Owner | Wallet (client) | Holds ring notes and their spending keys. Writes its member lists and registers its nullifier key. The sender of a transfer is its owner. |
| Payer | Key | SPP account `0`. Pays rent and fees. On the anonymous rail it is the only SPP signer. A relayer can be the payer. |
| Funder | Key | Signs a deposit leg or an `AuditedDeposit` and pays its tokens. |
| Co-signer | Key | A key with its own `CoSigner` record and scope. A ring has up to 255 per class. One co-signer whose scope covers every demanded class signs a demanded operation. An approval with no demanded class takes any co-signer. Its withdrawal thresholds are the `withdrawal_threshold` mint settings. |
| Party identities | Field elements | `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, each `0` when absent. The anonymous audit proof shows each nonzero one differs from the hidden owner. |
| Insert fee | Lamports | What a member write or key registration pays the config authority. The authority's own writes pay nothing. |
| Delegate | Key | Set once on a policy ring, which turns the ring to `ConfidentialEscrow`. Moves escrowed members' notes inside the ring. |
| Auditor | Key holder | Holds the X25519 auditor key in Ring RPC or a local file. Opens every transfer, deposit, merge and escrowed key. |
| Reader | Ed25519 or P-256 key | Holds a ring-wide or wallet grant in the ring's storage tree, or a wallet grant in the Ring RPC database. Reads audited history from Ring RPC. |
| SPP governance | Key | The SPP ring creation authority. Activates rings and enables the authority rail. |
| Ring indexer | Server | Projects every member registry from Solana blocks and serves record openings. Forwards every other call to Photon. |
| Ring prover | Server | The zolana prover with the ring circuits registered as extensions. Proves from a full client witness. |
| Ring RPC | Server | Holds the auditor key. Serves audited transfers, merges and notes to readers. Proves, pays for and sends relayed transfers. |
| Photon | Server | The zolana SPP indexer. Serves notes, tags, nullifiers and Merkle proofs. |
| SPP | Solana program | The zolana shielded pool. Holds every note, verifies the SPP proof, and moves a ring note only under a `ring_auth` signature. |

## Ring lifecycle

1. **Deploy.** The upgrade authority deploys the ring program with Loader v3. The binary carries the verifying keys of its [proving key lock](#keys-and-releases). No ring account exists.
2. **Create.** The upgrade authority signs `CreateConfig` with the auditor key and the ring kind. The config authority signs `CreateMemberRegistry`, creates the records in the Storage Program, then signs `CreatePolicy`, which binds the records on every ring and pins the table on a policy ring. Anyone then sends `SyncRoots` for the records and for a curator. The config authority signs `InitSppRingConfig`, which creates the SPP `RingConfig` at `ring_auth`. SPP activates the ring at creation when its protocol config allows it. Else SPP governance activates it later. No note moves until the ring is activated.
3. **Enrol.** An owner signs a [record update](#record-updates) for its own member lists. On a confidential ring the update can also carry an escrow entry, which seals the owner's nullifier secret to the auditor under a register key proof. An anonymous ring refuses the escrow entry. The config authority signs record updates for authority lists and mint settings. Each signer sends its update to Ring RPC, and the writer applies it to the ring's `StorageRegistry`. The CLI writes records only through record updates.
4. **Deposit.** A funder signs `AuditedDeposit` for up to 8 new ring notes. The deposit proof seals each note's opening to the auditor. On a `ConfidentialEscrow` ring it also proves each owner's escrow record. On a policy ring it proves each deposited asset against the asset rules under the own root.
5. **Transfer.** The sender proves the SPP proof, the audit proof and on a policy ring the policy proof, and submits `Transact`. The program rebuilds both ring statements, verifies the proofs and invokes SPP as `ring_auth`. On a confidential ring the owner signs the transaction. On an anonymous ring the hidden owner signs inside the SPP proof and only the payer signs the transaction.
6. **Leave.** A transfer pays an exit or withdraws a public leg. The rules screen exit owners and withdrawal owners as output owners. A delegate move can do neither.
7. **Merge.** An owner merges up to 24 notes of one asset into one note with `Merge`, with a disclosure proof to the auditor. The merge proves the owner's nullifier secret and carries no owner signature. On a `ConfidentialEscrow` ring the proof also opens the owner's escrow record.
8. **Delegate.** The config authority and the delegate sign `SetDelegate` on a confidential policy ring, which sets the mode to `ConfidentialEscrow`. SPP governance enables the ring's authority rail. The auditor opens an escrowed member's nullifier secret for the delegate, and the delegate moves that member's notes to escrowed members with `DelegateTransact`.
9. **Audit.** The auditor opens every transfer, deposit and merge from its auditor message. The authority of the ring's storage tree writes ring-wide and wallet grants to its `reader` list. A wallet also grants readers of its own rows through Ring RPC, and Ring RPC serves every granted reader the openings. A revoked reader keeps what it already read.
10. **Govern.** The config authority repins the policy, writes mint settings, sets the co-signer, the insert fee and the pause, and hands the config to a new authority. A repin refuses every proof over the old table. A records update reaches transfers at the next `SyncRoots`, and a sender whose root left the mirror proves again. A repin and a mint-setting write are separate instructions, so a transfer between them proves under the new table and the old settings.

### Properties

**Functional**

1. A ring note moves only in a transaction the ring program signs. SPP requires the `ring_auth` signer of the ring's `RingConfig` and binds `ring_program_id` in its proof. No other program or key spends a ring note.
2. The program builds the SPP instruction data and both ring statements from the one frame. The SPP proof and the audit proof therefore bind the same first nullifier, outputs, transaction viewing key, salt and auditor message. The policy proof binds the same `private_tx_hash` and public legs as the SPP proof.
3. The program reads every statement value it can from chain state, so the prover chooses none of them beyond the root revisions and the recipients the policy proof binds to the outputs:
   - the ring id from the executing program id and the auditor key from the config
   - the roots from the ring policy's mirrors and the SPP trees
   - the party identities from the accounts
   - the public legs, the withdrawal owners and the gross withdrawal per mint from the settlement accounts
4. Every transfer verifies an audit proof. The proof seals `tx_viewing_sk` to the auditor. It forces the blinding of each live output in slot `i` to `TXOB(n0, TXOS(n0, CRBS(tx_viewing_sk, salt)), i)` ([Blinding derivations](spec/crypto/hashing.md#blinding-derivations)), so the auditor opens every output of every transfer. On the delivered rails it proves that every ring output's body encrypts the output's blinding and amount to the key its slot publishes. On the anonymous rail the disclosure opens every ring output's owner key and every live output's asset and amount. No output carries data.
5. Every deposit verifies a deposit proof that seals each new note's opening to the auditor. On a policy ring every active asset rule holds for each deposited asset under the own root, its guard read as for a transfer output. The plain SPP ring deposit tag is refused.
6. On a policy ring every transfer verifies a policy proof under the stored `policy_hash`. Each active rule holds for each subject. The subjects are the sender, every live output owner and asset, and every withdrawal owner and asset. A rule holds when the subject is on one of its present lists or off one of its absent lists. A refused subject passes only when the rule's guard exempts its amount. Rules join with AND.
7. Record openings fold to roots the program reads from the ring policy's mirrors. `SyncRoots` copies a storage registry's roots into its mirror, and a transfer after it proves under the new lists. A curator update reaches a subscriber at the next `SyncRoots` of that subscriber's curator mirror.
8. On a policy ring the policy proof opens the own record of each live output's asset and of each nonzero public asset, absent assets included. For each such asset with a nonzero `cap` or `cosign_above`, `outflow = others - net`, and the co-signer signs above `cosign_above`:
   - `others` sums the asset over live outputs, except ring outputs to the sender's own identity. An exit counts, also to the sender.
   - `net` is the asset's signed public net, a deposit positive and a withdrawal negative.
   - The proof requires `net <= others`, and `outflow <= cap` when `cap != 0`.
   - The proof sets `approval_required` exactly when some asset has `cosign_above != 0` and `outflow > cosign_above`. The program then demands the co-signer.
9. An operation demands each of its classes that some `CoSigner` record covers, and one co-signer whose scope covers every demanded class signs:
   - `TRANSFERS` for every transfer, delegate move and merge
   - `DEPOSITS` for every transfer with a deposit leg and every audited deposit
   - `WITHDRAWALS` for every transfer with a withdrawal leg, unless the transfer carries a valid withdrawal exemption proof. The proof shows each withdrawn mint's gross withdrawal at or below the mint's `withdrawal_threshold`. A zero or absent threshold exempts no withdrawal, and a deposit leg does not lower the gross amount.

   A transfer with `approval_required` and no demanded class takes any co-signer.
   A demanded co-signer differs from every owner signer, the in-proof owner and the delegate.
10. Owners keep their spending keys. On the confidential rail every owner signer signs, and a policy transfer has exactly one owner. Under `OWNER_IN_PROOF` the owner signs inside the SPP proof and no owner signs the transaction, so any payer sends it. The program refuses every owner signer on that rail, so every input is the in-proof owner's and the policy reads that owner as the sender. On the anonymous rail the hidden owner's signature is inside the SPP proof. A merge proves the owner's nullifier secret. The delegate rail runs only in `ConfidentialEscrow` mode, keeps every note in the ring, and takes no public leg or exit.
11. In `ConfidentialEscrow` mode the policy proof requires each live output's owner record to hold `escrow_key = Poseidon(nullifier_pk, hash_bytes(ciphertext))` for the output's nullifier key. A deposit and a merge prove the same. The auditor therefore opens the nullifier secret of every note's owner.
12. An owner writes only its own record and only its member lists. Member writes and key registrations keep a record's mint settings. An owner's writes apply after `APPLY_DELAY_SLOTS` or a full member queue, through a proof any party submits. The apply proof binds the old root, the next index and both queue chain ends the program holds, so no submitter changes a queued write.
13. The program validates the rule table at every policy write. It requires canonical rows, authority-written lists only, a source for every referenced list and at most one curator. The policy circuit relies on that validation and checks the row encoding only.

**Privacy**

On every transfer, chain observers see:

- the shape, the published input and output counts, the nullifiers and their trees, and the output hashes
- `tx_viewing_pk`, the salt, `eph_u`, the sealed key, the masked disclosure and the auditor view tag
- the exits bitmap, each output's owner tag and body, and `private_tx_hash`
- the layout flags, the expiry, the approval bit, the root revisions and the SPP proof
- on the anonymous rail, the BSB22 commitment of the SPP proof and its proof of knowledge
- the payer and each public leg, with its account, mint and amount

On a `Confidential` or `ConfidentialEscrow` ring (confidential rail):

14. Public: the owner signer, the co-signer when it signs, each ring output's owner tag `u` (the recipient's viewing key), on a policy ring each live output's owner identity, each exit owner, and each SPL withdrawal owner. Under `OWNER_IN_PROOF` the owner key replaces the owner signer, each ring output publishes its owner key beside its `u`, a dummy slot names the sender or an output owner, and on a policy ring the frame marks each dummy slot.
15. Private from chain observers: the amount, asset, blinding and nullifier key of each output, the exit asset and amount, and which notes the nullifiers spend.
16. Every payment to one recipient carries the same `u`. The zolana user registry maps a registered `u` to its owner's Solana key, and no proof shows the owner holds `u`. Payments to one recipient therefore link to each other and name it. Change carries the sender's own `u`.
17. The disclosure opens outputs only, and a nullifier needs the owner's nullifier secret. The auditor therefore learns no spent note of an owner without a registered key. A registered owner's secret is sealed to the auditor on any confidential ring, so the auditor computes that owner's nullifiers and links its spends. A `ConfidentialEscrow` ring requires a registered key of every output owner.

On an `Anonymous` ring (anonymous rail):

18. Public: the signing co-signer identity, the withdrawal destination, each exit owner, each 32-byte view tag, the length of each body and, on a policy ring, the blinded sender commitment.
19. Private from chain observers: the sender, every recipient, the amounts, assets and blindings, and the spent notes. The audit proof shows the hidden owner differs from the payer, the co-signer and the withdrawal destination.
20. A transfer that spends a default-ring note publishes the hidden owner's identity `solana_owner_identity(key)` as `default_owner_tag`, so it names its sender. An exit or a withdrawal publishes its recipient. When ring notes are spent, SPP refuses an exit to the hidden owner's key, and the audit proof refuses a withdrawal to it. No layer checks a recipient key that is only linked to the sender.
21. A first payment takes the recipient's request tag or bootstrap tag. The bootstrap tag is the recipient's `u`, so it names the recipient's viewing key and links every bootstrap payment to that key. Two payments under one request tag link to each other. Later payments of a pair take shared tags only the holders of the two viewing keys derive. Only the first change output takes the sender tag. A second change output takes a random tag laid out as a derived tag and opens from the sender bundle. An empty body tells change from payments and dummies.
22. The auditor learns the hidden sender and names each spent note. It names the first by its hash and the others by 16-byte prefixes it matches against the sender's notes. An entry spend opens every spent note.

On deposits, merges and delegate moves:

23. An `AuditedDeposit` publishes the funder, the mint, each note's amount, owner commitment and view tag. On a confidential ring the SDK sets the view tag to the recipient's `u`, which links funder and recipient. No layer on chain checks that the funder differs from the owner.
24. A `Merge` publishes the payer and every input nullifier, and SPP requires one owner and one asset across the inputs. It links up to 24 notes to one owner. The auditor opens the owner, the amount and every input hash.
25. A delegate move publishes the delegate, the recipients' `u` and their owner identities as the confidential rail does. The source member stays private from chain observers. The delegate holds the source member's nullifier secret, so it computes that member's nullifiers.

In every mode:

26. The auditor opens every output, every exit's asset and amount, every deposit and merge, and every escrowed nullifier secret. Ring RPC serves every opening, blindings included, to every ring-wide reader, and to a wallet reader the rows of its wallet, with no expiry. It serves no nullifier secret. A revoked reader keeps what it read.
27. A recipient opens its body with its viewing key and finds the asset by trial. On the anonymous rail the body names the sender's viewing key, and no proof checks it.
28. A co-signer outside Ring RPC and a third-party relayer see chain data only. Ring RPC as relayer receives the sealed transfer with every secret its proofs take, and its co-signer sees the sender and the amount each asset moves.
29. The ring indexer sees the members a client opens. It learns a policy transfer's sender, recipients and assets before the transfer lands, and it sees authority writes before they land. Photon pairs each spent leaf with its nullifier and sees the tags of one stream of a viewing key grouped per request. The ring prover receives the full witness. [Services](#services) gives the details.

## Constants

| Constant | Value | Use |
| --- | --- | --- |
| `RING_PROGRAM_CONFIG` | `10` | Discriminator of `RingProgramConfig`, seed `[b"config"]`, 120 bytes. |
| `MEMBER_REGISTRY` | `11` | Discriminator of `MemberRegistry`, seed `[b"members"]`, 2388 bytes. |
| `RECORD_QUEUE` | `12` | Discriminator of `RecordQueue`, seed `[b"queue"]`, 698 bytes. |
| `RING_POLICY` | `13` | Discriminator of `RingPolicy`, seed `[b"policy"]`, 3991 bytes. |
| `READ_ACCESS_RECORD` | `2` | Discriminator of `ReadAccessRecord`, seed `[b"reader", sha256(reader)]`, 36 bytes. |
| `CO_SIGNER` | `14` | Discriminator of `CoSigner`, seed `[b"co_signer", signer]`, 35 bytes. |
| Reserved discriminators | `1`, `3` to `9` | Unused. `0` marks an empty account. |
| `ROOT_HISTORY` | `32` | Roots a member registry keeps. |
| `QUAD_ARITY`, `QUAD_HEIGHT` | `4`, `10` | Shape of the record tree, `2^20` leaves. |
| `MEMBER_REGISTRY_EMPTY_ROOT` | `053b2136ce0e6cffb89cb76c7a81b6d7e1bd424159ff4579f284a7e5f198956d` | Root of a tree that holds only the sentinel, 32 bytes big endian. |
| `QUEUE_CAPACITY`, `APPLY_BATCH` | `16` | Pending writes a queue holds and an apply proof takes. |
| `MEMBER_QUEUE_LIMIT` | `8` | Pending writes at which member writes stop. 8 queue positions stay free for the authority. |
| `AUTHORITY_RESERVED_LEAVES` | `2^16` | Last leaves only authority writes fill, so member writes cannot use up the leaves an authority write needs. |
| `APPLY_DELAY_SLOTS` | `150` slots (about 1 minute) | Age a queued write reaches before a partial apply, and the gap between permissionless applies. |
| `GRACE_SLOTS` | `750` slots (about 5 minutes) | Grace window of the member registry's curator rule, which no transfer reads. `InitializeStorage::records` also takes it as the records' `grace_slots`. |
| `DEFAULT_INSERT_FEE` | `1_000_000` lamports (0.001 SOL) | Insert fee of a new config. |
| `MAX_RULES`, `MAX_SOURCES` | `16`, `8` | Rule table widths. |
| `N_FOREIGN` | `1` | Curators per policy. |
| `POLICY_TABLE_VERSION` | `12` | Second field of the `policy_hash` preimage. |
| `POLICY_STATEMENT_VERSION` | `4` | Policy statement element after the public slots. |
| `POLICY_TABLE_FIELDS` | `44` | Fields of the `policy_hash` preimage, 35 values and 9 zeros, absorbed 11 per Poseidon call. |
| `N_PUBLIC_SLOTS` | `3` | Distinct assets of public legs per transfer, from SPP. |
| `ACCOUNT_UNITS`, `POLICY_UNITS`, `PROOF_UNITS` | `50_000`, `150_000`, `1_400_000` | Compute unit limits clients set per instruction tag. The program does not check them. |
| `CustomRingProof` | 192 bytes | Groth16 `a [32]`, `b [64]`, `c [32]` in compressed form, then the BSB22 `commitment [32]` and `commitment_pok [32]`. |
| `WithdrawalExemptionProof` | 200 bytes | A `CustomRingProof`, then the own revision `u64` LE. |
| Error codes | `8100` to `8306` | `CustomRingError`, above the SPP range. |

Each domain tag is its ASCII bytes read as one big-endian integer, as in zolana. A 33-byte tagged X25519 key is `0x04 || u` with `u` canonical little endian. Integers in ring accounts are little endian, and integers inside `EncodedRuleTable`, a mint-setting write and every proof field are big endian. [Hashing](spec/crypto/hashing.md) lists every domain tag and encoding.

## Accounts

The ring program owns the account types below. A loader checks the owner, the exact size, the discriminator and the type's `valid()` predicate, and does not derive the address again, because each account is created only at its canonical PDA. Every account is a `repr(C)` byte image without padding. The shared rows are:

```rust
pub struct RootEntry { pub root: [u8; 32], pub applied: [u8; 8], pub slot: [u8; 8] }              // 48 bytes
pub struct SourceSlot { pub list_id: u8, pub registry: Address }                            // 33 bytes, list_id 0 when empty
pub struct QueueCheckpoint { pub chain: [u8; 32], pub slot: [u8; 8] }                       // 40 bytes
```

### RingProgramConfig

One per ring at `[b"config"]`. `CreateConfig` creates it and nothing closes it. It fixes the auditor key and the tier for the ring's life. `valid()` requires `mode <= 2` and `has_policy <= 1`.

```rust
pub struct RingProgramConfig {
    pub discriminator: u8,
    /// Config authority. Written by `CreateConfig` and `SetAuthority`.
    pub authority: Address,
    /// `0x04 || u`, canonical and not of low order.
    pub auditor_pubkey: [u8; 33],
    pub bump: u8,
    pub has_policy: u8,
    /// `Confidential = 0`, `ConfidentialEscrow = 1`, `Anonymous = 2`.
    pub mode: u8,
    /// Lamports a record write pays the config authority. The authority's own writes pay nothing.
    pub insert_fee: [u8; 8],
    /// Counts of `CoSigner` records covering `TRANSFERS`, `DEPOSITS` and `WITHDRAWALS`, in that order.
    pub co_signers: [u8; 3],
    /// Zero without a delegate. Set once, together with `mode = ConfidentialEscrow`.
    pub delegate: Address,
    pub created_slot: [u8; 8],
}
```

The mode changes once at most. `CreateConfig` sets `Anonymous` for the anonymous kinds and `Confidential` for the others. `SetDelegate` sets `Confidential -> ConfidentialEscrow`. No instruction leaves `ConfidentialEscrow` or `Anonymous`.

`SetCoSigner` and `ClearCoSigner` keep each count equal to the records whose scope holds the class. A change that takes a count out of `0..=255` fails with `CoSignerCountOutOfRange`.

### CoSigner

One per co-signer at `[b"co_signer", signer]`, created by `SetCoSigner` and closed by `ClearCoSigner`. `valid()` requires a nonzero `signer` and a nonzero `scope` within the class bits.

```rust
pub struct CoSigner {
    pub discriminator: u8,
    pub signer: Address,
    /// `TRANSFERS = 1`, `DEPOSITS = 2`, `WITHDRAWALS = 4`.
    pub scope: u8,
    pub bump: u8,
}
```

### MemberRegistry

One per ring at `[b"members"]`, created by `CreateMemberRegistry` for any kind and never closed. It holds the root history the record queue instructions apply and the floor. `valid()` requires `history_cursor < 32` and `next_index <= 2^20`.

```rust
pub struct MemberRegistry {
    pub discriminator: u8,
    pub bump: u8,
    /// Index of the newest root in `history`.
    pub history_cursor: u8,
    /// Leaf the next insert takes. Leaf `0` is the sentinel.
    pub next_index: [u8; 4],
    /// Queue tail after the last authority write. Own roots below it are refused.
    pub floor: [u8; 8],
    pub prior_floor: [u8; 8],
    /// Starts the curator grace window.
    pub floor_slot: [u8; 8],
    /// `RootEntry { root, applied, slot }`, `applied` the queue head after the application.
    pub history: [RootEntry; 32],
    /// Unused, the ring policy holds the policy.
    pub policy_hash: [u8; 32],
    pub sources: [SourceSlot; 8],
    pub rules: EncodedRuleTable,
    pub generation: [u8; 4],
    pub generation_slot: [u8; 8],
}
```

`CreateMemberRegistry` starts it with `next_index = 1`, `history[0] = { MEMBER_REGISTRY_EMPTY_ROOT, 0, slot }` and floor `0`. An application pushes its new root over the oldest of the 32. No transfer, deposit or merge reads these roots. The [RingPolicy](#ringpolicy) mirrors serve every own and curator root.

### RingPolicy

One per ring at `[b"policy"]`, created by `CreatePolicy` for any kind and never closed. It holds the policy, the records address and one mirror each of the records and the curator root history.

```rust
pub struct Root {
    pub hash: [u8; 32],
    pub revision: [u8; 8],
    /// Zero on the current root, the first slot a retired root is refused.
    pub expires_at: [u8; 8],
}

pub struct RootMirror {
    /// Zero before the first `SyncRoots`.
    pub registry: Address,
    /// The registry's roots as the last `SyncRoots` copied them, newest first.
    pub roots: [Root; 32],
}

pub struct RingPolicy {
    pub discriminator: u8,
    pub bump: u8,
    /// The records `StorageRegistry`, fixed by `CreatePolicy`.
    pub records: Address,
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// `SourceSlot { list_id, registry }`. A zero registry reads the records.
    pub sources: [SourceSlot; 8],
    pub rules: EncodedRuleTable,
    /// Plus one per policy write. Not hashed.
    pub generation: [u8; 4],
    pub generation_slot: [u8; 8],
    pub own_roots: RootMirror,
    pub curator_roots: RootMirror,
}
```

`CreatePolicy` starts it with both mirrors zero. `SyncRoots` of `records` replaces `own_roots`, and `SyncRoots` of the curator replaces `curator_roots`, with the registry's `roots`. A statement names a root by its revision, and the program reads it from a mirror:

1. The mirror's `registry` equals `records` for an own root, or the one curator the sources name for a curator root (`MirrorNotSynced`).
2. The mirror holds a nonzero root at the revision, and that root is the newest one or its `expires_at` lies above the current slot (`MirrorRootExpired`).

Check 2 is `StorageRegistry::root` applied to the copy, so a root the registry retired keeps its expiry. A root the registry dropped since the last sync stays valid in the mirror until the next `SyncRoots`. A writer that sends each records update with `SyncRoots` in one transaction keeps the own mirror current. Anyone can sync a subscriber's curator mirror after a curator update. A sender whose root left the mirror reads the newest mirrored root and proves again. The Rust SDK does it on `MirrorRootExpired` and `MirrorNotSynced`.

The source map is positional: slot `i` is empty or holds `list_id = i + 1`. Every nonzero registry is the same curator. The hash reads a curator registry as `hash_bytes(address)` and the records as `0`.

### EncodedRuleTable

Stored inside the member registry, 513 bytes, align 1. `rule_count` selects the active rows, and every row past it is zero. The table holds no mint. Mint thresholds and outflow limits are [mint settings](#mint-settings) in the asset records.

```rust
pub struct EncodedRuleTable {
    pub rule_count: u8,
    pub rules: [[u8; 32]; 16],
}
```

A rule row is one 32-byte field element, big endian:

| Bytes | Content |
|---|---|
| `0..19` | reserved, zero |
| `19` | alternative list mask |
| `20..28` | threshold, u64 |
| `28` | guard: `Always = 0`, `AboveAmount = 1`, `AboveAmountByAsset = 2` |
| `29` | list mask |
| `30` | mode: `Present = 1`, `Absent = 2` |
| `31` | subject: `OutputOwner = 1`, `Sender = 2`, `Asset = 4` |

Bit `id - 1` of a mask names list `id`. A row with present lists stores them in `mask` with mode `Present`, and its absent lists in `alternative`. A row with absent lists only stores them in `mask` with mode `Absent` and `alternative = 0`. Only `AboveAmount` carries a nonzero threshold. Subject `3` (`ExitDestination`) is refused at write. `AboveAmount` on a sender rule is refused, and `AboveAmountByAsset` is accepted only on an output-owner rule. That guard reads each asset's `threshold` from the asset's own record.

```rust
fn policy_hash(table: &EncodedRuleTable, sources: &SourceMap) -> Field {
    let mut fields = vec![field("CRTB"), field_u8(POLICY_TABLE_VERSION)];
    for slot in sources.slots() {
        fields.push(field_u8(slot.list_id));
        fields.push(slot.registry_field()); // hash_bytes(curator registry address), or 0
    }
    fields.push(field_u8(table.rule_count));
    fields.extend(table.rules);
    fields.resize(POLICY_TABLE_FIELDS, Field::ZERO);
    // 44 fields, absorbed 11 at a time. Poseidon takes at most 12 inputs.
    fields.chunks(11).fold(Field::ZERO, |acc, chunk| Poseidon(acc, chunk))
}
```

The generation is not hashed, so a repin of the same table keeps `policy_hash`.

### RecordQueue

One per ring at `[b"queue"]`, created with the registry and never closed. `valid()` requires `head <= tail` and `tail - head <= 16`.

```rust
pub struct RecordQueue {
    pub discriminator: u8,
    pub bump: u8,
    /// Oldest pending position.
    pub head: [u8; 8],
    /// Next position.
    pub tail: [u8; 8],
    /// `chain(head - 1)`.
    pub chain_head: [u8; 32],
    /// `{ chain(p), slot }` of position `p` at index `p mod 16`.
    pub checkpoints: [QueueCheckpoint; 16],
    /// Earliest slot of the next permissionless apply.
    pub next_apply_slot: [u8; 8],
}
```

```rust
fn entry_hash(e: &QueueEntry) -> Field {
    let p = e.mint_policy.unwrap_or_default();
    Poseidon(field("CRQW"), e.member, right_align(e.mask), right_align(e.value), e.escrow_key,
        mint_policy_write(e), right_align(p.withdrawal_threshold), limits(p)[0], limits(p)[1])
}
// 0 when the entry keeps the settings, else 2^192 + pack(policy). See Mint settings.
fn mint_policy_write(e: &QueueEntry) -> Field {
    e.mint_policy.map_or(Field::ZERO, |policy| (1 << 192) + pack(policy))
}
// chain(-1) = 0. The apply statement binds chain(head - 1) and chain(tail - 1).
fn chain(p: u64) -> Field { Poseidon(chain(p - 1), entry_hash(entry(p))) }
```

A member write needs `pending < MEMBER_QUEUE_LIMIT` (`QueueFull`) and `next_index + pending + 1 <= 2^20 - AUTHORITY_RESERVED_LEAVES` (`AuthorityLeafReserve`), counting every pending write as an insert. Authority writes need `pending + count <= 16` (`AuthorityBatchTooLarge`). The authority can always write 8 records in one instruction.

### ReadAccessRecord

One per reader at `[b"reader", sha256(reader)]`. `GrantReadAccess` creates it, `RevokeReadAccess` closes it, and no other ring instruction reads it. Ring RPC does not read it.

```rust
pub struct ReadAccessRecord {
    pub discriminator: u8,
    /// `0x00 || SEC1 P-256 key`, or `0x01 || Ed25519 key || 0x00`.
    pub reader: [u8; 34],
    pub bump: u8,
}
```

The program requires an Ed25519 reader key to be a canonical point of the prime-order subgroup other than the identity. It checks a P-256 key for its SEC1 prefix only, and the SDK checks curve membership. A grant has no scope and no expiry.

### SPP ring config

SPP owns the `RingConfig` at `ring_auth`, 69 bytes: authority, program id, the authority rail flag, `paused`, `activated` and the bump. `InitSppRingConfig` creates it with `authority = ring_auth`, and SPP sets `activated` from its protocol config. Afterwards SPP governance alone sets `activated` and the authority rail flag. The ring writes only `paused`, through `SetPaused`. SPP refuses every ring rail while the ring is not activated or is paused.

## Member records

A record lists one member's lists and holds its escrow key and its mint settings. Records are public: every write names its member, its bits and its mint settings in instruction data, and the ring indexer serves every record with its path.

```rust
/// Leaf of the 4-ary record tree. Leaf 0 is the sentinel `(0, q - 1, 0, 0, 0, 0, 0, 0)`.
fn record_hash(r: &MemberRecord) -> Field {
    Poseidon(r.member, r.next, right_align(r.lists), r.escrow_key,
        pack(r.mint_policy), right_align(r.mint_policy.withdrawal_threshold),
        limits(r.mint_policy)[0], limits(r.mint_policy)[1])
}
/// Set once by `RegisterKey`. A second registration keeps the first key.
fn escrow_key(nullifier_pk: Field, ciphertext: &[u8; 32]) -> Field {
    Poseidon(nullifier_pk, hash_bytes(ciphertext))
}
```

Records form one list sorted by member through `next`. The empty leaf is `0`. A write sets `lists = (lists & !mask) | value`.

| Id | List | Writer |
|---|---|---|
| 1 | allow | Config authority |
| 2 | block | Config authority |
| 3 | frozen | Config authority |
| 4 | ring-viewing | Owner, own record |
| 5 | recovery | Owner, own record |
| 6 | reader | Config authority |
| 7 | approval | Config authority |
| 8 | escrow | `RegisterKey` only |

A list means only what the rules that read it make of it. No program check reads a list bit except through the policy proof. The ring-viewing and recovery bits are owner flags for off-chain use, and no rule may read them. A rule reads only the authority lists, so an owner cannot admit itself. Bits `8..63` belong to no list and no writer may set them.

A proof opens a present member by its leaf under the root. It opens an absent member by the low record with `low.member < member < low.next` and reads every list and every mint setting as `0`. Every opening the proof makes folds to the bound root, so a prover cannot leave out the record that convicts its subject.

### Mint settings

An asset member's record holds the ring's settings for that mint, each a u64:

| Field | Read by | Effect |
|---|---|---|
| `threshold` | Policy proof, `AboveAmountByAsset` | An owner's payments in the mint at or below it are exempt. Zero fails every payment in the mint under that guard, admitted or not. |
| `cap` | Policy proof, outflow | The outflow of one transfer in the mint is at most `cap`. Zero is no cap. |
| `cosign_above` | Policy proof, outflow | An outflow above it sets `approval_required`. Zero is no bound. |
| `withdrawal_threshold` | Withdrawal exemption proof | A gross withdrawal at or below it needs no withdrawal-scoped co-signer. Zero exempts nothing. |
| `sender_cap`, `sender_window_slots` | Ring RPC co-signer | The amount of the mint one sender may move in a window of that many slots. Zero is no cap. |
| `volume_cap`, `volume_window_slots` | Ring RPC co-signer | The amount of the mint all senders together may move in a window of that many slots. Zero is no cap. |
| `deposit_cap` | Ring RPC co-signer | The largest public deposit of the mint in one co-signed transaction. Zero is no cap. |
| `withdrawal_cap` | Ring RPC co-signer | The largest public withdrawal of the mint in one co-signed transaction. Zero is no cap. |

No proof bounds an amount by the six asset limits. They enter the leaf, so the indexer serves them under a root the program holds, and Ring RPC enforces them before it co-signs. A window cap and its window are both zero or both nonzero, and a write that sets only one of them fails with `InvalidAssetLimits`.

```rust
/// Below 2^192, with threshold at bits 128..192, cap at 64..128 and cosign_above at 0..64.
fn pack(p: MintPolicy) -> Field {
    (p.threshold << 128) + (p.cap << 64) + p.cosign_above
}
/// Two fields below 2^192, each three limits in table order with the first at bits 128..192.
fn limits(p: MintPolicy) -> [Field; 2] {
    let l = p.limits;
    [(l.sender_cap << 128) + (l.sender_window_slots << 64) + l.volume_cap,
        (l.volume_window_slots << 128) + (l.deposit_cap << 64) + l.withdrawal_cap]
}
```

Only `AuthorityWriteRecords` writes mint settings. One write replaces all ten values, and an all-zero value clears them. A write without a replacement keeps them, and so do member writes and key registrations. A record with nonzero mint settings counts as nonempty, so a settings write to an absent asset inserts its record. The policy proof and the withdrawal exemption proof read mint settings from the ring's own registry only, also when a curator serves the lists. A mint has no settings until the authority writes them, and the only bound on the number of configured mints is the record tree's capacity.

## Instructions

| # | Instruction | Tag | Description | Access |
| --- | --- | --- | --- | --- |
| | **Setup** | | | |
| 1 | `CreateConfig` | `1` | Creates the ring config with the auditor key and the ring kind. | Upgrade authority signs |
| 2 | `CreateMemberRegistry` | `28` | Creates the member registry and the record queue. | Config authority signs |
| 3 | `InitSppRingConfig` | `2` | Creates the SPP `RingConfig` at `ring_auth`. | Config authority signs |
| | **Policy** | | | |
| 4 | `CreatePolicy` | `7` | Creates the ring policy over the records and pins the first rule table and source map. | Config authority signs |
| 5 | `SetPolicyRules` | `12` | Same as `CreatePolicy`, over an existing policy. | Config authority signs |
| 6 | `SetPolicySource` | `10` | Points one list at the records or the curator. | Config authority signs |
| | **Controls** | | | |
| 7 | `SetAuthority` | `6` | Hands the config to a new authority. | Config authority and new authority sign |
| 8 | `SetPaused` | `11` | Pauses or resumes the ring in SPP. | Config authority signs |
| 9 | `GrantReadAccess` | `4` | Creates a reader's read access record. | Config authority signs |
| 10 | `RevokeReadAccess` | `5` | Closes a reader's read access record. | Config authority signs |
| 11 | `SetCoSigner` | `27` | Creates a co-signer's record or sets its scope. | Config authority signs |
| 12 | `ClearCoSigner` | `21` | Closes a co-signer's record. | Config authority signs |
| 13 | `SetInsertFee` | `42` | Sets the insert fee. | Config authority signs |
| 14 | `SetDelegate` | `24` | Sets the delegate and turns the ring to `ConfidentialEscrow`. | Config authority and delegate sign |
| | **Records** | | | |
| 15 | `WriteRecords` | `39` | Queues a write of the signer's member lists. | Owner signs |
| 16 | `RegisterKey` | `29` | Queues the signer's escrow key, proven sealed to the auditor. | Owner signs |
| 17 | `ApplyRecords` | `41` | Applies the queue to the record tree. | Anyone |
| 18 | `AuthorityWriteRecords` | `40` | Writes authority lists and mint settings and applies the queue at once. | Config authority signs |
| | **Money movement** | | | |
| 19 | `AuditedDeposit` | `31` | Forwards an SPP ring deposit with its deposit proof. | Funder signs |
| 20 | `Transact` | `43` | Verifies a transfer's ring proofs and forwards it to SPP. | Owner signs, or payer on an anonymous ring |
| 21 | `DelegateTransact` | `44` | Same as `Transact` on the authority rail. | Delegate signs |
| 22 | `Merge` | `20` | Forwards an SPP ring merge with its disclosure proof. | Payer signs |
| | **Roots** | | | |
| 23 | `SyncRoots` | `48` | Copies a storage registry's roots into its ring policy mirror. | Anyone |

Tag `18` (SPP `RING_DEPOSIT`) fails with `DepositAuditRequired`. Tags `3` and `25` fail with `InvalidInstructionData`. Tags `8`, `9`, `22`, `23`, `26`, `30` and `32` to `38` are reserved and fail as unknown with `InvalidInstructionData` (`8100`). Clients set each instruction's compute unit limit to `ACCOUNT_UNITS`, the policy writes to `POLICY_UNITS` and every proof instruction to `PROOF_UNITS`.

Variable instruction data is wincode: little-endian integers, `u8` length prefixes, `bool` as one byte `0` or `1`. Fixed structs are byte-identical Pod layouts. Every proof is a `CustomRingProof`.

Two authority checks recur. The upgrade authority check requires the program account and its program data under Loader v3, and a nonzero upgrade authority equal to the signer, else `UnauthorizedInitializer`. An immutable program fails it. The config authority check loads the config (`ConfigNotInitialized`) and requires the signer to equal `config.authority`, else `UnauthorizedAuthority`. Account lists below name each account's role, and an account marked signer fails without its signature. The forwarding instructions pass every trailing account to SPP. `SetPolicySource` refuses extra accounts, and the other instructions ignore them.

### Setup

Create the ring and register it with SPP.

#### 1. CreateConfig

Tag `1`. Creates the ring config with the auditor key and the ring kind. No SPP account changes.

**Accounts**

1. `payer`: pays rent. Signer, writable.
2. `authority`: the upgrade authority. Signer. Becomes the config authority.
3. `config`: `[b"config"]`. Writable.
4. `system_program`.
5. `program`: the ring program account.
6. `program_data`: its Loader v3 program data.

**Instruction data**

```rust
struct CreateConfigIxData {
    /// `0x04 || u`.
    auditor_pubkey: [u8; 33],
    /// `AuditOnly = 0`, `Policy = 1`, `Anonymous = 2`, `AnonymousPolicy = 3`.
    kind: RingKind,
}
```

The program checks, in order:

1. The data decodes, else `InvalidInstructionData`.
2. `system_program` is the system program (`InvalidSystemProgram`).
3. The upgrade authority check.
4. `auditor_pubkey` has tag `0x04` and a canonical `u` outside the 5 low-order values (`InvalidAuditorPubkey`).
5. `config` is the canonical `[b"config"]` (`InvalidConfigPda`) and empty (`ConfigAlreadyInitialized`).

It writes the discriminator, `authority`, the auditor key, `bump`, `has_policy` for `Policy` and `AnonymousPolicy`, `mode = Anonymous` for the anonymous kinds else `Confidential`, `insert_fee = DEFAULT_INSERT_FEE` and `created_slot = Clock::slot`. Every other field is zero.

The program does not check that the auditor holds the key's secret. Ring RPC releases its key with a signed statement. The operator CLI checks that signature against the pinned service key, or accepts any service key under `--trust-ring-rpc` when none is pinned.

#### 2. CreateMemberRegistry

Tag `28`. Creates the member registry and the record queue. It has no kind or mode check, so every ring can hold one.

**Accounts**

1. `payer`: signer, writable.
2. `authority`: the config authority. Signer.
3. `config`.
4. `registry`: `[b"members"]`. Writable.
5. `queue`: `[b"queue"]`. Writable.
6. `system_program`.

**Instruction data**

Empty.

The program checks the system program, the config authority, then creates each PDA at its canonical address (`InvalidMemberRegistry`, `InvalidRecordQueue`) when it is empty (`MemberRegistryAlreadyExists`). It writes the registry as [MemberRegistry](#memberregistry) states and an empty queue.

#### 3. InitSppRingConfig

Tag `2`. Creates the SPP `RingConfig` at `ring_auth`, with `ring_auth` as its authority.

**Accounts**

1. `payer`: signer, writable.
2. `authority`: the config authority. Signer.
3. `config`.
4. `protocol_config`: the SPP protocol config.
5. `ring_auth`: writable.
6. `system_program`.
7. `spp_program`.
8. `policy`: the ring policy, on a policy ring only.

**Instruction data**

Empty.

The program checks the config authority, that `spp_program` is SPP and executable (`InvalidShieldedPoolProgram`), on a policy ring that the ring policy loads (`InvalidRingPolicy`) and holds a policy (`PolicyNotSet`), and that `ring_auth` is canonical (`MissingRingAuth`). It invokes SPP `create_ring_config` signed as `ring_auth`. SPP sets `activated` from its protocol config and leaves the authority rail and `paused` off.

The program does not activate the ring. Until SPP governance activates it, no note moves.

### Policy

Pin and change the rule table and its sources. On a policy ring `InitSppRingConfig` needs the policy first.

#### 4. CreatePolicy

Tag `7`. Creates the ring policy, binds the records for the ring's life and pins the first rule table and source map. An audit-only ring takes an empty table and pins no policy. Its ring policy still binds the records its withdrawal exemptions read.

**Accounts**

1. `payer`: pays rent. Signer, writable.
2. `authority`: the config authority. Signer.
3. `config`.
4. `policy`: `[b"policy"]`. Writable.
5. `records`: the ring's own `StorageRegistry`.
6. `system_program`.
7. `curators`: zero or one curator `StorageRegistry` for each distinct source number.

**Instruction data**

```rust
struct CreatePolicyIxData {
    /// The records may answer to it beside the config authority.
    storage_authority: Address,
    table: PolicyTableIxData,
}

struct PolicyTableIxData {
    /// `source = 0` names the records, `source = n` the `n`th curator account.
    sources: Vec<SourceSpec { list_id: u8, source: u8 }>,
    rules: Vec<[u8; 32]>,
}
```

Every `Vec` has a `u8` length prefix.

The program checks, in order:

1. The data decodes, `system_program` is the system program and the config authority signs.
2. An audit-only ring takes no sources and no rules (`PolicyOnAuditOnlyRing`).
3. `records` is owned by the Storage Program and decodes as a `StorageRegistry` (`InvalidStorageRegistry`). Its authority is the config authority or `storage_authority` (`StorageAuthorityMismatch`).
4. `policy` is the canonical `[b"policy"]` (`InvalidRingPolicy`) and empty (`RingPolicyAlreadyExists`).

It writes the policy with `records` and both mirrors zero. An audit-only ring stops here. A policy ring then runs the table checks:

5. The table holds at most `MAX_RULES` rows (`InvalidPolicyRules`).
6. For each source in order, the source names a list the rules reference, once (`InvalidSource`), and a curator source passes check 7.
7. A curator is not `records` (`InvalidSource`). It is owned by the Storage Program and decodes as a `StorageRegistry` of any authority (`InvalidStorageRegistry`).
8. The generation is below `u32::MAX` (`PolicyGenerationOverflow`), and every curator source is one registry (`InvalidSource`).
9. Each rule decodes canonically, the rows past `rule_count` are zero, and the table holds no duplicate rule (`InvalidPolicyRules`).
10. Every referenced list is an authority list (`MemberWrittenListRule`) and has a source (`InvalidSource`).

It stores the table, the sources, `policy_hash`, `generation = 1` and `generation_slot = Clock::slot`. It copies no root, `SyncRoots` fills each mirror. It writes no mint setting. The config authority writes those with `AuthorityWriteRecords`.

The program does not check that the curator serves the list or that the storage authority is the one the ring operator runs. The ring trusts the roots of the records and the curator fully. The operator CLI names a curator by its ring and checks that the curator ring pins a policy serving the list from its own records.

#### 5. SetPolicyRules

Tag `12`. Replaces the table and the sources together, so every proof over the old table fails.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`.
3. `policy`: writable.
4. `curators`: as `CreatePolicy`.

**Instruction data**

`PolicyTableIxData`.

The program checks the config authority, that the ring policy loads (`InvalidRingPolicy`) and holds a policy (`PolicyNotSet`), then `CreatePolicy` checks 5 to 10. A changed curator reads nothing until `SyncRoots` fills its mirror (`MirrorNotSynced`).

#### 6. SetPolicySource

Tag `10`. Points one referenced list at the records or the curator, and stores the new hash over the stored rules.

**Accounts**

As `SetPolicyRules`, with no curator for an own source and one curator for a curator source.

**Instruction data**

```rust
struct SetPolicySourceIxData { list_id: u8, source: u8 }
```

The program checks the config authority, the list id (`InvalidListId`), that `(source, curators)` is `(0, [])` or `(1, [curator])` with the curator checks of `CreatePolicy` check 7 (`InvalidSource`, `InvalidStorageRegistry`), and that the list's slot is already set (`InvalidSource`). It refuses any other trailing account. It then stores the policy as `CreatePolicy` does, which refuses a second distinct curator.

### Controls

Change who controls the ring and how.

#### 7. SetAuthority

Tag `6`. Hands the config to `new_authority`.

**Accounts**

1. `authority`: the config authority. Signer.
2. `new_authority`: signer.
3. `config`: writable.

**Instruction data**

Empty.

The program checks the config authority and writes `authority = new_authority`. The new authority signs, so a mistyped address cannot strand the config.

#### 8. SetPaused

Tag `11`. Pauses or resumes the ring in SPP.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`.
3. `ring_auth`: writable.
4. `spp_program`.

**Instruction data**

```rust
struct SetPausedIxData { paused: bool }
```

The program checks the config authority, SPP (`InvalidShieldedPoolProgram`) and the canonical `ring_auth` (`MissingRingAuth`), then invokes SPP `update_ring_config` signed as `ring_auth`.

A pause stops every SPP rail of the ring, so no owner can transfer, exit or withdraw until the authority resumes it. Record writes, applications, policy writes and controls still run.

#### 9. GrantReadAccess

Tag `4`. Creates the read access record of one reader.

**Accounts**

1. `payer`: signer, writable.
2. `authority`: the config authority. Signer.
3. `config`.
4. `read_access_record`: `[b"reader", sha256(reader)]`. Writable.
5. `system_program`.

**Instruction data**

```rust
struct ReaderIxData { reader: [u8; 34] }
```

The program checks the reader key (`InvalidReaderKey`), the system program, the config authority, the canonical address (`InvalidReadAccessRecord`) and that the record is empty (`ReadAccessRecordAlreadyExists`).

A grant has no scope and no expiry. Ring RPC does not read the record.

#### 10. RevokeReadAccess

Tag `5`. Same as `GrantReadAccess`, with these parts replaced:

- Accounts: `authority` (config authority, signer), `config`, `read_access_record` (writable), `rent_recipient` (writable). No payer and no system program.
- Checks: the config authority, the record loads, its stored reader equals the data, and `rent_recipient` is not the record (`InvalidReadAccessRecord`). The program does not check the reader key format or derive the address again.
- Effect: the record closes into `rent_recipient`.

A revoked reader keeps every opening it read.

#### 11. SetCoSigner

Tag `27`. Creates the signer's `CoSigner` record, or sets the scope of an existing one. Other co-signers keep their records. The withdrawal thresholds are mint settings, which `AuthorityWriteRecords` writes.

**Accounts**

1. `payer`: signer, writable.
2. `authority`: the config authority. Signer.
3. `config`: writable.
4. `co_signer_record`: `[b"co_signer", signer]`. Writable.
5. `system_program`.

**Instruction data**

```rust
struct SetCoSignerRecordIxData {
    signer: Address,
    /// Nonzero subset of `TRANSFERS | DEPOSITS | WITHDRAWALS`.
    scope: u8,
}
```

The program checks the scope (`InvalidCoSignerScope`), a nonzero signer (`InvalidCoSigner`), the system program and the config authority. An empty record takes the canonical address (`InvalidCoSignerRecord`) and the payer funds it. An existing record must store `signer` (`InvalidCoSignerRecord`). The config counts move from the old scope to the new one.

The co-signer may equal any key here. A transfer refuses a demanded co-signer that equals an owner or the delegate.

#### 12. ClearCoSigner

Tag `21`. Closes one `CoSigner` record. It takes no data.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`: writable.
3. `co_signer_record`: writable.
4. `rent_recipient`: writable.

The program checks the config authority, that the record loads (`InvalidCoSignerRecord`) and that `rent_recipient` is not the record. The config counts drop the record's classes, and the record closes into `rent_recipient`. The mint settings keep their withdrawal thresholds.

#### 13. SetInsertFee

Tag `42`. Sets `insert_fee`.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`: writable.

**Instruction data**

`fee`, u64 little endian, exactly 8 bytes.

The program checks the config authority. A fee above zero and below the rent minimum of an empty account fails with `InsertFeeBelowRent`.

The fee has no upper bound. A writer bounds what it pays with `max_fee`.

#### 14. SetDelegate

Tag `24`. Sets the delegate and the `ConfidentialEscrow` mode on a confidential policy ring. Both are permanent for the deployed binary.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`: writable.
3. `delegate`: signer.
4. `policy`.

**Instruction data**

Empty.

The program checks, in order, the config authority, that no delegate exists (`DelegateAlreadySet`), that the ring is not anonymous (`AnonymousRingRefused`), the policy tier (`DelegateRequiresPolicy`), and that the ring policy loads (`InvalidRingPolicy`). It writes `delegate` and `mode = ConfidentialEscrow`.

From this point every transfer sets the key escrow layout bit, and every deposited note and every transfer output, exits included, needs an owner whose record escrows the note's nullifier key. SPP governance must also enable the ring's authority rail before `DelegateTransact` runs.

### Records

Write member records and apply them to the record tree.

#### 15. WriteRecords

Tag `39`. Queues one write of the signer's own member lists.

**Accounts**

1. `member`: signer. The record member is `solana_owner_identity(member)`.
2. `config`.
3. `registry`.
4. `queue`: writable.
5. `payer`: signer, writable, only when a fee is due.
6. `authority`: the config authority. Writable, only when a fee is due.
7. `system_program`: only when a fee is due.

**Instruction data**

```rust
struct MemberWriteIxData {
    /// u64 little endian each.
    lists: { mask: [u8; 8], value: [u8; 8] },
    /// The write fails when the fee is above this.
    max_fee: [u8; 8],
}
```

The program checks, in order:

1. The member is in `[1, q - 2]` (`MemberOutOfRange`).
2. `mask != 0` and `value & !mask == 0` (`ValueOutsideMask`).
3. `mask` holds only ring-viewing and recovery bits (`ListBitNotWritable`).
4. The queue admits a member write (`QueueFull`, `AuthorityLeafReserve`).
5. A fee is due when `insert_fee != 0` and the member is not the config authority. Then `fee <= max_fee` (`InsertFeeAboveMax`), the fee accounts are present, `system_program` is the system program (`InvalidSystemProgram`), and `authority` equals `config.authority` (`FeeRecipient`). The payer transfers the fee to the authority.

It pushes `{ member, mask, value, escrow_key: 0 }` with no mint setting at the current slot.

The program does not check the ring mode. On an anonymous ring a member write publishes the owner's Solana key as a ring participant.

#### 16. RegisterKey

Tag `29`. Queues the signer's escrow key: its nullifier key and its nullifier secret sealed to the auditor.

**Accounts**

As `WriteRecords`.

**Instruction data**

```rust
struct RegisterKeyIxData {
    proof: CustomRingProof,
    nullifier_pk: [u8; 32],
    eph_u: [u8; 32],
    /// The nullifier secret sealed to the auditor.
    ciphertext: [u8; 32],
    max_fee: [u8; 8],
}
```

**Proof**

The register key proof checks:

1. `nullifier_pk = Poseidon(secret)` for the 31-byte nullifier secret.
2. `ciphertext` seals the same secret to the config's auditor key under the envelope with label `CRING/nfk1`, from `eph_u`. [Envelope](spec/crypto/envelope.md)
3. The statement binds `solana_owner_identity(member)`, `nullifier_pk`, the auditor key, `eph_u` and `hash_bytes(ciphertext)`. [Public inputs](spec/crypto/public-inputs.md#register-key)

The program refuses an anonymous ring (`AnonymousRingRefused`), applies `WriteRecords` checks 1, 4 and 5, verifies the proof, charges the fee, and pushes `{ member, Escrow, Escrow, escrow_key(nullifier_pk, ciphertext) }` with no mint setting.

The proof does not show that the member's notes use `nullifier_pk`. The first applied key is final. A wrong key makes every later escrow check of that member fail, so the member cannot receive on a `ConfidentialEscrow` ring and moves to a new signing key. The Rust SDK checks `nullifier_pk` against the member's address before it proves.

#### 17. ApplyRecords

Tag `41`. Applies every pending write to the record tree. Anyone submits it.

**Accounts**

1. `registry`: writable.
2. `queue`: writable.

**Instruction data**

```rust
struct ApplyRecordsIxData {
    proof: CustomRingProof,
    new_root: [u8; 32],
    /// u32 little endian.
    new_next_index: [u8; 4],
}
```

It is exactly 228 bytes.

**Proof**

The apply proof checks that applying exactly `pending` chained writes in order moves `(old_root, old_next_index, chain_start)` to `(new_root, new_next_index, chain_end)`:

1. An update replaces the member's leaf with `(member, next, (lists & !mask) | value, escrow, mint settings)`. An escrow key fills only an empty slot. The mint settings take the entry's values when bit 192 of its `mint_policy_write` is set, and keep the stored values otherwise.
2. A write to an absent member proves `low.member < member < low.next`. It inserts a nonempty record at exactly `next_index` and links `low.next -> member`.
3. A write that leaves an absent record empty, with zero lists, escrow key and mint settings, inserts nothing.
4. The leaf index fits 20 bits, so no insert passes the capacity.

The program supplies `old_root = current_root`, `old_next_index`, both chain ends and `pending`, and picks the key of the smallest width in `{1, 2, 4, 8, 16}` at or above `pending`.

The program checks `apply_due`: `pending >= MEMBER_QUEUE_LIMIT`, or `pending > 0` with the head write at least `APPLY_DELAY_SLOTS` old, else `ApplyNotDue`. Then `slot >= next_apply_slot`, else `ApplyTooSoon`. It verifies the proof, pushes the new root with `applied = tail`, sets `head = tail`, `next_index = new_next_index` and `next_apply_slot = slot + APPLY_DELAY_SLOTS`. The floor does not move.

The proof does not check `value & !mask == 0`. The program checked it when the write was queued.

#### 18. AuthorityWriteRecords

Tag `40`. Writes up to 16 authority list changes or mint-setting replacements and applies the whole queue at once.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`.
3. `registry`: writable.
4. `queue`: writable.

**Instruction data**

`count: u8`, then `count` × `RecordWriteData` of 129 bytes each, then `ApplyRecordsIxData`.

```rust
struct RecordWriteData {
    member: [u8; 32],
    /// u64 little endian each. All zero when the write changes no list.
    lists: { mask: [u8; 8], value: [u8; 8] },
    /// `0` then 80 zero bytes keeps the mint settings. `1` then threshold, cap, cosign_above,
    /// withdrawal_threshold and the six asset limits in table order as u64 big endian replaces them.
    mint_policy: [u8; 81],
}
```

Same as `ApplyRecords`, with `apply_due` replaced. `count = 0` fails with `InvalidInstructionData` and `count > 16` with `AuthorityBatchTooLarge`. Every write names a member in range (`MemberOutOfRange`). A nonzero `lists` has a mask of authority lists only, as `WriteRecords` checks 2 and 3 with the authority lists. A `mint_policy` with another flag byte, a keep flag with nonzero bytes, or a write that neither changes a list nor replaces the settings fails with `InvalidInstructionData`. Then `pending + count <= 16` (`AuthorityBatchTooLarge`). The program pushes the writes behind the pending ones, verifies one apply proof over the whole queue, and raises the floor to the new root's queue position. It charges no fee and does not move `next_apply_slot`.

An authority write lands in the instruction that makes it, so a block or a cleared allow binds the next transfer of the ring. Every proof built under an older own root fails with `RootBelowFloor`.

### Money movement

Move notes into, inside and out of the ring.

#### 19. AuditedDeposit

Tag `31`. Forwards one SPP ring deposit of up to 8 new notes, with a proof that seals each opening to the auditor. Every deposit into a ring runs through it.

**Accounts**

1. `config`.
2. `policy`: the ring policy, in `ConfidentialEscrow` mode or on a policy ring.
3. `co_signer_record`, then `co_signer` (signer), only when demanded.
4. `spp_accounts`: the SPP `ring_deposit` list `[tree, depositor, ring_config, spp_program, asset groups…]`. `ring_config` is `ring_auth`.

**Instruction data**

```rust
struct AuditedDepositPrefix {
    tag: u8, // 31
    proof: CustomRingProof,
    /// The own root's revision, u64 LE, in `ConfidentialEscrow` mode or on a policy ring, else 0.
    own_revision: [u8; 8],
}
// followed by the SPP ring deposit data, from its tag byte 18
```

Each SPP deposit entry's ciphertext begins with a `CRDEP001` capsule: its slot index, the batch's ephemeral key and the 96-byte sealed opening, then the recipient ciphertext. [Envelope](spec/crypto/envelope.md#deposit-capsule)

**Proof**

The deposit proof checks, for each of `count` entries:

1. The note's `owner_utxo_hash = Poseidon(Poseidon(owner_pk_hash, nullifier_pk), Poseidon(CRDB, blinding_secret))`.
2. The capsule seals `(owner hash, blinding, owner key)` to the auditor. On an anonymous ring `owner_pk_hash = solana_owner_identity(owner key)`. Elsewhere the owner key is zero.
3. In `ConfidentialEscrow` mode the owner's record opens under the bound root with `escrow_key = Poseidon(nullifier_pk, ct_hash)`.
4. Under a nonzero `policy_hash` the rule table hashes to it, and the entry's asset record or its absence opens under the bound root. Every active asset rule holds for the asset as for a transfer output, an amount guard summing the batch's entries of the asset. An active asset rule that reads a curator list fails, the proof opens no curator root.
5. The statement binds a context hash over the ring id, the tree and the exact SPP data. It also binds each entry's asset and amount and the policy hash. [Public inputs](spec/crypto/public-inputs.md#deposit)

The program checks, in order:

1. The prefix is complete (`InvalidInstructionData`), its tag is `31` and the SPP data starts with tag `18` (`InvalidAuditedDeposit`), and the SPP body decodes (`InvalidDepositData`).
2. In `ConfidentialEscrow` mode or on a policy ring the ring policy loads (`InvalidRingPolicy`), its own mirror serves `own_revision` ([RingPolicy](#ringpolicy)), and a written `policy_hash` enters the statement. Otherwise the revision is `0` (`UnexpectedMemberRegistryRoot`).
3. When a record covers `DEPOSITS`, a record covering it loads (`InvalidCoSignerRecord`, `CoSignerOutOfScope`) and its signer signs (`MissingCoSigner`, `UnauthorizedCoSigner`).
4. On an anonymous ring every entry has `ring_data_hash = 0` (`AnonymousRingDataNotZero`).
5. `ring_auth` sits at SPP index 2 and at no other index (`MissingRingAuth`, `RingAuthOutOfSlot`). The depositor at SPP index 1 signs (`MissingFundingSigner`).
6. Each entry's asset is `SOL_ASSET_FIELD` for a SOL group and `hash_bytes(mint)` for an SPL group, the mint read at its group's SPP account position (`DepositMintAccountMissing`, `DepositAssetIndexUnknown`).
7. `1 <= count <= 8`. Each capsule parses with its own position and one shared ephemeral key of tag `0x04` (`InvalidDepositDisclosure`).

It verifies the proof under the key of the smallest capacity in `{1, 2, 4, 8}` at or above `count`, and invokes SPP with the deposit data unchanged.

No owner rule, sender rule or outflow limit runs on a deposit, and the funder is never screened. The rules screen the note's owner when it sends. SPP leaves the view tag opaque, and the proof binds it only through the context hash. A recipient's wallet finds the note by its view tag. The ring SDKs open the scheme 8 body in their ring scan, Rust `DepositOpener` and TypeScript `openRingDeposit`. They keep the note only when it rebuilds the published hash.

#### 20. Transact

Tag `43`. Verifies a ring transfer's audit proof, on a policy ring its policy proof, and an optional withdrawal exemption proof, expands the compact frame into the SPP transfer, and invokes SPP signed as `ring_auth`. The ring program writes no ring account.

The mode selects the rail:

| Mode | Rail | SPP instruction and circuit | Who signs | Sender in the policy statement |
|---|---|---|---|---|
| `Confidential`, `ConfidentialEscrow` | Confidential | `RING_TRANSACT` (19), `ConfidentialRingEddsa` | Each owner signer, the payer, a demanded co-signer | `solana_owner_identity(owner)` |
| `Confidential`, `ConfidentialEscrow` with `OWNER_IN_PROOF` | Confidential | `RING_TRANSACT` (19), `ConfidentialRingInCircuitEddsa` | The payer and a demanded co-signer only. The owner signs inside the SPP proof. | `solana_owner_identity` of the frame's owner key |
| `Anonymous` | Anonymous | `RING_TRANSACT` (19), `AnonymousRingEddsa` | The payer and a demanded co-signer only. The hidden owner signs inside the SPP proof. | `sender_commitment` |

SPP accepts `ConfidentialRingInCircuitEddsa` only in a build with its `ring-confidential-eddsa` feature.

**Accounts**

1. `config`.
2. `policy`: the ring policy, on a policy ring and on any ring when the frame carries a withdrawal exemption proof. Every own and curator root of the transfer comes from it.
3. `co_signer_record`, then `co_signer` (signer), when the transfer demands one.
4. `spp_accounts`: the SPP `ring_transact` list, verbatim: `[payer, output_tree, spp_program, system_program, ring_auth, input trees…, nullifier PDAs…, owner signers…, settlement groups…]`.

**Instruction data**

The frame is a byte string the program parses in this order. The shape byte selects the shape `n_in × n_out`. Short or trailing bytes and an input count outside `1..=n_in` fail with `RingTransactLength`. The `[exemption]` part has no flag. It is present when exactly 200 bytes follow the tree contexts, and SPP never receives it. A shape index outside the set fails with `RingShapeUnkeyed`. A bad interface transfer list or a bitmap bit past its count fails with `InvalidInstructionData`.

```text
flags            u8   POLICY 1, CURATOR 2, APPROVAL_REQUIRED 4, OWNER_IN_PROOF 8, SECOND_TREE 32,
                      bits 4, 6 and 7 clear
shape            u8   bits 0-5 index into SPP_SUPPORTED_SHAPES, bit 6 DEFAULT_OWNER_TAG, bit 7 clear
inputs           u8   bits 0-5 published input count, bit 6 KEY_ESCROW, bit 7 FULL_OPENINGS
audit_proof      CustomRingProof
[POLICY]         policy_proof CustomRingProof, own_revision u64 LE
[CURATOR]        curator_revision u64 LE
[POLICY, anonymous] sender_commitment [32]
[POLICY, confidential or delegate] recipients [32] per output slot, without OWNER_IN_PROOF
[POLICY, OWNER_IN_PROOF] dummies bitmap of ceil(n_out / 8) bytes
expiry_unix_ts   u32 LE
tx_viewing_u     [32]
salt             [16]
interface_transfers  Vec<InterfaceTransfer>, u8 length
[POLICY]         spl_withdrawal_owners [32] per SPL withdrawal
exits            bitmap of ceil(n_out / 8) bytes
outputs          per slot, by kind:
                   exit      hash [32], owner_tag [32], payload [83]
                   delivered hash [32], u [32], body [40]
                   owned     hash [32], owner [32], u [32], body [40], under OWNER_IN_PROOF
                   anonymous hash [32], tag [32], len u16 LE, body [len], empty on change
[anonymous]      sender bundle tag [32], len u16 LE nonzero, body [len]
eph_u            [32]
sealed           [32]
disclosure       [32] per field of the layout
private_tx_hash  [32]
[anonymous]      commitment [32], commitment_pok [32]
[DEFAULT_OWNER_TAG] default_owner_tag [32]
[OWNER_IN_PROOF] owner [32], commitment [32], commitment_pok [32]
spp_proof        a [32], b [64] compressed, c [32]
nullifiers       [32] per published input
[SECOND_TREE]    bitmap of second-tree inputs, then two TreeContext, else one
[exemption]      withdrawal_exemption_proof CustomRingProof, own_revision u64 LE
```

A bitmap holds bit `i` at byte `i / 8`, bit `i % 8`. A scheme is the zolana tag of an output's body format, stored by SPP without parsing. An exit payload is the zolana scheme 3 body of an output without data, any other length fails with `DataFreeBodyLength`. An anonymous output body is scheme 1, and an empty one marks a change output. The ring SDKs encode the scheme 1 recipient, scheme 2 sender bundle and scheme 8 deposit plaintexts with their own codecs, in Rust `anonymous_plaintext.rs` and `ring_deposit.rs` of `zolana-ring-transaction`. They take the scheme numbers, the view tag derivations and the body encryption from zolana. An empty sender bundle or a body past `u16::MAX` fails with `AnonymousBodyLength`. A set reserved flag bit fails with `FlagNotAllowed`. `InterfaceTransfer` and `TreeContext` are the zolana SPP types. `expiry_unix_ts` is the SPP expiry, checked by SPP against cluster time. Every transfer publishes exactly `n_out` slots, a dummy slot included.

The program expands the frame to SPP `TransactIxData`:

- `tx_viewing_pk = 0x04 || tx_viewing_u`, the salt and the interface transfers, with no transfer data hashes
- each output as `OwnerTag::Inline` in the `Encrypted` encoding, with scheme 10 (delivered), 11 (owned, `u || body` under the owner key), 1 (anonymous) or 3 (exit), and an anonymous change output with no data
- on the anonymous rail the sender bundle first, `{ view_tag: tag, data: Encrypted(2 || body) }`
- the auditor message last, `{ view_tag: auditor u, data: 0x04 || eph_u || sealed || disclosure }`
- `private_tx_hash`, the rail's circuit and the proof, under `OWNER_IN_PROOF` the circuit carrying the owner key and the commitment
- the expiry widened to u64, each nullifier as an input with its tree index, and the tree contexts
 A client computes the same SPP external data hash before any proof exists.

The audit key follows the rail and the published shape:

| Rail | `n_out` | Layout | Audit key |
|---|---|---|---|
| Confidential | 2, 4, 8, 16 | Delivered | `DeliveredAudit { outputs }` |
| Delegate | 2, 4 | Delivered | `DeliveredAudit { outputs }` |
| Anonymous | 2, 4, 8 | Anonymous | `AnonymousAudit { class, outputs }`, the smallest input class at or above the published inputs |
| Anonymous, `FULL_OPENINGS` | 2, 4, 8 | Anonymous entry | `AnonymousEntryAudit { 8, outputs }`, at most 8 inputs |

The anonymous input classes are `{4, 16}` at 2 and 4 outputs and `{4, 8}` at 8. A shape with no key fails with `RingShapeUnkeyed`.

The sender chooses each output's owner, asset and amount. The audit proof fixes every blinding from `tx_viewing_sk`, the salt and the first nullifier. A recipient finds its notes by its owner tag. That is its viewing key `u` on the confidential rail, or a view tag on the anonymous rail. Under `OWNER_IN_PROOF` the owner tag is the owner key, and the recipient's `u` leads the scheme 11 body. It opens the body and keeps the note only when a held mint rebuilds the published commitment. On the anonymous rail every payment and dummy carries one body sealed at its output position, and the sender's change leads with no body. Output 0 takes the sender tag, and a second change output takes a dummy tag. The sender bundle message lists one recipient viewing key per output after the change. An exit or a dummy takes the dummy key `0x04 || 0^32`, a custom-ring extension of the zolana sender bundle. [Anonymous rings](anonymous-rings.md#output-layout) The auditor finds every transfer by the auditor view tag.

**Proof**

The audit proof checks, on every rail:

1. `tx_viewing_sk` is clamped and `tx_viewing_pk` is its public key.
2. `sealed` seals `tx_viewing_sk` to the config's auditor key from `eph_u`. [Envelope](spec/crypto/envelope.md)
3. Every live output's blinding is `TXOB(n0, TXOS(n0, CRBS(tx_viewing_sk, salt)), i)`, so SPP's blinding seed is `CRBS(tx_viewing_sk, salt)` on every transfer with a live output.
4. A live output with a nonzero ring id is a ring output and the rest are exits. The exits layout bit equals "some exit exists". Every live ring output's owner is `solana_owner_identity(owner_key)` for its disclosed owner key.
5. Each published disclosure field equals its plaintext plus `Poseidon(Poseidon(CROD, tx_viewing_sk, salt), j)`. [Disclosure](spec/crypto/disclosure.md)
6. Delivered: each ring output's 40-byte body is `AES-256-CTR(blinding || amount)` under a slot secret from `ECDH(tx_viewing_sk, u)`, so the key `u` the frame publishes opens the body. Every output has `data_hash = 0` and `ring_data_hash = 0`. Amounts fit 64 bits.
7. Anonymous, commitment key: every spent note belongs to one hidden owner and carries the ring id. No live output carries a data hash or ring data, and every live output's amount fits 64 bits. The disclosure opens each ring output's owner key and each live output's asset and amount. No view tag and no body enters the proof. `private_tx_hash` reopens with the spent hashes and the outputs. Each nonzero party identity differs from the hidden owner. On a policy ring `sender_commitment = Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`.
8. Anonymous, entry key: the same over a spend of default-ring notes, without the ring id condition on spent notes. Every spent note shares input `0`'s nullifier key and carries no data. The disclosure opens every spent note's asset, amount and blinding, the shared nullifier key and `sender_key`. The commitment key of check 7 discloses the first spent note's hash and 16-byte prefixes of the others instead.

The policy proof checks, on a policy ring:

1. The rule table hashes to `policy_hash`. Each active row splits into its parts and recomposes to the stored row.
2. The outputs reopen `private_tx_hash`. The member key takes the spent note chain and the address nullifier chain as opaque values. The delegate key takes only the address nullifier chain as opaque and reopens the spent notes.
3. The sender is the statement's `sender` on the confidential rail. On the anonymous rail `sender` is the commitment and opens to `sender_pk_hash` with the blinding the `private_tx_hash` preimage fixes.
4. Each statement recipient is its slot's owner identity, the owner subject the rules screen, and `0` on a dummy slot and on the anonymous rail.
5. The withdrawal legs hash to `withdrawal_hash`. Each active leg has a nonzero asset and a nonzero 64-bit amount.
6. The own record pool folds to `own_root` through one shared canopy, and the curator pool to `curator_root` when some list is foreign. Each subject resolves to its own leaf in the pool, or to the low record that brackets it. A bracketed subject reads every list and mint setting as `0`. A list bit reads from the curator record when the list's source is foreign. The asset record of every live payment and of every nonzero public asset resolves in the own pool, whatever the rules. It gives that asset's mint settings.
7. Each active rule holds as [Properties](#properties) 6 states. A scalar `AboveAmount(t)` guard exempts an asset subject when the live payments of that asset sum to at most `t`. It exempts an owner subject when that owner's live payments sum to at most `t`, and then every payment is in one asset. `AboveAmountByAsset` exempts when the owner's payments in that asset sum to at most the asset's `threshold`. A live payment in an asset with a zero `threshold` fails the proof under such a rule, admitted or not. Comparisons are inclusive.
8. Outflow and `approval_required` follow [Properties](#properties) 8.
9. In `ConfidentialEscrow` mode every UTXO output's owner record holds the output's escrow key.
10. The own-only key requires `curator_root = 0` and no foreign source.

The policy key is `MemberPolicy { outputs: n_out, withdrawals, own_only }`, with `withdrawals` the smallest of `{0, 1, 2, 4, 8, 16, 32}` at or above the withdrawal count and `own_only` when the policy has no curator. Its record pools hold, with `o = n_out`, `w = withdrawals` and `p = N_PUBLIC_SLOTS`:

```text
distinct = 1 + 2·o + w
own      = distinct + max(min(w, 3), p)
curator  = distinct + min(w, 3), none on the own-only key
```

The delegate key takes `w = 0` and `p = 0`. [Policy circuit](circuit-policy.md#record-pool)

The withdrawal exemption proof checks, under the `WithdrawalExemption` key:

1. For each of the 3 slots with a nonzero asset, the asset's record opens under the bound own root. An absent asset reads `withdrawal_threshold = 0`.
2. The slot's amount and the threshold fit 64 bits, and `amount <= withdrawal_threshold`.
3. A slot with a zero asset has a zero amount.
4. The statement binds the root and every `(asset, amount)` slot. [Public inputs](spec/crypto/public-inputs.md#withdrawal-exemption)

The program builds each slot from the settlement accounts: the asset `hash_bytes(mint)` of each withdrawn mint in first-seen order and the gross sum of its withdrawal legs. Deposit legs do not enter the sum.

The program checks, in order:

1. The rail: `Transact` on `Confidential` or `ConfidentialEscrow` is confidential, on `Anonymous` anonymous.
2. The frame parses. `CURATOR` and `APPROVAL_REQUIRED` need `POLICY`. `DEFAULT_OWNER_TAG` and `FULL_OPENINGS` need the anonymous rail, `OWNER_IN_PROOF` the confidential rail (`FlagNotAllowed`). No disclosure field is zero (`ZeroDisclosureField`).
3. The settlement accounts cover the interface transfers (`InvalidSettlementAccounts`). At most 32 legs, none of zero amount (`TooManyPublicLegs`, `ZeroPublicLegAmount`). With a withdrawal exemption proof, the ring policy loads (`InvalidRingPolicy`), the own mirror serves its `own_revision`, the transfer withdraws at most 3 mints (`InvalidInstructionData`), and the proof verifies (`ProofVerificationFailed`).
4. Policy ring: a policy proof is present (`MissingPolicyProof`), the `CURATOR` flag matches the policy (`FlagNotAllowed`), a policy exists (`PolicyNotSet`), the own mirror serves `own_revision` and the curator mirror serves `curator_revision` ([RingPolicy](#ringpolicy)). Audit-only ring: no policy proof (`UnexpectedPolicyProof`).
5. No curator account follows, the curator root comes from the ring policy.
6. `ring_auth` sits at SPP index 4 and at no other SPP index (`MissingRingAuth`, `RingAuthOutOfSlot`). The payer at SPP index 0 signs (`MissingFundingSigner`).
7. Confidential: every owner signer signs (`MissingOwnerSigner`). On a policy ring there is at least one and all are one address (`OwnerSignerCount`). A demanded co-signer is no owner (`CoSignerIsOwner`). Under `OWNER_IN_PROOF` the owner signer run is empty (`OwnerSignerOnInProofRail`). SPP then authorizes every input by the owner whose signature its proof verifies, and the policy sender is that owner. A demanded co-signer is not that owner (`CoSignerIsOwner`). Anonymous: no SPP account but the payer signs (`InvalidAnonymousSigner`).
8. Every deposit leg's funder signs (`MissingFundingSigner`). On the anonymous rail check 7 makes every funder the payer.
9. The public legs fold to at most 3 assets, each with a nonzero net within u64 (`TooManyPublicAssets`, `ZeroNetPublicAmount`, `PublicAmountOverflow`).
10. Policy ring: each SOL withdrawal's owner is its recipient. Each SPL withdrawal's token account is a Token or Token-2022 account of the leg's mint owned by the declared owner (`InvalidSettlementAccounts`, `AnonymousExitTokenAccountInvalid`).
11. Anonymous: every withdrawal names one destination key (`AnonymousExitDestinationsDiffer`). A SOL destination is a system account with no data. An SPL destination is an off-curve token account with no delegate and no close authority (`AnonymousExitAccountHasData`, `AnonymousExitTokenAccountOnCurve`, `AnonymousExitTokenAccountShared`). The party identities are `solana_owner_identity` of the payer, the signing co-signer and the destination key, each `0` when absent. For an SPL withdrawal the destination key is the token account's owner.
12. The co-signer demand of [Properties](#properties) 9, with the withdrawal class waived when check 3 verified an exemption proof. An approval needs some record (`ApprovalWithoutCoSigner`). The record is the program's (`InvalidCoSignerRecord`) and covers every demanded class (`CoSignerOutOfScope`), and its signer signs (`MissingCoSigner`, `UnauthorizedCoSigner`).
13. The SPP `proof_b` decompresses (`InvalidSppProofPoint`).
14. The key escrow layout bit equals `mode == ConfidentialEscrow` (`FlagNotAllowed`).
15. It builds the audit statement and the policy statement, with the frame's recipients on the confidential and delegate rails and zeros on the anonymous rail, and resolves both keys (`UnsupportedCircuit`). Under `OWNER_IN_PROOF` each recipient is `solana_owner_identity` of the slot's owner tag, or `0` on a slot the dummies bitmap marks. It verifies the audit proof, then the policy proof, each point decompressed (`InvalidRingProofPoint`) and the pairing checked (`ProofVerificationFailed`).
16. It checks the SPP program (`InvalidShieldedPoolProgram`), the forwarded list size (`TooManyAccounts`), and invokes SPP.

The ring proofs do not check ownership, inclusion, conservation, nullifier uniqueness or expiry. SPP checks them in the same instruction. Exit payloads are not proven, as on any default-ring output, so a sender can publish a payload that does not open, and the recipient misses the exit. The auditor still opens the exit from the disclosure. No proof relates a published `u` to the output's owner, and no proof checks an anonymous tag or body, see [the limitation](#a-sender-can-make-a-note-unreadable-for-its-owner). The program does not check the Solana fee payer of the outer transaction against the hidden owner. The Rust SDK refuses a fee payer or signer equal to the hidden owner, and the TS SDK checks the payer and the co-signer.

#### 21. DelegateTransact

Tag `44`. Same as `Transact` on the SPP authority rail, signed by the delegate instead of an owner. It moves an escrowed member's notes to escrowed members of the same ring.

Rail row replaced: `Confidential` or `ConfidentialEscrow` with a delegate (`DelegateDisabled`) gives the delegate rail, `RING_AUTHORITY_TRANSACT` (21) with the `RingAuthority` circuit, shapes 2×2 and 4×4 only. An anonymous ring fails with `AnonymousRingRefused`.

Accounts: as `Transact`, with `delegate` (signer) after the co-signer slot and no owner signers. The SPP list is the `ring_authority_transact` list.

Audit key replaced: the 2×2 and 4×4 shapes take `DeliveredAudit { 2 | 4 }`.

Program checks replaced:

- Check 2: an exit fails with `FlagNotAllowed`.
- Check 4: `APPROVAL_REQUIRED` fails with `UnexpectedApproval`.
- Check 7: any interface transfer fails with `DelegatePublicLeg`. The delegate account signs and equals `config.delegate` (`UnauthorizedDelegate`). A demanded co-signer is not the delegate (`CoSignerIsDelegate`). The policy statement's sender is `0`.

Policy proof replaced: the `DelegatePolicy` key reopens the inputs. Input `0` is a UTXO and every UTXO input belongs to one source member. The rules apply with that member as sender, and every output needs its escrow record. It runs no outflow check and binds `approval_required = 0`, `key_escrow = 1` and no anonymous element.

The SPP authority circuit keeps every input and output in the ring, and no owner signature binds the output owners. The delegate moves a member's notes to any escrowed member the rules admit.

#### 22. Merge

Tag `20`. Forwards an SPP ring merge, which joins up to 24 notes of one owner and one asset into one note, with a disclosure proof to the auditor. On a `ConfidentialEscrow` ring the proof also opens the owner's escrow record.

**Accounts**

1. `config`.
2. `policy`: the ring policy, on a `ConfidentialEscrow` ring only.
3. `co_signer_record`, then `co_signer` (signer), only when demanded.
4. `spp_accounts`: the SPP `ring_merge_transact` list `[input_tree, output_tree, ring_config, payer, system_program, spp_program, nullifier PDAs…, merge cache…]`.

**Instruction data**

`own_revision: u64 LE`, `output_ring_data_hash: [32]`, then the disclosure as `proof`, `eph_pk [33]`, `ciphertext [32]`, `count u8` and `count` fields, then the SPP merge body with a compressed `proof_b`.

**Proof**

The merge proof checks:

1. Every input is a UTXO or a dummy, input `0` is a UTXO, and every UTXO has the owner, the asset and the ring id of the output and `data_hash = 0`.
2. The output amount is the 64-bit sum of the inputs, its blinding is `TMOB(nullifier_secret, n0)`, and its hash is the published output hash.
3. `private_tx_hash` reopens with the inputs and the output.
4. The envelope seals a disclosure key to the auditor under label `CRING/mrg1`. Each disclosure field is a chunk of the owner key, nullifier key, mint, amount, output blinding and input hashes, plus a pad from that key and the salt. [Disclosure](spec/crypto/disclosure.md#merge-disclosure)
5. The party identities are the payer and the co-signer, each different from the owner, and the third is `0`.
6. When `key_escrow = 1`, the owner's record opens under `member_registry_root` with `escrow_key = Poseidon(nullifier_pk, ct_hash)` for the nullifier key the inputs and the output spend under. `ct_hash` is the hash of the owner's `RegisterKey` ciphertext.

The program checks, in order:

1. The data parses, and the SPP merge body is a supported form (`InvalidInstructionData`).
2. On a `ConfidentialEscrow` ring the ring policy loads (`InvalidRingPolicy`), its own mirror serves `own_revision`, and the statement binds `key_escrow = 1` and that root. On another ring `own_revision = 0` (`UnexpectedMemberRegistryRoot`), and the statement binds `key_escrow = 0` and root `0`.
3. When a record covers `TRANSFERS`, a record covering it loads and its signer signs.
4. `ring_auth` sits at SPP index 2 and at no other index. The payer at SPP index 3 signs. The SPP `proof_b` decompresses (`InvalidSppProofPoint`).
5. The disclosure has the field count of the merge width (`MergeDisclosureWidth`), and its ephemeral key has tag `0x04` (`InvalidMergeDisclosure`). On an anonymous ring `output_ring_data_hash = 0` (`AnonymousRingDataNotZero`).

It verifies the proof under `Merge { 8 }` or `Merge { 24 }`. A merge of more than 24 inputs takes SPP width 52 and fails with `UnsupportedCircuit`.

No rule runs on a merge, because SPP keeps the owner, asset and value. The proof does not check that the merge output ciphertext opens. SPP publishes it unverified.

### Roots

Copy storage registry roots into the ring policy.

#### 23. SyncRoots

Tag `48`. Copies a storage registry's root history into the ring policy mirror of that registry. Anyone sends it, and it pays no lamports.

**Accounts**

1. `policy`: the ring policy. Writable.
2. `registry`: the records or the curator `StorageRegistry`.

**Instruction data**

Empty.

The program checks, in order:

1. The data is empty (`InvalidInstructionData`).
2. `registry` is owned by the Storage Program and decodes as a `StorageRegistry` (`InvalidStorageRegistry`).
3. The ring policy loads (`InvalidRingPolicy`).
4. `registry` is `records` or the curator the sources name (`UnmirroredRegistry`).

It writes `RootMirror { registry, roots }` over that mirror. The copy is the registry's state at the slot of the instruction, so a repeat in one slot writes the same copy and no sender can restore an older state.

## Storage program

The storage program keeps the root history of a record tree for one authority. It is one deployment at `STORAGE_PROGRAM_ID`, apart from the ring program. It verifies apply proofs and keeps no policy. A consumer reads a root through `StorageRegistry::root(revision, slot)`, the one rule for which root a revision names. `StorageError` holds codes `9000` to `9004`, and the write and proof checks fail with `CustomRingError` codes.

### StorageRegistry

One per creator and registry id at `[b"storage", creator, registry_id]`, 1581 bytes, discriminator `1`. `Initialize` creates it and nothing closes it. The creator is in the seeds, so no other signer can take its addresses. The loader checks the owner, the size, the discriminator and `1 <= next_index <= 2^20`, and does not derive the address again.

```rust
pub struct Root { pub hash: [u8; 32], pub revision: Revision, pub expires_at: [u8; 8] }   // 48 bytes

pub struct StorageRegistry {
    pub discriminator: u8,
    /// Written by `Initialize` and `UpdateAuthority`.
    pub authority: Address,
    pub grace_slots: [u8; 8],
    /// Leaf the next insert takes. Leaf `0` is the sentinel.
    pub next_index: [u8; 4],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; 32],
}
```

`root(revision, slot)` returns the hash of the nonzero root with that revision when it is the newest root, or when `slot < expires_at`. Else it fails with `RootExpired`.

### Storage instructions

| Instruction | Tag | Description | Access |
| --- | --- | --- | --- |
| `Initialize` | `0` | Creates the registry with the sentinel root at revision `0`. | Payer and creator sign |
| `Update` | `1` | Applies writes and retires the old root after the grace period. | Authority signs |
| `UpdateImmediate` | `2` | Applies writes and clears every earlier root. | Authority signs |
| `UpdateAuthority` | `4` | Hands the registry to a new authority. | Authority and new authority sign |

Tag `3` is retired. Every tag outside the table fails with `InvalidInstructionData`.

#### Initialize

**Accounts**

1. `payer`: signer, writable. Funds the account.
2. `creator`: signer. Becomes the authority.
3. `registry`: writable, at `[b"storage", creator, registry_id]` under the canonical bump.
4. `system_program`.

**Instruction data**

```rust
struct InitializeIxData {
    registry_id: [u8; 32],
    /// u64 little endian.
    grace_slots: [u8; 8],
}
```

Another system program fails with `IncorrectProgramId`, another address with `InvalidRegistry` and an occupied account with `AccountAlreadyInitialized`. The registry starts with `next_index = 1` and `roots[0] = { MEMBER_REGISTRY_EMPTY_ROOT, 0, 0 }`.

#### Update and UpdateImmediate

**Accounts**

1. `authority`: signer.
2. `registry`: writable.

**Instruction data**

`revision: u64` little endian, `count: u8`, then `count` × `StorageWriteData` of 113 bytes each, then `ApplyRecordsIxData`.

```rust
struct StorageWriteData {
    member: [u8; 32],
    /// u64 little endian each. All zero when the write changes no list.
    lists: { mask: [u8; 8], value: [u8; 8] },
    /// As in `RecordWriteData`.
    mint_policy: [u8; 33],
    /// Nonzero only on an escrow write.
    escrow_key: [u8; 32],
}
```

`count = 0` fails with `InvalidInstructionData` and `count > 16` with `AuthorityBatchTooLarge`. A write with a zero `escrow_key` is checked as an `AuthorityWriteRecords` write, with every list except the escrow list writable. A write with a nonzero `escrow_key` is an escrow write, `QueueEntry::escrow_hash(member, escrow_key)`, and fails with `InvalidInstructionData` when it also carries lists or mint settings. The program does not check an escrow key. The authority checks it before it writes. An escrow key fills once and no write removes it.

A signer other than the authority fails with `Unauthorized`, and a `revision` other than the newest root's with `RevisionChanged`. The chain starts at `HashChain4([APPLY_RECORDS, hash_bytes(registry), revision])` and folds each entry with `queue_chain` in order. The program verifies one apply proof as `ApplyRecords` does, over `(roots[0].hash, next_index, chain_start)` to `(new_root, new_next_index, chain_end)` and `count`.

`Update` fails with `HistoryFull` while the oldest root has not expired. It sets the outgoing root's `expires_at = slot + grace_slots`, saturating, and shifts the history by one. `UpdateImmediate` clears every root. Both then write `roots[0] = { new_root, revision + 1, 0 }` and `next_index = new_next_index`. The revision does not wrap.

#### UpdateAuthority

**Accounts**

1. `authority`: signer.
2. `new_authority`: signer.
3. `registry`: writable.

**Instruction data**

Empty.

A signer other than the authority fails with `Unauthorized`. The new authority signs, so a mistyped key cannot take the registry out of reach.

## Services

A ring runs with three services next to Photon. None holds an authority key. Each answer a client acts on is checked against chain state, except where this section says otherwise.

### Ring indexer

Projects the member registry, record queue and records of every ring from confirmed Solana blocks. It serves seven JSON-RPC methods and forwards every other call, and every batch, to Photon unchanged.

- It decodes `CreateMemberRegistry`, `WriteRecords`, `RegisterKey`, `AuthorityWriteRecords` and `ApplyRecords` of successful transactions. A ring counts once SPP holds an activated `RingConfig` for it.
- It applies the program's own admission rules and replays every application. A projected root or next index that differs from the instruction's quarantines the ring, and a quarantined ring answers every read with `-32070` until the block rolls back.
- It links every block to its parent by slot and blockhash and rolls back on a reorg within its journal.
- Before it answers, it reads the registry and queue accounts at its tip and requires the root it serves to be in the chain history at its index.

| Method | Serves |
|---|---|
| `getRingMemberRecord` | One member's opening under a named root. |
| `getRingMemberOpenings` | Up to 100 openings under one root, absent members as their low record. |
| `getRingRecordPool` | The distinct records of up to 100 members under one root, with paths below a canopy sized for the requested openings, and each member's record index. |
| `getRingMemberRecords` | A page of up to 100 records with paths. |
| `getRingMemberRegistryRoot` | The 32-root history, floors and the append path. |
| `getRingRecordQueue` | The pending writes from `head` to `tail`. |
| `getRingApplyProofInputs` | The witness of the next application, with optional authority writes. |

Errors: `-32070` out of sync, `-32071` root changed, `-32075` page gap, `-32076` queue changed.

A client reads the root from the chain `MemberRegistry` and checks every opening against it, so a faulty indexer can refuse or delay but not make a client accept a wrong record. The indexer serves `ephPk` of a registered key, and no tree field binds it. The program binds `eph_u` only in the register key proof. The indexer binds all interfaces with permissive CORS and no authentication, so exposure control is the deployment's.

### Ring RPC

Holds the auditor key and serves audited history to readers.

- It runs with one local key for one ring, or derives a key per ring from a root secret with HKDF-SHA256 over the cluster genesis hash and the ring program address. It binds to loopback unless told otherwise.
- `createAuditorKey` releases the auditor public key to the ring's config authority, or before the config to the upgrade authority, with an Ed25519 signature of the service key over the cluster, ring, key and the request nonce. The program does not check this signature. The operator CLI checks it against the pinned service key, or accepts any key under `--trust-ring-rpc` when none is pinned.
- `getDecryptedTransactions`, `getAuditedMerges` and `getAuditedUtxos` serve a reader that signs a request with its Ed25519 key or a WebAuthn P-256 passkey, within 60 seconds of the service clock, with a fresh nonce. The service requires the ring config to name its key and the reader to hold a grant.
- A ring-wide grant is the `reader` list on the reader's own record in the ring's storage tree, keyed by the owner identity of an Ed25519 reader or the `hash_bytes` of a passkey's tagged key. A wallet grant is the `reader` list on the record `Poseidon(CRWG, wallet identity, reader identity)`. The service opens the reader's record, and the wallet grant record when a read names a wallet, through the indexer and checks each against the newest own root the ring policy mirrors. A revocation applies at the next synced root.
- A read that names a wallet serves only the rows where that wallet is the sender, a signer or an output owner, the merges and notes it owns, and no skipped rows. A ring-wide grant covers every wallet, a wallet grant only its own.
- With its optional database the service also stores wallet grants. `setReaderGrant` takes the wallet's Ed25519 signature over the ring, reader and action, with the timestamp and nonce rules of a read. A row is sealed with AES-256-GCM under a key HKDF-SHA256 derives from the service key source, and it keeps in plaintext only its insert order and a keyed hash of the reader key. The newest signed row for a wallet and reader holds.
- `ringDeposits`, `ringStatus` and `health` need no signature.
- With a fee payer key, a store and a ring prover it relays transfers. The wallet seals the transfer and sends its proof inputs with the nullifier secret, the transaction viewing secret and the audit ephemeral secret. The service reads the record openings and SPP Merkle paths, proves every statement and pays the fees. On the anonymous and confidential rails it verifies the owner's Ed25519 signature over `SppProofInputs::message_hash` before it proves. On the anonymous rail that signature is the prepared owner authorization of the SPP proof, and the service sends at once. On the confidential and delegate rails it returns the v1 message and sends once each owner or the delegate has signed it. It does not relay deposits or merges.
- A relay is stored by its `relayId` with its message and signatures, never its proof inputs. A repeated request returns the stored relay. The co-signer signs before the send and settles when the relay confirms or fails. A relay that has not landed when its blockhash expires fails.
- A `LimitedCoSigner` signs a transaction only under the [co-signer limits](#co-signer-limits).
- `setMergeSettings` stores a wallet's target note count and minimum average amount for one mint. The wallet signs them under `zolana/ring-rpc-merge-settings/v1` with the cluster, service key, ring, timestamp and nonce, and the service verifies the signature under the named owner. A later signed request replaces them, and a zero target revokes them.
- On a `ConfidentialEscrow` ring a host that runs the service with a relay merges a wallet's notes toward its settings. It opens the wallet's escrowed nullifier secret with the auditor key, proves one merge of the smallest notes and sends it through the relay. The merge carries no owner signature.
- Every audited row is bound to the confirmed SPP event the service rebuilds from Solana `getTransaction`. Photon is trusted for completeness only. A row Photon omits, or labels with no ring, never reaches a reader, and no client detects the gap.

A reader receives each output's owner key, nullifier key, asset, amount and blinding, the recipient `u` on the delivered rails, and on the anonymous rail the view tag, the hidden sender and every input's opening. It receives no nullifier secret. Pages carry no signature, so a faulty service can serve a false opening to a reader that does not rebuild the commitment. `getAuditedUtxos` answers are checked by both SDKs against their requested hashes. Nonces and rate windows live in memory, so one key runs in one process.

#### Co-signer limits

Each asset's record in the ring's own storage registry holds `AssetLimits`, six u64 values. Ring RPC reads them under the registry's newest root before it co-signs, and checks every opening against that root. A ring without a `RingPolicy` account has no limits. A zero cap is no cap.

| Limit | Bounds, per asset |
|---|---|
| `sender_cap` over `sender_window_slots` | What one sender transfers and withdraws |
| `volume_cap` over `volume_window_slots` | What the ring transfers, deposits and withdraws |
| `deposit_cap` over `volume_window_slots` | What the ring deposits |
| `withdrawal_cap` over `volume_window_slots` | What the ring withdraws |

A window counts every reservation less than its length in slots before the current slot. A zero window counts the checked transaction alone. A co-signature reserves the transaction's flows under its own signature, in the database transaction that read the window. `settle` with a confirmation keeps the reservation, and a failure, an expiry included, deletes it unless it was confirmed. A transaction never settled counts until its window passes. The same message signed again returns the same signature and reserves nothing more. The co-signer key derives from the auditor key or the root secret with HKDF-SHA256 under `zolana/ring-rpc-co-signer/v1`.

### Record updates

A record update is a signed list of entries for one ring and one `StorageRegistry`. The signer sends it to Ring RPC `submitRecordUpdate`, and the writer applies it.

```rust
/// The signer signs these 32 bytes with Ed25519, and the hash is the update id.
fn record_update_hash(ring: Address, registry: Address, entries: &[Entry], valid_until_slot: u64) -> Field {
    Poseidon(CRRU, hash_bytes(ring), hash_bytes(registry),
        entries.fold(0, |chain, entry| Poseidon(chain, entry_hash(entry))),
        right_align(valid_until_slot))
}
```

| Entry | Signer | Write |
|---|---|---|
| `write` | Owner, own record | The ring-viewing and recovery lists. |
| `write` | Config authority | Authority lists and mint settings of any record. |
| `escrow` | Owner, own record | The escrow key, with the register key proof the writer verifies. |
| `walletGrant` | The wallet | The reader list of the record `Poseidon(CRWG, wallet, reader)`. |

Each entry becomes the queue entry the apply proof hashes, so the signature binds every write that reaches the tree. A wallet grant names the wallet and the reader identity, so the writer can rebuild the record key and compare the wallet with the signer. The writer refuses an update after `validUntilSlot`, an update with an invalid signature, and an entry the signer does not hold. Both SDKs verify the signature before they send an update, and they refuse a service that answers another update id. `getRecordUpdateStatus` reports `queued`, `submitted`, `applied` with the new registry revision, or `refused` with a reason.

The hash binds no cluster. A registry address that exists on two clusters accepts the same update on both until `validUntilSlot`.

### Relayed transfers

A wallet sends an anonymous transfer, or a confidential one under `OWNER_IN_PROOF`, through the Ring RPC relay and reads no Merkle path and no record. The operator CLI and the tests keep the direct path, which proves and sends from the caller.

1. `getRelayQuote` names the fee payer, and the wallet builds the transfer with it as the payer.
2. The wallet stages the transfer from its own notes and keys, seals the auditor message into the external data and signs `SppProofInputs::message_hash` with the owner's Ed25519 key. It reads the ring config, the SPP ring registration, the tree accounts and the exit accounts only.
3. `prepareRelay` carries the sealed transfer as `proofInputs` and the signature as `ownerSignature`. The wallet hashes the request to its own `relayId` and refuses an answer that names another one.
4. On the anonymous rail and under `OWNER_IN_PROOF` the owner signs inside the SPP proof, and the wallet accepts only `submitted`. It refuses `signMessage`. On another rail it signs a `signMessage` step only when the message is a canonical v1 message that lists the signer among its signers.
5. `getRelayStatus` follows the relay to `confirmed` or `failed`.

`proofInputs` hands Ring RPC the nullifier secret, the transaction viewing secret and the auditor ephemeral secret. Ring RPC can link every spend of the owner and open every output of the transfer, so a relayed transfer stays anonymous only toward a Ring RPC trusted as the indexer of [condition 5](#anonymity-breaks-when-its-conditions-fail) and the prover of condition 6.

### Ring prover

The zolana prover with the 86 ring circuits registered as extensions. It proves every ring statement from a complete client witness and fetches no record itself. It sees every secret of the witness: the transaction viewing secret, every opening, owner keys, recipient keys and the hidden owner's key. The zolana client attests a remote prover's TEE by default.

The SPP half of a transfer can use zolana's indexed route, where the prover reads Merkle and non-inclusion proofs from the indexer its operator configures. The client checks the resolved trees, roots and public input hash, and the program verifies the proof.

## Keys and releases

The ring circuits have 86 Groth16 keys, each with one public input and one BSB22 commitment over private wires:

| Family | Keys |
|---|---|
| `DeliveredAudit` | outputs 2, 4, 8, 16 |
| `AnonymousAudit` | class 4 and 16 at outputs 2 and 4, class 4 and 8 at outputs 8 |
| `AnonymousEntryAudit` | class 8, outputs 2, 4, 8 |
| `MemberPolicy` | outputs {2, 4, 8, 16} × withdrawals {0, 1, 2, 4, 8, 16, 32} × {own, curator} |
| `DelegatePolicy` | 2×2, 4×4 × {own, curator} |
| `ApplyRecords` | writes 1, 2, 4, 8, 16 |
| `RegisterKey` | one |
| `WithdrawalExemption` | one |
| `Deposit` | capacity 1, 2, 4, 8 |
| `Merge` | width 8, 24 |

The proving key lock pins each proving key's name, SHA-256 and size and the release that serves it. Each verifying key the program compiles carries its proving key's SHA-256, and the lock, the verifying keys and the program change together. The program binary carries a setup marker per key. The operator CLI refuses to deploy a binary whose markers do not cover every key it pins, or that carries an insecure test setup marker. Both SDKs pin the key name and SHA-256 of every ring proof request. The Rust SDK also verifies each ring proof against the committed verifying key before it submits it.

The setup is single party: the key generation runs gnark `Setup` once and keeps no randomness. A ring trusts its key generator as it trusts its upgrade authority.

A release publishes the ring program, the proving keys and the Ring RPC binaries. The CLI deploys from the release lock it embeds, and checks each artifact by size and SHA-256. A release image carries a tag derived from its commit on `main`, and no publish overwrites an existing tag.

## Limitations

### The upgrade authority can move every note

The ring program's checks are all the protection a ring note has. An upgrade can replace them and sign any SPP move of any ring note. Owners trust the upgrade authority with custody until it renounces the upgrade.

### A forged proof key breaks every guarantee

The proving keys come from a single-party setup. A key generator that kept its randomness can forge audit, policy, apply and deposit proofs, which hides transfers from the auditor and passes any rule. SPP's own proof still keeps conservation and ownership.

### A paused ring freezes its notes

A pause, or an SPP ring that governance has not activated, stops every SPP rail of the ring. No owner can transfer, exit or withdraw until the config authority resumes the ring. Ring-local instructions still run.

### Confidential rings name their parties

On a confidential ring the sender signs the transaction, and each ring output publishes the recipient's viewing key `u`. The zolana user registry maps a registered `u` to its owner's Solana key, so every payment names its sender and recipient. On a policy ring each live output also publishes its owner identity, which anyone can test against a candidate key. Amounts, assets, blindings, nullifier keys and the spent notes stay private.

### Anonymity breaks when its conditions fail

An anonymous transfer hides the sender and the recipient only when all of these hold:

1. The payer and the Solana fee payer are a relayer or another key that does not link to the hidden owner. Only the SPP payer is checked on chain.
2. The transfer spends ring notes only. A default-ring note publishes the owner.
3. No exit or withdrawal pays a key linked to the owner. SPP and the audit proof refuse only the hidden key itself.
4. A first payment takes a request tag. A bootstrap payment publishes the recipient's viewing key, see [the limitation](#a-bootstrap-payment-names-its-recipients-viewing-key).
5. The wallet runs its own indexer, or trusts its indexer with the leaf and nullifier pairing and with the grouping of each stream's tags in one request.
6. The prover runs locally or under an attested TEE.
7. The rules admit many owners. An allow rule bounds every sender and recipient to the public allow list.
8. Deposit and withdrawal amounts and timing do not single out a later spend.

### Repeated view tags link outputs

Each view tag derives from a counter of the sender's viewing history. No layer refuses a tag an earlier output used, and equal tags link both outputs for every observer. A wallet repeats a tag when it pays from a history that missed its own earlier transfers, as a second device or a restore before its first sync does. Two senders that pay one payment request publish its request tag twice.

### A bootstrap payment names its recipient's viewing key

The bootstrap tag is the recipient's `u`. Every observer reads the recipient's viewing key from the output and links it to every other output under that key, the recipient's confidential ring outputs and deposits included. A request tag derives from the recipient's viewing secret, so an observer cannot link it to the recipient.

### The sender key in a body is unauthenticated

A recipient body names `sender_pubkey`, and no proof checks it, so a body can attribute a payment to any viewing key. A recipient that opens a body adds the named key to its known senders and reads its shared tags on every later sync. A payer that names fresh keys adds `TAG_GAP` tags per key to every later sync, and the known senders have no limit, so a real sender is still learned.

### Member writes name members

`WriteRecords` publishes the owner's Solana key on every ring, the anonymous ones included. `RegisterKey` publishes the owner's Solana key beside its nullifier key. Authority writes publish member identities, which anyone can test against a candidate key.

### Outflow limits bound one transfer

An outflow limit applies per transfer, per mint and per signing key. It keeps no counter and no window. Only the [co-signer limits](#co-signer-limits) count across transactions, and only on transactions that demand the co-signer. The real-world controls map as follows:

| Control | Enforced |
|---|---|
| Cap per transfer and mint | Yes, `outflow <= cap`. |
| Dual control above an amount per transfer | Yes, the co-signer signs when `outflow > cosign_above`, and the transfer publishes the approval bit. |
| Cap per customer per day | Only on co-signed transactions, by `sender_cap` over `sender_window_slots`. A transfer that demands no co-signer passes alone. |
| Cap per person across keys | No. Each signing key is its own sender. |
| Deposit and withdrawal volume per window | Only on co-signed transactions, by `deposit_cap` and `withdrawal_cap` over `volume_window_slots`. Ring RPC counts them, no proof does. |

A deposit leg in the same transfer lowers the outflow of its mint, and its funder is not screened. A deposit leg above what the transfer pays away in a limited mint fails the proof, so a sender deposits to itself with `AuditedDeposit`. An exit counts as outflow, also to the sender. A mint whose record holds a zero `cap` and a zero `cosign_above` is unbounded. The delegate rail runs no outflow check.

### Guards and block lists bind one transfer and one key

An `AboveAmount` or `AboveAmountByAsset` guard sums the payments of one transfer. A payment split across transfers passes a guard each part stays under. A block list refuses known members only, so a fresh signing key passes it. Only an allow list bounds the senders and recipients to known members.

### Deposits screen assets only and merges screen nothing

Only the asset rules run on `AuditedDeposit`, and no rule runs on `Merge`. No outflow limit runs on either. A deposit can credit any owner, registered or not. On a `ConfidentialEscrow` ring a deposit and a merge require an escrowed owner. An active asset rule over a curator list refuses every deposit, the deposit proof opens no curator root. The rules screen an owner when it sends and every output owner it pays.

### List rules publish what they screen

The rule table and the member registry are public. An observer reads which lists a ring screens, every member on them and every mint setting. The approval bit tells that some mint's outflow passed its `cosign_above`.

### A sender can make a note unreadable for its owner

On the delivered rails no proof relates a recipient key `u` to the owner of its output. The audit proof shows only that the body opens for the holder of the published `u`. The anonymous audit proof derives no view tag and opens no body. It proves each output's owner key, asset and amount in the disclosure, the blinding the auditor rebuilds, and the spent notes. A wrong tag or a body sealed to the wrong key costs the recipient the note, as a payment to a wrong address does, gains the sender nothing, and the auditor still opens the output.

### A curator controls its subscribers

A ring trusts its curator's roots fully. The program checks only that the curator is a storage registry other than the records. A curator update reaches a subscriber at the next `SyncRoots` of its curator mirror, and until then a root the curator dropped stays valid there.

### Public legs that net to zero fail

The program folds every transfer's public legs per asset and refuses a net of zero with `ZeroNetPublicAmount`. A transfer that deposits and withdraws the same amount of one asset fails, on every tier. The sender splits the legs into two transfers.

### Escrow and delegate are permanent

A registered nullifier key cannot change. A delegate and the `ConfidentialEscrow` mode cannot be removed by any instruction of the deployed binary. Only a program upgrade by the upgrade authority changes them.

### Rings of another layout need a migration

The program, the SDKs, the ring indexer and the proving keys accept only the 120-byte config, the 2388-byte registry, the eight-field record leaf, the nine-field queue entry and policy table version 12. A ring whose accounts or record tree use another layout fails these checks, and its records do not open under these circuits. Its operator migrates the accounts and the record tree before the program upgrade. No ring instruction performs that migration, and a reindex of the ring's instructions does not rebuild its on-chain roots.

### The auditor reads everything

The auditor key opens every note, every anonymous sender and every escrowed nullifier secret. Ring RPC serves every opening to every ring-wide reader, and a grant has no expiry. A leaked auditor key exposes the ring's whole history, and on a `ConfidentialEscrow` ring it also lets its holder compute every escrowed member's nullifiers.
