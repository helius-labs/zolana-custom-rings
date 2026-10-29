# Custom rings

A custom ring is a Solana program that governs its notes in the zolana shielded pool (SPP). SPP moves a ring note only under the ring program's `ring_auth` signature. The ring program signs after it verifies an audit proof of the move. On a policy ring it also verifies a policy proof over the rule table and the member registry. Owners fund the ring by audited deposits and pay each other inside it. They leave it by an exit to the default ring or by a public withdrawal, while SPP has the ring activated and not paused. Owners keep their spending keys and sign every transfer, except a delegate move on a `ConfidentialEscrow` ring. The upgrade authority deploys and creates the ring, and an upgrade can replace every check. The config authority sets the policy, the lists and the controls. The auditor reads every transfer. An optional co-signer approves the operations its scope or an outflow limit names. A `Confidential` or `ConfidentialEscrow` ring is confidential. Amounts, assets and blindings are private, but the sender and the recipient's viewing key are public. An `Anonymous` ring also hides the sender and the recipient from chain observers. That holds only under the conditions of [Anonymity breaks when its conditions fail](#anonymity-breaks-when-its-conditions-fail). The first three are that the payer does not link to the sender, the transfer spends no default-ring note, and no exit or withdrawal pays a key linked to the sender.

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
| Record | Tree leaf | `Poseidon(member, next, lists, escrow_key, mint_policy, withdrawal_threshold)`. One per member, sorted by member through `next`. |
| Mint settings | Record fields | `threshold`, `cap`, `cosign_above` and `withdrawal_threshold`, each a u64, in the record of an asset member. Only the config authority writes them. [Mint settings](#mint-settings) gives the effect of each value, zero included. |
| Member registry | Account and tree | The `MemberRegistry` account holds the last 32 roots of the record tree, the floor and the policy. Record contents live in instruction data and the ring indexer. |
| Own root, curator root | Root | A root of the ring's own member registry, or of its curator's, named by its history index. |
| Record queue | Account | The `RecordQueue` account holds pending record writes as a hash chain. An apply proof moves them into the tree. |
| Floor | Queue position | The queue tail after the last authority write. An own root below it is refused. |
| Policy | Rule table, source map and hash | Stored in the member registry. The policy proof binds `policy_hash`. |
| Rule | Table row | A list condition on one subject: the sender, every output owner, or every output asset. A guard exempts amounts at or below a threshold. |
| Outflow limit | Mint settings | The `cap` and `cosign_above` of an asset's record. Bounds the outflow of that asset in one transfer and names when the co-signer must sign. |
| Curator | Program | Another program whose member registry a ring reads for its foreign lists. A ring has at most one. |
| Transaction viewing key | X25519 key pair | `tx_viewing_sk` and `tx_viewing_pk = 0x04 \|\| tx_viewing_u`, drawn by the sender per transfer. The secret seeds every output blinding and the disclosure pad. |
| Viewing key `u` | X25519 key | A recipient's 32-byte X25519 public key, the `u` of its zolana viewing key. Its secret opens the notes sent to it. |
| Owner tag | 32 bytes | The tag SPP publishes with each output. A recipient finds its notes by it. A confidential ring output carries the recipient's `u`, an anonymous one a view tag, and an exit its owner's Solana key. |
| Auditor message | SPP message | The one message the program builds per transfer, `0x04 \|\| eph_u \|\| sealed \|\| disclosure`. Its view tag is the auditor's `u`, by which the auditor finds every transfer. `sealed` is `tx_viewing_sk` sealed to the auditor from the ephemeral key `eph_u`. |
| Disclosure | Field list | The openings of the outputs, each field masked by a pad. On the anonymous rail it also names each spent note by hash or prefix, or opens it. |
| Audit proof | Groth16 proof | Proves the auditor message opens every output of the transfer. Verified on every transfer, under the key of its rail and shape. On the anonymous rail a commitment key (`AnonymousAudit`) serves a spend of ring notes and an entry key (`AnonymousEntryAudit`) serves an entry spend. |
| Policy proof | Groth16 proof | Proves the rules and the outflow limits over record openings. Verified on every transfer of a policy ring. |
| Withdrawal exemption proof | Groth16 proof | Proves that the gross withdrawal of each withdrawn mint is at or below the `withdrawal_threshold` of the mint's record under an own root. A transfer on any ring with a member registry can carry one. It waives only the withdrawal class of the co-signer. |
| Nullifier secret | Field element | An owner's 31-byte secret, with public key `nullifier_pk = Poseidon(secret)`. A note's nullifier needs the secret, so its holder can link the owner's spends. |
| Key escrow | Record field | A record's nullifier secret sealed to the auditor by `RegisterKey`. A `ConfidentialEscrow` ring requires it of every output owner. |
| Ring address | Payment address | The recipient's shielded address and the ring program id, shared off chain. A `zolana:` payment request adds a request view tag. |
| View tag | 32 bytes | The owner tag of an anonymous ring output, a zolana [view tag](../zolana/docs/spec.md#view-tags) or a random tag on a dummy. No proof derives it. |
| First payment | Ring output | A payment to a recipient the sender holds no shared tags with. It takes the recipient's request tag or bootstrap tag, as the caller chooses. |
| Upgrade authority | Key | The Loader v3 upgrade authority of the ring program. Signs `CreateConfig` and `SetDelegate`. |
| Config authority | Key | `RingProgramConfig.authority`. Sets the policy, authority lists, mint settings, readers, co-signer, insert fee and pause. Receives the insert fee. |
| Owner | Wallet (client) | Holds ring notes and their spending keys. Writes its member lists and registers its nullifier key. The sender of a transfer is its owner. |
| Payer | Key | SPP account `0`. Pays rent and fees. On the anonymous rail it is the only SPP signer. A relayer can be the payer. |
| Funder | Key | Signs a deposit leg or an `AuditedDeposit` and pays its tokens. |
| Co-signer | Key | One key in the config, with a scope. Signs every operation its scope or an approval demands. Its withdrawal thresholds are the `withdrawal_threshold` mint settings. |
| Party identities | Field elements | `solana_owner_identity` of the payer, the configured co-signer and the withdrawal destination, each `0` when absent. The anonymous audit proof shows each nonzero one differs from the hidden owner. |
| Insert fee | Lamports | What a member write or key registration pays the config authority. The authority's own writes pay nothing. |
| Delegate | Key | Set once on a policy ring, which turns the ring to `ConfidentialEscrow`. Moves escrowed members' notes inside the ring. |
| Auditor | Key holder | Holds the X25519 auditor key in Ring RPC or a local file. Opens every transfer, deposit, merge and escrowed key. |
| Reader | Ed25519 or P-256 key | Holds a read access record. Reads audited history from Ring RPC. |
| SPP governance | Key | The SPP ring creation authority. Activates rings and enables the authority rail. |
| Ring indexer | Server | Projects every member registry from Solana blocks and serves record openings. Forwards every other call to Photon. |
| Ring prover | Server | The zolana prover with the ring circuits registered as extensions. Proves from a full client witness. |
| Ring RPC | Server | Holds the auditor key. Serves audited transfers, merges and notes to readers. |
| Photon | Server | The zolana SPP indexer. Serves notes, tags, nullifiers and Merkle proofs. |
| SPP | Solana program | The zolana shielded pool. Holds every note, verifies the SPP proof, and moves a ring note only under a `ring_auth` signature. |

## Ring lifecycle

1. **Deploy.** The upgrade authority deploys the ring program with Loader v3. The binary carries the verifying keys of its [proving key lock](#keys-and-releases). No ring account exists.
2. **Create.** The upgrade authority signs `CreateConfig` with the auditor key and the ring kind. The config authority signs `CreateMemberRegistry`, then `CreatePolicy` on a policy ring, then `InitSppRingConfig`, which creates the SPP `RingConfig` at `ring_auth`. SPP activates the ring at creation when its protocol config allows it. Else SPP governance activates it later. No note moves until the ring is activated.
3. **Enrol.** An owner writes its own member lists with `WriteRecords`. On a confidential ring it also seals its nullifier secret to the auditor with `RegisterKey`, which an anonymous ring refuses. Both pay the insert fee and wait in the record queue. Anyone applies the queue with `ApplyRecords` when 8 writes wait or the oldest is 150 slots old, at most once per 150 slots. The config authority writes authority lists and mint settings with `AuthorityWriteRecords`, which applies at once and raises the floor.
4. **Deposit.** A funder signs `AuditedDeposit` for up to 8 new ring notes. The deposit proof seals each note's opening to the auditor. On a `ConfidentialEscrow` ring it also proves each owner's escrow record. No list rule runs.
5. **Transfer.** The sender proves the SPP proof, the audit proof and on a policy ring the policy proof, and submits `Transact`. The program rebuilds both ring statements, verifies the proofs and invokes SPP as `ring_auth`. On a confidential ring the owner signs the transaction. On an anonymous ring the hidden owner signs inside the SPP proof and only the payer signs the transaction.
6. **Leave.** A transfer pays an exit or withdraws a public leg. The rules screen exit owners and withdrawal owners as output owners. A delegate move can do neither.
7. **Merge.** On an anonymous ring an owner merges up to 24 notes of one asset into one note with `Merge`, with a disclosure proof to the auditor. The merge proves the owner's nullifier secret and carries no owner signature. A merge on a confidential ring fails.
8. **Delegate.** The upgrade authority and the delegate sign `SetDelegate` on a confidential policy ring, which sets the mode to `ConfidentialEscrow`. SPP governance enables the ring's authority rail. The auditor opens an escrowed member's nullifier secret for the delegate, and the delegate moves that member's notes to escrowed members with `DelegateTransact`.
9. **Audit.** The auditor opens every transfer, deposit and merge from its auditor message. The config authority grants readers with `GrantReadAccess`, and Ring RPC serves them the openings. A revoked reader keeps what it already read.
10. **Govern.** The config authority repins the policy, writes mint settings, sets the co-signer, the insert fee and the pause, and hands the config to a new authority. A repin refuses every proof over the old table. A floor raise refuses every proof under an older own root, and the sender proves again. A repin and a mint-setting write are separate instructions, so a transfer between them proves under the new table and the old settings.

### Properties

**Functional**

1. A ring note moves only in a transaction the ring program signs. SPP requires the `ring_auth` signer of the ring's `RingConfig` and binds `ring_program_id` in its proof. No other program or key spends a ring note.
2. The program builds the SPP instruction data and both ring statements from the one frame. The SPP proof and the audit proof therefore bind the same first nullifier, outputs, transaction viewing key, salt and auditor message. The policy proof binds the same `private_tx_hash` and public legs as the SPP proof.
3. The program reads every statement value it can from chain state, so the prover chooses none of them beyond the root indexes:
   - the ring id from the executing program id and the auditor key from the config
   - the roots from the member registries and the SPP trees
   - the party identities from the accounts
   - the public legs, the withdrawal owners and the gross withdrawal per mint from the settlement accounts
4. Every transfer verifies an audit proof. The proof seals `tx_viewing_sk` to the auditor. It forces the blinding of each live output in slot `i` to `TXOB(n0, TXOS(n0, CRBS(tx_viewing_sk, salt)), i)` ([Blinding derivations](spec/crypto/hashing.md#blinding-derivations)), so the auditor opens every output of every transfer. On the delivered rails it proves that every ring output's body encrypts the output's blinding and amount to the key its slot publishes. On the anonymous rail the disclosure opens every ring output's owner key and every live output's asset and amount. No output carries data.
5. Every deposit verifies a deposit proof that seals each new note's opening to the auditor. The plain SPP ring deposit tag is refused.
6. On a policy ring every transfer verifies a policy proof under the stored `policy_hash`. Each active rule holds for each subject. The subjects are the sender, every live output owner and asset, and every withdrawal owner and asset. A rule holds when the subject is on one of its present lists or off one of its absent lists. A refused subject passes only when the rule's guard exempts its amount. Rules join with AND.
7. Record openings fold to roots the program reads from the registries. An authority write raises the floor, so the next transfer proves under the new lists. A curator's authority write reaches its subscribers within `GRACE_SLOTS`.
8. On a policy ring the policy proof opens the own record of each live output's asset and of each nonzero public asset, absent assets included. For each such asset with a nonzero `cap` or `cosign_above`, `outflow = others - net`, and the co-signer signs above `cosign_above`:
   - `others` sums the asset over live outputs, except ring outputs to the sender's own identity. An exit counts, also to the sender.
   - `net` is the asset's signed public net, a deposit positive and a withdrawal negative.
   - The proof requires `net <= others`, and `outflow <= cap` when `cap != 0`.
   - The proof sets `approval_required` exactly when some asset has `cosign_above != 0` and `outflow > cosign_above`. The program then demands the co-signer.
9. The co-signer must sign:
   - every transfer, delegate move and merge, when its scope holds `TRANSFERS`
   - every transfer with a deposit leg and every audited deposit, when its scope holds `DEPOSITS`
   - every transfer with a withdrawal leg, when its scope holds `WITHDRAWALS`, unless the transfer carries a valid withdrawal exemption proof. The proof shows each withdrawn mint's gross withdrawal at or below the mint's `withdrawal_threshold`. A zero or absent threshold exempts no withdrawal, and a deposit leg does not lower the gross amount.
   - every transfer with `approval_required`, whatever its scope

   A demanded co-signer differs from every owner signer and from the delegate.
10. Owners keep their spending keys. On the confidential rail every owner signer signs, and a policy transfer has exactly one owner. On the anonymous rail the hidden owner's signature is inside the SPP proof. A merge proves the owner's nullifier secret. The delegate rail runs only in `ConfidentialEscrow` mode, keeps every note in the ring, and takes no public leg or exit.
11. In `ConfidentialEscrow` mode the policy proof requires each live output's owner record to hold `escrow_key = Poseidon(nullifier_pk, hash_bytes(ciphertext))` for the output's nullifier key. A deposit proves the same. The auditor therefore opens the nullifier secret of every note's owner.
12. An owner writes only its own record and only its member lists. Member writes and key registrations keep a record's mint settings. An owner's writes apply after `APPLY_DELAY_SLOTS` or a full member queue, through a proof any party submits. The apply proof binds the old root, the next index and both queue chain ends the program holds, so no submitter changes a queued write.
13. The program validates the rule table at every policy write. It requires canonical rows, authority-written lists only, a source for every referenced list and at most one curator. The policy circuit relies on that validation and checks the row encoding only.

**Privacy**

On every transfer, chain observers see:

- the shape, the published input and output counts, the nullifiers and their trees, and the output hashes
- `tx_viewing_pk`, the salt, `eph_u`, the sealed key, the masked disclosure and the auditor view tag
- the exits bitmap, each output's owner tag and body, and `private_tx_hash`
- the layout flags, the expiry, the approval bit, the root indexes and the SPP proof
- on the anonymous rail, the BSB22 commitment of the SPP proof and its proof of knowledge
- the payer and each public leg, with its account, mint and amount

On a `Confidential` or `ConfidentialEscrow` ring (confidential rail):

14. Public: the owner signer, the co-signer when it signs, each ring output's owner tag `u` (the recipient's viewing key), each exit owner, and each SPL withdrawal owner.
15. Private from chain observers: the amount, asset, blinding and nullifier key of each output, the exit asset and amount, and which notes the nullifiers spend.
16. Every payment to one recipient carries the same `u`. The zolana user registry maps a registered `u` to its owner's Solana key, and no proof shows the owner holds `u`. Payments to one recipient therefore link to each other and name it. Change carries the sender's own `u`.
17. The disclosure opens outputs only, and a nullifier needs the owner's nullifier secret. The auditor therefore learns no spent note of an owner without a registered key. A registered owner's secret is sealed to the auditor on any confidential ring, so the auditor computes that owner's nullifiers and links its spends. A `ConfidentialEscrow` ring requires a registered key of every output owner.

On an `Anonymous` ring (anonymous rail):

18. Public: the configured co-signer identity, the withdrawal destination, each exit owner, each 32-byte view tag, the length of each body and, on a policy ring, the blinded sender commitment.
19. Private from chain observers: the sender, every recipient, the amounts, assets and blindings, and the spent notes. The audit proof shows the hidden owner differs from the payer, the co-signer and the withdrawal destination.
20. A transfer that spends a default-ring note publishes the hidden owner's identity `solana_owner_identity(key)` as `default_owner_tag`, so it names its sender. An exit or a withdrawal publishes its recipient. When ring notes are spent, SPP refuses an exit to the hidden owner's key, and the audit proof refuses a withdrawal to it. No layer checks a recipient key that is only linked to the sender.
21. A first payment takes the recipient's request tag or bootstrap tag. The bootstrap tag is the recipient's `u`, so it names the recipient's viewing key and links every bootstrap payment to that key. Two payments under one request tag link to each other. Later payments of a pair take shared tags only the holders of the two viewing keys derive. Only the first change output takes the sender tag. A second change output takes a random tag laid out as a derived tag and opens from the sender bundle. An empty body tells change from payments and dummies.
22. The auditor learns the hidden sender and names each spent note. It names the first by its hash and the others by 16-byte prefixes it matches against the sender's notes. An entry spend opens every spent note.

On deposits, merges and delegate moves:

23. An `AuditedDeposit` publishes the funder, the mint, each note's amount, owner commitment and view tag. On a confidential ring the SDK sets the view tag to the recipient's `u`, which links funder and recipient. No layer on chain checks that the funder differs from the owner.
24. An anonymous `Merge` publishes the payer and every input nullifier, and SPP requires one owner and one asset across the inputs. It links up to 24 notes to one owner. The auditor opens the owner, the amount and every input hash.
25. A delegate move publishes the delegate and the recipients' `u` as the confidential rail does. The source member stays private from chain observers. The delegate holds the source member's nullifier secret, so it computes that member's nullifiers.

In every mode:

26. The auditor opens every output, every exit's asset and amount, every deposit and anonymous merge, and every escrowed nullifier secret. Ring RPC serves every opening, blindings included, to every reader, with no scope or expiry. It serves no nullifier secret. A revoked reader keeps what it read.
27. A recipient opens its body with its viewing key and finds the asset by trial. On the anonymous rail the body names the sender's viewing key, and no proof checks it.
28. The co-signer and the relayer see chain data only. No ring code hands them plaintext.
29. The ring indexer sees the members a client opens. It learns a policy transfer's sender, recipients and assets before the transfer lands, and it sees authority writes before they land. Photon pairs each spent leaf with its nullifier and sees the tags of one stream of a viewing key grouped per request. The ring prover receives the full witness. [Services](#services) gives the details.

## Constants

| Constant | Value | Use |
| --- | --- | --- |
| `RING_PROGRAM_CONFIG` | `10` | Discriminator of `RingProgramConfig`, seed `[b"config"]`, 150 bytes. |
| `MEMBER_REGISTRY` | `11` | Discriminator of `MemberRegistry`, seed `[b"members"]`, 2388 bytes. |
| `RECORD_QUEUE` | `12` | Discriminator of `RecordQueue`, seed `[b"queue"]`, 698 bytes. |
| `READ_ACCESS_RECORD` | `2` | Discriminator of `ReadAccessRecord`, seed `[b"reader", sha256(reader)]`, 36 bytes. |
| Reserved discriminators | `1`, `3` to `9` | Unused. `0` marks an empty account. |
| `ROOT_HISTORY` | `32` | Roots a member registry keeps. |
| `QUAD_ARITY`, `QUAD_HEIGHT` | `4`, `10` | Shape of the record tree, `2^20` leaves. |
| `MEMBER_REGISTRY_EMPTY_ROOT` | `0771d415ec42a482ed0169394bd583c89f08f5377bb20a45b240f7d241cd9841` | Root of a tree that holds only the sentinel, 32 bytes big endian. |
| `QUEUE_CAPACITY`, `APPLY_BATCH` | `16` | Pending writes a queue holds and an apply proof takes. |
| `MEMBER_QUEUE_LIMIT` | `8` | Pending writes at which member writes stop. 8 queue positions stay free for the authority. |
| `AUTHORITY_RESERVED_LEAVES` | `2^16` | Last leaves only authority writes fill, so member writes cannot use up the leaves an authority write needs. |
| `APPLY_DELAY_SLOTS` | `150` slots (about 1 minute) | Age a queued write reaches before a partial apply, and the gap between permissionless applies. |
| `GRACE_SLOTS` | `750` slots (about 5 minutes) | Time a curator root below the curator's new floor stays valid. |
| `DEFAULT_INSERT_FEE` | `1_000_000` lamports (0.001 SOL) | Insert fee of a new config. |
| `MAX_RULES`, `MAX_SOURCES` | `16`, `8` | Rule table widths. |
| `N_FOREIGN` | `1` | Curators per policy. |
| `POLICY_TABLE_VERSION` | `12` | Second field of the `policy_hash` preimage. |
| `POLICY_STATEMENT_VERSION` | `3` | Policy statement element after the public slots. |
| `POLICY_TABLE_FIELDS` | `44` | Fields of the `policy_hash` preimage, 35 values and 9 zeros, absorbed 11 per Poseidon call. |
| `N_PUBLIC_SLOTS` | `3` | Distinct assets of public legs per transfer, from SPP. |
| `ACCOUNT_UNITS`, `POLICY_UNITS`, `PROOF_UNITS` | `50_000`, `150_000`, `1_400_000` | Compute unit limits clients set per instruction tag. The program does not check them. |
| `CustomRingProof` | 192 bytes | Groth16 `a [32]`, `b [64]`, `c [32]` in compressed form, then the BSB22 `commitment [32]` and `commitment_pok [32]`. |
| `WithdrawalExemptionProof` | 193 bytes | A `CustomRingProof`, then the own root index `u8`. |
| Error codes | `8100` to `8252` | `CustomRingError`, above the SPP range. |

Each domain tag is its ASCII bytes read as one big-endian integer, as in zolana. A 33-byte tagged X25519 key is `0x04 || u` with `u` canonical little endian. Integers in ring accounts are little endian, and integers inside `EncodedRuleTable`, a mint-setting write and every proof field are big endian. [Hashing](spec/crypto/hashing.md) lists every domain tag and encoding.

## Accounts

The ring program owns four account types. A loader checks the owner, the exact size, the discriminator and the type's `valid()` predicate, and does not derive the address again, because each account is created only at its canonical PDA. Every account is a `repr(C)` byte image without padding. The shared rows are:

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
    /// Zero without a co-signer.
    pub co_signer: Address,
    /// `TRANSFERS = 1`, `DEPOSITS = 2`, `WITHDRAWALS = 4`.
    pub co_sign_scope: u8,
    /// Zero without a delegate. Set once, together with `mode = ConfidentialEscrow`.
    pub delegate: Address,
    pub created_slot: [u8; 8],
}
```

The mode changes once at most. `CreateConfig` sets `Anonymous` for the anonymous kinds and `Confidential` for the others. `SetDelegate` sets `Confidential -> ConfidentialEscrow`. No instruction leaves `ConfidentialEscrow` or `Anonymous`.

### MemberRegistry

One per ring at `[b"members"]`, created by `CreateMemberRegistry` for any kind and never closed. It holds the root history of the record tree, the floor, and the policy. `valid()` requires `history_cursor < 32` and `next_index <= 2^20`.

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
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// `SourceSlot { list_id, registry }`. A zero registry reads the ring's own records.
    pub sources: [SourceSlot; 8],
    pub rules: EncodedRuleTable,
    /// Plus one per policy write. Not hashed.
    pub generation: [u8; 4],
    pub generation_slot: [u8; 8],
}
```

`CreateMemberRegistry` starts it with `next_index = 1`, `history[0] = { MEMBER_REGISTRY_EMPTY_ROOT, 0, slot }` and floor `0`. An application pushes its new root over the oldest of the 32. A transfer names a root by its index:

- An own root needs a nonempty slot (`RootIndexEmpty`) with `applied >= floor` (`RootBelowFloor`).
- A curator root needs a nonempty slot (`RootIndexEmpty`), then `applied >= floor`, or `now < floor_slot + GRACE_SLOTS` and `applied >= prior_floor` (`CuratorRootStale`).

A second floor raise inside the grace window makes every root below the first raise stale at once. A root leaves the history after 32 later applications. A sender whose root went stale reads the newest roots and proves again. The SDKs do it on `RootBelowFloor`, `CuratorRootStale` and `RootIndexEmpty`.

The source map is positional: slot `i` is empty or holds `list_id = i + 1`. Every nonzero registry is the same curator. The hash reads a curator registry as `hash_bytes(address)` and the own registry as `0`.

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
    Poseidon(field("CRQW"), e.member, right_align(e.mask), right_align(e.value), e.escrow_key,
        mint_policy_write(e), right_align(e.mint_policy.unwrap_or_default().withdrawal_threshold))
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

One per reader at `[b"reader", sha256(reader)]`. `GrantReadAccess` creates it, `RevokeReadAccess` closes it, and no other ring instruction reads it. Ring RPC reads it before it serves a reader.

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
/// Leaf of the 4-ary record tree. Leaf 0 is the sentinel `(0, q - 1, 0, 0, 0, 0)`.
fn record_hash(r: &MemberRecord) -> Field {
    Poseidon(r.member, r.next, right_align(r.lists), r.escrow_key,
        pack(r.mint_policy), right_align(r.mint_policy.withdrawal_threshold))
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

```rust
/// Below 2^192, with threshold at bits 128..192, cap at 64..128 and cosign_above at 0..64.
fn pack(p: MintPolicy) -> Field {
    (p.threshold << 128) + (p.cap << 64) + p.cosign_above
}
```

Only `AuthorityWriteRecords` writes mint settings. One write replaces all four values, and an all-zero value clears them. A write without a replacement keeps them, and so do member writes and key registrations. A record with nonzero mint settings counts as nonempty, so a settings write to an absent asset inserts its record. The policy proof and the withdrawal exemption proof read mint settings from the ring's own registry only, also when a curator serves the lists. A mint has no settings until the authority writes them, and the only bound on the number of configured mints is the record tree's capacity.

## Instructions

| # | Instruction | Tag | Description | Access |
| --- | --- | --- | --- | --- |
| | **Setup** | | | |
| 1 | `CreateConfig` | `1` | Creates the ring config with the auditor key and the ring kind. | Upgrade authority signs |
| 2 | `CreateMemberRegistry` | `28` | Creates the member registry and the record queue. | Config authority signs |
| 3 | `InitSppRingConfig` | `2` | Creates the SPP `RingConfig` at `ring_auth`. | Config authority signs |
| | **Policy** | | | |
| 4 | `CreatePolicy` | `7` | Pins the first rule table and source map. | Config authority signs |
| 5 | `SetPolicyRules` | `12` | Same as `CreatePolicy`, over an existing policy. | Config authority signs |
| 6 | `SetPolicySource` | `10` | Points one list at the own registry or the curator. | Config authority signs |
| | **Controls** | | | |
| 7 | `SetAuthority` | `6` | Hands the config to a new authority. | Config authority and new authority sign |
| 8 | `SetPaused` | `11` | Pauses or resumes the ring in SPP. | Config authority signs |
| 9 | `GrantReadAccess` | `4` | Creates a reader's read access record. | Config authority signs |
| 10 | `RevokeReadAccess` | `5` | Closes a reader's read access record. | Config authority signs |
| 11 | `SetCoSigner` | `27` | Sets the co-signer and its scope. | Config authority signs |
| 12 | `ClearCoSigner` | `21` | Removes the co-signer. | Config authority signs |
| 13 | `SetInsertFee` | `42` | Sets the insert fee. | Config authority signs |
| 14 | `SetDelegate` | `24` | Sets the delegate and turns the ring to `ConfidentialEscrow`. | Upgrade authority and delegate sign |
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
8. `registry`: on a policy ring only.

**Instruction data**

Empty.

The program checks the config authority, that `spp_program` is SPP and executable (`InvalidShieldedPoolProgram`), on a policy ring that the registry loads and holds a policy (`PolicyNotSet`), and that `ring_auth` is canonical (`MissingRingAuth`). It invokes SPP `create_ring_config` signed as `ring_auth`. SPP sets `activated` from its protocol config and leaves the authority rail and `paused` off.

The program does not activate the ring. Until SPP governance activates it, no note moves.

### Policy

Pin and change the rule table and its sources. On a policy ring `InitSppRingConfig` needs the policy first.

#### 4. CreatePolicy

Tag `7`. Pins the first rule table and source map of a policy ring.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`.
3. `registry`: writable.
4. `curators`: zero or one curator registry for each distinct source number.

**Instruction data**

```rust
struct PolicyTableIxData {
    /// `source = 0` names the own registry, `source = n` the `n`th curator account.
    sources: Vec<SourceSpec { list_id: u8, source: u8 }>,
    rules: Vec<[u8; 32]>,
}
```

Every `Vec` has a `u8` length prefix.

The program checks, in order:

1. The data decodes and the config authority signs.
2. The ring has the policy tier (`PolicyOnAuditOnlyRing`) and no policy yet (`PolicyAlreadySet`).
3. The table holds at most `MAX_RULES` rows (`InvalidPolicyRules`).
4. For each source in order, the source names a list the rules reference, once (`InvalidSource`), and a curator source passes check 5.
5. A curator is not owned by this ring program (`InvalidSource`). It decodes as a `MemberRegistry` whose address derives from `[b"members", stored bump]` under its owner program (`InvalidCuratorRegistry`).
6. The generation is below `u32::MAX` (`PolicyGenerationOverflow`), and every curator source is one registry (`InvalidSource`).
7. Each rule decodes canonically, the rows past `rule_count` are zero, and the table holds no duplicate rule (`InvalidPolicyRules`).
8. Every referenced list is an authority list (`MemberWrittenListRule`) and has a source (`InvalidSource`).

It stores the table, the sources, `policy_hash`, `generation = 1` and `generation_slot = Clock::slot`. It writes no mint setting. The config authority writes those with `AuthorityWriteRecords`.

The program does not check that the curator has a policy, serves the list, or runs the ring program. The ring trusts the curator's roots and floors fully. The operator CLI checks that a named curator is deployed, pins a policy and serves the list from its own registry.

#### 5. SetPolicyRules

Tag `12`. Same as `CreatePolicy`, with check 2 replaced: a policy exists (`PolicyNotSet`). It replaces the table and the sources together, so every proof over the old table fails.

#### 6. SetPolicySource

Tag `10`. Points one referenced list at the own registry or the curator, and stores the new hash over the stored rules.

**Accounts**

As `CreatePolicy`, with no curator for an own source and one curator for a curator source.

**Instruction data**

```rust
struct SetPolicySourceIxData { list_id: u8, source: u8 }
```

The program checks the config authority, the list id (`InvalidListId`), that `(source, curators)` is `(0, [])` or `(1, [curator])` with the curator checks of `CreatePolicy` check 5 (`InvalidSource`, `InvalidCuratorRegistry`), and that the list's slot is already set (`InvalidSource`). It refuses any other trailing account. It then stores the policy as `CreatePolicy` does, which refuses a second distinct curator.

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

A grant has no scope and no expiry. Ring RPC serves the reader the ring's whole audited history.

#### 10. RevokeReadAccess

Tag `5`. Same as `GrantReadAccess`, with these parts replaced:

- Accounts: `authority` (config authority, signer), `config`, `read_access_record` (writable), `rent_recipient` (writable). No payer and no system program.
- Checks: the config authority, the record loads, its stored reader equals the data, and `rent_recipient` is not the record (`InvalidReadAccessRecord`). The program does not check the reader key format or derive the address again.
- Effect: the record closes into `rent_recipient`.

Ring RPC sees the revocation at `confirmed` and does not recheck a read in progress. A revoked reader keeps every opening it read.

#### 11. SetCoSigner

Tag `27`. Sets the co-signer and its scope, and replaces any earlier ones. The withdrawal thresholds are mint settings, which `AuthorityWriteRecords` writes.

**Accounts**

1. `authority`: the config authority. Signer.
2. `config`: writable.

**Instruction data**

```rust
struct SetCoSignerIxData {
    signer: [u8; 32],
    /// Nonzero subset of `TRANSFERS | DEPOSITS | WITHDRAWALS`.
    scope: u8,
}
```

The program checks the scope (`InvalidCoSignerScope`), a nonzero signer (`InvalidCoSigner`) and the config authority.

The co-signer may equal any key here. A transfer refuses a demanded co-signer that equals an owner or the delegate.

#### 12. ClearCoSigner

Tag `21`. Same as `SetCoSigner` with empty data: it zeroes the co-signer and the scope. The mint settings keep their withdrawal thresholds. It succeeds on a ring without a co-signer.

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

1. `authority`: the upgrade authority. Signer.
2. `config`: writable.
3. `delegate`: signer.
4. `registry`.
5. `program`.
6. `program_data`.

**Instruction data**

Empty.

The program checks, in order, the upgrade authority, that no delegate exists (`DelegateAlreadySet`), that the ring is not anonymous (`AnonymousRingRefused`), the policy tier (`DelegateRequiresPolicy`), and that the registry loads (`InvalidMemberRegistry`). It writes `delegate` and `mode = ConfidentialEscrow`.

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

`count: u8`, then `count` × `RecordWriteData` of 81 bytes each, then `ApplyRecordsIxData`.

```rust
struct RecordWriteData {
    member: [u8; 32],
    /// u64 little endian each. All zero when the write changes no list.
    lists: { mask: [u8; 8], value: [u8; 8] },
    /// `0` then 32 zero bytes keeps the mint settings. `1` then
    /// threshold, cap, cosign_above, withdrawal_threshold as u64 big endian replaces them.
    mint_policy: [u8; 33],
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
2. `registry`: in `ConfidentialEscrow` mode only.
3. `co_signer`: signer, only when demanded.
4. `spp_accounts`: the SPP `ring_deposit` list `[tree, depositor, ring_config, spp_program, asset groups…]`. `ring_config` is `ring_auth`.

**Instruction data**

```rust
struct AuditedDepositPrefix {
    tag: u8, // 31
    proof: CustomRingProof,
    /// Index of the own root in `ConfidentialEscrow` mode, else 0.
    registry_root_index: u8,
}
// followed by the SPP ring deposit data, from its tag byte 18
```

Each SPP deposit entry's ciphertext begins with a `CRDEP001` capsule: its slot index, the batch's ephemeral key and the 96-byte sealed opening, then the recipient ciphertext. [Envelope](spec/crypto/envelope.md#deposit-capsule)

**Proof**

The deposit proof checks, for each of `count` entries:

1. The note's `owner_utxo_hash = Poseidon(Poseidon(owner_pk_hash, nullifier_pk), Poseidon(CRDB, blinding_secret))`.
2. The capsule seals `(owner hash, blinding, owner key)` to the auditor. On an anonymous ring `owner_pk_hash = solana_owner_identity(owner key)`. Elsewhere the owner key is zero.
3. In `ConfidentialEscrow` mode the owner's record opens under the bound root with `escrow_key = Poseidon(nullifier_pk, ct_hash)`.
4. The statement binds a context hash over the ring id, the tree and the exact SPP data. [Public inputs](spec/crypto/public-inputs.md#deposit)

The program checks, in order:

1. The prefix is complete (`InvalidInstructionData`), its tag is `31` and the SPP data starts with tag `18` (`InvalidAuditedDeposit`), and the SPP body decodes (`InvalidDepositData`).
2. In `ConfidentialEscrow` mode the own root at `registry_root_index` passes the floor. Otherwise the index is `0` (`UnexpectedMemberRegistryRoot`).
3. A co-signer with `DEPOSITS` in scope signs (`MissingCoSigner`, `UnauthorizedCoSigner`).
4. On an anonymous ring every entry has `ring_data_hash = 0` (`AnonymousRingDataNotZero`).
5. `ring_auth` sits at SPP index 2 and at no other index (`MissingRingAuth`, `RingAuthOutOfSlot`). The depositor at SPP index 1 signs (`MissingFundingSigner`).
6. `1 <= count <= 8`. Each capsule parses with its own position and one shared ephemeral key of tag `0x04` (`InvalidDepositDisclosure`).

It verifies the proof under the key of the smallest capacity in `{1, 2, 4, 8}` at or above `count`, and invokes SPP with the deposit data unchanged.

No list rule or outflow limit runs on a deposit, and the funder is never screened. The rules screen the note's owner when it sends. SPP leaves the view tag opaque, and the proof binds it only through the context hash. A recipient's wallet finds the note by its view tag. The ring SDKs open the scheme 8 body in their ring scan, Rust `DepositOpener` and TypeScript `openRingDeposit`. They keep the note only when it rebuilds the published hash.

#### 20. Transact

Tag `43`. Verifies a ring transfer's audit proof, on a policy ring its policy proof, and an optional withdrawal exemption proof, expands the compact frame into the SPP transfer, and invokes SPP signed as `ring_auth`. The ring program writes no ring account.

The mode selects the rail:

| Mode | Rail | SPP instruction and circuit | Who signs | Sender in the policy statement |
|---|---|---|---|---|
| `Confidential`, `ConfidentialEscrow` | Confidential | `RING_TRANSACT` (19), `ConfidentialRingEddsa` | Each owner signer, the payer, a demanded co-signer | `solana_owner_identity(owner)` |
| `Anonymous` | Anonymous | `RING_TRANSACT` (19), `AnonymousRingEddsa` | The payer and a demanded co-signer only. The hidden owner signs inside the SPP proof. | `sender_commitment` |

**Accounts**

1. `config`.
2. `registry`: on a policy ring, and on any ring when the frame carries a withdrawal exemption proof.
3. `curator`: when the policy has a curator.
4. `co_signer`: signer, when the transfer demands one.
5. `spp_accounts`: the SPP `ring_transact` list, verbatim: `[payer, output_tree, spp_program, system_program, ring_auth, input trees…, nullifier PDAs…, owner signers…, settlement groups…]`.

**Instruction data**

The frame is a byte string the program parses in this order. The shape byte selects the shape `n_in × n_out`. Short or trailing bytes and an input count outside `1..=n_in` fail with `RingTransactLength`. The `[exemption]` part has no flag. It is present when exactly 193 bytes follow the tree contexts, and SPP never receives it. A shape index outside the set fails with `RingShapeUnkeyed`. A bad interface transfer list or a bitmap bit past its count fails with `InvalidInstructionData`.

```text
flags            u8   POLICY 1, CURATOR 2, APPROVAL_REQUIRED 4, SECOND_TREE 32,
                      bits 3, 4, 6 and 7 clear
shape            u8   bits 0-5 index into SPP_SUPPORTED_SHAPES, bit 6 DEFAULT_OWNER_TAG, bit 7 clear
inputs           u8   bits 0-5 published input count, bit 6 KEY_ESCROW, bit 7 FULL_OPENINGS
audit_proof      CustomRingProof
[POLICY]         policy_proof CustomRingProof, own_root_index u8
[CURATOR]        curator_root_index u8
[POLICY, anonymous] sender_commitment [32]
expiry_unix_ts   u32 LE
tx_viewing_u     [32]
salt             [16]
interface_transfers  Vec<InterfaceTransfer>, u8 length
[POLICY]         spl_withdrawal_owners [32] per SPL withdrawal
exits            bitmap of ceil(n_out / 8) bytes
outputs          per slot, by kind:
                   exit      hash [32], owner_tag [32], payload [83]
                   delivered hash [32], u [32], body [40]
                   anonymous hash [32], tag [32], len u16 LE, body [len], empty on change
[anonymous]      sender bundle tag [32], len u16 LE nonzero, body [len]
eph_u            [32]
sealed           [32]
disclosure       [32] per field of the layout
private_tx_hash  [32]
[anonymous]      commitment [32], commitment_pok [32]
[DEFAULT_OWNER_TAG] default_owner_tag [32]
spp_proof        a [32], b [64] compressed, c [32]
nullifiers       [32] per published input
[SECOND_TREE]    bitmap of second-tree inputs, then two TreeContext, else one
[exemption]      withdrawal_exemption_proof CustomRingProof, root_index u8
```

A bitmap holds bit `i` at byte `i / 8`, bit `i % 8`. A scheme is the zolana tag of an output's body format, stored by SPP without parsing. An exit payload is the zolana scheme 3 body of an output without data, any other length fails with `DataFreeBodyLength`. An anonymous output body is scheme 1, and an empty one marks a change output. The ring SDKs encode the scheme 1 recipient, scheme 2 sender bundle and scheme 8 deposit plaintexts with their own codecs, in Rust `anonymous_plaintext.rs` and `ring_deposit.rs` of `zolana-ring-transaction`. They take the scheme numbers, the view tag derivations and the body encryption from zolana. An empty sender bundle or a body past `u16::MAX` fails with `AnonymousBodyLength`. A set reserved flag bit fails with `FlagNotAllowed`. `InterfaceTransfer` and `TreeContext` are the zolana SPP types. `expiry_unix_ts` is the SPP expiry, checked by SPP against cluster time. Every transfer publishes exactly `n_out` slots, a dummy slot included.

The program expands the frame to SPP `TransactIxData`:

- `tx_viewing_pk = 0x04 || tx_viewing_u`, the salt and the interface transfers, with no transfer data hashes
- each output as `OwnerTag::Inline` in the `Encrypted` encoding, with scheme 10 (delivered), 1 (anonymous) or 3 (exit), and an anonymous change output with no data
- on the anonymous rail the sender bundle first, `{ view_tag: tag, data: Encrypted(2 || body) }`
- the auditor message last, `{ view_tag: auditor u, data: 0x04 || eph_u || sealed || disclosure }`
- `private_tx_hash`, the rail's circuit and the proof
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

The sender chooses each output's owner, asset and amount. The audit proof fixes every blinding from `tx_viewing_sk`, the salt and the first nullifier. A recipient finds its notes by its owner tag. That is its viewing key `u` on the confidential rail, or a view tag on the anonymous rail. It opens the body and keeps the note only when a held mint rebuilds the published commitment. On the anonymous rail every payment and dummy carries one body sealed at its output position, and the sender's change leads with no body. Output 0 takes the sender tag, and a second change output takes a dummy tag. The sender bundle message lists one recipient viewing key per output after the change. An exit or a dummy takes the dummy key `0x04 || 0^32`, a custom-ring extension of the zolana sender bundle. [Anonymous rings](anonymous-rings.md#output-layout) The auditor finds every transfer by the auditor view tag.

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
4. The withdrawal legs hash to `withdrawal_hash`. Each active leg has a nonzero asset and a nonzero 64-bit amount.
5. The own record pool folds to `own_root` through one shared canopy, and the curator pool to `curator_root` when some list is foreign. Each subject resolves to its own leaf in the pool, or to the low record that brackets it. A bracketed subject reads every list and mint setting as `0`. A list bit reads from the curator record when the list's source is foreign. The asset record of every live payment and of every nonzero public asset resolves in the own pool, whatever the rules. It gives that asset's mint settings.
6. Each active rule holds as [Properties](#properties) 6 states. A scalar `AboveAmount(t)` guard exempts an asset subject when the live payments of that asset sum to at most `t`. It exempts an owner subject when that owner's live payments sum to at most `t`, and then every payment is in one asset. `AboveAmountByAsset` exempts when the owner's payments in that asset sum to at most the asset's `threshold`. A live payment in an asset with a zero `threshold` fails the proof under such a rule, admitted or not. Comparisons are inclusive.
7. Outflow and `approval_required` follow [Properties](#properties) 8.
8. In `ConfidentialEscrow` mode every UTXO output's owner record holds the output's escrow key.
9. The own-only key requires `curator_root = 0` and no foreign source.

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
2. The frame parses. `CURATOR` and `APPROVAL_REQUIRED` need `POLICY`. `DEFAULT_OWNER_TAG` and `FULL_OPENINGS` need the anonymous rail (`FlagNotAllowed`). No disclosure field is zero (`ZeroDisclosureField`).
3. The settlement accounts cover the interface transfers (`InvalidSettlementAccounts`). At most 32 legs, none of zero amount (`TooManyPublicLegs`, `ZeroPublicLegAmount`). With a withdrawal exemption proof, the registry loads (`InvalidMemberRegistry`), the own root at its `root_index` passes the floor, the transfer withdraws at most 3 mints (`InvalidInstructionData`), and the proof verifies (`ProofVerificationFailed`).
4. Policy ring: a policy proof is present (`MissingPolicyProof`), the `CURATOR` flag matches the policy (`FlagNotAllowed`), a policy exists (`PolicyNotSet`) and the own root passes the floor. Audit-only ring: no policy proof (`UnexpectedPolicyProof`).
5. The curator account equals the stored curator (`InvalidCuratorRegistry`) and its root passes the floor or the grace window.
6. `ring_auth` sits at SPP index 4 and at no other SPP index (`MissingRingAuth`, `RingAuthOutOfSlot`). The payer at SPP index 0 signs (`MissingFundingSigner`).
7. Confidential: every owner signer signs (`MissingOwnerSigner`). On a policy ring there is at least one and all are one address (`OwnerSignerCount`). A demanded co-signer is no owner (`CoSignerIsOwner`). Anonymous: no SPP account but the payer signs (`InvalidAnonymousSigner`).
8. Every deposit leg's funder signs (`MissingFundingSigner`). On the anonymous rail check 7 makes every funder the payer.
9. The public legs fold to at most 3 assets, each with a nonzero net within u64 (`TooManyPublicAssets`, `ZeroNetPublicAmount`, `PublicAmountOverflow`).
10. Policy ring: each SOL withdrawal's owner is its recipient. Each SPL withdrawal's token account is a Token or Token-2022 account of the leg's mint owned by the declared owner (`InvalidSettlementAccounts`, `AnonymousExitTokenAccountInvalid`).
11. Anonymous: every withdrawal names one destination key (`AnonymousExitDestinationsDiffer`). A SOL destination is a system account with no data. An SPL destination is an off-curve token account with no delegate and no close authority (`AnonymousExitAccountHasData`, `AnonymousExitTokenAccountOnCurve`, `AnonymousExitTokenAccountShared`). The party identities are `solana_owner_identity` of the payer, the configured co-signer and the destination key, each `0` when absent. For an SPL withdrawal the destination key is the token account's owner.
12. The co-signer demand of [Properties](#properties) 9, with the withdrawal class waived when check 3 verified an exemption proof: a demanded co-signer is configured (`ApprovalWithoutCoSigner`), signs (`MissingCoSigner`) and equals the stored one (`UnauthorizedCoSigner`).
13. The SPP `proof_b` decompresses (`InvalidSppProofPoint`).
14. The key escrow layout bit equals `mode == ConfidentialEscrow` (`FlagNotAllowed`).
15. It builds the audit statement and the policy statement and resolves both keys (`UnsupportedCircuit`). It verifies the audit proof, then the policy proof, each point decompressed (`InvalidRingProofPoint`) and the pairing checked (`ProofVerificationFailed`).
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

Tag `20`. Forwards an SPP ring merge, which joins up to 24 notes of one owner and one asset into one note, with a disclosure proof to the auditor. It succeeds on an anonymous ring only.

**Accounts**

1. `config`.
2. `registry`: on a non-anonymous ring.
3. `co_signer`: signer, only when demanded.
4. `spp_accounts`: the SPP `ring_merge_transact` list `[input_tree, output_tree, ring_config, payer, system_program, spp_program, nullifier PDAs…, merge cache…]`.

**Instruction data**

`registry_root_index: u8`, `output_ring_data_hash: [32]`, then the disclosure as `Option` (`0` none, `1` then `proof`, `eph_pk [33]`, `ciphertext [32]`, `count u8` and `count` fields), then the SPP merge body with a compressed `proof_b`.

**Proof**

The anonymous merge proof checks:

1. Every input is a UTXO or a dummy, input `0` is a UTXO, and every UTXO has the owner, the asset and the ring id of the output and `data_hash = 0`.
2. The output amount is the 64-bit sum of the inputs, its blinding is `TMOB(nullifier_secret, n0)`, and its hash is the published output hash.
3. `private_tx_hash` reopens with the inputs and the output.
4. The envelope seals a disclosure key to the auditor under label `CRING/mrg1`. Each disclosure field is a chunk of the owner key, nullifier key, mint, amount, output blinding and input hashes, plus a pad from that key and the salt. [Disclosure](spec/crypto/disclosure.md#merge-disclosure)
5. The party identities are the payer and the co-signer, each different from the owner, and the third is `0`.

The program checks, in order:

1. The data parses, and the SPP merge body is a supported form (`InvalidInstructionData`).
2. On an anonymous ring `registry_root_index = 0` (`UnexpectedMemberRegistryRoot`). On another ring the own root at that index passes the floor.
3. A co-signer with `TRANSFERS` in scope signs.
4. `ring_auth` sits at SPP index 2 and at no other index. The payer at SPP index 3 signs. The SPP `proof_b` decompresses (`InvalidSppProofPoint`).
5. On an anonymous ring the disclosure is present (`MissingMergeDisclosure`), it has the field count of the merge width (`MergeDisclosureWidth`), its ephemeral key has tag `0x04` (`InvalidMergeDisclosure`), and `output_ring_data_hash = 0` (`AnonymousRingDataNotZero`).

It verifies the proof under `AnonymousMerge { 8 }` or `AnonymousMerge { 24 }`. A merge of more than 24 inputs takes SPP width 52 and fails with `UnsupportedCircuit`.

On a confidential ring every merge fails: without a disclosure with `EscrowMergeUnverified`, with one with `InvalidMergeDisclosure`. The ring has no merge key for those modes.

No rule runs on a merge, because SPP keeps the owner, asset and value. The proof does not check that the merge output ciphertext opens. SPP publishes it unverified.

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
- `getDecryptedTransactions`, `getAuditedMerges` and `getAuditedUtxos` serve a reader that signs a request with its Ed25519 key or a WebAuthn P-256 passkey, within 60 seconds of the service clock, with a fresh nonce. The service requires the ring config to name its key and the reader to hold a read access record.
- `ringDeposits`, `ringStatus` and `health` need no signature.
- Every audited row is bound to the confirmed SPP event the service rebuilds from Solana `getTransaction`. Photon is trusted for completeness only. A row Photon omits, or labels with no ring, never reaches a reader, and no client detects the gap.

A reader receives each output's owner key, nullifier key, asset, amount and blinding, the recipient `u` on the delivered rails, and on the anonymous rail the view tag, the hidden sender and every input's opening. It receives no nullifier secret. Pages carry no signature, so a faulty service can serve a false opening to a reader that does not rebuild the commitment. `getAuditedUtxos` answers are checked by both SDKs against their requested hashes. Nonces and rate windows live in memory, so one key runs in one process.

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
| `AnonymousMerge` | width 8, 24 |

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

On a confidential ring the sender signs the transaction, and each ring output publishes the recipient's viewing key `u`. The zolana user registry maps a registered `u` to its owner's Solana key, so every payment names its sender and recipient. Amounts, assets, blindings, nullifier keys and the spent notes stay private.

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

An outflow limit applies per transfer, per mint and per signing key. It keeps no counter and no window. The real-world controls map as follows:

| Control | Enforced |
|---|---|
| Cap per transfer and mint | Yes, `outflow <= cap`. |
| Dual control above an amount per transfer | Yes, the co-signer signs when `outflow > cosign_above`, and the transfer publishes the approval bit. |
| Cap per customer per day | No. Several transfers each pass alone. |
| Cap per person across keys | No. Each signing key is its own sender. |
| Deposit and withdrawal volume per window | No. Only the co-signer's per-transfer withdrawal thresholds apply. |

A deposit leg in the same transfer lowers the outflow of its mint, and its funder is not screened. A deposit leg above what the transfer pays away in a limited mint fails the proof, so a sender deposits to itself with `AuditedDeposit`. An exit counts as outflow, also to the sender. A mint whose record holds a zero `cap` and a zero `cosign_above` is unbounded. The delegate rail runs no outflow check.

### Guards and block lists bind one transfer and one key

An `AboveAmount` or `AboveAmountByAsset` guard sums the payments of one transfer. A payment split across transfers passes a guard each part stays under. A block list refuses known members only, so a fresh signing key passes it. Only an allow list bounds the senders and recipients to known members.

### Deposits and merges are not screened

No rule or outflow limit runs on `AuditedDeposit` or `Merge`. A deposit can credit any owner, registered or not, except that a `ConfidentialEscrow` ring requires an escrowed owner. The rules screen an owner when it sends and every output owner it pays.

### List rules publish what they screen

The rule table and the member registry are public. An observer reads which lists a ring screens, every member on them and every mint setting. The approval bit tells that some mint's outflow passed its `cosign_above`.

### A sender can make a note unreadable for its owner

On the delivered rails no proof relates a recipient key `u` to the owner of its output. The audit proof shows only that the body opens for the holder of the published `u`. The anonymous audit proof derives no view tag and opens no body. It proves each output's owner key, asset and amount in the disclosure, the blinding the auditor rebuilds, and the spent notes. A wrong tag or a body sealed to the wrong key costs the recipient the note, as a payment to a wrong address does, gains the sender nothing, and the auditor still opens the output.

### A curator controls its subscribers

A ring trusts its curator's roots and floors fully. The program checks the curator's account shape and address derivation only. A curator that stops raising its floor keeps stale lists valid, and a curator write reaches subscribers within `GRACE_SLOTS`.

### Confidential rings cannot merge

The ring has no merge key for `Confidential` and `ConfidentialEscrow`, so every merge there fails. An owner on a confidential ring joins notes with a transfer to its own address.

### Public legs that net to zero fail

The program folds every transfer's public legs per asset and refuses a net of zero with `ZeroNetPublicAmount`. A transfer that deposits and withdraws the same amount of one asset fails, on every tier. The sender splits the legs into two transfers.

### Escrow and delegate are permanent

A registered nullifier key cannot change. A delegate and the `ConfidentialEscrow` mode cannot be removed by any instruction of the deployed binary. Only a program upgrade by the upgrade authority changes them.

### Rings of another layout need a migration

The program, the SDKs, the ring indexer and the proving keys accept only the 150-byte config, the 2388-byte registry, the six-field record leaf, the seven-field queue entry and policy table version 12. A ring whose accounts or record tree use another layout fails these checks, and its records do not open under these circuits. Its operator migrates the accounts and the record tree before the program upgrade. No ring instruction performs that migration, and a reindex of the ring's instructions does not rebuild its on-chain roots.

### The auditor reads everything

The auditor key opens every note, every anonymous sender and every escrowed nullifier secret. Ring RPC serves every opening to every reader with a grant, and a grant has no scope or expiry. A leaked auditor key exposes the ring's whole history, and on a `ConfidentialEscrow` ring it also lets its holder compute every escrowed member's nullifiers.
