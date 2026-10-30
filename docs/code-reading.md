# Reading the custom rings code

Read `zolana/` paths at the submodule pin, not at the checkout.

## Route

**SPP holds the gate**

1. `zolana/programs/shielded-pool/src/instructions/transact/account.rs`. `RingTransactAccounts` needs the `RingConfig` as signer and returns its `program_id`, and `processor.rs` feeds `hash_bytes` of it to the SPP proof as `ring_program_id`. The `RingConfig` account is the ring program's `ring_auth` PDA. Only the ring program signs for it, so only it moves a ring note.
2. `zolana/programs/shielded-pool/src/instructions/ring_config/`. `create.rs` derives `ring_auth` canonically under the ring program. `loader.rs` refuses every ring rail while the ring is not activated or is paused.

**The ring program signs only what it checked**

3. `programs/custom-ring/src/lib.rs`. Only `Transact`, `DelegateTransact`, `AuditedDeposit` and `Merge` sign a note move. The plain SPP deposit tag fails with `DepositAuditRequired`, so no deposit skips the audit.
4. `programs/custom-ring/src/instructions/runtime/instruction_runtime.rs`. `RingAuth::check_slot` puts `ring_auth` at its one SPP index and refuses it at any other, so its signature cannot be lent to another account role.
5. `program-libs/interface/src/instructions/transact.rs`. The frame is the compact `Transact` data. `transact_ix_data` writes the SPP data from it, with one auditor message. The SPP proof binds those bytes, and both ring statements, the audit and the policy public inputs, read the same parsed frame. All three proofs therefore bind one set of nullifiers, outputs, keys, salt and disclosure. `RingRail::of` takes the rail from the tag and the mode, never from the frame.
6. `programs/custom-ring/src/instructions/transact/`. `processor.rs` runs the config, the rail, the parse, `accounts.rs`, `verify.rs` and then the CPI. The ring id comes from the executing program, the auditor key from the config, the roots from the member registries, and the parties and withdrawals from the accounts. [Transact](spec.md#20-transact)
7. `program-libs/interface/src/proof/statement.rs`. Each statement folds to one `HashChain4` field, the only public input. Each circuit's `statement` function in Go is its twin, so check that the element order matches. [Public inputs](spec/crypto/public-inputs.md)
8. `programs/custom-ring/src/instructions/verification/verifier.rs`, `program-libs/interface/src/proof/key_catalog.rs`. The key follows the published shape and layout, and the layout is a statement element the circuit decodes in `prover/circuits/audit/layout.go`. `new_with_commitment` refuses a key without BSB22.

**Audit by construction**

9. `prover/circuits/audit/`. `audit.go` seals `tx_viewing_sk` to the auditor key, and `assertBlinding` pins each live output blinding to SPP's `TXOB` under the ring blinding seed `CRBS(tx_viewing_sk, salt)`. Every SPP output commitment therefore opens under the sealed secret. [Hashing](spec/crypto/hashing.md#blinding-derivations) `delivered.go` and `anonymous.go` add each layout's disclosure, mirrored in `program-libs/interface/src/proof/disclosure.rs`. [Disclosure](spec/crypto/disclosure.md)
10. `delivery.go` proves on the delivered rails that every ring output body opens for the holder of its published `u`, and no output carries data. `anonymous.go` opens each output's owner key, asset and amount and checks no tag and no body. Exit payloads are not proven, and no proof ties `u` to the owner. A recipient can miss a note, but the auditor still opens it. [Limitation](spec.md#a-sender-can-make-a-note-unreadable-for-its-owner)

**Policy is validated at write and evaluated only in the circuit**

11. `program-libs/policy/src/rule_table/mod.rs`. `EncodedRuleTable::validate` runs only on policy writes, through `MemberRegistry::set_policy` in `program-libs/interface/src/accounts/state.rs`. `prover/circuits/policy/table.go` only rehashes to `policy_hash` and splits rows, so a gap in validation is a gap in the circuit. The table holds rules only. Mint thresholds and outflow limits are `MintPolicy` values in asset records, `program-libs/policy/src/mint.rs`. [EncodedRuleTable](spec.md#encodedruletable)
12. `prover/circuits/policy/`. `rules.go` and `subjects.go` are the only code where a list bit decides. They cover the sender, every live output owner and asset, and every withdrawal. `RuleTable::admit` in `program-libs/policy/src/rules.rs`, called from `sdk-libs/sdk/src/operations/pipeline/policy.rs`, is a client precheck only.
13. `program-libs/member-registry/src/`, `prover/circuits/policy/record_pool.go`, `prover/circuits/registry/shared_path.go`. The 4-ary record tree is sorted through `next`, and an absent member opens by its low record, the record whose `member` and `next` bracket it. The policy proof opens one record pool per registry, and every pool path folds through one shared canopy to the bound root. A prover cannot leave out the record that convicts its subject. [Record pool](circuit-policy.md#record-pool)
14. `program-libs/interface/src/accounts/member_registry.rs`, `prover/circuits/registry/apply_records.go`. Writes queue as a Poseidon chain, and the apply proof binds both chain ends the program holds, so a permissionless submitter cannot alter a write. Owners write only bits no rule may read (`ListBitNotWritable`, `MemberWrittenList`), so no owner admits itself. Only an authority write sets bit 192 of `mint_policy_write` (`RecordWriteData::entry` in `program-libs/interface/src/instructions/instruction.rs`), and without it the apply proof keeps the stored mint settings, so no owner changes a limit.
15. `program-libs/interface/src/accounts/state.rs`. The floor is the record queue position of the last authority write. Every authority write calls `raise_floor`, and `own_root` refuses a root below the floor, so a block binds the next transfer. `curator_root` reads a curator, another ring whose registry a policy reads, and accepts its prior floor for `GRACE_SLOTS`. That is the only lag a ring accepts. [MemberRegistry](spec.md#memberregistry)
16. `prover/circuits/policy/outflow.go`, `program-libs/interface/src/instructions/cosign.rs`. Every live output's asset and every nonzero public asset opens its own record, so the transaction, not the prover, picks which mint settings apply. Outflow is bounded per transfer, and `approval_required` is set exactly when an outflow passes its `cosign_above`. `CoSignDemand` is the one co-sign rule for the program and both SDKs. Only a verified `prover/circuits/policy/withdrawal_exemption.go` proof waives its withdrawal class, over the gross withdrawals the program computes. No counter or window exists. [Limitation](spec.md#outflow-limits-bound-one-transfer)

**The confidential and anonymous border**

17. `programs/custom-ring/src/instructions/transact/accounts.rs`. On the confidential rail every owner signer signs, and a policy ring needs one owner address, which becomes the policy `sender`. On the anonymous rail any SPP signer other than the payer fails with `InvalidAnonymousSigner`. The hidden owner signs inside SPP's `AnonymousRingEddsa` proof.
18. `program-libs/interface/src/instructions/anonymous_exit.rs`. The payer, the configured co-signer and the one withdrawal destination are the party identities. `prover/circuits/audit/anonymous.go` proves that each one differs from the hidden owner. SPP refuses an exit to the hidden owner's key on a ring spend (`AssertDefaultHiddenOwner` in `zolana/prover/server/circuits/spp_transaction/shared/signers.go`). No layer checks a linked key or the outer fee payer. [Limitation](spec.md#anonymity-breaks-when-its-conditions-fail)
19. `sdk-libs/client/src/state/viewing_history.rs`. A recipient finds anonymous outputs by zolana view tags, and the wallet takes each tag by the spec selection over its viewing history. No proof checks a tag, so the program reads no chain value for one. In `program-libs/interface/src/codec/stream.rs` the policy `sender_commitment` hides the sender under the `private_tx_hash` blinding, and the audit proof opens it to the spent notes' owner. The scheme 1 and scheme 2 plaintexts are ring codecs in `sdk-libs/transaction/src/anonymous_plaintext.rs`. `anonymous_rail.rs` gives output 0 the sender tag and lists the dummy key `0x04 || 0^32` for every exit and dummy in the sender bundle. The wallet syncs in `sdk-libs/client/src/operations/anonymous.rs`, and ring addresses live in `sdk-libs/keys/src/ring_address.rs`. [View Tags](../zolana/docs/spec.md#view-tags)

**Key escrow, deposits and merges**

20. `programs/custom-ring/src/instructions/records/register_key.rs`, `prover/circuits/registry/register_key.go`. A confidential member seals its nullifier secret to the auditor, and an anonymous ring refuses the write. In `ConfidentialEscrow` mode `escrows_keys` in `programs/custom-ring/src/instructions/transact/verify.rs` takes `key_escrow` from the mode, and the policy proof requires each output owner's record to escrow that output's nullifier key.
21. `programs/custom-ring/src/instructions/configuration/access/set_delegate.rs`. The upgrade authority and the delegate together set `ConfidentialEscrow` mode, once, on a confidential policy ring. `DelegateTransact` refuses public legs and exits. SPP's authority rail keeps every note in the ring. [DelegateTransact](spec.md#21-delegatetransact)
22. `programs/custom-ring/src/instructions/settlement/deposit_audit.rs`, `prover/circuits/deposit.go`. The deposit proof binds a context hash over the program id, the tree and the exact SPP data, and it seals each opening to the auditor. No rule runs on a deposit. The ring scan opens the scheme 8 body with `DepositOpener` in `sdk-libs/client/src/crypto/deposit.rs`, over the plaintext of `sdk-libs/transaction/src/ring_deposit.rs`. [AuditedDeposit](spec.md#19-auditeddeposit)
23. `programs/custom-ring/src/instructions/settlement/forward.rs`, `merge_disclosure.rs`, `prover/circuits/merge.go`. A merge verifies only on an anonymous ring and fails on every other ring. SPP keeps the owner, the asset and the value, so no rule runs. [Merge](spec.md#22-merge)

**Trust outside the program**

24. `prover/ring/proving-keys.lock`. It pins every proving key by SHA-256. `prover/ring/ring.go` embeds it and registers the ring circuits as zolana prover extensions. `program-libs/interface/src/verifying_keys/mod.rs` compiles the same hashes, and `just check-custom-ring-keys` diffs the keys. The setup has one party. [Keys](spec.md#keys-and-releases)
25. `services/ring-indexer/`, `sdk-libs/client/src/operations/records.rs`. `OpeningCheck` and `RecordPoolCheck` check each opening and each record pool against the root on chain, so the indexer can refuse but cannot lie. [Ring indexer](spec.md#ring-indexer)
26. `services/ring-rpc/`. It holds the auditor key and serves openings to every holder of a `ReadAccessRecord`. Nothing on chain checks its pages. The ring prover sees every witness secret. [Services](spec.md#services)
27. `sdk-libs/sdk/src/operations/pipeline/`, `sdk-libs/sdk/src/operations/submission.rs`. One pipeline with the sealed rails `Owner`, `Anonymous` and `Delegated` proves SPP, audit, policy and, when it applies, a withdrawal exemption together over one frame. It proves again on `RootBelowFloor`, `CuratorRootStale` and `RootIndexEmpty`. `sdk-libs/ts/src/operations/workflow/` mirrors it.

## Key decisions

- One signer. Every check a ring note has lives in the ring program binary. [Limitation](spec.md#the-upgrade-authority-can-move-every-note)
- One frame. The program writes the SPP data, so the three proofs cannot disagree about the move. [Transact](spec.md#20-transact)
- Chain supplies the statement. The prover chooses no bound value that the chain holds. [Properties](spec.md#properties)
- Audit by construction. Blindings derive from the sealed secret, so the auditor opens what SPP commits. [Envelope](spec/crypto/envelope.md)
- Validate at write, evaluate in the circuit. No transfer path reads a list bit. [Properties](spec.md#properties)
- Public sorted records. A floor makes each authority write bind at once. [MemberRegistry](spec.md#memberregistry)
- The mode fixes the rail. It changes once at most, and no instruction reverts it. [RingProgramConfig](spec.md#ringprogramconfig)
- Trust anchors. These are the upgrade authority, the key generator, the curator and the auditor. [Limitations](spec.md#limitations)
