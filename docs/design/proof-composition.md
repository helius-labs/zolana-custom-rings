# Proof composition

A ring transfer settles only when the ring proof and SPP's proof both verify over values the ring program rebuilds. This guide states which side enforces each guarantee. Read it before you change a ring circuit, a statement builder or a program binding. `TransferStatement::elements` in `program-libs/interface/src/proof/statement.rs` contains the exact encoding.

## Enforcers

Each guarantee below names its enforcer as the subject of the sentence:

- The circuit states a local constraint in `prover/circuits`, true of every proof that verifies under the key.
- The program states a program fact. The ring or Storage program derives the value from accounts and the frame, or refuses the transaction before verification.
- SPP states a guarantee of the SPP program or its proof. The ring relies on it through shared values and does not check it again.
- A reader states an off-chain check. It protects the party that runs it and binds nobody else.

A statement element enforces nothing alone. It fixes a value, and a constraint or a program check gives the value its meaning.

## The cross-component argument

1. The program builds the statement from the frame it forwards to SPP. The statement hash is the one public input of the ring proof, so the prover picks no element the program derives.
2. The circuit opens each output through `audit.OpenSlots` and each input through `OpenInputs`, both through `shared.UtxoWires.Open`. Audit, policy and the tracking checks read those wires, so no two sections describe different notes.
3. The circuit binds its private nullifiers to `input_nullifier_chain`, which the program hashes from the nullifiers it forwards to SPP. It derives the address chain from those nullifiers and the address selectors. It then reopens `private_tx_hash` over the opened inputs, the opened outputs, the address chain and the blinding. SPP's proof binds the same hash to its nullifiers and outputs, so the opened slots are the slots SPP settles.
4. The program hands SPP the output hashes that `output_chain` covers. SPP zero-fills past `m`, and the circuit multiplies each cell past `m` by zero. Both sides read one list.
5. SPP derives every output blinding and `private_tx_blinding` from one seed. The circuit holds each published blinding to the seed the sealed key derives. Slot 0 is always published, so the sealed key fixes SPP's seed.
6. The program reads each registry root live from the account the ring binds. A record opening under that root therefore carries the write rules of the Storage program and of its apply circuits.
7. SPP's external data hash covers each frame's tags, bodies and messages. It binds the submitted bytes and proves nothing about what they contain.

No Go test composes the ring proof with SPP's proof. Steps 3, 4, 5 and 7 are true across the program binding.

## Predicate ledger

Tests sit under `prover/circuits/transfer` unless the entry names another path.

### The statement has one schema and one length

- The program builds `TransferStatement::elements`, with the element count last.
- The circuit ends `Define` with one `HashChain4` equality, and `closeStatement` appends the same count.
- The tests are `TestTransferStatementVector`, `TestSignerSetVector` and `TestStatementBindsEveryElement`.

### A rail is one fixed combination of bits

- The program fixes the rail from the instruction tag, the ring mode and the frame flags. `rail_bits` writes `in_proof`, `hidden` and `delegate`.
- The program refuses `OWNER_IN_PROOF` on an anonymous ring and on the delegate rail. It refuses reply metadata except on the anonymous frame. It refuses a policy section on the delegate rail.
- The circuit holds the bits boolean with at most one set, and holds `sender` to zero except on the in-proof rail, in `assertRail`.
- One key serves every rail, so only the program-set `delegate` bit separates the signer and delegate rails.
- The tests are `TestRailsSolve`, `TestRailCells` and `TestDelegateBitIsTheProgramsWall`.

### Every input slot is a note, an address or a canonical dummy

- The circuit opens each slot in `OpenInputs`. A dummy contains `CheckDummy` fields, and an address spends nothing.
- Notes and addresses interleave in SPP's order, and dummies form the suffix. The circuit holds `input_count` to at least one through `SelectCount`, and refuses a note or an address at or past the count.
- The program sets `input_count` to the frame's nullifier count, and `input_nullifier_chain` to `HashChain4([n, nullifier_0 .. nullifier_{C-1}])` over those nullifiers, zero past `n`.
- The circuit binds its nullifiers to that chain and forces its tail past `n` to zero. It derives the address chain from the address selectors over the same list, so a moved nullifier or a selected zero fails.
- SPP's `AssertDummiesLast` orders its slots the same way, so entry `k` names nullifier `k`.
- The hidden rail holds slot 0 to a note.
- The tests are `TestInputOrder`, `TestAddressSlots`, `TestInputsInterleaveBeforePadding`, `TestInputCompositionRefusesChangedBindings`, `TestInputCompositionUsesTheLastBitmapSlot` and `TestHiddenOwnerRequiresANoteInSlotZero`.

### Every live input answers its rail's owner predicate

- Except on the delegate rail, the circuit holds each live input to the run, the hidden owner or the in-proof sender, in `AssertOwners`.
- The circuit reads the hidden owner from input 0, holds that input live and holds the owner outside the run.
- The circuit holds each live ring note to the transfer's ring, in `AssertRingNotes`. Only a key with entry capacity also spends a default-ring note.
- SPP verifies each owner signer, and the hidden owner's signature inside its proof. SPP's authority rail holds every input to the ring.
- The tests are `TestOwnerPredicates`, `TestAnonymousOwnerRails` and `TestEntry`.

### Every live input has its owner's row

- The circuit holds each live input to a live row, in `AssertInputOwners`. Only a zero-key note on the delegate rail goes without.
- The circuit holds a ring note's nonzero key to the row's enrolled key under the tracking root. A default-ring note carries a key the ring never enrolled.
- The circuit refuses a hidden owner's zero-key input, since anyone who holds the opening computes that nullifier.
- The circuit holds live rows strictly ascending with zero rows last, except on the delegate rail, in `assertRowsAscending`.
- The tests are `TestInputPredicateOnEveryRail`, `TestZeroKeyInputs`, `TestDelegateInputOwners`, `TestOwnerCapacity`, and `TestRowsAscend` in `prover/circuits/policy`.

### The signer set is the run SPP authorizes

- The program reads the SPP owner run, deduplicates by first occurrence, and builds `signer_count` and `signer_chain`. Each entry must sign, and none can be a demanded co-signer.
- The program refuses a note-spending frame with an empty run on the signer and public-owner rails.
- On the hidden and public-owner rails the program refuses any signer other than the payer, the run, the co-signers and the funders, with `InvalidAnonymousSigner`.
- The circuit holds each member past the count to zero, and chains zero at a count of zero. It holds the count to zero on the delegate rail.
- The tests are `TestSignerSetVector` and `TestRailsSolve`.

### Every live ring output reads its owner's row

- The circuit holds a nonzero key to its owner's enrolled key under the tracking root, in `AssertOutputOwners`. A literal zero is refused.
- A zero-key output to an enrolled owner passes only while no salted payee read is active. Under a salted payee read a zero key needs the payee's row absent.
- An exit reads `Ring = 0`, so it stands outside the rule.
- A present row opens by its leaf, and an absent owner by the leaf that brackets it, in `prover/circuits/registry/tracking.go`.
- The tests are `TestOutputPredicateOnEveryRail`, and `TestTrackingOpeningRefusals` and `TestTrackingOpeningResolvesPresentAndAbsentOwners` in `prover/circuits/registry`.

### Policy sections switch from the rail and two statement values

- The circuit derives every gate once in `Rail.Gates`. Except on the delegate rail, a nonzero `policy_hash` sets `Screened`. A nonzero `own_root` sets `Outflow`.
- The program writes `policy_hash` and `own_root` through `RootRead::transfer`, so no prover bit clears a threshold.
- The circuit holds `policy_hash`, `own_root` and `curator_root` to zero on the delegate rail, in `assertBypass`.
- A disabled section keeps its range checks, table decoding and lookups over zero rows.
- The test is `TestDelegateBypass`, and the tests in `prover/circuits/policy` are `TestPooledPolicyModes`, `TestThresholdsBindOffAPolicy` and `TestDelegateClearsTheMask`.

### Every subject reads its lists from an authenticated record

- The circuit answers each query through a pool bound to a root, present or proven absent, in `resolveSubjects`. No prover list bit reaches a rule.
- `curatorColumns` projects list bits alone, and mint settings read the own pool.
- The circuit forces a present owner's salt to open its row's `list_tag`, then reads the record at the forced salted key. An owner proven absent reads off every private list.
- `RegistrySlots::load` refuses a salted source that pins another tracking registry. `LiveRoots::tracking` refuses a tracking revision below the highest floor of the salted sources.
- The tests in `programs/custom-ring/tests/rules/storage_root_rules.rs` are `a_tracking_root_below_the_salted_floor_is_refused_at_load` and `a_private_list_mapped_to_a_curator_on_another_tracking_registry_is_refused`.
- The tests in `prover/circuits/policy` are `TestPooledPolicyBindsSubjectReferences`, `TestRecordPoolBindsEveryActiveQuery`, `TestPublicAndPrivateBlocksAreTwoRules` and `TestPresentRowCannotSkipTheSaltedRead`.

### Every owner, payment and input asset meets its rules

- The circuit screens each live row under every sender rule, in `assertSenderRules`, whether or not that owner receives an output.
- The circuit screens each live output and withdrawal leg by owner and asset within its guard, in `assertPaymentRules`.
- A guard reads same-ring receipts net of the owner's own inputs, and exits and legs gross. Entry funding stays a receipt.
- The circuit screens each live input's asset under every unconditional asset rule, in `assertInputAssetRules`. A zero-value note therefore cannot carry a delisted asset past the rules.
- The tests in `prover/circuits/policy` are `TestEveryCoOwnerIsScreened`, `TestReceiptTable`, `TestAssetGuardNetsChange`, `TestZeroValueDelistedInputFailsAnUnconditionalAssetRule` and `TestPolicyWithdrawalBindingAndPadding`.

### The settled outputs are the audited outputs

- The circuit opens each slot once in `OpenSlots`, then hands one `shared.Output` to the tracking checks, the policy and the stream.
- The circuit reopens `private_tx_hash` in `bindTransaction`. A note called an address would leave the input chain SPP hashed.
- SPP holds each output's ring id to 0 or the ring's in `AssertRingMemberOrFree`. Its authority rail holds it to the ring's in `AssertRingMember`, and its exit selector lets an output leave.
- The circuit holds both data hashes to zero while `has_data` is clear, and opens them in the tail while it is set.
- The tests are `TestDataOutputs`, and `TestDataTails` in `prover/circuits/audit`.

### Every published blinding derives from the sealed key

- The circuit holds each published slot's blinding to the sealed key's derivation in `AssertBlinding`, a hidden dummy included. Omission removes a suffix, so no index moves.
- The circuit holds `tx_viewing_sk` to its clamped encoding, so one byte string names the key the auditor recovers.
- The circuit proves no freshness of that key or the salt. A resend repeats the key, and the salt gives it a different keystream.
- The tests in `prover/circuits/audit` are `TestSealedKeyStaysClamped` and `TestResendUnderAnotherSaltSealsAnotherStream`.

### Compact padding removes a suffix and nothing else

- The program parses `1 <= m <= N`, refuses a bitmap bit at or past `m`, and refuses a frame of any other length.
- The circuit reads `SelectCount(m, 1, N)`. A live note at or past `m` is refused, and every statement cell past `m` multiplies by zero.
- The key's cost does not fall with `m`.
- A hidden dummy is a published slot. Its hash enters `output_chain` and stays out of the private chain.
- The tests are `TestCompactFrames` in `prover/circuits/audit`, and `bitmap_bits_past_the_count_are_refused` in `program-libs/interface/tests/transact.rs`.

### The auditor stream opens every slot

- The program supplies the auditor key from the ring account, and hashes the transmitted envelope, records and tails from the frame.
- The circuit proves one key expansion and one `CTREncrypt` under `CRING/adt` over every region, in `SealStream`. `countedDigest` covers the transmitted envelope with its length as a tag.
- The circuit derives each record's kind from the slot, holds the owner key to the owner identity, and holds the mint to the asset. A slot's counter is fixed by its index.
- The auditor rebuilds each commitment and accepts only an exact match with the published hash. That check is the reader's, and the record proof makes it complete.
- The tests in `prover/circuits/audit` are `TestStreamVector`, `TestStreamRangesAreTheSharedVector`, `TestEveryRecordFieldIsSealed`, `TestKindFollowsTheSlot`, `TestReaderRebuildsEverySlot`, `TestZeroAndEnrolledKeysReadApart` and `TestRecordAtAnotherSlotFailsTheReader`.

### The envelope counts the spent notes and opens entry inputs

- The circuit seals `R` as the count of notes and `A` as the address bitmap, both from the slot classes. It binds `no_spend` in the statement as `R == 0`.
- The circuit refuses a default-ring input on a key with no entry capacity, since no evidence would open it.
- On an entry key the circuit derives the default bits from the slots, and seals each default-ring input's opening per input.
- No constraint binds a nullifier to an earlier record. The auditor's link is a reader check.
- The tests in `prover/circuits/audit` are `TestRealInputCountIsSealed`, `TestInputMapsBindAbsolutePositions`, `TestInputMapRefusesWitnessClassChangeWithSealedEvidence`, `TestAddressOnlyInputsSetNoSpend`, `TestNoSpendEqualsAZeroCount`, `TestDefaultInputNeedsEntryCapacity`, `TestDefaultBitsAndEvidenceFollowTheSlots`, `TestEntryEvidenceServesMixedOwners` and `TestReaderRebuildsADefaultInput`.

### Each owner's charged outflow stays within the asset's limits

- The circuit computes `debit`, `kept`, `charge` and the charged outflow per row and asset in `constrainOutflow`. The rows' order alone fixes each share.
- The circuit holds each asset's peak charged outflow to a nonzero `cap`. It consumes the statement's gross and does not rebuild it from legs.
- The program folds settled legs into `PublicSlots`, and the gross per asset excludes deposits.
- The tests in `prover/circuits/policy` are `TestDebitKeepsOwnersApart`, `TestSameOwnerExitCountsAsLeaving`, `TestDepositOffsetsASingleOwnersDebit`, `TestOutflowSettlesAtItselfAndRefusesOneBelow`, `TestOwnerPastTheCapBesideOneUnderIt`, `TestOutflowWithNothingLeaving`, `TestDebitVector` and `TestQuantitiesVector`.

### The approval mask is proven and the program acts on it

- The circuit sets `OUTFLOW` from each peak and `WITHDRAWAL` from each gross, and holds the statement's `approval_mask` equal to them.
- The program demands the class of each set bit, and refuses a set bit on the delegate rail.
- The circuit binds a nonzero `approval_totals` to the outflow section's values under a blinder, and refuses one while the section is off.
- The test is `TestApprovalTotalsReachTheStatement`, and the tests in `prover/circuits/policy` are `TestWithdrawalBitReadsTheGross`, `TestApprovalTotalsBindTheProvedOutflow`, `TestApprovalTotalsCoverPrivateAssets`, `TestApprovalTotalsCannotUnderstateOutflow` and `TestApprovalTotalsNeedTheOutflowSection`.

### Each signer's data-bearing outputs are counted

- SPP takes one signature as authorization for every data-bearing output of that signer. A selective opening cannot show the sender named them all.
- The circuit counts each run entry's live slots with a nonzero `data_hash`, and holds the packed element to those counts, in `SignerDataCounts`. An entry past the run reads zero.
- A member past the last entry must own no data-bearing slot, since it has no bits to publish a count.
- The element publishes which signers receive data-bearing outputs and how many.
- The tests are `TestSignerDataCountsOnTheRails`, `TestSignerDataCountsRefusedOnTheRails`, `TestEveryKeyFitsTheSignerDataEncoding`, and `TestRunsPastTheLastEntry` in `prover/circuits/audit`.

### Roots come from the ring's registries

- The program reads each root live at the frame's revision, from the account the ring binds, through `RootRead`.
- The program refuses a records registry of another ring at `Initialize`. It refuses a salted source that pins another tracking registry at `Initialize` and `UpdatePolicy`, before it stores the policy. It refuses one again when a frame reads it.
- The tests are `programs/custom-ring/tests/rules/storage_root_rules.rs` and `programs/custom-ring/tests/rules/operator_rules.rs`.

### An enrollment binds its owner and its seal

- The Storage program computes the member from the signer. It takes the ring id and the auditor key from the tracking registry the ring created.
- The circuit holds the nullifier key and the list tag to nonzero secrets, and seals both secrets under `CRING/nfk`, in `RegisterKeyCircuit`.
- The program computes each applied entry from its account and refuses an account already applied. `ApplyEnrollmentsCircuit` inserts each owner once at the next index and keeps the tree sorted, so no insert changes a leaf's member, nullifier key, ciphertext hash or list tag.
- The proof does not show that the secret came from a particular derivation. A wallet that seals another secret harms itself alone.
- The tests in `prover/circuits/registry` are `TestRegisterKeySealsTheEnrolledSecret`, `TestRegisterKeyRefusals`, `TestApplyEnrollmentsAppliesEntriesInNamedOrder`, `TestApplyEnrollmentsRefusals` and `TestApplyEnrollmentsAtCapacity`. The tests in `programs/storage/tests/lifecycle.rs` are `a_first_enrollment_needs_the_owner_and_a_proof_the_pairing_accepts`, `a_rotation_moves_the_viewing_key_with_no_proof` and `anyone_applies_named_enrollments_with_no_authority_signature`. `a_pda_enrolls_and_applies_its_key_on_the_validator` in `program-tests/custom-ring/tests/ring/sanity.rs` runs both steps on the validator.

### A private owner write proves its owner's row and raises the floor

- The Storage program classes each write from its masks. A private write needs its owner's row unless an asset entry names a mint whose hash is the member.
- A batch with a private write proves under the private apply key. Its statement adds the private write bitmap and the tracking root at the revision the update names. The program reads that root from the tracking registry the source pins.
- `ApplyRecordsCircuit` proves that `ListKey(member, salt)` equals the written member, and that the salt opens the `list_tag` of the owner's row under that root. The row must hold a nonzero nullifier key, and the write a private list bit.
- After the proof the program raises `tracking_floor` to the revision together with the new root. A refusal writes neither.
- The tests are `TestPrivateWriteOpensTheOwnersTrackingRow` and `TestPrivateKeyRefusesAPublicMask` in `prover/ringtest/ringregistry`, and `a_private_write_refuses_a_missing_or_substituted_tracking_registry` and `private_proof_failure_and_stale_revision_keep_the_root_and_floor` in `programs/storage/tests/lifecycle.rs`.

### A policy update applies its writes in order

- The program chains each entry from the instruction data, and takes the grace from the statement's restrictive bit.
- `ApplyRecordsCircuit` keeps list bits outside each mask, moves mint settings only under the entry's flag, and keeps the records sorted. It sets the restrictive bit exactly when an active write tightens a list, guard or bound, writes a private list or changes an asset limit. It reads an absent member's old fields as zero.
- The tests in `prover/circuits/registry` are `TestApplyRecordsAppliesWritesInOrder`, `TestApplyRecordsRefusals` and `TestMintRecordsMatchRustAndPreserveSettings`.

### A hidden sender stays apart from the public parties

- The program supplies the identities of the payer, each co-signer, each funder and a hidden sender's withdrawal destination as party cells.
- The circuit refuses each nonzero party that equals the hidden owner, in `AssertAnonymousParties`.
- No layer checks a key only linked to the sender.
- The test is `TestAnonymousOwnerRails`.

### A merge seals its output and keeps one owner

- The program forwards SPP's merge and reads the tracking root under the ring authority alone.
- The circuit holds the output hash to the record's fields and the seed's blinding. It seals the record and the seed under `CRING/mrg`.
- The circuit holds a nonzero key to its owner's row and refuses that owner as the payer. A zero key reads no row, and the statement names the owner for SPP's signature.
- SPP's proof ties every input to that owner, asset and sum, and refuses a note with a data hash. No list, guard, cap or co-signer rule is proven.
- The tests are `TestMergeRefusals`, `TestMergeRecordOffItsOpening`, `TestMergeTrackingRow`, `TestMergeModes`, `TestMergeZeroKeyIgnoresEveryRow`, `TestMergePayer` and `TestMergeRecordRebuildsTheOutput` in `prover/circuits`.

### A deposit is a transfer that spends no note

- The frame sets `no_spend`, every SPP input is a dummy and a deposit leg funds the outputs. The program checks the funder's signature as on any public leg.
- Each output opens to the auditor, holds its key to its owner's row and meets the payment rules, through the transfer sections above. No row is live, so no sender rule binds.
- No ring instruction signs SPP's proofless ring deposit.
- The test is `TestPublicDepositIntoTheRing` in `prover/circuits/transfer`.

## What no proof covers

- The circuit constrains no recipient body, slot tag, sender bundle or reply. `the_external_data_hash_binds_every_delivery_byte` in `program-libs/interface/tests/transact.rs` pins the byte binding.
- A reader rebuilds a commitment under its own keys, and that match is its only authentication. [Recipient delivery](audit-and-recovery.md#recipient-delivery) states what recovers a bad tag and a bad body.
- A reader's coverage describes finalized history, and no proof backs it. [Reading through Ring RPC](audit-and-recovery.md#reading-through-ring-rpc) states what it claims.
- A hidden owner's privacy rests on the conditions in [privacy](privacy.md). No constraint covers them.

## Review practice

Keep each output's owner, asset, amount, class and hash together through a section handoff. Pairing one output's fields with another output's hash screens a payment other than the settled one.

For a predicate test, construct an invalid transaction and recompute its statement before solving. A failure otherwise proves only that the public hash changed. For a binding test, keep the proof and change a program-derived field or a settled leg.

Compare ordered elements and counts before hashes when you test across languages. A fixture that repeats the circuit's layout cannot prove agreement with another language. Use compiled BN254 constraints and proof verification alongside solve tests, and check the verifier's public input and commitment structure for each key.

Treat circuit capacity, SPP shape support and serialized transaction fit as separate limits. Measure the assembled frame with its payer, co-signer, settlement accounts and header. A shape with no key is a catalog choice, and an SDK size refusal does not establish a circuit or program restriction.
