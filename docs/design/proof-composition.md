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
2. The circuit opens each output through `audit.OpenSlots` and each input through `OpenInputs`, both through `shared.UtxoWires.OpenSlot`, which admits a note or a dummy. Audit, policy and the tracking checks read those wires, so no two sections describe different notes.
3. The circuit holds its inputs to SPP's spent notes in note order, then dummies, and its outputs to SPP's output form, dummies last. It reopens `private_tx_hash` over the opened notes, the real outputs, the address chain and the blinding. The address chain is a private witness the shared hash alone checks. SPP's proof binds the same hash to its nullifiers and outputs, and both proofs keep dummies last, so the opened slots are the slots SPP settles at SPP's indices.
4. The program hands SPP the frame's output hashes and binds each slot's record through `record_chain`. SPP zero-fills past `m`, and the circuit refuses a note at or past `m`.
5. SPP derives every output blinding and `private_tx_blinding` from one seed. The circuit derives `private_tx_blinding` as `TXPB(n0, CRBS(tx_viewing_sk, salt))` from the sealed key and reopens `private_tx_hash` over it, so the sealed key fixes SPP's seed. SPP then holds each published blinding to that seed, a dummy's included.
6. The program reads each registry root live from the account the ring binds. A record opening under that root therefore carries the write rules of the Storage program and of its apply circuits.
7. SPP's external data hash covers each frame's tags, payloads and messages. It binds the submitted bytes and proves nothing about what they contain.

No Go test composes the ring proof with SPP's full proof. Steps 3, 4 and 7 are true across the program binding. Step 3's address witness is tested in `TestAddressChainIsBoundThroughThePrivateTransactionHash`. Step 5 is tested against SPP's own blinding and `private_tx_hash` checks in `blinding_composition_test.go`.

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

### Every input slot is a note or a canonical dummy

- The circuit opens each slot in `OpenInputs` through `OpenSlot`. A dummy carries nothing but its blinding, as SPP's `CheckDummy` reads it. No address enters a ring input slot.
- The notes come in SPP's note order, then the dummies, in `AssertDummiesLast`. The circuit holds `input_count` to at least one through `SelectCount`, and refuses a note at or past the count.
- The program sets `input_count` to the frame's nullifier count. No statement element carries a nullifier but `n0`, so the proof names no note position.
- The circuit takes the address chain as a private witness, and `private_tx_hash` alone checks it.
- Position `k` is note `k`, the order the entry records and the hidden rail read. The hidden rail holds slot 0 to a note.
- The tests are `TestInputOrder`, `TestAddressSlots`, `TestInputsHoldNotesThenDummies`, `TestInputCompositionRefusesAnotherOrder`, `TestInputCompositionFillsTheEntryBitmap`, `TestAddressChainIsBoundThroughThePrivateTransactionHash` and `TestHiddenOwnerRequiresAFirstNote`, and `TestAnInputSlotHoldsANoteOrADummy` in `prover/circuits/audit`.

### Every live input answers its rail's owner predicate

- Except on the delegate rail, the circuit holds each live input to the run, the hidden owner or the in-proof sender, in `AssertOwners`.
- The circuit reads the hidden owner from input 0, holds that input live and holds the owner outside the run.
- The circuit holds each live ring note to the transfer's ring, in `AssertRingNotes`. Only a key with entry capacity also spends a default-ring note.
- SPP verifies each owner signer, and the hidden owner's signature inside its proof. SPP's authority rail holds every input to the ring.
- The tests are `TestOwnerPredicates`, `TestAnonymousOwnerRails` and `TestEntry`.

### Every live input has its owner's row

- The circuit holds each live input to a live row, in `AssertInputOwners`. Only a zero-key note on the delegate rail goes without.
- The circuit holds a ring note's nonzero key to the row's enrolled key under the tracking root. A default-ring note carries a key the ring never enrolled.
- A hidden owner may spend a zero-key note. Anyone who holds the opening computes that nullifier and names the spender, the wallet decides.
- The circuit holds live rows strictly ascending with zero rows last, except on the delegate rail, in `assertRowsAscending`.
- The tests are `TestInputPredicateOnEveryRail`, `TestZeroKeyInputs`, `TestDelegateInputOwners`, `TestOwnerCapacity`, and `TestRowsAscend` in `prover/circuits/policy`.

### The signer set is the run SPP authorizes

- The program reads the SPP owner run, deduplicates by first occurrence, and builds `signer_count` and `signer_chain`. Each entry must sign, and none can be a demanded co-signer.
- The program refuses a note-spending frame with an empty run on the signer and public-owner rails.
- On the anonymous rails the program takes any other signer. The proof holds the hidden owner out of the run, and the payer, a funder or another signer may still name it.
- The circuit holds each member past the count to zero, and chains zero at a count of zero. It holds the count to zero on the delegate rail.
- The tests are `TestSignerSetVector` and `TestRailsSolve`.

### A zero-key ring output reads its owner's row

- A ring output may carry any nonzero key, in `AssertOutputOwners`. Its note spends only once that key is its owner's enrolled key. A literal zero is refused.
- A zero-key output requires owner absence at the accepted tracking root. A retained root can prove absence during the enrollment grace period.
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
- An owner reads its public lists at `ListKey(owner, 0)`, and an asset at its asset field.
- The circuit forces a present owner's salt to open its row's `list_tag`, then reads the record at the forced salted key. An owner proven absent reads off every private list. Registration refuses a zero salt, so no private record sits on the public key.
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
- The circuit reopens `private_tx_hash` in `bindTransaction`. A note relabelled as an address changes the note chain, and `private_tx_hash` fails.
- The circuit holds every output slot to the UTXO or the dummy domain, dummies last, and a dummy to zero fields but its blinding. Ring slot `i` is then SPP slot `i` with no output hash in the statement.
- SPP holds each output's ring id to 0 or the ring's in `AssertRingMemberOrFree`. Its authority rail holds it to the ring's in `AssertRingMember`, and its exit selector lets an output leave.
- The data hashes enter no ring constraint but the UTXO hash, and no layout bit reads them. A malformed payload loses them for the recipient and the auditor.
- The tests are `TestDataOutputs`, and `TestOutputSlotsKeepSppForm` and `TestDataHashesNeedNoLayoutBit` in `prover/circuits/audit`.

### Every published blinding derives from the sealed key

- The circuit derives `private_tx_blinding` from the sealed key in `OpenEnvelope` and binds it in `bindTransaction`. SPP holds each published slot's blinding to the same seed, a hidden dummy included. Omission removes a suffix, so no index moves.
- The ring proof solves with a changed output blinding, and SPP's derivation refuses it.
- The circuit holds `tx_viewing_sk` to its clamped encoding, so one byte string names the key the auditor recovers.
- The circuit proves no freshness of that key or the salt. A resend repeats the key, and the salt gives it a different keystream.
- The tests are `TestSppSeedComposesOnEveryRail`, `TestRingRefusesAnotherSeed`, `TestRingRefusesAnotherTransactionBlinding` and `TestSppRefusesAChangedOutputBlinding`.
- The tests in `prover/circuits/audit` are `TestSealedKeyStaysClamped` and `TestResendUnderAnotherSaltSealsAnotherStream`.

### Compact padding removes a suffix and nothing else

- The program parses `1 <= m <= N`, refuses a bitmap bit at or past `m`, and refuses a frame of any other length.
- The circuit reads `SelectCount(m, 1, N)`. A live note at or past `m` is refused, every record cell past `m` multiplies by zero, and the key digest stops at `m`.
- The key's cost does not fall with `m`.
- A hidden dummy is a published slot. It has a zero record and stays out of the private chain.
- The tests are `TestCompactFrames` in `prover/circuits/audit`, and `bitmap_bits_past_the_count_are_refused` in `program-libs/interface/tests/transact.rs`.

### Every slot's record opens to its key and the auditor reads the key

- The program supplies the auditor key from the ring account. It hashes the transmitted envelope and recipient keys into `envelope_digest`, and each slot's record into `record_chain`, from the frame.
- The circuit seals each slot's record to its supplied recipient key under that slot's secret, in `RecordChain`. It refuses a noncanonical key and a zero agreement. No constraint ties the key to the intended recipient.
- The circuit proves one key expansion and one `CTREncrypt` under `CRING/adt` over the envelope and every recipient key, in `SealStream`. `countedDigest` covers the transmitted envelope over `n` and the keys over `m`, each with its length as a tag.
- The circuit derives each record's kind from the slot, holds the owner key to the owner identity, the mint to the asset and the blinding to the slot's blinding wire. A slot's key counter is fixed by its index.
- The auditor rebuilds each commitment and accepts only an exact match with the published hash. That check is the reader's, and the record proof makes it complete for every slot whose payload carries its data hashes.
- The test in `prover/circuits/transfer` is `TestWrongAuditorRecordFailsAtTheStatement`. The tests in `prover/circuits/audit` are `TestStreamVector`, `TestStreamRangesAreTheSharedVector`, `TestStreamRegionsHoldTheirPlaintext`, `TestRecordsAreSealedToTheSealedRecipientKey`, `TestEveryRecordFieldIsSealed`, `TestKindFollowsTheSlot`, `TestSlotPredicatesRefuseBeforeTheBinding`, `TestReaderRebuildsEverySlot`, `TestZeroAndEnrolledKeysReadApart` and `TestRecordAtAnotherSlotFailsTheReader`.

### The envelope counts the spent notes and names entry inputs

- The circuit seals `R` as the count of notes from the slots. It binds `no_spend` in the statement as `R == 0`.
- The circuit refuses a default-ring input on a key with no entry capacity, since no evidence would open it.
- On an entry key the circuit derives the default bits from the slots, and seals each default-ring note's record at its note position. The record names the owner key, nullifier key, amount, mint and the spent commitment the input section opened.
- No constraint binds a nullifier to an earlier record. The auditor's link is a reader check, and `R` is its completeness check.
- The tests in `prover/circuits/audit` are `TestRealInputCountIsSealed`, `TestNoSpendEqualsAZeroCount`, `TestDefaultInputNeedsEntryCapacity`, `TestDefaultBitsAndRecordsFollowTheSlots`, `TestEntryRecordsFollowNoteOrder`, `TestEntryRecordsServeMixedOwners` and `TestReaderReadsADefaultInput`.

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

### A relayed signer opens every output before it signs

- SPP takes one signature as authorization for every data-bearing output of that signer. No statement element counts them.
- A relayed signer's SDK requires one opening per published slot, each rebuilding its slot's commitment, before it signs. That check is the reader's and binds nobody else.
- The test is `a_data_recipient_reads_every_slot_and_signs` in `sdk-libs/sdk/src/tests/operations/relay.rs`.

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

### A hidden sender approves none of its own outflow

- The program supplies each co-signer's identity as a party cell on the anonymous frame.
- The circuit refuses each nonzero cell that equals the hidden owner, in `AssertAnonymousParties`.
- The payer, a funder and the withdrawal destination take no cell, and may name the hidden owner.
- The test is `TestAnonymousOwnerRails`.

### A merge seals its output and keeps one owner

- The program forwards SPP's merge and reads the tracking root under the ring authority alone.
- The circuit holds the output hash to the record's fields and the seed's blinding. It seals the record and the seed under `CRING/mro` to the owner's viewing key, and `eph_sk` with that key under `CRING/mrg` to the auditor.
- The circuit holds a nonzero key to its owner's row. A zero key reads no row, and the statement names the owner for SPP's signature. No constraint holds the payer apart from the owner.
- SPP's proof ties every input to that owner, asset and sum, and refuses a note with a data hash. No list, guard, cap or co-signer rule is proven.
- The tests are `TestMergeRefusals`, `TestMergeRecordOffItsOpening`, `TestMergeRecordIsSealedToTheEnvelopesKey`, `TestMergeTrackingRow`, `TestMergeModes`, `TestMergeZeroKeyIgnoresEveryRow`, `TestMergePayer` and `TestMergeRecordRebuildsTheOutput` in `prover/circuits`.

### A deposit is a transfer that spends no note

- The frame sets `no_spend`, every SPP input is a dummy and a deposit leg funds the outputs. The program checks the funder's signature as on any public leg.
- Each output opens to the auditor, holds its key to its owner's row and meets the payment rules, through the transfer sections above. No row is live, so no sender rule binds.
- No ring instruction signs SPP's proofless ring deposit.
- The test is `TestPublicDepositIntoTheRing` in `prover/circuits/transfer`.

## What no proof covers

- The circuit constrains no payload, slot tag, sender bundle or reply, and no recipient key choice. `the_external_data_hash_binds_every_delivery_byte` in `program-libs/interface/tests/transact.rs` pins the byte binding.
- A reader rebuilds a commitment under its own keys, and that match is its only authentication. [Recipient delivery](audit-and-recovery.md#recipient-delivery) states what recovers a bad tag, a wrong key and a bad payload.
- A reader's coverage describes finalized history, and no proof backs it. [Reading through Ring RPC](audit-and-recovery.md#reading-through-ring-rpc) states what it claims.
- A hidden owner's privacy rests on the conditions in [privacy](privacy.md). No constraint covers them.

## Review practice

Keep each output's owner, asset, amount, class and hash together through a section handoff. Pairing one output's fields with another output's hash screens a payment other than the settled one.

For a predicate test, construct an invalid transaction and recompute its statement before solving. A failure otherwise proves only that the public hash changed. For a binding test, keep the proof and change a program-derived field or a settled leg.

Compare ordered elements and counts before hashes when you test across languages. A fixture that repeats the circuit's layout cannot prove agreement with another language. Use compiled BN254 constraints and proof verification alongside solve tests, and check the verifier's public input and commitment structure for each key.

Treat circuit capacity, SPP shape support and serialized transaction fit as separate limits. Measure the assembled frame with its payer, co-signer, settlement accounts and header. A shape with no key is a catalog choice, and an SDK size refusal does not establish a circuit or program restriction.
