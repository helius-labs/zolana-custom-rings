# Privacy by mode

The confidential mode and the anonymous mode differ at the sender and the recipients. Amounts, assets and blindings stay private from chain observers in both. [Spec](../spec.md)

## Confidential rings

- Chain observers see the sender, in the owner run or as the in-proof owner. An authority transfer shows the delegate in its place.
- Each slot publishes the last 8 bytes of its recipient's viewing key as its tag. Payments to one recipient therefore link to each other, and a dictionary of known viewing keys names that recipient.
- They see each exit owner and each public leg's account, asset and amount.
- They do not see amounts, assets, blindings or which notes a transfer spends.
- A confidential deposit's tag is the recipient's viewing key. The tag links the funder to the recipient.

## Anonymous rings

- Chain observers see the payer, the published input count, the published output count and the change slots by their zero tag. They see a short tag on each other non-exit slot, and the sender bundle with its tag.
- A public co-owner signs in the open. Its link to the transfer is public, and the hidden owner's stays hidden.
- Under `HAS_DATA` the program requires one payload width for every non-exit slot of the frame, dummies included. Data can increase that width, and observers see whether a frame carries payloads.
- A reply has one length per frame, and a slot with no reply carries random bytes of that length. Observers see whether a frame carries reply bytes.
- They see each exit owner and each public leg.
- They do not see the hidden sender, the recipients, the amounts, the assets or the spent notes.
- The hiding holds only while all of these hold:
  1. The payer, each funder and each other signer do not link to the owner.
  2. The transfer spends ring notes only, none under the zero key. A default-ring spend publishes its owner, and a zero-key spend names it to anyone who holds the note's opening.
  3. No exit or withdrawal pays a key linked to the owner.
  4. An anonymous deposit takes a sender or request tag. The SDK refuses a viewing key tag for a payment, since it links every such deposit to one recipient.
  5. The wallet trusts its indexer, which pairs each spent leaf with its nullifier.
  6. The prover runs locally or in an attested enclave.
  7. The rules admit many owners. An allow rule bounds every sender and recipient to its list.
  8. Deposit and withdrawal amounts and timing do not single out a later spend.
- No proof holds a tag to any form. A sender can repeat a tag or encode data in one, and two slots under equal tags link to each other.
- A published `ring_data_hash` of an application value can link notes. No proof holds it to a salted commitment.

## Every mode

- Enrollment is public. An `Enroll` names the owner as a signer and stores its nullifier key, list tag and viewing key in an account. Anyone sees that a wallet enrolled on a ring.
- A tracking authorization holds the owner's viewing key for one ring. A leaked viewing secret opens the bodies sealed to that key on every ring whose authorization holds it. A rotation on one ring moves that ring alone to a new key.
- A transfer, deposit or nonzero-key merge publishes the tracking revision it reads. The revision shows that each row the proof opens existed at that revision, and names no owner.
- A private write raises the source's tracking floor to the revision its rows open under. The floor shows that the written owner was enrolled by that revision.
- A public record write names its member. A rule table is public, so observers see which lists a ring screens and who is on the public ones.
- A deposit publishes the funder, the asset and each amount.
- A merge links its input notes to one owner. A zero-key merge also publishes that owner.

## Private lists

- A private entry is an ordinary record under a member key salted per owner. The key is pseudorandom to anyone without that owner's salt.
- List bits on a salted record stay visible with no identity, so per-list counts and update timing are public.
- A holder of an owner's salt links the owner to its record and reads the record's list bits. A published ring address contains the salt, so every reader of the address can make that link.
- The salt is final, so a disclosed salt reveals status permanently.
- An unenrolled identity has no salt, so a curator can list it only on a public list.
- A transaction can read a salted list. The party that proves the transaction holds the witness and learns the salts and list status of the other enrolled owners in that proof.

## Who else sees what

- The auditor opens every output record and merge record. With an owner's sealed secret it links that owner's spends, see [nullifier secrets](audit-and-recovery.md#nullifier-secrets).
- The auditor reads each owner's list salt from the enrollment ciphertext. A curator learns the salt of each owner it writes for.
- A zero-key note's sender computes its nullifier and sees when the note is spent.
- A reader sees what its grant covers, blindings included, and keeps it after a revocation.
- Ring RPC as relayer receives every secret the proofs need. It links the owner's spends and opens the outputs, so a relayed transfer is anonymous only toward a trusted Ring RPC.
- Ring RPC as co-signer sees each owner's charged outflow of each asset. It reads them from the frame with the auditor key.
- An outside co-signer that reads exact totals sees each asset's totals and no sender list.
- The ring indexer sees which members a client opens, before the transfer lands.
- Photon sees which leaf each nullifier spends, and the deposit tags of one viewing key grouped per request. It sees which ring history a scanning wallet reads, and from which slot.
