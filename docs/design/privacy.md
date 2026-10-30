# Privacy by mode

The confidential modes and the anonymous mode differ at the sender and the recipients. Amounts, assets and blindings stay private from chain observers in both. [Spec](../spec.md)

## Confidential rings

- Chain observers see the sender, each recipient's viewing key and, on a policy ring, each output's owner identity.
- The in-proof rail also publishes each output's owner key. An authority transfer shows the delegate in place of the sender.
- They see each exit owner and each public leg's account, asset and amount.
- They do not see amounts, assets, blindings or which notes a transfer spends.
- Every payment to one recipient carries the same viewing key, and the zolana registry maps a registered viewing key to its owner. Payments to one recipient link to each other and name it.
- A deposit's view tag is the recipient's viewing key, which links the funder to the recipient.

## Anonymous rings

- Chain observers see the payer and the spent note count. They see one view tag and one body length per ring output, and the sender bundle.
- They see each exit owner, each public leg and, on a policy ring, a blinded sender commitment.
- They do not see the sender, the recipients, the amounts, the assets or the spent notes.
- The hiding holds only while all of these hold:
  1. The payer does not link to the owner.
  2. The transfer spends ring notes only. A default-ring spend publishes its owner.
  3. No exit or withdrawal pays a key linked to the owner.
  4. A first payment takes a request tag. The bootstrap tag is the recipient's viewing key and links every bootstrap payment to it.
  5. The wallet trusts its indexer, which pairs each spent leaf with its nullifier.
  6. The prover runs locally or in an attested enclave.
  7. The rules admit many owners. An allow rule bounds every sender and recipient to the public list.
  8. Deposit and withdrawal amounts and timing do not single out a later spend.
- Equal view tags link both outputs. A wallet that pays before it syncs its own history can repeat a tag.

## Every mode

- Records are public. A record write names its member, and an escrow write names the owner's Solana key.
- The rule table is public, so observers see which lists a ring screens and who is on them.
- A deposit publishes the funder, the asset and each amount.
- A merge links its input notes to one owner.

## Who else sees what

- The auditor opens every output, deposit and merge and every hidden sender. With an escrowed nullifier secret it also links that owner's spends.
- A reader sees what its grant covers, blindings included, and keeps it after a revocation.
- Ring RPC as relayer receives every secret the proofs need. It links the owner's spends and opens the outputs, so a relayed transfer is anonymous only toward a trusted Ring RPC.
- Ring RPC as co-signer sees the sender and each asset's flow.
- The ring indexer sees which members a client opens, before the transfer lands.
- Photon sees which leaf each nullifier spends, and the tags of one viewing key grouped per request.
