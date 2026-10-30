# Owner rails

SPP authorizes a ring spend in one of four ways. The instruction, the ring mode and one frame flag pick the rail, and each rail gives the policy a different sender. [Spec](../spec.md)

## The rails

1. **Signer rail.** Each input owner signs the Solana transaction. A policy transfer has exactly one owner, and the policy reads it as the sender.
2. **In-proof rail.** The owner signs the SPP message inside the proof of SPP's anonymous rail, and SPP hides the owner. The delivered audit publishes the owner as the sender. Any payer sends the transaction.
3. **Anonymous rail.** A hidden owner signs inside the SPP proof. The policy reads a blinded commitment to the sender. Only the payer and a demanded co-signer sign the transaction.
4. **Authority rail.** The ring PDA moves notes with no owner signature. The delegate signs instead, and every note stays in the ring.

## Why the in-proof rail exists

- Ring RPC relays and pays for a wallet spend unless it has a deposit leg or needs an outside co-signer. A relayed anonymous or confidential transfer names no owner signer, its owner signs inside the proof.
- Zolana's in-proof owner circuit serves default-ring transfers only. SPP's anonymous rail verifies the owner's Ed25519 signature inside the proof on ring transfers, and the ring uses it with no default owner tag.
- Follows the maintainer's suggestion; keeps no new SPP circuit.
- With it, one wallet signature over the message hash lets Ring RPC prove, pay and send.

## The rule that makes it sound

- An in-proof owner could spend nothing while Solana owner signers spend the inputs. The policy would then screen the wrong sender.
- The ring program refuses any owner signer on the in-proof rail. Every input is then SPP's hidden owner's.
- SPP hides that owner. The delivered sender audit holds every spent UTXO to the sender it publishes and reopens SPP's `private_tx_hash` over the same inputs and outputs. The hidden owner is then the published sender, and the policy reads it as the sender.
- The owner is public on a confidential ring, so the anonymous rail's party separation does not apply. The ring program refuses a co-signer that is the owner.

## Limits of the in-proof rail

- It spends ring notes only. A default-ring input makes SPP publish the owner it hides, so the SDKs refuse it and the signer rail spends it.
- SPP refuses an exit to the sender's own default-ring identity on a ring spend. Exits keep their scheme 3 data, and SPP publishes each exit owner.
- The sender key holds one input class per output capacity. The program refuses a transfer that publishes more inputs than the class holds.

## Why the signer rail stays

- It spends default-ring notes, and its delivered audit opens no spent input.
- It serves owners and operators who send their own transaction, the operator CLI and the tests included.

## What each rail publishes

- Signer rail: the owner signer, each output's recipient viewing key and, on a policy ring, each output's owner identity.
- In-proof rail: the owner key in the transfer data in place of the signer, and the outputs as the signer rail publishes them.
- Anonymous rail: one view tag per ring output, the sender bundle, each exit owner and, on a policy ring, the sender commitment. A default-ring spend also publishes the hidden owner's key.
- Authority rail: the delegate, and the outputs as the signer rail publishes them.

## Separation from the hidden owner

- On the anonymous rail SPP separates the hidden owner only from the owner signers.
- The ring's audit proof also shows the payer, the co-signer and the withdrawal destination differ from the hidden owner.
- No layer checks a key that is only linked to the owner.
