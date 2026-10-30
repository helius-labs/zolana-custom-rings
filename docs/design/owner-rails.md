# Owner rails

SPP authorizes a ring spend in one of four ways. The instruction, the ring mode and one frame flag pick the rail, and each rail gives the policy a different sender. [Spec](../spec.md)

## The rails

1. **Signer rail.** Each input owner signs the Solana transaction. A policy transfer has exactly one owner, and the policy reads it as the sender.
2. **In-proof rail.** The owner signs the SPP message inside the SPP proof, and SPP publishes the owner's key. Any payer sends the transaction.
3. **Anonymous rail.** A hidden owner signs inside the SPP proof. The policy reads a blinded commitment to the sender. Only the payer and a demanded co-signer sign the transaction.
4. **Authority rail.** The ring PDA moves notes with no owner signature. The delegate signs instead, and every note stays in the ring.

## Why the in-proof rail exists

- Ring RPC relays every wallet spend and pays its fee. On the signer rail the owner must sign the final transaction after Ring RPC builds it.
- Zolana's in-proof owner circuit serves default-ring transfers only. The ring needs the same authorization on SPP ring transfers.
- Its twin enters zolana as new circuit files, and the audited circuits stay untouched.
- With it, one wallet signature over the message hash lets Ring RPC prove, pay and send.

## The rule that makes it sound

- An in-proof owner could spend nothing while Solana owner signers spend the inputs. The policy would then screen the wrong sender.
- The ring program refuses any owner signer on the in-proof rail. Every input is then the in-proof owner's, and the policy sender is that owner.

## Why the signer rail stays

- It needs no SPP build with the in-proof feature.
- It serves owners and operators who send their own transaction, the operator CLI and the tests included.

## What each rail publishes

- Signer rail: the owner signer, each output's recipient viewing key and, on a policy ring, each output's owner identity.
- In-proof rail: the owner key in place of the signer, and each output's owner key beside its viewing key.
- Anonymous rail: one view tag per ring output, the sender bundle, each exit owner and, on a policy ring, the sender commitment. A default-ring spend also publishes the hidden owner's key.
- Authority rail: the delegate, and the outputs as the signer rail publishes them.

## Separation from the hidden owner

- On the anonymous rail SPP separates the hidden owner only from the owner signers.
- The ring's audit proof also shows the payer, the co-signer and the withdrawal destination differ from the hidden owner.
- No layer checks a key that is only linked to the owner.
