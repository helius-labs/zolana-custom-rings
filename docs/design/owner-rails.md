# Owner rails

One transfer circuit serves every rail, and three statement bits select it. The instruction tag, the ring mode and the frame flags fix those bits. Each rail gives the policy the same owner rows through a different authorization. [Spec](../spec.md)

## The rails

1. **Signer rail.** Each public owner signs the Solana transaction, and the statement binds the deduplicated owner run. A confidential ring uses it, and a frame of public legs alone takes an empty run.
2. **In-proof rail.** A confidential ring's owner signs inside the proof of SPP's anonymous rail, and the statement publishes that owner as the sender. Any payer sends the transaction, and signing co-owners can sit beside it.
3. **Hidden rail.** An anonymous ring's hidden owner signs inside the SPP proof. Input 0 names that owner, and the owner stays outside the published run. Public co-owners can sign beside it.
4. **Public-owner rail.** An anonymous ring's frame sets `PUBLIC_OWNERS`, every live owner signs in the open and SPP's confidential rail settles it. Recipients stay hidden.
5. **Delegate rail.** `AuthorityTransfer` moves notes with no owner signature. The configured delegate signs, and the run stays empty because a published run would name the owner whose notes move.

An entry key is not a rail. It adds a default-ring input to the signer, hidden or public-owner rail. The delegate rail holds every input to the ring, so it spends no default-ring note.

## Owner rows

- Except on the delegate rail, a key's rows contain the distinct live input owners, strictly ascending with zero rows last. No prover input orders them.
- Every live input needs its owner's row, whatever the rail. The sender rules, attribution and the auditor's nullifier all read rows.
- A live ring input under a nonzero key must match its owner's enrolled key under the tracking root.
- A default-ring input needs a row and no key match, since the ring never enrolled that key.
- On the delegate rail a zero-key note alone goes without a row, since no policy reads the rows there.
- A subject past a key's rows has no valid proof. The SDK selects the first key that fits the spend, and it refuses by name a spend no key fits.

## Why the in-proof rail exists

- Ring RPC relays and pays for a wallet transfer. A relayed confidential transfer needs one wallet signature over the message hash, then Ring RPC proves, pays and sends.
- The SDK refuses a default-ring input on the rail, since SPP would publish the owner it hides.
- The proof reopens SPP's `private_tx_hash` over the same inputs and outputs, and holds each live input to the published sender or the run.
- The program refuses a co-signer that is the in-proof owner.

## Why the signer rail stays

- It takes several owners in one transfer, and each signs the transaction.
- It serves owners and operators who send their own transaction.

## Zero-key notes

A zero-key note has `nullifier_secret = 0`. Anyone who knows its opening computes its nullifier, its sender included. Encryption cannot remove the exposure, and a chain observer without the opening cannot compute the nullifier.

- A ring output may carry any nonzero key. Its note spends only once that key is its owner's enrolled key.
- A zero-key output requires owner absence at the accepted tracking root. A retained root can prove absence during the enrollment grace period.
- The SDKs refuse a zero-key recipient with a tracking row under the selected root.
- The circuit cannot tell a PDA from a wallet.
- A hidden owner may spend a zero-key note, and that spend names it to anyone who holds the opening. The SDKs refuse it by default, and a caller can waive that. A public signer spends it on the public-owner rail or as a public co-owner.
- The delegate moves a zero-key note with its owner unpublished.
- A wallet reports such a note as exposed if spent and never selects it automatically. `spend_public` names the wallet that becomes public.
- A program-owned note uses the zero key, and its program signs through CPI.

## Merge authority

- A merge under a nonzero key runs on the ring PDA's authority, so the holder of the owner's secret and openings can merge. The merge proof admits the owner as the payer, and the SDKs refuse it, since that payer names the owner.
- A merge under the zero key needs the owner's signature in SPP. SPP's signer check stops a holder of an opening. A private seed from the owner's viewing key keeps the output blinding from that holder.
- A program-run merge with a seed its owner cannot derive leaves the wallet path unable to open the note. Its program recovers through `OwnerGrant` and the auditor record.
- A merge runs no list, guard, cap or approval rule, and it needs one owner, asset and nullifier key.

## Delegate

- The delegate is permanent and set once. It may move any eligible note of the ring, its own and several members' included.
- The rail clears the rules, caps and approval bits, and its statement reads no policy root. A curator's restrictive update therefore cannot fail a delegate's proof in flight.
- The tracking root, the input predicate, the output predicate, the output records and the sealed note count all stay.
- A delegate may withdraw and exit, and SPP's exit selector settles an exit. A deposit leg is refused, since it would bring an unlisted asset in.
- `getDelegateNotes` serves the owner's openings and secret to the delegate on a signed request. Recovery therefore depends on Ring RPC.

## What each rail publishes

- The signer rail publishes the owner run, each slot's short tag and each exit owner.
- The in-proof rail publishes the owner key in place of the signer, then the outputs as the signer rail does.
- The hidden rail publishes each exit owner, the change slots by their zero tag, a short tag on each other non-exit slot and the sender bundle with its tag. A public co-owner signs in the open, and a default-ring spend also publishes the hidden owner's key.
- The public-owner rail publishes the owner run, then the outputs as the hidden rail does.
- The delegate rail publishes the delegate, then the outputs as the ring's frame does.

## Separation from the hidden owner

- The ring's transfer proof shows the hidden owner is outside the run and differs from every co-signer, so it approves none of its own outflow.
- The program supplies the co-signer identities, so the prover picks none of them.
- The payer, a funder, another signer and an exit destination may name the hidden owner, and each then exposes it. The SDKs refuse each by default, and a caller can waive that.
- No layer checks a key that is only linked to the owner.

## A wallet with only its owner key

- The signer rail lets the owner pay on a confidential ring. An in-proof owner can pay its own transaction.
- The public-owner rail serves an anonymous ring, and it publishes the owner.
