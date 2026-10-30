# Audit and key escrow

The auditor holds one viewing key for the ring's life. That key opens every operation, and key escrow lets it link spends. [Spec](../spec.md)

## Transfers

- The sender draws a transaction viewing key for each transfer. The audit proof shows its secret is sealed to the auditor in the auditor message.
- The proof forces every output blinding to derive from that secret, the salt and the first nullifier. The auditor rebuilds every output.
- On the confidential and authority rails the proof also shows each output body encrypts the blinding and the amount to the viewing key the output publishes.
- On the anonymous rail the disclosure opens each output's owner, asset and amount, and names each spent note by its hash or a prefix. A spend of default-ring notes opens every spent note.
- No proof checks an anonymous output's recipient body. A sender can settle an output the auditor opens and its recipient cannot.
- The program builds both ring statements from the frame it forwards to SPP, so the proofs bind the transfer that settles.

## Deposits and merges

- A deposit seals each new note's owner hash, blinding and owner key to the auditor.
- On every ring the proof binds the sealed owner key to the owner identity the owner hash commits to, so the auditor names each owner.
- A merge seals a disclosure key to the auditor. The proof opens the owner, the mint, the total, the output blinding and each input's hash under it.

## Key escrow

- A wallet escrows its nullifier secret by sealing it to the auditor with a proof of the seal. Ring RPC checks that proof before it writes the escrow entry.
- The record keeps a hash of the nullifier key and the sealed secret. The update publishes the owner key, the nullifier key and the sealed secret.
- A ring with a delegate requires an escrowed owner for every output, every deposit and every merge.
- With the secret the auditor computes that owner's nullifiers and links its spends. Ring RPC uses it for managed merges and delegate moves.
- An escrow key never changes. A write the storage authority signs directly can escrow a key the auditor cannot open.

## Why the audit stays provable

- A wide confidential policy payout fits one transaction only when the owner pays. A relayed one does not fit.
- Fitting a relayed one needs SPP to publish less per output, or an audit statement without the recipient viewing key. The second loses the proof that each body opens for its recipient.
- The SDKs refuse those shapes instead. A sender splits the payout or merges first.

## Reading through Ring RPC

- Ring RPC binds every audited row to the confirmed SPP event it rebuilds from the chain.
- Photon is trusted for completeness. A row Photon omits never reaches a reader.
- No nullifier secret leaves Ring RPC.
