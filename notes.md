## Questions

1. Why do we have `services/ring-indexer`? Can't we just use Photon?
2. Why do we need to enforce tags in the policy proof?
3. Why are the tags in this repo better than the ones in Zolana's `docs/spec.md`?
4. Why can't confidential rings merge?
5. Why is it better to have a new Merkle tree in each custom ring program?
6. What if we limit transfers to 5 signers instead of 1?

## Notes

- We should encrypt the sender's identity to the recipient so the recipient can build a transaction history.
- The terminology differs: this repo uses "notes" instead of "UTXOs".
- A transfer can have multiple senders (check that the policy proof supports multiple senders).
- Best to omit the TypeScript SDK or the Rust SDK for now.
- It probably makes sense to unify the audit and policy proofs, with two shapes per output count: 4 inputs and 16 inputs.
- Confidential SPP outputs use signing public keys as tags, while confidential custom-ring outputs use viewing public keys.
- Rename "escrow" to "share nullifier key" to make clear which key is disclosed to the auditor.

### Proposal: policy record reads through SPP

- Store policy records in SPP, reusing its forester and Photon instead of separate registry trees and indexing per ring.
- Prove each record's existence and unspent status privately once, then reuse it across policy checks.
- Skip nullifier PDA accounts for policy reads to fit more reads within Solana's 64-account limit.
- Accept the latest nullifier root or one published within `N` slots.
- Record the publication slot in SPP when the forester applies a root. Check its age in the ring program.
- Updates spend the old record and create a successor. Revocation takes effect after the forester applies the nullifier and older roots expire. If the forester stops, the latest root stays accepted.
- Keep SPP's double-spend checks for UTXO spends.

### Proposal: shared policy records in a concurrent tree

- SPP record reads need nullifier PDA accounts for freshness. These share the 64-account budget with the nullifier PDAs required to spend UTXOs, so more policy reads leave fewer accounts available for actual spends.
- Update records in place. The new root no longer authenticates the old state.
- Read records without passing nullifier PDA accounts, preserving the account budget for UTXO spends. The accepted root window determines how long older record versions remain usable.
- Keep one record per user identity: the user's identity hash, KYC and Blocked flags, encrypted nullifier secret, its ephemeral public key, `nullifier_pk = Poseidon(nullifier_secret)`, and `last_updated_slot`.
- Preserve default-ring nullifier key derivation. At signup, prove the encrypted secret matches `nullifier_pk`.
- The authority controls KYC and Blocked flags; users register their own nullifier-key information.
- Use a concurrent indexed tree for unique identities and a concurrent state tree for records. Replace queues and batch update proofs with direct Merkle-path updates in the ring program.
- Creation: atomically prove `hash(user_signing_pubkey)` is absent from the indexed tree, insert it, and append the user's record to the state tree. Include that identity hash in the record and set `last_updated_slot` to the current Solana slot.
- Update: verify authorization and the old record's Merkle path, then replace the record at the same state-tree leaf. Preserve its identity hash and set `last_updated_slot` to the current Solana slot.
- Allow a record update only when `current_slot >= last_updated_slot + N_update`. Enforce this per record in the ring program; `N_update` is separate from the root-age window.
- Combine audit and policy in one proof, with variants for 4 and 16 inputs per output count. Prove each distinct record once and reuse it across checks.
- Cap transfers at 5 input owners, 16 outputs and 3 assets: at most 24 shared records, or 25 with one additional withdrawal recipient. The proof checks that input and output owners and assets reference the correct records.
- Accept the latest state-tree root or one published at most `N` slots ago. Store publication slots with the root history; older roots allow delayed revocation within that window.

### Proposal: larger batched registry queue

- Replace the 16-write queue with 100 batches of up to 250 writes: 25,000 writes at full capacity. Partial batches consume a batch slot, so effective capacity can be lower.
- Store a hash-chain commitment per batch, plus its sequence number, write count, first-write slot and status. Write contents remain in transaction data for the indexer to reconstruct.
- Start the write window on the batch's first write. Accept writes while `current_slot < first_write_slot + 5`; seal the batch when full or when that window expires. Later writes start the next batch.
- A sealed batch is immutable. Prove its real write count and pad unused circuit slots to a capacity of 250; padding does not count as queued writes.
- Apply batches in strict queue order. Each proof checks the next batch's committed writes against the current registry root, updating existing records or inserting absent records as today.
- Target one batch application per second when a sealed batch contains at least one write: up to 250 writes per second with full batches. Wait when the queue is empty; do not publish unchanged-root checkpoints. Build witnesses in order and prove batches in parallel as needed; a later batch can apply only after its predecessors.
- Retain 100 applied roots, including their publication slots and applied write positions. At one root per second this is approximately 100 seconds of history; retain the latest-or-`N`-slots-old read rule.
- Reuse a batch slot only after its writes are applied. Reject new writes when the queue is full.
- Authority and member writes use the same queue and application schedule. Changes take effect when their batch applies. A full 25,000-write backlog takes about 100 seconds to process at the proposed maximum rate.
