# PR 5 review follow-up

Implementation base: PR 5 at `2bd20ae9c343ac5292c085e5c51a39828048dee7`.
Work is isolated on `alex/circuit-policy`.

## Required circuit guarantees

- An anonymous sender differs from the actual payer, configured co-signer and public withdrawal owner. Bind these identities into transfer, entry and merge statements.
- Existing owner and asset lists, including their amount guards, cover public withdrawals as well as private outputs. Aggregate gross payments; deposits never offset list thresholds. Keep net public amounts for outflow accounting to avoid counting withdrawals twice.
- The auditor can verify each committed owner, asset, amount and transaction relationship. Preserve recipient-body checks until an independent auditor disclosure format replaces their audit dependency.
- Specialize local-registry policies and smaller deposit/registry batches without weakening their statements or count bounds.

Public SPL withdrawal screening concerns the token account's recorded owner. Include the checked owner in authenticated instruction metadata so historical audits survive account changes and closure. Validate against live account state before verifying the proof.

## Intentionally excluded

Deliberate burns, unusable recipient keys and voluntary loss of funds are outside scope. Velocity accounting is removed from the roadmap. Same-owner merges do not acquire list screening. Per-transfer amount guards, outflow caps and co-sign thresholds remain.

## Other work for future planning

| Area | Follow-up | Acceptance criterion |
| --- | --- | --- |
| TypeScript anonymous receive | Complete receive/sync and the skipped live integration scenario. | Recipient discovers and spends anonymous payments across supported stream layouts. |
| TypeScript sync errors | Key-provider failures are caught and unresolved assets can disappear from the report. Define explicit partial/error results. | Failed reads are visible and retryable without presenting a complete stale report. |
| Sync performance | Replace repeated full-history scans with resumable cursors. | Restart, reorg and pagination tests preserve discovery and spent status. |
| Prover key cache | Zolana's lazy key manager retains every loaded key. Add a bounded cache for services that prove many shapes; the exhaustive localnet test restarts its prover between shapes. | Memory stays bounded across the full key catalog without interrupting active proofs. |
| Auditor CLI pagination | Restore earlier transfer openings when resuming with `--cursor`; the current seed scan supplies only deposits and merges. | A resumed audit resolves inputs from previous pages and fails explicitly if that history is unavailable. |
| Confidential escrow merges | Currently rejected by the verifier. Design support separately. | Complete escrow disclosure and verification before enabling this operation. |
| Documentation | Reconcile API descriptions, proof shapes/counts and broken links with the implementation. | Examples compile and generated counts match the current circuit catalog. |
| CI baseline | The stack now pins merged Zolana, selects keyed delegate shapes, loads created notes for CLI audits, and uses the required signers and existing withdrawal accounts in live fixtures. | Full CI on the final commit, including real proofs and live validator/indexer flows. |
| Confidential withdrawal setup | Add explicit per-destination owner hints for creating an SPL ATA in the same transaction. Current policy assembly requires an existing token account; anonymous withdrawals can use their validated named-owner hint. | A hint is bound to the expected ATA/mint and execution checks its actual owner. |
| Auditor disclosure | Measure an independent disclosure of amount and blinding before removing recipient ECDH/AES constraints. Anonymous ring data also depends on the derived slot secret. | Auditor reconstructs every output commitment without recipient secrets; cross-language vectors and adversarial tests demonstrate the replacement. |

Circuit changes require new proving/verifying keys. Historical frames retain their original decoding semantics; upgraded verification must not accept a legacy key for a stronger statement. Generated key artifacts and release publication must be verified before deployment.
