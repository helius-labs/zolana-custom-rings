# Current state

Differences between the implementation and the [high-level spec](highlevel-spec.md), based on source-code inspection.

1. **Ring RPC orchestration:** It currently exposes audit/read APIs, not the preparation, proving, co-signing, fee payment and transaction submission flows in the spec. [RPC methods](../services/ring-rpc/src/rpc/server.rs#L135)

2. **Wallet proof fetching:** The SDK still fetches and verifies Merkle paths; the spec assigns that work to Ring RPC. [Record reads](../sdk-libs/sdk/src/operations/records.rs#L101)

3. **Storage integration:** Ring records remain in registries owned by the Ring Program, rather than the shared Storage Program. [Registry creation](../programs/custom-ring/src/instructions/configuration/setup/create_member_registry.rs#L17)

4. **Queue location:** Pending record updates are stored in a Solana account; the spec puts the queue in Ring RPC. [Record writes](../programs/custom-ring/src/instructions/records/write_records.rs#L20)

5. **Storage instructions:** The existing `policy-store` program still exposes `VerifyPolicy` and lacks `UpdateAuthority`. Its writer is fixed at initialization. [Instruction dispatch](../programs/policy-store/src/lib.rs#L21), [initialization](../programs/policy-store/src/instructions/initialize.rs#L49)

6. **Registration trust:** Wallet signatures and key-escrow validity proofs are enforced by the Ring Program. The spec instead trusts stored data to the storage authority by default. [Registration verification](../programs/custom-ring/src/instructions/records/register_key.rs#L24)

7. **Transfer signing:** Confidential transfers require the Wallet's Solana transaction signature; anonymous transfers authorize the owner inside the proof. The proposed common authorization flow is missing. [Signer checks](../programs/custom-ring/src/instructions/transact/accounts.rs#L118), [proof preparation](../sdk-libs/sdk/src/operations/pipeline/spp.rs#L110)

8. **Confidential recipient identities:** Recipient identities remain private circuit inputs, whereas the spec describes them as public inputs for confidential transfers. [Policy statement](../prover/circuits/policy/policy.go#L138)

9. **Deposit asset allowlist:** Direct deposits verify audit and escrow requirements but do not run the policy's asset-allowlist checks. [Deposit processing](../programs/custom-ring/src/instructions/settlement/forward.rs#L82)

10. **User merge:** Confidential and key-escrow rings explicitly reject merges; anonymous merges are supported. [Merge verification](../programs/custom-ring/src/instructions/settlement/merge_disclosure.rs#L78)

11. **Managed merge:** Ring RPC has no automatic consolidation worker or configurable UTXO-count/average-amount targets. Its background work audits existing activity. [Background worker](../services/ring-rpc/src/operations/hub.rs#L282)

12. **Reader access:** Only the Config Authority grants access, using Solana PDA records. Wallet-scoped grants, storage-tree permissions and encrypted database storage are missing. [Access grants](../programs/custom-ring/src/instructions/configuration/access/read_access.rs#L25), [grant lookup](../services/ring-rpc/src/rpc/upstream.rs#L500)

13. **Multiple co-signers:** Configuration holds one co-signer, and setting another replaces it. The proposed PDA-per-co-signer model is missing. [Co-signer configuration](../programs/custom-ring/src/instructions/configuration/access/set_cosigner.rs#L21)

14. **Co-signer limits:** Existing caps and approval thresholds operate per transaction in the circuit. Ring RPC has no sender-window limits, aggregate token-volume limits or configuration workflow. [Outflow checks](../prover/circuits/policy/outflow.go#L18), [RPC methods](../services/ring-rpc/src/rpc/server.rs#L135)

15. **Delegate appointment:** The Upgrade Authority appoints the delegate, exceeding its initialization-and-upgrade role in the spec. [Delegate setup](../programs/custom-ring/src/instructions/configuration/access/set_delegate.rs#L26)

16. **Curators:** Curated sources must be another ring's member registry, rather than a general third-party storage tree. [Curator loading](../programs/custom-ring/src/instructions/accounts/loader.rs#L96)

17. **Initialization:** Configuration, member-registry creation, policy creation and SPP registration are separate instructions rather than the spec's single `Initialize`. [Instruction dispatch](../programs/custom-ring/src/lib.rs#L26)
