A custom ring lets you enforce your own compliance rules on private transfers  
in the Solana Privacy Program: you define a policy that every transfer and  
withdrawal must prove it satisfies, and ring settings such as co-signer  
approval that your ring program checks directly. This document describes each  
control you can configure and who can change it.

## Compliance Rules

1. ZK Policy
   1. Allowlist (kyc)
   2. Blocklist (sanctions)
   3. Frozen list
   4. Asset allowlist
   5. Auditor
2. Global Program Config
   1. Pause
   2. Permanent delegate
3. Ring Rpc
   1. Readers
   2. Co-signer
      1. Sender limits
      2. Token volume limits

## 1. ZK Policy

The policy defines which checks a transfer must prove. The ring authority configures these rules and maintains the list entries.

### 1.1. Allowlist

An allowlist is a list of approved identities that the ring authority  
maintains. Sender and or recipient must be on allow list.  
Recipients above threshold must be on allow list.

### 1.2. Blocklist

A blocklist is a list of identities or tokens the ring refuses transfers to  
or from. This freezes all tokens the blocked identity holds.

### 1.3. Asset allowlist

Only allowed assets can be deposited.  
Only allowed assets can be transferred.

### 1.4. Auditor

The auditor holds the ring's viewing key and can read every transfer and  
withdrawal through the ring: tokens, amounts and recipients. The auditor  
can't move funds.

## 2. Global Program Config

### 2.1. Pause

Pausing stops all activity in the ring until it's resumed: deposits,  
transfers, withdrawals, merges and delegate moves. Funds stay where they are.

### 2.2. Permanent delegate

A permanent delegate is a key that can move any user's funds to another user  
within the custom ring.

## 3. Ring RPC

### 3.1. Readers

A reader accesses decrypted activity through **Ring RPC** without holding the auditor key. The **Config Authority** grants access across the ring; a **Wallet** grants access to its own activity.

Read-access records are stored in the **Storage tree**. Optionally, **Ring RPC** stores these records encrypted in its database only.

### 3.2. Co-signer

A co-signer is a key that the ring authority designates to approve selected  
operations. The co-signer on its own cannot move funds.

#### Operations that can require approval

- **Deposits**
- **Transfers** 
- **Withdrawals**
- **Transfer/withdrawal threshold**

## Trust Assumptions

1. **Storage tree write authority:** Trusted for membership data, list entries and key registrations. The tree proof verifies the update; each record's validity and the wallet's consent depend on the authority unless additional checks are defined.
2. **Config Authority:** Trusted to set policy rules, ring settings and access grants across the ring.
3. **Ring RPC:** Trusted to protect auditor keys and proof inputs, enforce reader permissions and apply co-signer limits.
4. **Curators:** A ring trusts the authorities of the external storage trees used by its policy.
5. **Delegate:** Trusted to move users' funds within the ring under the configured controls.
6. **Upgrade Authority:** Trusted to create the initial configuration and deploy upgrades that preserve the intended program guarantees.

## Glossary


| #   | Term                  | Type           | Definition                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | --------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Member record**     | Registry entry | A public entry in the member registry for an owner or asset, containing list memberships, key escrow information and asset limits used to prove that a transfer meets the ring's rules.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 2   | **Ring RPC**          | Service        | Our hosted service that indexes member records, generates proofs, pays fees, submits transactions and serves decrypted activity to authorized readers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 3   | **Ring Program**      | Solana program | Enforces ring controls and verifies proofs before SPP CPI. <br><br>1. `Initialize`: Creates the initial ring configuration and registers the ring with SPP.<br>2. `UpdateAuthority`: Changes the Config Authority, authorized by the current Config Authority.<br>3. `UpdatePolicy`: Updates the configured policy rules and storage tree references.<br>4. `SetPaused`: Pauses or resumes ring operations.<br>5. `SetDelegate`: Sets the permanent delegate once.<br>6. `SetCoSigner`: Adds or updates a co-signer and the operations it must approve.<br>7. `ClearCoSigner`: Removes a co-signer.<br>8. `Deposit`: Verifies deposit and audit proofs before SPP CPI.<br>9. `Transfer`: Verifies the required proofs for transfers and withdrawals before SPP CPI.<br>10. `Merge`: Verifies merge and audit proofs before SPP CPI.<br>11. `AuthorityTransfer`: Verifies permanent delegate authorization and the required proofs before SPP CPI. |
| 4   | **Storage Program**   | Solana program | Stores storage tree roots and verifies that authorized record updates produce the correct new root. Shared write authority is managed through a smart account. <br><br>1. `Initialize`: Initializes a storage tree, its root history and write authority.<br>2. `Update`: Applies record updates with a proof of the tree update, keeping earlier roots valid for the grace period.<br>3. `UpdateImmediate`: Applies record updates with a proof of the tree update and invalidates earlier roots.<br>4. `UpdateAuthority`: Changes the tree's write authority, authorized by its current write authority.                                                                                                                                                                                                                                                                                                                                        |
| 5   | **Storage tree**      | Merkle tree    | Merkle tree using account compression, with roots held by the Storage Program. Ring RPC maintains the pending record-update queue outside Solana, generates apply proofs for eligible batches, then indexes applied records and serves their Merkle proofs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 6   | **Curator**           | Authority      | Authority to a third party storage tree.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 7   | **Wallet**            | User           | Holds spending keys and authorizes transfers of its ring UTXOs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 8   | **Reader**            | User           | Uses granted read access to query decrypted ring activity through Ring RPC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 9   | **Config Authority**  | Authority      | Sets ring policies, member lists, readers, co-signer requirements, fees and pause controls.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 10  | **Upgrade Authority** | Authority      | Upgrades the ring program and creates its initial configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 11  | **Auditor**           | Authority      | Holds the auditor key and decrypts ring transfers, deposits, merges and escrowed keys.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 12  | **Co-signer**         | Authority      | Signs operations when the ring's configured scope or approval rules require it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 13  | **Delegate**          | Authority      | Uses delegated authority to move members' UTXOs within a ring with key escrow.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |


## Flows

1. Member enrollment and key escrow
2. Member record updates
3. Deposit
4. Transfer (anonymous, confidential, withdrawal, to/from default ring)
5. User Merge
6. Managed Merge
7. Authority transfer
8. Reader access grants and revocation
9. Co-signer Policy limits configuration

## 1. Member enrollment and key escrow

Enrollment depends on the ring's policy. Key escrow is required on key-escrow rings, optional on other confidential rings, and unavailable on anonymous rings.

1. **Wallet:** Authorizes its member-record updates and, when registering an escrow key, encrypts its nullifier secret to the **Auditor**.
2. **Ring RPC:**
   1. Coordinates required authority-list updates with the **Config Authority**.
   2. Queues authorized member updates and key-registration requests.
   3. Generates an apply proof for eligible batches of storage tree updates.
   4. Submits the record batch and apply proof to the **Storage Program**, paying fees.
   5. Indexes the applied member records and serves their updated proofs.

## 2. Member record updates

The **Wallet** updates its own viewing and recovery settings. The **Config Authority** updates the ring's policy list entries.

1. **Wallet or Config Authority:** Signs the changes it is authorized to make and sends them to **Ring RPC**.
2. **Ring RPC:**
   1. Reads the current member records and pending updates.
   2. Queues wallet updates until they are eligible to apply; prepares authority updates for immediate application.
   3. Generates an apply proof and submits the registry update to the **Storage Program**, paying fees.
   4. Indexes the updated member records and serves their proofs.

## 3. Deposit

A deposit moves SOL or tokens from a wallet's public balance into ring UTXOs. The token and amount are public.

Compared with a transfer, a deposit adds a round trip for the **Wallet** to sign the transaction that moves its SOL or SPL tokens.

1. **Wallet:**
   1. Chooses the token, amount and recipient.
   2. Prepares the deposit UTXOs and encrypts their details to the recipient and the **Auditor**.
   3. Sends the deposit request to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the ring is active, the asset is allowed and any required recipient key escrow is registered.
   2. Generates the required deposit proof.
   3. Builds the deposit transaction and returns it to the **Wallet** for signing.
3. **Wallet:** Signs the prepared transaction to authorize the SOL or SPL token transfer and returns it to **Ring RPC**.
4. **Ring RPC:**
   1. Co-signs.
   2. Pays fees and submits the deposit to the **Ring Program**.
   3. Indexes the confirmed deposit so the recipient's **Wallet** can find its new UTXOs.

## 4. Transfer flow

A unified flow for anonymous,  confidential transfers, and withdrawals.

**Variants:**

1. anonymous: default
2. confidential:  policy circuit checks sender and recipients as public inputs same as default ring.
3. transfer to default ring: some outputs of a transfer can be owned by the default ring program.
4. public withdrawal: spl tranfer to 1 or multiple spl accounts, optionally alongside other transfers
5. **Wallet:** Signs the transfer authorization and sends it with the proof inputs to **Ring RPC**.
6. **Ring RPC:**
   1. Reads the required member records.
   2. Generates the required proofs.
   3. Obtains the **Co-signer** signature when required.
   4. Pays fees and submits the transaction to Solana.

## 5. User Merge

A merge combines UTXOs of the same wallet, token and ring into one UTXO with their total value. 

1. **Wallet:** Selects the UTXOs, prepares the merged UTXO and sends the merge request with its proof inputs to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the UTXOs are unspent and belong to the same wallet, token and ring.
   2. Generates proofs that preserve the wallet, token and total value and let the **Auditor** read the merged UTXO.
   3. Obtains the **Co-signer** signature when required.
   4. Pays fees and submits the merge to the **Ring Program**.
   5. Indexes the result, marking the input UTXOs spent and adding the merged UTXO.

## 6. Managed Merge

Managed merge is initiated by **Ring RPC** on a ring with a permanent delegate and registered escrow keys. It combines one wallet's UTXOs of the same token and ring while preserving their total value. The user should be able to configure, how many utxos with what average amount. 

1. **Ring RPC:**
   1. Selects unspent UTXOs belonging to the same wallet, token and ring.
   2. Uses the wallet's escrowed nullifier key to prepare the merged UTXO and encrypt its details to the **Auditor**.
   3. Generates proofs that preserve the wallet, token, ring and total value.
   4. Pays fees and submits the merge to the **Ring Program**.
   5. Indexes the result, marking the input UTXOs spent and adding the merged UTXO.



## 7. Authority transfer

An authority transfer moves a wallet's funds to recipients within the same ring, authorized by the permanent **Delegate**. **Ring RPC** uses the wallet's escrowed nullifier key to prepare the spend.

1. **Delegate:** Requests a transfer specifying the source wallet, recipients, token and amounts.
2. **Ring RPC:**
   1. Retrieves the source wallet's unspent UTXOs and escrowed nullifier key.
   2. Prepares recipient and change UTXOs within the same ring and encrypts their details to the recipients and the **Auditor**.
   3. Generates the required transfer, audit and policy proofs, including recipient key-escrow checks.
3. **Delegate:** Signs the transaction; the **Co-signer** also signs when required.
4. **Ring RPC:**
   1. Pays fees and submits the transfer to the **Ring Program**.
   2. Indexes the result, marking the input UTXOs spent and adding the new UTXOs.

## 8. Reader access grants and revocation

The **Config Authority** grants and revokes **Reader** access across the ring. A **Wallet** grants and revokes access to its own activity. Each manages its own grants.

1. **Config Authority or Wallet:** Signs a grant or revocation naming the ring, the **Reader**'s wallet or passkey and the activity covered, and sends it to **Ring RPC**.
2. **Ring RPC:**
   1. Verifies the signer's authority over the requested activity: the ring's **Config Authority**, or the **Wallet** for its own activity.
   2. Queues the grant or revocation for a **Storage tree** update, or stores the record encrypted in its database when that option is selected.
   3. For tree updates, generates an apply proof when eligible, submits it to the **Storage Program** and indexes the applied records.
   4. Confirms the change to the signer once the selected storage has been updated.
3. **Reader:** Signs a read request with its wallet or passkey and sends it to **Ring RPC**.
4. **Ring RPC:** Verifies the signature and checks the stored grants for an active grant covering the requested activity, then returns the permitted decrypted activity.



## 9. Co-signer Policy limits configuration

The **Config Authority** configures the limits applied by a **Co-signer**. **Ring RPC** stores the configuration in the **Storage tree** and enforces it before co-signing.

1. **Config Authority:**
   1. Selects the ring and configured **Co-signer**.
   2. Sets, updates or removes per-token sender limits, public deposit and withdrawal caps, and their slot windows.
   3. Signs the configuration update and sends it to **Ring RPC**.
2. **Ring RPC:**
   1. Verifies the **Config Authority** signature and the target ring and co-signer.
   2. Validates the configured limits and slot windows.
   3. Queues the record update, generates an apply proof when ready and submits the batch to the **Storage Program**, paying fees.
   4. Indexes the applied configuration, activates the limits and confirms the changes to the **Config Authority**.

**Ring RPC** tracks usage and enforces the active limits when deciding whether to co-sign. The **Ring Program** checks the required co-signer signature.

## Notes

1. The program's upgrade authority is responsible only for upgrading the program and creating its initial configuration. The ring authority manages policy rules, list entries and ongoing ring settings.
2. We should implement support for multiple co signers using smart accounts in a hot path is too expensive. We can just create a pda per co signer and check it in the program.
3. We need to test that we can make the ring rpc relayer flow work with third party zk programs.
4. The wallet should never fetch merkle proofs.
5. Storage tree update proofs will be need to be small if we require all the data that we publish to be in the same instruction.
6. We should probably not include validity proofs of the actual data that is stored in the storage tree update process to keep complexity low. If we want to add them a wrapper ix in the ring program that checks a batch proof over the data and a cpi into the storage program could be a clean way to extend this.



### Further things to align on:

1. align on account state structs member records state
2. custom ring rpc api
3. Instruction data + accounts for the important instructions
4. can we get this into 2 weeks audit scope?

## Questions:

1. Do we always need key escrow? Only if we use permanent delegate right? For auditor only we dont need it.
2. Should we have ownership checks inside the Storage program proofs so that only the owner of the data can modify certain fields, and only the authority can modify other fields?
3. Is the curator program a third party policy program?
   1. I don't want us to pass too many accounts for a ring transfer, ideally it is only 1 the policy account, we could sync root history of curated trees and the policy store program trees to the policy pda so that all roots originate from that account.