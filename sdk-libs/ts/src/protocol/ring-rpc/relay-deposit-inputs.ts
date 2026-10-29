/** The sealed deposit `RelayIntent.proofInputs` carries, Rust `RelayDepositInputs` in wincode. */
import { SALT_LENGTH, Writer, addressBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RingAssetDeposit } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";

/** Rust `RelayDepositInputs`, Ring RPC derives the owner commitment again from the blinding secret. */
export interface RelayDepositInputs {
  readonly ringProgramId: Address;
  readonly tree: Address;
  readonly depositor: Address;
  readonly recipient: ShieldedAddress;
  readonly deposit: RingAssetDeposit;
  readonly blindingSecret: Bytes32;
  /** Ephemeral secret of the auditor capsule in `deposit.encrypted`. */
  readonly auditEphemeralKey: Bytes32;
}

/** The caller wipes the returned bytes, they hold the note's blinding secret. */
export function encodeRelayDepositInputs(value: RelayDepositInputs): Uint8Array {
  const { deposit } = value;
  const writer = new Writer()
    .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
    .bytes(addressBytes(value.tree), 32, "tree")
    .bytes(addressBytes(value.depositor), 32, "depositor")
    .bytes(value.recipient.toBytes(), undefined, "recipient");
  if (deposit.asset.kind === "sol") writer.u8(0, "asset");
  else
    writer
      .u8(1, "asset")
      .bytes(addressBytes(deposit.asset.accounts.mint), 32, "asset.mint")
      .bytes(addressBytes(deposit.asset.accounts.sourceTokenAccount), 32, "asset.userToken")
      .bytes(addressBytes(deposit.asset.accounts.tokenProgram), 32, "asset.tokenProgram");
  const { encrypted } = deposit;
  return writer
    .u64(deposit.amount, "amount")
    .bytes(deposit.viewTag, 32, "viewTag")
    .bytes(encrypted.txViewingPublicKey, 33, "encrypted.txViewingPk")
    .bytes(encrypted.salt, SALT_LENGTH, "encrypted.salt")
    .u16(encrypted.ciphertext.length, "encrypted.ciphertext.length")
    .bytes(encrypted.ciphertext, undefined, "encrypted.ciphertext")
    .bytes(value.blindingSecret, 32, "blindingSecret")
    .bytes(value.auditEphemeralKey, 32, "auditEphemeralKey")
    .finish();
}
