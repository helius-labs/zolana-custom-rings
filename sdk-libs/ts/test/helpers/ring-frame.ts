import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import { disclosureFieldCount } from "../../src/protocol/codec/ring-disclosure-layout.js";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { RingInstructionTag } from "../../src/operations/management/admin.js";
import {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  ringDisclosureLayout,
  type RingOutput,
  type RingRail,
} from "../../src/protocol/transaction/transact.js";
import { RING_AUTHORITY_SHAPES } from "../../src/protocol/transaction/spp.js";
import { RECIPIENT_BODY_LEN } from "../../src/protocol/codec/anonymous-body.js";

function field(byte: number): Bytes32 {
  const value = new Uint8Array(32);
  value[31] = byte;
  return value as Bytes32;
}

/** An exit-free frame of `inputs` and `outputs` the rail's audit key serves, no proof valid. */
export function ringFrame(
  input: Readonly<{ rail: RingRail; inputs: number; outputs: number; fullOpenings?: boolean }>,
): RingTransactData {
  const { rail, inputs, outputs } = input;
  const keyed = rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
  const shape = keyed.find((entry) => entry.inputs >= inputs && entry.outputs === outputs);
  if (shape === undefined) throw new Error("no shape serves the counts");
  const flags = {
    exits: false,
    keyEscrow: rail === "delegate",
    fullOpenings: input.fullOpenings ?? false,
  };
  const layout = ringDisclosureLayout({
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs,
    outputs,
    layout: flags,
  });
  const slot = (index: number): RingOutput =>
    rail === "anonymous"
      ? {
          kind: "anonymous",
          hash: field(10 + index),
          tag: field(index + 1),
          ...(index === 0 ? {} : { body: new Uint8Array(RECIPIENT_BODY_LEN) }),
        }
      : {
          kind: "delivered",
          hash: field(10 + index),
          u: field(40 + index),
          body: new Uint8Array(40),
        };
  return {
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    auditProof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    approvalRequired: false,
    expiryUnixTs: 0,
    txViewingU: field(1),
    salt: new Uint8Array(16).fill(3) as Bytes16,
    interfaceTransfers: [],
    keyEscrow: flags.keyEscrow,
    fullOpenings: flags.fullOpenings,
    outputs: Array.from({ length: outputs }, (_, index) => slot(index)),
    ...(rail === "anonymous" ? { sender: { tag: field(1), body: new Uint8Array(150) } } : {}),
    ephU: field(2),
    sealed: field(3),
    disclosure: Array.from({ length: disclosureFieldCount(layout) }, (_, index) =>
      field(index + 1),
    ),
    privateTxHash: field(4),
    ...(rail === "anonymous"
      ? { anonymous: { commitment: field(5), commitmentPok: field(6) } }
      : {}),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Array.from({ length: inputs }, (_, index) => field(70 + index)),
    inputTrees: { kind: "one", context: { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 } },
  };
}

/** The ring program's own instruction data around `frame`. */
export function ringInstructionData(frame: RingTransactData): Uint8Array {
  const tag =
    frame.rail === "delegate" ? RingInstructionTag.authorityTransfer : RingInstructionTag.transfer;
  return Uint8Array.of(tag, ...RingTransactData.encode(frame));
}
