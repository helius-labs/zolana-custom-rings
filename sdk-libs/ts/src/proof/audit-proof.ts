/**
 * The audit section of a ring transfer, the auditor stream and its opened slots. Each published
 * input classifies once through `inputClassOf`, the envelope counts, entry bits and owner rows read
 * that class alone.
 * Read after `protocol/codec/audit-stream.ts`. Read before `proof/transfer-proof.ts`.
 */
import { RING_INPUT_PADDING, ringInputOpening, ringOutputOpening } from "../rpc/prover/assembly.js";
import {
  bigIntBytes,
  bytesKey,
  isZero,
  mergeMintChunks,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/spr/internal";
import { equalBytes } from "@heliuslabs/spr/internal";
import type { Address, Bytes32, MessageData } from "@heliuslabs/spr/interface";
import type { X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { ProofInputUtxo, ProofOutputUtxo, TreeId } from "@heliuslabs/spr/transaction";
import type {
  AuditEnvelopeProofInputs,
  EntryOpeningProofInput,
  OutputOpeningProofInput,
  RingSlotOpening,
} from "../rpc/prover/ring.js";
import {
  DUMMY_RECORD,
  EMPTY_ENTRY_RECORD,
  EMPTY_TAIL,
  InputClass,
  InputMap,
  RecordKind,
  type AuditEnvelope,
  type AuditRecord,
  type DataTail,
  type EntryRecord,
} from "../protocol/codec/audit-stream.js";
import {
  checkedStreamLayout,
  DisclosureFormat,
  SINGLE_ASSET_PAYOUT_INPUTS,
  disclosureFormat,
  type AuditLayout,
  type AuditStreamLayout,
} from "../protocol/codec/ring-disclosure-layout.js";
import { compareField } from "../protocol/membership/owner-debits.js";
import { RingError } from "../protocol/error.js";
import { auditorMessageData } from "../crypto/audit/audit.js";
import { sealRingDisclosure, type RingDisclosure } from "../crypto/audit/ring-disclosure.js";

import type { PublishedSlot, RingOutputRail } from "../operations/payments/output-rail.js";

/** The auditor stream every transfer statement binds, Rust `SealedAudit`. */
export interface SealedAudit {
  /** The statement's layout element. */
  readonly audit: AuditLayout;
  readonly layout: AuditStreamLayout;
  readonly ephemeralPublicKey: X25519PublicKey;
  /** `tx_viewing_sk ‖ R ‖ A ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  /** One per published slot. */
  readonly records: readonly Uint8Array[];
  /** One per published slot under `hasData`. */
  readonly tails?: readonly Uint8Array[];
  /** Sent to the relay, the caller wipes it. */
  readonly ephemeralSecret: Bytes32;
}

/** The transaction viewing key and salt seal, a resend under a new salt keeps the keystream apart. */
export function sealAudit(
  input: Readonly<{
    rail: RingOutputRail;
    layout: AuditStreamLayout;
    published: readonly PublishedSlot[];
    /** The published inputs in SPP order, compact padding left out. */
    inputs: readonly ProofInputUtxo[];
    auditor: X25519PublicKey;
  }>,
): SealedAudit {
  const { layout } = input;
  const txViewingSecret = input.rail.txViewingKey.secretBytes();
  try {
    const sealed = sealRingDisclosure({
      layout,
      auditorPublicKey: input.auditor,
      salt: input.rail.salt,
      disclosure: auditDisclosure({
        txViewingSecret,
        layout,
        outputs: input.published.map((slot) => slot.output),
        inputs: input.inputs,
      }),
    });
    return Object.freeze({
      audit: Object.freeze({
        hasData: layout.hasData,
        entry: layout.key.entry,
        format: disclosureFormat(layout.key.format),
      }),
      layout,
      ...sealed,
    });
  } finally {
    txViewingSecret.fill(0);
  }
}

/** The message the program expands under the auditor's view tag, Rust `SealedAudit::message`. */
export function sealedAuditMessage(sealed: SealedAudit, auditor: X25519PublicKey): MessageData {
  return auditorMessageData(sealed, auditor);
}

/** Every plaintext of one transfer's stream, pure over its values. */
export function auditDisclosure(
  input: Readonly<{
    txViewingSecret: Bytes32;
    layout: AuditStreamLayout;
    /** The published slots' proof outputs. */
    outputs: readonly ProofOutputUtxo[];
    inputs: readonly ProofInputUtxo[];
  }>,
): RingDisclosure {
  const { layout, outputs, inputs } = input;
  return Object.freeze({
    envelope: auditEnvelopeOf(input.txViewingSecret, inputs, layout),
    records: Object.freeze(outputs.map(outputRecord)),
    ...(layout.hasData ? { tails: Object.freeze(outputs.map(outputTail)) } : {}),
  });
}

/** `R ‖ A ‖ default_input_bits ‖ entries` past the sealed key. */
function auditEnvelopeOf(
  txViewingSecret: Bytes32,
  inputs: readonly ProofInputUtxo[],
  layout: AuditStreamLayout,
): AuditEnvelope {
  const map = inputMapOf(inputs, layout);
  const head = {
    txViewingSecret,
    realInputs: map.noteCount,
    addressInputBits: map.addressInputBits,
  };
  if (disclosureFormat(layout.key.format) === DisclosureFormat.SingleAssetPayout) {
    const first = inputs[0];
    if (
      first === undefined ||
      map.noteCount !== SINGLE_ASSET_PAYOUT_INPUTS ||
      map.addressInputBits !== 0n
    )
      throw new RingError("RING_CATALOG_KEY_MISSING");
    return { ...head, evidence: { kind: "singleAssetPayout", mint: first.utxo.asset } };
  }
  if (!layout.key.entry) return { ...head, evidence: { kind: "none" } };
  return {
    ...head,
    evidence: {
      kind: "entry",
      defaultInputBits: defaultInputBits(inputs),
      inputs: inputs.map(entryRecord),
    },
  };
}

/** One published input's class, Rust `InputClass`, compact padding a dummy. */
export function inputClassOf(input: ProofInputUtxo): InputClass {
  if (input.isAddress()) return InputClass.address;
  return input.isDummy() ? InputClass.dummy : InputClass.note;
}

export function isDefaultRingNote(input: ProofInputUtxo): boolean {
  return inputClassOf(input) === InputClass.note && input.utxo.ringProgramId === undefined;
}

/** The map of the published inputs, dummies filling the key's class, refused unless `n` matches. */
export function inputMapOf(inputs: readonly ProofInputUtxo[], layout: AuditStreamLayout): InputMap {
  const { key } = checkedStreamLayout(layout);
  if (inputs.length !== layout.inputs)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "RingTransactLength" },
    });
  return InputMap.fromClasses(
    [
      ...inputs.map(inputClassOf),
      ...Array<InputClass>(key.class - inputs.length).fill(InputClass.dummy),
    ],
    layout.inputs,
  );
}

/** Bit `i` set for a default-ring note. */
export function defaultInputBits(inputs: readonly ProofInputUtxo[]): bigint {
  return inputs.reduce(
    (bits, input, index) => (isDefaultRingNote(input) ? bits | (1n << BigInt(index)) : bits),
    0n,
  );
}

/** Zero off a default-ring note, the blinding and data hashes stay out of the stream. */
export function entryRecord(input: ProofInputUtxo): EntryRecord {
  if (!isDefaultRingNote(input)) return EMPTY_ENTRY_RECORD;
  const { utxo } = input;
  return Object.freeze({
    ownerKey: utxo.owner.confidentialViewTag() as Bytes32,
    nullifierPk: input.nullifierPublicKey,
    amount: utxo.amount,
    mint: utxo.asset,
    inputCommitment: input.hash(),
  });
}

/** The circuit derives the kind from the slot's domain and ring id, a dummy's plaintext is zero. */
export function outputRecord(output: ProofOutputUtxo): AuditRecord {
  const owner = output.ownerAddress;
  if (owner === undefined) return DUMMY_RECORD;
  return Object.freeze({
    kind: output.ringProgramId === undefined ? RecordKind.exit : RecordKind.ring,
    amount: output.amount,
    ownerKey: owner.signingPublicKey.confidentialViewTag() as Bytes32,
    mint: output.asset,
    nullifierPk: owner.nullifierPublicKey,
  });
}

/** Zero on a dummy. */
export function outputTail(output: ProofOutputUtxo): DataTail {
  if (output.ownerAddress === undefined) return EMPTY_TAIL;
  return Object.freeze({
    dataHash: output.dataHash ?? ZERO_32,
    ringDataHash: output.ringDataHash ?? ZERO_32,
  });
}

/** Go `AuditParams`, the secret copied last, a refusal before it leaves no copy to wipe. */
export function auditEnvelope(
  input: Readonly<{
    rail: RingOutputRail;
    sealed: SealedAudit;
    firstNullifier: Bytes32;
    auditor: X25519PublicKey;
  }>,
): AuditEnvelopeProofInputs {
  return Object.freeze({
    firstNullifier: input.firstNullifier,
    auditorPk: input.auditor.u(),
    salt: input.rail.salt,
    layout: input.sealed.audit,
    txViewingSk: input.rail.txViewingKey.secretBytes(),
  });
}

/** Go `OutputOpening` per slot of the key's capacity, an omitted suffix slot runs on its own padding proof output. */
export function outputOpenings(
  outputs: readonly ProofOutputUtxo[],
  tree: TreeId,
  capacity: number,
): readonly OutputOpeningProofInput[] {
  const padding = Array.from({ length: Math.max(0, capacity - outputs.length) }, () =>
    Object.freeze({ output: zeroSlotOpening(), ...zeroEntryOpening() }),
  );
  return Object.freeze([
    ...outputs.map((output) =>
      Object.freeze({
        output: ringOutputOpening(output, tree),
        ...(output.ownerAddress === undefined
          ? zeroEntryOpening()
          : {
              ownerKey: output.ownerAddress.signingPublicKey.confidentialViewTag() as Bytes32,
              mintChunks: mintChunks(output.asset),
            }),
      }),
    ),
    ...padding,
  ]);
}

/** The spent notes' openings in SPP order, padding past them to the key's input class. */
export function inputOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly RingSlotOpening[] {
  return Object.freeze([
    ...inputs.map(ringInputOpening),
    ...Array.from({ length: inputClass - inputs.length }, () => RING_INPUT_PADDING),
  ]);
}

/** Go `EntryOpening` per input slot on an entry key, zero off a default-ring note. */
export function entryOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly EntryOpeningProofInput[] {
  return Object.freeze(
    Array.from({ length: inputClass }, (_, slot) => {
      const input = inputs[slot];
      return input === undefined || !isDefaultRingNote(input)
        ? zeroEntryOpening()
        : {
            ownerKey: input.utxo.owner.confidentialViewTag() as Bytes32,
            mintChunks: mintChunks(input.utxo.asset),
          };
    }),
  );
}

/** Distinct note owners ascending as field integers, zero rows last, a delegate rail's zero-key note needs no row. */
export function ownerRows(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    delegate: boolean;
    /** The key's rows, absent returns the live rows alone. */
    slots?: number;
  }>,
): readonly Bytes32[] {
  const owners = new Map<string, Bytes32>();
  for (const spent of input.inputs) {
    if (inputClassOf(spent) !== InputClass.note) continue;
    if (input.delegate && equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK)) continue;
    const owner = spent.utxo.owner.ownerProofInputHash();
    if (!isZero(owner)) owners.set(bytesKey(owner), owner);
  }
  const rows = [...owners.values()].sort(compareField);
  const { slots } = input;
  if (slots === undefined) return Object.freeze(rows);
  if (rows.length > slots)
    throw new RingError("RING_TOO_MANY_OWNERS", {
      details: { owners: rows.length, maximum: slots },
    });
  return Object.freeze([...rows, ...Array<Bytes32>(slots - rows.length).fill(ZERO_32)]);
}

function zeroSlotOpening(): RingSlotOpening {
  return {
    domain: ZERO_32,
    treeId: ZERO_32,
    ownerPkHash: ZERO_32,
    nullifierPk: ZERO_32,
    asset: ZERO_32,
    amount: ZERO_32,
    blinding: ZERO_32,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
    ringProgramId: ZERO_32,
  };
}

function zeroEntryOpening(): EntryOpeningProofInput {
  return { ownerKey: ZERO_32, mintChunks: [ZERO_32, ZERO_32] };
}

function mintChunks(mint: Address): readonly Bytes32[] {
  return mergeMintChunks(mint).map((chunk) => bigIntBytes(chunk) as Bytes32);
}
