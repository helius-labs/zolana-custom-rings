/**
 * The audit section of a ring transfer, the auditor stream and its opened slots. Each published
 * input classifies once through `inputClassOf`. The ring proof opens the notes alone, in SPP's note
 * order, the envelope counts, entry records and owner rows read that order.
 * Read after `protocol/codec/audit-stream.ts`. Read before `proof/transfer-proof.ts`.
 */
import { RING_SLOT_PADDING, ringInputOpening, ringOutputOpening } from "../rpc/prover/assembly.js";
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
  EMPTY_ENTRY_RECORD,
  InputClass,
  type AuditEnvelope,
  type EntryRecord,
} from "../protocol/codec/audit-stream.js";
import {
  checkedStreamLayout,
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
  /** `tx_viewing_sk ‖ R ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  /** One sealed `V_i` per published slot. */
  readonly recipientKeys: readonly Uint8Array[];
  /** Each exit's record in slot order, the auditor message carries them. */
  readonly exitRecords: readonly Uint8Array[];
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
        recipientKeys: input.published.map((slot) => slot.recipientKey),
        inputs: input.inputs,
      }),
    });
    return Object.freeze({
      audit: Object.freeze({ entry: layout.key.entry }),
      layout,
      ...sealed,
      exitRecords: Object.freeze(
        input.published.flatMap((slot) =>
          slot.wire.body.kind === "exit" ? [slot.wire.record] : [],
        ),
      ),
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
    /** `V_i` of each published slot. */
    recipientKeys: readonly X25519PublicKey[];
    inputs: readonly ProofInputUtxo[];
  }>,
): RingDisclosure {
  const { layout, inputs } = input;
  return Object.freeze({
    envelope: auditEnvelopeOf(input.txViewingSecret, inputs, layout),
    recipientKeys: Object.freeze(input.recipientKeys.map((key) => key.u())),
  });
}

/** `R ‖ default_note_bits ‖ entries` past the sealed key, the records by note order. */
function auditEnvelopeOf(
  txViewingSecret: Bytes32,
  inputs: readonly ProofInputUtxo[],
  layout: AuditStreamLayout,
): AuditEnvelope {
  checkedStreamLayout(layout);
  if (inputs.length !== layout.inputs)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "RingTransactLength" },
    });
  const notes = spentNotes(inputs);
  const head = { txViewingSecret, realInputs: notes.length };
  if (!layout.key.entry) return { ...head, evidence: { kind: "none" } };
  return {
    ...head,
    evidence: {
      kind: "entry",
      defaultNoteBits: defaultNoteBits(notes),
      inputs: Array.from({ length: layout.inputs }, (_, note) => {
        const spent = notes[note];
        return spent === undefined ? EMPTY_ENTRY_RECORD : entryRecord(spent);
      }),
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

/** The spent notes in SPP's note order, the ring proof's input slots ahead of its padding. */
export function spentNotes(inputs: readonly ProofInputUtxo[]): readonly ProofInputUtxo[] {
  return inputs.filter((input) => inputClassOf(input) === InputClass.note);
}

/** Bit `k` set when note `k` is a default-ring note. */
export function defaultNoteBits(notes: readonly ProofInputUtxo[]): bigint {
  return notes.reduce(
    (bits, input, note) => (isDefaultRingNote(input) ? bits | (1n << BigInt(note)) : bits),
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

/**
 * Go `OutputOpening` per slot of the key's capacity. The published slots seal to their `V_i`, an
 * unpublished capacity slot is prover only and seals to the auditor's key.
 */
export function outputOpenings(
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    tree: TreeId;
    capacity: number;
    /** `V_i` of each published slot, the outputs past them are the omitted suffix. */
    recipientKeys: readonly X25519PublicKey[];
    auditor: X25519PublicKey;
  }>,
): readonly OutputOpeningProofInput[] {
  const { outputs, tree, capacity, recipientKeys, auditor } = input;
  const keyOf = (slot: number): Bytes32 => (recipientKeys[slot] ?? auditor).u();
  const padding = Array.from({ length: Math.max(0, capacity - outputs.length) }, (_, index) =>
    Object.freeze({
      output: RING_SLOT_PADDING,
      ...zeroEntryOpening(),
      recipientKey: keyOf(outputs.length + index),
    }),
  );
  return Object.freeze([
    ...outputs.map((output, slot) =>
      Object.freeze({
        output: ringOutputOpening(output, tree),
        ...(output.ownerAddress === undefined
          ? zeroEntryOpening()
          : {
              ownerKey: output.ownerAddress.signingPublicKey.confidentialViewTag() as Bytes32,
              mintChunks: mintChunks(output.asset),
            }),
        recipientKey: keyOf(slot),
      }),
    ),
    ...padding,
  ]);
}

/** The spent notes' openings in SPP's note order, padding past them to the key's input class. */
export function inputOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly RingSlotOpening[] {
  const notes = spentNotes(inputs);
  return Object.freeze([
    ...notes.map(ringInputOpening),
    ...Array.from({ length: inputClass - notes.length }, () => RING_SLOT_PADDING),
  ]);
}

/** Go `EntryOpening` per input slot by note order on an entry key, zero off a default-ring note. */
export function entryOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly EntryOpeningProofInput[] {
  const notes = spentNotes(inputs);
  return Object.freeze(
    Array.from({ length: inputClass }, (_, slot) => {
      const input = notes[slot];
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

function zeroEntryOpening(): EntryOpeningProofInput {
  return { ownerKey: ZERO_32, mintChunks: [ZERO_32, ZERO_32] };
}

function mintChunks(mint: Address): readonly Bytes32[] {
  return mergeMintChunks(mint).map((chunk) => bigIntBytes(chunk) as Bytes32);
}
