import { readFileSync } from "node:fs";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";
import { encodeBase58 } from "@heliuslabs/spr/internal";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/spr/interface";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/spr/interface";

import approvalFrames from "../../../../../test-vectors/proof/approval_totals_frame.json" with { type: "json" };
import expansion from "../../../../../test-vectors/proof/ring-transact-expansion.json" with { type: "json" };
import keyed from "../../../../../test-vectors/proof/ring_keyed_shapes.json" with { type: "json" };
import statements from "../../../../../test-vectors/audit/transfer_statement.json" with { type: "json" };
import { encodeRingTransactInstructionData } from "../../../src/protocol/proof/circuit.js";
import {
  applyEnrollmentsStatementHash,
  signerBinding,
  transferStatementElements,
  transferStatementHash,
  type TransferStatement,
} from "../../../src/protocol/proof/statement.js";
import {
  TRANSFER_SHAPES,
  fittedSpend,
  ringTransferCircuit,
} from "../../../src/protocol/proof/transfer-shapes.js";
import {
  trackingEntryChained,
  trackingEntryHash,
  trackingRecordHash,
  type TrackingEntry,
  type TrackingRecord,
} from "../../../src/protocol/membership/tracking.js";
import {
  RingTransactData,
  railShapes,
  type RingRail,
} from "../../../src/protocol/transaction/transact.js";

const field = (value: string): Bytes32 => hexToBytes(value) as Bytes32;
const hex = (value: Uint8Array): string => bytesToHex(value);

const RAILS: Readonly<Record<string, RingRail>> = {
  confidential: "confidential",
  anonymous: "anonymous",
  delegate: "delegate",
  "anonymous delegate": "anonymousDelegate",
};

beforeAll(initializePoseidon);

describe("ring-transact-expansion.json", () => {
  const config = { auditorPubkey: hexToBytes(expansion.auditor_pubkey) as Bytes33 };

  it.each(expansion.cases)("$name reads, writes and expands as Rust does", (vector) => {
    const rail = RAILS[vector.rail];
    if (rail === undefined) throw new Error(vector.rail);
    const data = RingTransactData.parse(hexToBytes(vector.compact), rail);
    expect(hex(RingTransactData.encode(data))).toBe(vector.compact);
    expect(hex(encodeRingTransactInstructionData(RingTransactData.expand(data, config)))).toBe(
      vector.transact_ix_data,
    );
    expect(hex(RingTransactData.sppInstructionData(data, config))).toBe(
      vector.spp_instruction_data,
    );
    const settlements = vector.settlements.map(([asset, user]) => ({
      asset: encodeBase58(hexToBytes(asset as string)),
      user: encodeBase58(hexToBytes(user as string)),
    }));
    expect(hex(RingTransactData.externalDataHash(data, config, settlements))).toBe(
      vector.external_data_hash,
    );
  });
});

describe("approval_totals_frame.json", () => {
  const APPROVAL_TOTALS_BIT = 1 << 4;

  describe.each(approvalFrames.cases.map((entry) => [entry.name, entry] as const))(
    "%s",
    (_, entry) => {
      const frame = hexToBytes(entry.frame);
      const digest = hexToBytes(entry.digest);

      it("reads the digest under bit 4 of the extension byte", () => {
        expect(frame[entry.extension_offset]).toBe(entry.extension_byte);
        expect(entry.extension_byte & APPROVAL_TOTALS_BIT).toBe(APPROVAL_TOTALS_BIT);
        expect(hex(frame.subarray(entry.digest_offset, entry.digest_offset + 32))).toBe(
          entry.digest,
        );
        const parsed = RingTransactData.parse(frame, "confidential");
        expect(hex(parsed.extensions.approvalTotals as Uint8Array)).toBe(entry.digest);
      });

      it("writes the same bytes back", () => {
        expect(hex(RingTransactData.encode(RingTransactData.parse(frame, "confidential")))).toBe(
          entry.frame,
        );
      });

      it("adds the digest to the frame that has none", () => {
        const base = RingTransactData.parse(hexToBytes(entry.base), "confidential");
        expect(base.extensions.approvalTotals).toBeUndefined();
        const written = RingTransactData.encode({
          ...base,
          extensions: { ...base.extensions, approvalTotals: digest as Bytes32 },
        });
        expect(hex(written)).toBe(entry.frame);
      });

      it("refuses the next extension bit", () => {
        const unknown = frame.slice();
        unknown[entry.extension_offset] = entry.extension_byte | 0x80;
        expect(() => RingTransactData.parse(unknown, "confidential")).toThrow(
          expect.objectContaining({
            code: "RING_TRANSACT_DATA_INVALID",
            details: { reason: "FlagNotAllowed" },
          }),
        );
      });
    },
  );
});

describe("frame.hex", () => {
  const lines = readFileSync(
    new URL("../../../../../test-vectors/settlement/frame.hex", import.meta.url),
    "utf8",
  )
    .split("\n")
    .filter((line) => line.length > 0);

  it.each(lines.map((line, index) => [index, line] as const))(
    "line %i reads under a rail and writes the same bytes",
    (_, line) => {
      const bytes = hexToBytes(line);
      const written = Object.values(RAILS).flatMap((rail) => {
        try {
          return [hex(RingTransactData.encode(RingTransactData.parse(bytes, rail)))];
        } catch {
          return [];
        }
      });
      expect(written).toContain(line);
    },
  );
});

describe("transfer_statement.json", () => {
  it.each(statements.cases)("$name rebuilds its elements and public input", (vector) => {
    const parties = vector.party_identities;
    const statement: TransferStatement = {
      head: {
        firstNullifier: field(vector.first_nullifier),
        ringId: field(vector.ring_id),
        txViewingU: field(vector.tx_viewing_u),
        auditorPubkey: hexToBytes(vector.auditor_pubkey) as Bytes33,
        envelope: hexToBytes(vector.envelope),
        recipientKeys: hexToBytes(vector.recipient_keys),
        salt: hexToBytes(vector.salt) as Bytes16,
        layout: { entry: (vector.layout & 2) !== 0 },
      },
      family:
        vector.family === "confidential"
          ? {
              kind: "confidential",
              inProof: vector.in_proof,
              delegate: vector.delegate,
              sender: field(vector.sender ?? "00".repeat(32)),
            }
          : {
              kind: "anonymous",
              partyIdentities: (parties ?? []).map(field),
              publicOwners: vector.public_owners,
              delegate: vector.delegate,
            },
      approvalMask: vector.approval_mask,
      approvalTotals: field(vector.approval_totals),
      noSpend: vector.no_spend,
      outputs: vector.outputs.map((output) => ({ record: hexToBytes(output.record) })),
      capacity: vector.output_capacity,
      inputCount: vector.input_count,
      privateTxHash: field(vector.private_tx_hash),
      signers: signerBinding(vector.signers.map(field), vector.signer_slots),
      roots: {
        policyHash: field(vector.policy_hash),
        ownRoot: field(vector.own_root),
        curatorRoot: field(vector.curator_root),
        trackingRoot: field(vector.tracking_root),
      },
      publicAssets: vector.public_assets.map(field),
      publicAmounts: vector.public_amounts.map(field),
      publicGross: vector.public_gross.map(field),
      withdrawalHash: field(vector.withdrawal_hash),
    };
    expect(hex(statement.signers.chain)).toBe(vector.signer_chain);
    expect(transferStatementElements(statement).map(hex)).toEqual(vector.elements);
    expect(hex(transferStatementHash(statement))).toBe(vector.public_input_hash);
  });
});

describe("ring_keyed_shapes.json", () => {
  const served = (rail: RingRail, spendsDefaultRing: boolean) =>
    SPP_SUPPORTED_SHAPES.filter(
      (shape) =>
        railShapes(rail).some(
          (held) => held.inputs === shape.inputs && held.outputs === shape.outputs,
        ) &&
        ringTransferCircuit(
          fittedSpend({
            rail,
            inputs: shape.inputs,
            outputs: shape.outputs,
            spendsDefaultRing,
            legs: 0,
            owners: 0,
            pools: { own: 0, curator: 0, tracking: 0 },
            wide: false,
          }),
        ) !== undefined,
    ).map((shape) => [shape.inputs, shape.outputs]);

  it("lists the catalog's shapes", () => {
    expect(TRANSFER_SHAPES.map((shape) => ({ ...shape }))).toEqual(
      keyed.transfer_shapes.map((shape) => expect.objectContaining(shape)),
    );
  });

  it("serves the shapes of every rail", () => {
    expect(served("confidential", false)).toEqual(keyed.confidential_ring);
    expect(served("anonymous", false)).toEqual(keyed.anonymous_ring);
    expect(served("anonymous", true)).toEqual(keyed.anonymous_entry_ring);
    expect(served("delegate", false)).toEqual(keyed.ring_authority);
  });
});

interface TrackingRow {
  readonly member: string;
  readonly next: string;
  readonly nullifier_pk: string;
  readonly ct_hash: string;
  readonly list_tag: string;
  readonly leaf_hash: string;
}

interface TrackingApplication {
  readonly name: string;
  readonly old_root: string;
  readonly new_root: string;
  readonly old_next_index: number;
  readonly new_next_index: number;
  readonly chain_start: string;
  readonly chain_end: string;
  readonly count: number;
  readonly statement_hash: string;
  readonly writes: readonly Readonly<{
    entry: Omit<TrackingRow, "next" | "leaf_hash"> & Readonly<{ entry_hash: string }>;
    low: TrackingRow;
  }>[];
}

describe("tracking-records.json", () => {
  const entryOf = (row: Omit<TrackingRow, "next" | "leaf_hash">) =>
    ({
      member: field(row.member),
      nullifierPk: field(row.nullifier_pk),
      ctHash: field(row.ct_hash),
      listTag: field(row.list_tag),
    }) satisfies TrackingEntry;
  const recordOf = (row: TrackingRow) =>
    ({ ...entryOf(row), next: field(row.next) }) satisfies TrackingRecord;

  it("hashes, chains and states every application as Rust does", () => {
    const tracking = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/registry/tracking-records.json", import.meta.url),
        "utf8",
      ),
    ) as Readonly<{ applications: readonly TrackingApplication[] }>;
    for (const application of tracking.applications) {
      let chain = field(application.chain_start);
      for (const write of application.writes) {
        expect(hex(trackingEntryHash(entryOf(write.entry))), application.name).toBe(
          write.entry.entry_hash,
        );
        expect(hex(trackingRecordHash(recordOf(write.low))), application.name).toBe(
          write.low.leaf_hash,
        );
        chain = trackingEntryChained(chain, entryOf(write.entry));
      }
      expect(hex(chain), application.name).toBe(application.chain_end);
      expect(
        hex(
          applyEnrollmentsStatementHash({
            oldRoot: field(application.old_root),
            newRoot: field(application.new_root),
            oldNextIndex: BigInt(application.old_next_index),
            newNextIndex: BigInt(application.new_next_index),
            chainStart: field(application.chain_start),
            chainEnd: field(application.chain_end),
            count: BigInt(application.count),
          }),
        ),
        application.name,
      ).toBe(application.statement_hash);
    }
  });
});
