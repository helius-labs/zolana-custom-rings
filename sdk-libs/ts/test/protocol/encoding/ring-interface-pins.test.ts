import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  APPLY_BATCH,
  QUAD_ARITY,
  QUAD_HEIGHT,
} from "../../../src/protocol/membership/member-registry.js";
import { InstructionTag } from "@heliuslabs/zolana/interface";
import {
  RingInstructionTag,
  ringComputeUnitLimit,
} from "../../../src/operations/management/admin.js";
import {
  GRACE_SLOTS,
  RING_PROGRAM_CONFIG_DISCRIMINATOR,
  RING_PROGRAM_CONFIG_SIZE,
} from "../../../src/protocol/codec/ring-codecs.js";

function rust(file: string): string {
  return readFileSync(
    new URL(`../../../../../program-libs/interface/src/${file}`, import.meta.url),
    "utf8",
  );
}

/** A Rust integer literal or `a << b`, underscores allowed. */
function integer(literal: string): bigint {
  const [base = "", shift] = literal.split("<<").map((part) => part.trim().replaceAll("_", ""));
  return shift === undefined ? BigInt(base) : BigInt(base) << BigInt(shift);
}

function lowerFirst(name: string): string {
  return `${name.slice(0, 1).toLowerCase()}${name.slice(1)}`;
}

function camel(name: string): string {
  return name.toLowerCase().replace(/_([a-z])/gu, (_, letter: string) => letter.toUpperCase());
}

describe("ring interface pins", () => {
  it("tags and budgets every instruction like Rust `instruction_tags!`", () => {
    const source = rust("instructions/instruction.rs");
    const units = new Map(
      [...source.matchAll(/^const ([A-Z_]+): u32 = ([\d_]+);$/gmu)].map(
        ([, name = "", value = ""]) => [name, integer(value)] as const,
      ),
    );
    const tags = new Map(Object.entries(RingInstructionTag));
    const spp = new Map<string, number>(Object.entries(InstructionTag));
    const rows = [...source.matchAll(/^ {4}([A-Za-z]+) = [A-Z_]+: ([\w:]+) => ([\w]+),$/gmu)];
    expect(rows.map(([, variant = ""]) => lowerFirst(variant)).sort()).toEqual(
      [...tags.keys()].sort(),
    );
    for (const [, variant = "", tag = "", budget = ""] of rows) {
      const name = lowerFirst(variant);
      const forwarded = /::([A-Z_]+)$/u.exec(tag)?.[1];
      const expected = forwarded === undefined ? Number(tag) : spp.get(camel(forwarded));
      const actual = tags.get(name);
      expect(actual, name).toBe(expected);
      if (actual === undefined) continue;
      expect(BigInt(ringComputeUnitLimit(actual)), name).toBe(units.get(budget) ?? integer(budget));
    }
  });

  it("bounds the record tree like Rust `member_registry`", () => {
    const constants = new Map(
      [
        ...rust("accounts/member_registry.rs").matchAll(
          /^pub const ([A-Z_]+): (?:u64|usize) = ([\d_ <]+);$/gmu,
        ),
      ].map(([, name = "", value = ""]) => [name, integer(value)] as const),
    );
    expect(constants.get("QUAD_ARITY")).toBe(BigInt(QUAD_ARITY));
    expect(constants.get("QUAD_HEIGHT")).toBe(BigInt(QUAD_HEIGHT));
    expect(constants.get("APPLY_BATCH")).toBe(BigInt(APPLY_BATCH));
    expect(constants.get("GRACE_SLOTS")).toBe(GRACE_SLOTS);
  });

  it("reads each ring account at the discriminator and size Rust asserts", () => {
    const source = rust("accounts/state.rs");
    const discriminator = (name: string): number =>
      Number(new RegExp(`^ {4}${name} = [A-Z_]+: (\\d+),`, "mu").exec(source)?.[1]);
    const size = (name: string): number =>
      Number(new RegExp(`assert!\\(${name}::SIZE == (\\d+)\\)`, "u").exec(source)?.[1]);
    expect([discriminator("RingProgramConfig"), size("RingProgramConfig")]).toEqual([
      RING_PROGRAM_CONFIG_DISCRIMINATOR,
      RING_PROGRAM_CONFIG_SIZE,
    ]);
  });
});
