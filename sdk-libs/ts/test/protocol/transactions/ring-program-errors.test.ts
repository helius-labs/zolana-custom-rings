import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RingProgramError, StorageProgramError } from "../../../src/protocol/error.js";

function fixture(file: string): readonly (readonly [string, number])[] {
  const codes = JSON.parse(
    readFileSync(new URL(`../../../../../test-vectors/errors/${file}`, import.meta.url), "utf8"),
  ) as Record<string, number>;
  return Object.entries(codes).map(([name, code]) => [
    `${name[0]?.toLowerCase()}${name.slice(1)}`,
    code,
  ]);
}

describe("RingProgramError", () => {
  const entries = Object.entries(RingProgramError);

  it("matches the shared Rust error code fixture exactly", () => {
    expect(entries).toEqual(fixture("custom-ring-errors.json"));
  });

  it("names each code once", () => {
    const codes = entries.map(([, code]) => code);
    expect(new Set(codes).size).toBe(codes.length);
  });
});

describe("StorageProgramError", () => {
  it("matches the shared Rust error code fixture exactly", () => {
    expect(Object.entries(StorageProgramError)).toEqual(fixture("storage-errors.json"));
  });
});
