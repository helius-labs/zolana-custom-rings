import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RingProgramError } from "../../../src/protocol/error.js";

describe("RingProgramError", () => {
  it("matches the shared Rust error code fixture exactly", () => {
    const fixture = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/errors/custom-ring-errors.json", import.meta.url),
        "utf8",
      ),
    ) as Record<string, number>;
    const expected = Object.entries(fixture).map(([name, code]) => [
      `${name[0]?.toLowerCase()}${name.slice(1)}`,
      code,
    ]);
    expect(Object.entries(RingProgramError)).toEqual(expected);
  });
});
