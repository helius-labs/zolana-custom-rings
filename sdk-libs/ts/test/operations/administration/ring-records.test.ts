import { describe, expect, it } from "vitest";

import { ListId } from "../../../src/protocol/membership/policy.js";
import { checkWriter, listWrite } from "../../../src/operations/management/record-writes.js";

describe("list writes", () => {
  it("refuses a list the writer does not write and a write that changes nothing or both ways", () => {
    for (const listId of [ListId.allow, ListId.escrow])
      expect(() => checkWriter(listWrite({ set: [listId] }), "member")).toThrow(
        expect.objectContaining({
          code: "RING_LIST_WRITER_UNAUTHORIZED",
          details: { listId, writer: "member" },
        }),
      );
    expect(() => listWrite({})).toThrow(
      expect.objectContaining({ code: "RING_LIST_WRITE_INVALID", details: { reason: "Empty" } }),
    );
    expect(() => listWrite({ set: [ListId.allow], clear: [ListId.allow] })).toThrow(
      expect.objectContaining({ details: { reason: "SetAndCleared" } }),
    );
  });
});
