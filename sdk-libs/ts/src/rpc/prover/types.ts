import type { RecordOpening } from "../../protocol/membership/member-registry.js";

/** Rust `MAX_RULES`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 9;

/** A member's record in a member registry, the opening a ring merge proves. */
export type PresentRecordOpening = Extract<RecordOpening, { kind: "present" }>;
