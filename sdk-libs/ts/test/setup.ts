import { beforeAll } from "vitest";

import { initializePoseidon } from "@heliuslabs/spr";

beforeAll(async () => {
  await initializePoseidon();
});
