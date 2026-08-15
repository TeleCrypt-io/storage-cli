import { defineConfig } from "vitest/config";

// Unit-only release gate: no Podman/Synapse global setup or functional stack.
export default defineConfig({
  test: {
    include: ["test/profile.test.ts", "test/storage.test.ts"],
  },
});
