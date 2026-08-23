import { defineConfig } from "vitest/config";

// Unit-only release gate: no Podman/Synapse global setup or functional stack.
export default defineConfig({
  test: {
    include: [
      "test/profile.test.ts",
      "test/storage.test.ts",
      "test/oidcApproval.test.ts",
      "test/cryptoSnapshot.test.ts",
      "test/oidcValidation.test.ts",
    ],
  },
});
