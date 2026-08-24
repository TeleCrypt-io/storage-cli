import { defineConfig } from "vitest/config";

// Unit-only release gate: no Podman/Synapse global setup or functional stack.
export default defineConfig({
  test: {
    include: [
      "test/profile.test.ts",
      "test/storage.test.ts",
      "test/oidcApproval.test.ts",
      "test/globalSetup.test.ts",
      "test/cryptoSnapshot.test.ts",
      "test/fileTransfer.test.ts",
      "test/oidcValidation.test.ts",
      "test/logout.test.ts",
      "test/loginTransaction.test.ts",
      "test/output.test.ts",
      "test/processExit.test.ts",
      "test/releaseArchive.test.ts",
      "test/waitFor.test.ts",
      "test/recoveryInput.test.ts",
      "test/indexRuntime.test.ts",
    ],
  },
});
