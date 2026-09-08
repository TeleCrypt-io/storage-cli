import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/harness/globalSetup.ts"],
    bail: 1,
    retry: 0,
    testTimeout: 30000,
    hookTimeout: 30000,
    exclude: ["**/node_modules/**"],
  },
});
