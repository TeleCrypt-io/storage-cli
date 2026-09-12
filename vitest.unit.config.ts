import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: [],
    exclude: ["**/node_modules/**", "test/functional/**", "test/harness/**"],
  },
});
