// @ts-check
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: ["dist/**", "node_modules/**", "throwaway_synapse/**"],
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      // Matches this codebase's existing convention (predates this config file)
      // of prefixing intentionally-unused bindings with an underscore.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // matrix-js-sdk's MSC3089 types are frequently too narrow/incomplete for
      // how the test suite exercises them (e.g. casting branch/file objects
      // returned from listFiles()); the existing tests already lean on `any`
      // for this pervasively.
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
];
