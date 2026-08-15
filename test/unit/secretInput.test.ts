import { describe, expect, it } from "vitest";
import { Readable } from "node:stream";
import { CliError } from "../../src/errors.js";
import { readSecret } from "../../src/secretInput.js";

function stdinFrom(chunks: string[]): NodeJS.ReadStream {
  return Readable.from(chunks) as NodeJS.ReadStream;
}

describe("readSecret from stdin", () => {
  it("rejects empty stdin", async () => {
    await expect(readSecret({ prompt: "", fromStdin: true, input: stdinFrom(["  \n"]) })).rejects.toEqual(
      expect.objectContaining<CliError>({ message: "Recovery Key must not be empty" }),
    );
  });

  it("returns a trimmed valid recovery key", async () => {
    await expect(readSecret({ prompt: "", fromStdin: true, input: stdinFrom(["  key-123  \n"]) })).resolves.toBe(
      "key-123",
    );
  });

  it("rejects an oversized streamed recovery key", async () => {
    const oversized = "x".repeat(16 * 1024 + 1);

    await expect(readSecret({ prompt: "", fromStdin: true, input: stdinFrom([oversized]) })).rejects.toEqual(
      expect.objectContaining<CliError>({ message: "Recovery Key is unexpectedly large" }),
    );
  });
});
