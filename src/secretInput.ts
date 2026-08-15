import * as readline from "node:readline";
import { CliError } from "./errors.js";

const MAX_SECRET_BYTES = 16 * 1024;

export interface ReadSecretOptions {
  prompt: string;
  fromStdin: boolean;
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
}

function validateSecret(value: string): string {
  const secret = value.trim();
  if (secret === "") throw new CliError("Recovery Key must not be empty");
  if (secret.includes("\0")) throw new CliError("Recovery Key contains an invalid NUL byte");
  if (Buffer.byteLength(secret) > MAX_SECRET_BYTES) {
    throw new CliError("Recovery Key is unexpectedly large");
  }
  return secret;
}

async function readAllStdin(input: NodeJS.ReadStream): Promise<string> {
  input.setEncoding("utf8");
  let value = "";
  for await (const chunk of input) {
    value += chunk;
    if (Buffer.byteLength(value) > MAX_SECRET_BYTES) {
      throw new CliError("Recovery Key is unexpectedly large");
    }
  }
  return validateSecret(value);
}

async function readHiddenLine(
  prompt: string,
  input: NodeJS.ReadStream,
  output: NodeJS.WriteStream,
): Promise<string> {
  if (!input.isTTY || typeof input.setRawMode !== "function") {
    throw new CliError(
      "Recovery Key input requires an interactive terminal; use --recovery-key-stdin for automation",
    );
  }

  output.write(prompt);
  readline.emitKeypressEvents(input);
  const wasRaw = Boolean(input.isRaw);
  input.setRawMode(true);
  input.resume();

  return await new Promise<string>((resolve, reject) => {
    let value = "";

    const finish = (error?: Error) => {
      input.off("keypress", onKeypress);
      input.setRawMode(wasRaw);
      input.pause();
      output.write("\n");
      if (error) reject(error);
      else {
        try {
          resolve(validateSecret(value));
        } catch (err) {
          reject(err);
        }
      }
    };

    const onKeypress = (character: string, key: readline.Key) => {
      if (key.ctrl && key.name === "c") {
        finish(new CliError("Recovery Key input cancelled"));
        return;
      }
      if (key.name === "return" || key.name === "enter") {
        finish();
        return;
      }
      if (key.name === "backspace") {
        value = Array.from(value).slice(0, -1).join("");
        return;
      }
      if (!key.ctrl && !key.meta && character) {
        value += character;
        if (Buffer.byteLength(value) > MAX_SECRET_BYTES) {
          finish(new CliError("Recovery Key is unexpectedly large"));
        }
      }
    };

    input.on("keypress", onKeypress);
  });
}

export async function readSecret(options: ReadSecretOptions): Promise<string> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stderr;
  return options.fromStdin
    ? readAllStdin(input)
    : readHiddenLine(options.prompt, input, output);
}
