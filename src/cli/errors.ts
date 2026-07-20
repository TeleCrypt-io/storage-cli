/** A user-facing CLI error: message goes straight to stderr (JSON or text),
 * never a stack trace. Thrown for expected failure conditions (bad login,
 * wrong recovery key, missing file, not logged in, ...). */
export class CliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliError";
  }
}
