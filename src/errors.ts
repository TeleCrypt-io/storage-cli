// The storage library owns the shared error contract; the CLI re-exports it
// so its command modules retain a local, focused import path.
export { CliError } from "@telecrypt-io/storage/core";
