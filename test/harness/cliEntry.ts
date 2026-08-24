import { main } from "../../src/index.js";

// This entrypoint is intentionally outside the npm package; the shipped bin
// and the local fixture use the same fixed loopback identity binding.
await main(process.argv);
