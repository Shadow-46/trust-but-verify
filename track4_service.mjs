// Track 4 judging adapter (contract v1).
// Reads one UTF-8 JSON object from stdin until EOF, writes one JSON object to
// stdout, then exits. Diagnostics go to stderr and never include request data.
// The core is TypeScript executed directly by Node 24 (type stripping): no build
// step and no third-party dependencies.
import { handle } from "./core/adapter.ts";

const MAX_INPUT_BYTES = 32 * 1024 * 1024;

let reply;
try {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_INPUT_BYTES) throw new Error("input too large");
    chunks.push(chunk);
  }
  reply = handle(Buffer.concat(chunks).toString("utf8"));
} catch {
  reply = { status: 1, body: { error: "invalid_request" } };
}

process.stdout.write(`${JSON.stringify(reply.body)}\n`);
process.exitCode = reply.status;
