import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ClusterNode } from "./node.ts";

/**
 * Run one node as its own OS process: poll the published policy every
 * `pollMs`, verify and adopt newer epochs, and record each adoption in
 * <nodeDir>/ack.json. Stops when <nodeDir>/stop exists.
 *
 *   node dist/core/cluster/nodeProcess.js <name> <nodeDir> <controlDir> <pollMs>
 */
const [name, nodeDir, controlDir, pollArg] = process.argv.slice(2);
if (!name || !nodeDir || !controlDir) {
  process.stderr.write("usage: nodeProcess <name> <nodeDir> <controlDir> [pollMs]\n");
  process.exit(2);
}
const pollMs = Math.max(5, Number(pollArg ?? 50));
const anchor = Buffer.from(readFileSync(join(controlDir, "anchor.pub"), "utf8"), "base64");
const node = new ClusterNode(name, nodeDir, anchor, join(controlDir, "policy.signed.json"));

const timer = setInterval(() => {
  if (existsSync(join(nodeDir, "stop"))) {
    clearInterval(timer);
    return;
  }
  try {
    const r = node.sync(Date.now());
    if (r.status === "rejected" && r.reason !== "unreadable") {
      process.stderr.write(`[${name}] refused policy update: ${r.reason}\n`);
    }
  } catch (err) {
    // A transient I/O failure must not take the node down: keep enforcing the
    // last verified policy and retry on the next tick.
    process.stderr.write(`[${name}] sync failed (${(err as NodeJS.ErrnoException).code ?? "error"}); retrying\n`);
  }
}, pollMs);
