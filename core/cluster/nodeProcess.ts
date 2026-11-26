import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ClusterNode } from "./node.ts";
import { pullPolicy } from "./transport.ts";

/**
 * Run one node as its own OS process: poll the published policy every
 * `pollMs`, verify and adopt newer epochs, and record each adoption in
 * <nodeDir>/ack.json. Stops when <nodeDir>/stop exists.
 *
 *   node dist/core/cluster/nodeProcess.js <name> <nodeDir> <controlDir | http://host:port/policy> [pollMs]
 *
 * With an http:// source the node pulls over the network and trusts only its
 * provisioning record (<nodeDir>/trust.json: anchor + epoch floor).
 */
const [name, nodeDir, source, pollArg] = process.argv.slice(2);
if (!name || !nodeDir || !source) {
  process.stderr.write("usage: nodeProcess <name> <nodeDir> <controlDir|url> [pollMs]\n");
  process.exit(2);
}
const pollMs = Math.max(5, Number(pollArg ?? 50));
const overHttp = source.startsWith("http://") || source.startsWith("https://");
const node = overHttp
  ? ClusterNode.provisioned(name, nodeDir, source)
  : new ClusterNode(name, nodeDir, Buffer.from(readFileSync(join(source, "anchor.pub"), "utf8"), "base64"), join(source, "policy.signed.json"));

const report = (status: string, reason: string) => {
  if (status === "rejected" && reason !== "unreadable") process.stderr.write(`[${name}] refused policy update: ${reason}\n`);
};

async function tick(): Promise<void> {
  if (existsSync(join(nodeDir, "stop"))) return;
  try {
    if (overHttp) {
      const r = await pullPolicy(node, source);
      if (r.status === "rejected") report(r.status, r.reason);
    } else {
      const r = node.sync();
      if (r.status === "rejected") report(r.status, r.reason);
    }
  } catch (err) {
    // A transient I/O failure must not take the node down: keep enforcing the
    // last verified policy and retry on the next tick.
    process.stderr.write(`[${name}] sync failed (${(err as NodeJS.ErrnoException).code ?? "error"}); retrying\n`);
  }
  setTimeout(() => void tick(), pollMs);
}
void tick();
