import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { newIdentity } from "./protocol.ts";
import type { Directory } from "./protocol.ts";
import { serveMessaging } from "./net.ts";

/**
 * A messaging peer in its own OS process (used by the network demo/tests):
 *
 *   node dist/core/messaging/peerProcess.js <id> <exchangeDir> <peerId>
 *
 * Generates its identity, publishes ONLY its public key to <exchangeDir>/<id>.pub
 * (standing in for the signed directory), reads the peer's public key from
 * <exchangeDir>/<peerId>.pub, listens on 127.0.0.1, prints `ready <port>` and
 * one JSON line per delivered message (sizes only, never plaintext). Exits when stdin closes.
 */
const [id, exchangeDir, peerId] = process.argv.slice(2);
if (!id || !exchangeDir || !peerId) {
  process.stderr.write("usage: peerProcess <id> <exchangeDir> <peerId>\n");
  process.exit(2);
}
const me = newIdentity(id);
writeFileSync(join(exchangeDir, `${id}.pub`), me.keys.publicKey.toString("base64"));
const peerPub = join(exchangeDir, `${peerId}.pub`);
if (!existsSync(peerPub)) {
  process.stderr.write("peer public key not found\n");
  process.exit(2);
}
const dir: Directory = new Map([[peerId, Buffer.from(readFileSync(peerPub, "utf8"), "base64")]]);
const server = await serveMessaging(me, dir, 0, (from, data) => process.stdout.write(`${JSON.stringify({ delivered_from: from, bytes: data.length })}\n`));
process.stdout.write(`ready ${server.port}\n`);
process.stdin.resume();
process.stdin.on("end", () => void server.close().then(() => process.exit(0)));
