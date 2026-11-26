import { connect, createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import { initiate, respond } from "./protocol.ts";
import type { Directory, Envelope, Hello, Identity, Reply, Session } from "./protocol.ts";

/**
 * Network transport for the messaging protocol: newline-delimited JSON frames
 * over TCP. The wire is untrusted; everything security-relevant (handshake
 * signatures, hybrid key agreement, AEAD, replay and recipient binding) is
 * done by protocol.ts exactly as in the in-memory tests. This layer only adds
 * framing limits: a frame over 64 KB or one that is not JSON closes the
 * connection with a fixed error code (never echoing the input).
 */

export const MAX_FRAME_BYTES = 64 * 1024;

export type WireResult =
  | { type: "result"; status: "delivered"; msg_id: string; bytes: number }
  | { type: "result"; status: "buffered"; msg_id: string }
  | { type: "result"; status: "rejected"; reason: string }
  | { type: "error"; reason: string }
  | { type: "closed" };

function readFrames(socket: Socket, onFrame: (f: unknown) => void, onError: (reason: string) => void): void {
  let buf = "";
  let dead = false;
  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    if (dead) return;
    buf += chunk;
    for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) return void ((dead = true), onError("frame_too_large"));
      let f: unknown;
      try {
        f = JSON.parse(line);
      } catch {
        return void ((dead = true), onError("malformed_frame"));
      }
      onFrame(f);
    }
    if (Buffer.byteLength(buf, "utf8") > MAX_FRAME_BYTES) {
      dead = true;
      onError("frame_too_large");
    }
  });
}

const write = (s: Socket, f: unknown) => {
  if (!s.destroyed) s.write(`${JSON.stringify(f)}\n`);
};

export type MessagingServer = { port: number; close: () => Promise<void> };

/** Accept sessions for `me`: the first frame must be a signed hello, every later frame an envelope. */
export function serveMessaging(me: Identity, dir: Directory, port = 0, onDelivered?: (from: string, data: Buffer) => void): Promise<MessagingServer> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    let session: Session | null = null;
    socket.on("close", () => {
      sockets.delete(socket);
      session?.close();
    });
    socket.on("error", () => socket.destroy());
    readFrames(
      socket,
      (f) => {
        if (!session) {
          try {
            const r = respond(me, f as Hello, dir);
            session = r.session;
            write(socket, r.reply);
          } catch {
            write(socket, { type: "error", reason: "handshake_rejected" });
            socket.end();
          }
          return;
        }
        let r;
        try {
          r = session.receive(f as Envelope);
        } catch {
          r = { status: "rejected" as const, reason: "malformed_envelope" };
        }
        if (r.status === "delivered") {
          onDelivered?.(session.peer, r.data);
          write(socket, { type: "result", status: "delivered", msg_id: r.msg_id, bytes: r.data.length });
        } else if (r.status === "buffered") {
          write(socket, { type: "result", status: "buffered", msg_id: r.msg_id });
        } else {
          write(socket, { type: "result", status: "rejected", reason: r.reason });
        }
      },
      (reason) => {
        write(socket, { type: "error", reason });
        socket.end();
      },
    );
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () =>
      resolve({
        port: (server.address() as AddressInfo).port,
        close: () => {
          for (const s of sockets) s.destroy();
          return new Promise((r) => server.close(() => r()));
        },
      }),
    );
  });
}

export type MessagingClient = {
  session: Session;
  /** Encrypt and send; resolves with the peer's result for every chunk. */
  sendText: (text: string, chunkSize?: number) => Promise<{ envelopes: Envelope[]; results: WireResult[] }>;
  /** Send an arbitrary frame (used to demonstrate replay/tamper/oversize attacks on the wire). */
  sendRaw: (frame: unknown, rawLine?: string) => Promise<WireResult>;
  close: () => void;
};

/** Open a TCP connection to `peer` and run the signed hybrid handshake. */
export async function connectMessaging(me: Identity, peer: string, port: number, dir: Directory, host = "127.0.0.1", timeoutMs = 3_000): Promise<MessagingClient> {
  const socket = connect(port, host);
  socket.on("error", () => socket.destroy());
  const inbox: unknown[] = [];
  const waiting: ((f: unknown) => void)[] = [];
  const deliver = (f: unknown) => {
    const w = waiting.shift();
    if (w) w(f);
    else inbox.push(f);
  };
  readFrames(socket, deliver, (reason) => deliver({ type: "error", reason }));
  socket.on("close", () => {
    while (waiting.length) waiting.shift()?.({ type: "closed" });
  });
  const next = (): Promise<WireResult> =>
    new Promise((resolve) => {
      if (inbox.length) return resolve(inbox.shift() as WireResult);
      if (socket.destroyed) return resolve({ type: "closed" });
      const t = setTimeout(() => resolve({ type: "error", reason: "timeout" }), timeoutMs);
      waiting.push((f) => {
        clearTimeout(t);
        resolve(f as WireResult);
      });
    });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });

  const h = initiate(me, peer);
  write(socket, h.hello);
  const reply = (await next()) as unknown as Reply;
  const session = h.finish(reply, dir); // throws if the peer's signature or identity is wrong

  return {
    session,
    sendText: async (text, chunkSize = 1024) => {
      const envelopes = session.send(Buffer.from(text, "utf8"), chunkSize);
      const results: WireResult[] = [];
      for (const e of envelopes) {
        write(socket, e);
        results.push(await next());
      }
      return { envelopes, results };
    },
    sendRaw: async (frame, rawLine) => {
      if (rawLine !== undefined) socket.write(`${rawLine}\n`);
      else write(socket, frame);
      return next();
    },
    close: () => {
      session.close();
      socket.end();
    },
  };
}
