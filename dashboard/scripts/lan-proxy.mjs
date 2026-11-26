// Read-only LAN gateway for the two-laptop demo.
//
// The console (Next.js) listens on 127.0.0.1 only, so only this laptop can drive it.
// This proxy listens on all interfaces (default :3001) and lets another laptop open
// pages (e.g. /monitor) and call READ-ONLY API actions. Anything that changes state
// (reset, revoke, attacks, cluster control...) is refused with 403, so nobody else on
// the Wi-Fi can drive the demo.
//
//   npm run lan            # then open http://<this-laptop-ip>:3001/monitor on laptop B
import { createServer, request } from "node:http";
import { connect } from "node:net";
import { networkInterfaces } from "node:os";

const TARGET = { host: "127.0.0.1", port: Number(process.env.CONSOLE_PORT ?? 3000) };
const PORT = Number(process.env.LAN_PORT ?? 3001);
const READ_ONLY = new Set(["monitor", "session-get", "state", "log", "alerts", "evidence", "attacks", "cluster-status", "lab-runs"]);
const MAX_BODY = 16 * 1024;

function forward(req, res, body) {
  const headers = { ...req.headers, host: `${TARGET.host}:${TARGET.port}` };
  if (body) headers["content-length"] = String(body.length);
  const up = request({ ...TARGET, method: req.method, path: req.url, headers }, (r) => {
    res.writeHead(r.statusCode ?? 502, r.headers);
    r.pipe(res);
  });
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  if (body) up.end(body);
  else req.pipe(up);
}

const server = createServer((req, res) => {
  if (req.method === "GET" || req.method === "HEAD") return forward(req, res);
  if (req.method === "POST" && req.url === "/api/run") {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) req.destroy();
      else chunks.push(c);
    });
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      let action;
      try {
        action = JSON.parse(body.toString("utf8")).action;
      } catch {
        action = undefined;
      }
      if (!READ_ONLY.has(action)) {
        res.writeHead(403, { "content-type": "application/json" }).end(JSON.stringify({ ok: false, out: { error: "read_only_from_lan" } }));
        return;
      }
      forward(req, res, body);
    });
    return;
  }
  res.writeHead(403).end();
});

// Next dev's hot-reload socket (so a dev-mode page on laptop B doesn't keep reloading).
server.on("upgrade", (req, socket, head) => {
  if (!req.url?.startsWith("/_next/")) return socket.destroy();
  const up = connect(TARGET.port, TARGET.host, () => {
    up.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n${Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n")}\r\n\r\n`);
    up.write(head);
    socket.pipe(up).pipe(socket);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});

server.listen(PORT, "0.0.0.0", () => {
  const ips = Object.values(networkInterfaces()).flat().filter((i) => i && i.family === "IPv4" && !i.internal).map((i) => i.address);
  console.log(`Read-only LAN gateway on port ${PORT} -> console 127.0.0.1:${TARGET.port}`);
  for (const ip of ips) console.log(`  Laptop B: http://${ip}:${PORT}/monitor`);
});
