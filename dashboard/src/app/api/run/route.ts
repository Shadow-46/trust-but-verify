import { spawn, spawnSync } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Demo-only operator API. Every action maps to a fixed command of the real
 * service (track4_service.mjs, the same adapter the judges call) or the ops CLI,
 * run as a child process against a dashboard-only state directory. No arbitrary
 * commands or paths are accepted.
 */
// Route handlers for POST are dynamic and run on the Node.js runtime by default.

const ROOT = resolve(process.cwd(), "..");
const STATE = join(tmpdir(), "tbv-dashboard");
const SNAPSHOT = join(tmpdir(), "tbv-dashboard-snapshot.json");
const WITNESS = join(tmpdir(), "tbv-dashboard-witness");
const CLUSTER = join(tmpdir(), "tbv-dashboard-cluster");
const SESSION = join(tmpdir(), "tbv-dashboard-session.json");
const LAB = join(tmpdir(), "tbv-dashboard-lab");
const LAB_CURRENT = join(LAB, "current.json");
const SESSION_KEYS = ["checklist", "lastRead", "verify", "detector", "chat", "attackResults", "ripple"];
const NODE_NAMES = ["node-a", "node-b", "node-c"];
// Node processes and the policy server survive between requests (and dev hot reloads) on globalThis.
const g = globalThis as unknown as { __tbvNodes?: Map<string, ChildProcess>; __tbvPolicy?: { proc: ChildProcess; port: number } };
const nodes = (g.__tbvNodes ??= new Map<string, ChildProcess>());
function stopNode(name: string) {
  nodes.get(name)?.kill();
  nodes.delete(name);
}

/** The control plane's HTTP policy endpoint (its own process); nodes pull from it over the network. */
function stopPolicyServer() {
  g.__tbvPolicy?.proc.kill();
  g.__tbvPolicy = undefined;
}
function startPolicyServer(): Promise<number> {
  stopPolicyServer();
  const proc = spawn(process.execPath, [join(ROOT, "dist", "core", "cluster", "policyServerProcess.js"), join(CLUSTER, "control")], { stdio: ["ignore", "pipe", "ignore"] });
  return new Promise((resolvePort, reject) => {
    const t = setTimeout(() => reject(new Error("policy server did not start")), 10_000);
    let buf = "";
    proc.stdout!.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      const m = /ready (\d+)/.exec(buf);
      if (m) {
        clearTimeout(t);
        g.__tbvPolicy = { proc, port: Number(m[1]) };
        resolvePort(Number(m[1]));
      }
    });
  });
}
const policyUrl = () => (g.__tbvPolicy ? `http://127.0.0.1:${g.__tbvPolicy.port}/policy` : join(CLUSTER, "control"));

function setBlocked(name: string, blocked: boolean) {
  const file = join(CLUSTER, "control", "blocked.json");
  const list = new Set<string>(existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as string[]) : []);
  if (blocked) list.add(name);
  else list.delete(name);
  writeFileSync(file, JSON.stringify([...list]));
}

function startNode(name: string) {
  stopNode(name);
  const p = spawn(process.execPath, [join(ROOT, "dist", "core", "cluster", "nodeProcess.js"), name, join(CLUSTER, name), policyUrl(), "40"], { stdio: "ignore" });
  nodes.set(name, p);
  p.on("exit", () => {
    if (nodes.get(name) === p) nodes.delete(name);
  });
}
const ID = /^[A-Za-z0-9._-]{1,64}$/;

const DEMO = {
  op: "setup",
  owners: { "design-doc": "maya", "payroll.xlsx": "omar", roadmap: "maya", "budget.xlsx": "lee" },
  contents: {
    "design-doc": "Q3 design: PQC migration plan (confidential)",
    "payroll.xlsx": "salary bands v7 (confidential)",
    roadmap: "2027 roadmap draft",
    "budget.xlsx": "team budget FY27 (internal)",
  },
  disabled: ["dana"],
};

function run(args: string[], input?: unknown) {
  mkdirSync(STATE, { recursive: true });
  mkdirSync(WITNESS, { recursive: true });
  const started = performance.now();
  const r = spawnSync(process.execPath, args, {
    cwd: ROOT,
    input: input === undefined ? undefined : JSON.stringify(input),
    // The demo runs with the external witness and auto-quarantine enabled.
    env: { ...process.env, TRACK4_STATE_DIR: STATE, TRACK4_WITNESS_DIR: WITNESS, TRACK4_AUTO_QUARANTINE: "1", TRACK4_LAB_DIR: LAB, TRACK4_CLUSTER_DIR: CLUSTER },
    encoding: "utf8",
    timeout: 20_000,
  });
  let out: unknown;
  try {
    out = JSON.parse(r.stdout);
  } catch {
    out = { error: "no_output" };
  }
  // A fail-closed integrity refusal is the defence working, not a crash: flag it for the UI.
  const blocked = (out as { error?: string } | null)?.error === "integrity_failure";
  return { ok: r.status === 0, out, blocked, ms: Math.round(performance.now() - started) };
}

const adapter = (req: unknown) => run([join(ROOT, "track4_service.mjs")], req);
const ops = (...a: string[]) => run([join(ROOT, "dist", "core", "ops.js"), ...a]);
const evidence = (name: string) => {
  const p = join(ROOT, "evidence", name);
  return existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
};

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const str = (k: string) => {
    const v = body[k];
    if (typeof v !== "string" || !ID.test(v)) throw new Error(`invalid ${k}`);
    return v;
  };
  try {
    switch (body.action) {
      case "lab-catalog":
        return Response.json(ops("lab-catalog"));
      case "lab-runs":
        return Response.json(ops("lab-runs"));
      case "lab-start": {
        const id = str("id");
        const cat = ops("lab-catalog").out as { id: string; needs_cluster: boolean }[];
        // Cluster storyboards need the live node processes; start them if they are not running.
        if (cat.find((a) => a.id === id)?.needs_cluster && (!g.__tbvPolicy || NODE_NAMES.some((n) => !nodes.has(n)))) {
          NODE_NAMES.forEach(stopNode);
          stopPolicyServer();
          ops("cluster-init", CLUSTER);
          await startPolicyServer();
          NODE_NAMES.forEach(startNode);
          await new Promise((r) => setTimeout(r, 1200));
        }
        return Response.json(ops("lab-start", id));
      }
      case "lab-step": {
        const runId = typeof body.run === "string" && /^[0-9]+-[0-9a-f]{6}$/.test(body.run) ? body.run : null;
        if (!runId) throw new Error("invalid run");
        return Response.json(ops("lab-step", runId));
      }
      case "monitor": {
        // Read-only snapshot for the Live Monitor (laptop B): state, log tail, alerts, cluster, Lab step.
        const r = ops("monitor", ...(existsSync(join(CLUSTER, "demo-device.json")) ? [CLUSTER] : []));
        const lab = existsSync(LAB_CURRENT) ? JSON.parse(readFileSync(LAB_CURRENT, "utf8")) : null;
        return Response.json({ ...r, out: { ...(r.out as object), lab, running: Object.fromEntries(NODE_NAMES.map((n) => [n, nodes.has(n)])) } });
      }
      case "session-get":
        return Response.json({ ok: true, out: existsSync(SESSION) ? JSON.parse(readFileSync(SESSION, "utf8")) : {} });
      case "session-set": {
        // Demo panels shared by every open console (both laptops) and kept across refreshes.
        const s = (body.session ?? {}) as Record<string, unknown>;
        const kept = Object.fromEntries(SESSION_KEYS.filter((k) => k in s).map((k) => [k, s[k]]));
        const text = JSON.stringify(kept);
        if (text.length > 256 * 1024) throw new Error("session too large");
        writeFileSync(SESSION, text);
        return Response.json({ ok: true, out: { saved: true } });
      }
      case "reset":
        rmSync(SNAPSHOT, { force: true });
        rmSync(SESSION, { force: true });
        rmSync(LAB_CURRENT, { force: true });
        return Response.json(adapter({ ...DEMO, key_material: `synthetic-${randomBytes(8).toString("hex")}` }));
      case "setup":
        return Response.json(adapter({ ...DEMO, key_material: `synthetic-${randomBytes(8).toString("hex")}` }));
      case "read":
        return Response.json(adapter({ op: "read", actor: str("actor"), asset: str("asset"), request_id: `r-${randomBytes(4).toString("hex")}` }));
      case "revoke":
        return Response.json(adapter({ op: "revoke", actor: str("actor") }));
      case "audit":
        return Response.json(adapter({ op: "audit", request_id: str("request_id") }));
      case "log":
        return Response.json(ops("audit-log"));
      case "state":
        return Response.json(ops("state-summary"));
      case "verify":
        return Response.json(ops("verify-log"));
      case "rotate":
        return Response.json(ops("rotate"));
      case "snapshot":
        copyFileSync(join(STATE, "state.json"), SNAPSHOT);
        return Response.json({ ok: true, out: { saved: true } });
      case "rollback":
        // Simulated attacker with disk access restores an older, validly authenticated state file.
        copyFileSync(SNAPSHOT, join(STATE, "state.json"));
        return Response.json({ ok: true, out: { rolled_back: true } });
      case "cluster-start": {
        NODE_NAMES.forEach(stopNode);
        stopPolicyServer();
        const r = ops("cluster-init", CLUSTER);
        await startPolicyServer();
        NODE_NAMES.forEach(startNode);
        return Response.json(r);
      }
      case "cluster-partition":
      case "cluster-heal": {
        const name = str("node");
        if (!NODE_NAMES.includes(name)) throw new Error("invalid node");
        setBlocked(name, body.action === "cluster-partition");
        return Response.json({ ok: true, out: { node: name, partitioned: body.action === "cluster-partition" } });
      }
      case "cluster-status": {
        const r = ops("cluster-status", CLUSTER);
        return Response.json({ ...r, running: Object.fromEntries(NODE_NAMES.map((n) => [n, nodes.has(n)])), server: g.__tbvPolicy ? { port: g.__tbvPolicy.port } : null });
      }
      case "cluster-revoke":
        return Response.json(ops("cluster-revoke", CLUSTER));
      case "cluster-enrol":
        return Response.json(ops("cluster-enrol", CLUSTER));
      case "cluster-stop":
      case "cluster-restart": {
        const name = str("node");
        if (!NODE_NAMES.includes(name)) throw new Error("invalid node");
        if (body.action === "cluster-stop") stopNode(name);
        else startNode(name);
        return Response.json({ ok: true, out: { node: name, running: nodes.has(name) } });
      }
      case "messaging": {
        const text = typeof body.text === "string" ? body.text.replace(/[\r\n]+/g, " ").slice(0, 200) : "";
        return Response.json(text ? ops("messaging", text) : ops("messaging"));
      }
      case "attacks":
        return Response.json(ops("attacks"));
      case "attack":
        return Response.json(ops("attack", body.id === "all" ? "all" : str("id")));
      case "alerts":
        return Response.json(ops("alerts"));
      case "detect":
        return Response.json(ops("detect-sample", String(Number(body.seed ?? 1) || 1)));
      case "evidence":
        return Response.json({ ok: true, out: { cluster: evidence("t6-cluster.json"), detector: evidence("t5-detector.json") } });
      default:
        return Response.json({ ok: false, out: { error: "unknown action" } }, { status: 400 });
    }
  } catch (err) {
    return Response.json({ ok: false, out: { error: err instanceof Error ? err.message : "failed" } }, { status: 400 });
  }
}
