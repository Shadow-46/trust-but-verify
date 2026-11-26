import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
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
const ID = /^[A-Za-z0-9._-]{1,64}$/;

const DEMO = {
  op: "setup",
  owners: { "design-doc": "maya", "payroll.xlsx": "omar", roadmap: "maya" },
  contents: {
    "design-doc": "Q3 design: PQC migration plan (confidential)",
    "payroll.xlsx": "salary bands v7 (confidential)",
    roadmap: "2027 roadmap draft",
  },
  disabled: ["dana"],
};

function run(args: string[], input?: unknown) {
  mkdirSync(STATE, { recursive: true });
  const started = performance.now();
  const r = spawnSync(process.execPath, args, {
    cwd: ROOT,
    input: input === undefined ? undefined : JSON.stringify(input),
    env: { ...process.env, TRACK4_STATE_DIR: STATE },
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
      case "reset":
        rmSync(SNAPSHOT, { force: true });
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
