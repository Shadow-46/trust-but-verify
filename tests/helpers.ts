import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const ENTRY = join(ROOT, "track4_service.mjs");

export type Result = { status: number | null; out: Record<string, unknown>; stdout: string; stderr: string };

export function freshStateDir(): string {
  return mkdtempSync(join(tmpdir(), "tbv-test-"));
}

function parse(stdout: string): Record<string, unknown> {
  try {
    return JSON.parse(stdout) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Run one adapter request in a new process, exactly like the judging worker. */
export function call(stateDir: string, request: unknown, raw?: string): Result {
  const r = spawnSync(process.execPath, [ENTRY], {
    input: raw ?? JSON.stringify(request),
    env: { ...process.env, TRACK4_STATE_DIR: stateDir, TRACK4_MASTER_KEY: "" },
    encoding: "utf8",
  });
  return { status: r.status, out: parse(r.stdout), stdout: r.stdout, stderr: r.stderr };
}

export function callAsync(stateDir: string, request: unknown): Promise<Result> {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [ENTRY], {
      env: { ...process.env, TRACK4_STATE_DIR: stateDir, TRACK4_MASTER_KEY: "" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolvePromise({ status, out: parse(stdout), stdout, stderr }));
    child.stdin.end(JSON.stringify(request));
  });
}

/** Concatenated bytes of every file under `dir` (to prove secrets are not stored in plaintext). */
export function allBytes(dir: string): string {
  let acc = "";
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    acc += statSync(p).isDirectory() ? allBytes(p) : readFileSync(p, "latin1");
  }
  return acc;
}

export const SETUP = {
  op: "setup",
  owners: { brief: "maya", ledger: "omar" },
  contents: { brief: "demo note — ✓ unicode", ledger: "quarterly numbers 42" },
  disabled: ["dana"],
  key_material: "synthetic-only-KEYMAT-8c1f",
};
