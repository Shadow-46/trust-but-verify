import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./helpers.ts";

test("committed dist/ matches a fresh build of core/ (run `npm run build` if this fails)", async () => {
  const mod = (await import(pathToFileURL(join(ROOT, "tools", "build.mjs")).href)) as {
    build: (out: string) => string[];
  };
  const fresh = mkdtempSync(join(tmpdir(), "tbv-build-"));
  const files = mod.build(fresh);
  assert.ok(files.length > 0);
  for (const f of files) {
    const committed = readFileSync(join(ROOT, "dist", f), "utf8");
    assert.equal(committed, readFileSync(join(fresh, f), "utf8"), `dist/${f} is stale`);
  }
});
