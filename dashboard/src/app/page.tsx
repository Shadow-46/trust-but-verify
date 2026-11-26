"use client";

import { useCallback, useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Res = { ok: boolean; out: any; ms?: number };
type LogRow = { seq: number; ts: string; type: string; request_id: string | null; actor: string | null; asset: string | null; decision: string | null; reason: string | null; hash: string };

const ACTORS = ["maya", "omar", "dana", "mallory"];
const ASSETS = ["design-doc", "payroll.xlsx", "roadmap"];
const REASONS: Record<string, string> = {
  owner: "Owner, device trusted",
  not_owner: "Not the owner of this file",
  revoked: "Identity revoked (lost device)",
  disabled: "Account disabled",
  unknown_asset: "No such file",
  integrity_failure: "Stored data failed integrity check",
  request_id_reused: "Reused request ID",
};

async function call(action: string, extra: Record<string, unknown> = {}): Promise<Res> {
  const r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...extra }) });
  return r.json();
}

function Decision({ d }: { d: string | null }) {
  if (!d) return <Badge variant="secondary">event</Badge>;
  return d === "allow" ? <Badge className="bg-emerald-600 text-white">ALLOW</Badge> : <Badge variant="destructive">DENY</Badge>;
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-2xl font-semibold">{value}</div>
    </div>
  );
}

export default function Console() {
  const [actor, setActor] = useState("maya");
  const [asset, setAsset] = useState("design-doc");
  const [last, setLast] = useState<{ label: string; res: Res } | null>(null);
  const [log, setLog] = useState<LogRow[]>([]);
  const [state, setState] = useState<any>(null);
  const [verify, setVerify] = useState<any>(null);
  const [ev, setEv] = useState<any>(null);
  const [det, setDet] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const [l, s] = await Promise.all([call("log"), call("state")]);
    setLog(Array.isArray(l.out) ? [...l.out].reverse() : []);
    setState(s.ok ? s.out : null);
  }, []);

  const act = async (label: string, action: string, extra: Record<string, unknown> = {}) => {
    setBusy(true);
    try {
      const res = await call(action, extra);
      setLast({ label, res });
      await refresh();
      return res;
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    // Initial load of the operator view from the local API (client-only console).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    void call("evidence").then((r) => setEv(r.out));
  }, [refresh]);

  const select = "h-9 rounded-md border bg-background px-2 text-sm";
  const det0 = ev?.detector;
  const cl = ev?.cluster;

  return (
    <main className="mx-auto max-w-6xl space-y-6 p-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Trust, but verify</h1>
          <p className="text-muted-foreground">Operator console · post-quantum zero-trust · every decision explained and signed</p>
        </div>
        <div className="flex gap-2 text-xs">
          <Badge variant="outline">ML-KEM-768</Badge>
          <Badge variant="outline">ML-DSA-65</Badge>
          <Badge variant="outline">X25519 hybrid</Badge>
          <Badge variant="outline">AES-256-GCM</Badge>
        </div>
      </header>

      <Tabs defaultValue="device">
        <TabsList>
          <TabsTrigger value="device">Lost device</TabsTrigger>
          <TabsTrigger value="integrity">Integrity &amp; keys</TabsTrigger>
          <TabsTrigger value="cluster">Revocation across nodes</TabsTrigger>
          <TabsTrigger value="detector">Detector</TabsTrigger>
        </TabsList>

        <TabsContent value="device" className="grid gap-4 md:grid-cols-3">
          <Card className="md:col-span-1">
            <CardHeader>
              <CardTitle>Protected workflow</CardTitle>
              <CardDescription>Calls the same adapter the judges call.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button className="w-full" variant="outline" disabled={busy} onClick={() => act("Setup", "setup")}>
                1 · Set up demo files
              </Button>
              <div className="flex gap-2">
                <select className={select} value={actor} onChange={(e) => setActor(e.target.value)}>
                  {ACTORS.map((a) => <option key={a}>{a}</option>)}
                </select>
                <select className={select} value={asset} onChange={(e) => setAsset(e.target.value)}>
                  {ASSETS.map((a) => <option key={a}>{a}</option>)}
                </select>
              </div>
              <Button className="w-full" disabled={busy} onClick={() => act(`${actor} reads ${asset}`, "read", { actor, asset })}>
                2 · Read as {actor}
              </Button>
              <Button className="w-full" variant="destructive" disabled={busy} onClick={() => act(`Revoke ${actor} (device lost)`, "revoke", { actor })}>
                3 · Report {actor}&apos;s device lost
              </Button>
              {last && (
                <div className="rounded-md border p-3 text-sm">
                  <div className="mb-1 flex items-center justify-between font-medium">
                    {last.label}
                    {typeof last.res.ms === "number" && <span className="text-xs text-muted-foreground">{last.res.ms} ms</span>}
                  </div>
                  {last.res.out?.decision && <Decision d={last.res.out.decision} />}
                  <pre className="mt-2 whitespace-pre-wrap break-all text-xs text-muted-foreground">{JSON.stringify(last.res.out, null, 1)}</pre>
                </div>
              )}
              {state && (
                <div className="space-y-1 text-xs text-muted-foreground">
                  <div>State version {state.version} · active key v{state.active_key}</div>
                  <div>Revoked: {state.revoked.length ? state.revoked.join(", ") : "none"} · Disabled: {state.disabled.join(", ") || "none"}</div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>Signed decision trail</CardTitle>
              <CardDescription>Every allow and every block, with its reason. Hash-chained and ML-DSA-65 signed.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="max-h-[460px] overflow-auto text-sm">
                <table className="w-full">
                  <thead className="text-left text-xs text-muted-foreground">
                    <tr><th className="py-1">#</th><th>Event</th><th>Who</th><th>File</th><th>Decision</th><th>Why</th><th>Hash</th></tr>
                  </thead>
                  <tbody>
                    {log.map((r) => (
                      <tr key={r.seq} className="border-t">
                        <td className="py-1 text-muted-foreground">{r.seq}</td>
                        <td>{r.type.replace(/_/g, " ")}</td>
                        <td>{r.actor ?? "—"}</td>
                        <td>{r.asset ?? "—"}</td>
                        <td><Decision d={r.decision} /></td>
                        <td>{(r.reason && REASONS[r.reason]) ?? r.reason ?? ""}</td>
                        <td className="font-mono text-xs text-muted-foreground">{r.hash}…</td>
                      </tr>
                    ))}
                    {log.length === 0 && <tr><td colSpan={7} className="py-6 text-center text-muted-foreground">Run setup to begin.</td></tr>}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="integrity" className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Verify &amp; rotate</CardTitle>
              <CardDescription>Operators can verify the key-event log with only the public key.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button className="w-full" disabled={busy} onClick={async () => setVerify((await act("Verify signed log", "verify")).out)}>
                Verify audit log (chain + ML-DSA signatures)
              </Button>
              {verify && (
                <div className="flex items-center gap-2 text-sm">
                  {verify.ok ? <Badge className="bg-emerald-600 text-white">VALID</Badge> : <Badge variant="destructive">BROKEN</Badge>}
                  {verify.records} records · signatures checked: {String(verify.signatures_checked)}
                  {verify.first_bad_seq ? ` · first bad record #${verify.first_bad_seq}` : ""}
                </div>
              )}
              <Button className="w-full" variant="outline" disabled={busy} onClick={() => act("Rotate data key", "rotate")}>
                Rotate data key (re-encrypt every file atomically)
              </Button>
              {state && <div className="text-xs text-muted-foreground">Keys: {state.keys.map((k: any) => `v${k.version} ${k.status}`).join(" · ")}</div>}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Attack: undo a revocation on disk</CardTitle>
              <CardDescription>An attacker restores an older, validly authenticated state file to re-enable a revoked user.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button className="w-full" variant="outline" disabled={busy} onClick={() => act("Snapshot state (attacker copies it)", "snapshot")}>
                1 · Attacker copies today&apos;s state file
              </Button>
              <p className="text-xs text-muted-foreground">Now revoke someone on the Lost device tab, then:</p>
              <Button className="w-full" variant="destructive" disabled={busy} onClick={() => act("Attacker rolls state back", "rollback")}>
                2 · Attacker restores the old copy
              </Button>
              <Button className="w-full" disabled={busy} onClick={() => act(`${actor} reads ${asset} after rollback`, "read", { actor, asset })}>
                3 · Try to read as {actor}
              </Button>
              <p className="text-xs text-muted-foreground">
                Expected: <code>integrity_failure</code> — the state version no longer matches the signed audit log, so the
                service fails closed instead of trusting the rolled-back file.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cluster">
          <Card>
            <CardHeader>
              <CardTitle>Revocation &amp; rotation across 3 nodes</CardTitle>
              <CardDescription>
                Signed (ML-DSA-65), epoch-versioned policy pulled by separate node processes · evidence/t6-cluster.json ·{" "}
                {cl?.environment?.node} on {cl?.environment?.platform}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {cl && (
                <div className="grid gap-4 sm:grid-cols-3">
                  <Stat label="Revocation → last node enforcing (median)" value={`${cl.revocation_propagation_ms.median} ms`} />
                  <Stat label="Worst case (max)" value={`${cl.revocation_propagation_ms.max} ms`} />
                  <Stat label="Rotation grace period (demo)" value={`${cl.config.grace_ms} ms`} />
                </div>
              )}
              <table className="w-full text-sm">
                <tbody>
                  {cl?.steps?.map((s: any) => (
                    <tr key={s.step} className="border-t">
                      <td className="py-1">{s.pass ? <Badge className="bg-emerald-600 text-white">PASS</Badge> : <Badge variant="destructive">FAIL</Badge>}</td>
                      <td className="font-medium">{s.step}</td>
                      <td className="text-muted-foreground">{s.expect}</td>
                      <td className="text-xs text-muted-foreground">{String(Object.values(s.observed)[0])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-xs text-muted-foreground">Re-run live with <code>npm run demo:cluster</code>.</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="detector" className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle>Accuracy (labelled synthetic logs)</CardTitle>
              <CardDescription>Rules + approvals context + service-edge graph. No ML.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {det0 && (
                <>
                  <Stat label="F1 (standard / hard)" value={`${det0.standard.aggregate.f1} / ${det0.hard.aggregate.f1}`} />
                  <Stat label="Median time-to-alert" value={`${det0.standard.aggregate.median_time_to_alert_ms} ms`} />
                  <Stat label="False alerts per 1,000 benign" value={`${det0.standard.aggregate.false_alerts_per_1000_benign}`} />
                  <p className="text-xs text-muted-foreground">10 seeds per mode. Upper bound: synthetic data models the documented environment.</p>
                </>
              )}
              <Button className="w-full" disabled={busy} onClick={async () => setDet((await act("Run detector on a fresh log", "detect", { seed: Math.floor(Math.random() * 1e6) })).out)}>
                Run detector on a fresh synthetic log
              </Button>
            </CardContent>
          </Card>
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>Explained alerts</CardTitle>
              <CardDescription>Each alert names the identity, services, events and the rule that fired.</CardDescription>
            </CardHeader>
            <CardContent className="max-h-[480px] space-y-3 overflow-auto">
              {det?.alerts?.map((a: any) => (
                <div key={a.id} className="rounded-md border p-3 text-sm">
                  <div className="flex items-center gap-2">
                    <Badge variant={a.severity === "high" ? "destructive" : "secondary"}>{a.severity}</Badge>
                    <span className="font-medium">{a.rule.replace(/_/g, " ")}</span>
                    <span className="text-muted-foreground">· {a.actor}</span>
                  </div>
                  <p className="mt-1">{a.summary}</p>
                  <p className="mt-1 text-xs text-muted-foreground">services {a.services.join(" → ")} · events {a.events.join(", ")}</p>
                  <p className="text-xs text-muted-foreground">limits: {a.limits}</p>
                </div>
              ))}
              {det?.incidents && (
                <p className="text-xs text-muted-foreground">
                  Ground truth (hidden from the detector): {det.incidents.map((i: any) => i.kind.replace(/_/g, " ")).join(", ")}
                </p>
              )}
              {!det && <p className="text-sm text-muted-foreground">Run the detector to see explained alerts.</p>}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </main>
  );
}
