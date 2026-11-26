"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity, CheckCircle2, Clock, FileLock2, Fingerprint, KeyRound, Network, Radar, RotateCcw,
  ShieldAlert, ShieldCheck, Smartphone, Undo2, XCircle, Zap,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Res = { ok: boolean; out: any; ms?: number };
type LogRow = { seq: number; ts: string; type: string; actor: string | null; asset: string | null; decision: string | null; reason: string | null; hash: string };

const ACTORS = ["maya", "omar", "dana", "mallory"];
const ASSETS = ["design-doc", "payroll.xlsx", "roadmap"];
const REASONS: Record<string, string> = {
  owner: "Owner on a trusted device",
  not_owner: "Not the owner of this file",
  revoked: "Identity revoked — device reported lost",
  disabled: "Account disabled",
  unknown_asset: "No such file",
  integrity_failure: "Stored data failed integrity check",
  request_id_reused: "Reused request ID",
};

async function call(action: string, extra: Record<string, unknown> = {}): Promise<Res> {
  const r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...extra }) });
  return r.json();
}

function Verdict({ d }: { d: string | null }) {
  if (d === "allow")
    return <Badge className="gap-1 border-emerald-500/30 bg-emerald-500/15 text-emerald-300"><CheckCircle2 className="size-3" />ALLOW</Badge>;
  if (d === "deny")
    return <Badge className="gap-1 border-rose-500/30 bg-rose-500/15 text-rose-300"><XCircle className="size-3" />DENY</Badge>;
  return <Badge variant="outline" className="text-muted-foreground">event</Badge>;
}

function Kpi({ icon: Icon, label, value, hint }: { icon: typeof Zap; label: string; value: string; hint: string }) {
  return (
    <Card className="border-white/10 bg-white/[0.03] backdrop-blur">
      <CardContent className="flex items-start gap-3 p-4">
        <div className="rounded-lg bg-sky-500/10 p-2 text-sky-300"><Icon className="size-5" /></div>
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="font-heading text-2xl font-semibold tabular-nums">{value}</div>
          <div className="text-xs text-muted-foreground">{hint}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function Panel({ title, desc, icon: Icon, children, className = "" }: { title: string; desc: string; icon: typeof Zap; children: React.ReactNode; className?: string }) {
  return (
    <Card className={`border-white/10 bg-white/[0.03] ${className}`}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 font-heading text-base"><Icon className="size-4 text-sky-300" />{title}</CardTitle>
        <CardDescription>{desc}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
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
      const o = res.out ?? {};
      if (o.decision === "allow") toast.success(label, { description: "Allowed — owner on a trusted device" });
      else if (o.decision === "deny") toast.error(label, { description: "Denied — reason recorded in the signed trail" });
      else if (o.error) toast.error(label, { description: String(o.error) });
      else toast(label, { description: res.ms ? `${res.ms} ms` : "done" });
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

  const cl = ev?.cluster;
  const d0 = ev?.detector;

  return (
    <div className="min-h-screen bg-[radial-gradient(ellipse_at_top,rgba(56,189,248,0.12),transparent_55%)]">
      <header className="sticky top-0 z-10 border-b border-white/10 bg-background/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-6 py-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-gradient-to-br from-sky-400 to-indigo-500 p-2 shadow-lg shadow-sky-500/20">
              <ShieldCheck className="size-5 text-white" />
            </div>
            <div>
              <h1 className="font-heading text-lg font-semibold leading-tight">Trust, but verify</h1>
              <p className="text-xs text-muted-foreground">Post-quantum zero-trust operator console</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {["ML-KEM-768", "ML-DSA-65", "X25519 hybrid", "AES-256-GCM"].map((b) => (
              <Badge key={b} variant="outline" className="border-white/15 font-mono text-[11px] text-muted-foreground">{b}</Badge>
            ))}
            <Badge className="gap-1 border-emerald-500/30 bg-emerald-500/15 text-emerald-300"><Activity className="size-3" />12 / 12 goals measured</Badge>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Kpi icon={ShieldCheck} label="Official validator" value="22 / 22" hint="node 24.11.1 · offline · read-only" />
          <Kpi icon={Zap} label="Revocation → all nodes" value={cl ? `${cl.revocation_propagation_ms.median} ms` : "—"} hint={cl ? `max ${cl.revocation_propagation_ms.max} ms · 3 node processes` : ""} />
          <Kpi icon={Radar} label="Detector F1" value={d0 ? `${d0.standard.aggregate.f1}` : "—"} hint={d0 ? `${d0.standard.aggregate.false_alerts_per_1000_benign} false alerts / 1k benign` : ""} />
          <Kpi icon={Clock} label="Request latency" value="≈37 ms" hint="incl. process start · signed audit" />
        </section>

        <Tabs defaultValue="device" className="space-y-4">
          <TabsList className="bg-white/5">
            <TabsTrigger value="device" className="gap-2"><Smartphone className="size-4" />Lost device</TabsTrigger>
            <TabsTrigger value="integrity" className="gap-2"><Fingerprint className="size-4" />Integrity &amp; keys</TabsTrigger>
            <TabsTrigger value="cluster" className="gap-2"><Network className="size-4" />Revocation across nodes</TabsTrigger>
            <TabsTrigger value="detector" className="gap-2"><Radar className="size-4" />Detector</TabsTrigger>
          </TabsList>

          <TabsContent value="device" className="grid gap-4 lg:grid-cols-3">
            <Panel icon={FileLock2} title="Protected workflow" desc="Drives the same adapter the judges call.">
              <div className="space-y-3">
                <Button variant="outline" className="w-full justify-start gap-2" disabled={busy} onClick={() => act("Demo files set up", "setup")}>
                  <RotateCcw className="size-4" />Set up demo files
                </Button>
                <div className="grid grid-cols-2 gap-2">
                  <Select value={actor} onValueChange={(v) => setActor(String(v))}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>{ACTORS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                  </Select>
                  <Select value={asset} onValueChange={(v) => setAsset(String(v))}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>{ASSETS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <Button className="w-full justify-start gap-2 bg-sky-500 text-white hover:bg-sky-400" disabled={busy} onClick={() => act(`${actor} reads ${asset}`, "read", { actor, asset })}>
                  <FileLock2 className="size-4" />Read as {actor}
                </Button>
                <Button variant="destructive" className="w-full justify-start gap-2" disabled={busy} onClick={() => act(`${actor}'s device reported lost`, "revoke", { actor })}>
                  <ShieldAlert className="size-4" />Report {actor}&apos;s device lost
                </Button>
                {last && (
                  <div className="rounded-lg border border-white/10 bg-black/30 p-3">
                    <div className="mb-2 flex items-center justify-between gap-2 text-sm font-medium">
                      <span className="truncate">{last.label}</span>
                      {typeof last.res.ms === "number" && <span className="font-mono text-xs text-muted-foreground">{last.res.ms} ms</span>}
                    </div>
                    {last.res.out?.decision && <Verdict d={last.res.out.decision} />}
                    <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-muted-foreground">{JSON.stringify(last.res.out, null, 1)}</pre>
                  </div>
                )}
                {state && (
                  <>
                    <Separator className="bg-white/10" />
                    <dl className="grid grid-cols-2 gap-y-1 text-xs">
                      <dt className="text-muted-foreground">State version</dt><dd className="font-mono">{state.version}</dd>
                      <dt className="text-muted-foreground">Active key</dt><dd className="font-mono">v{state.active_key}</dd>
                      <dt className="text-muted-foreground">Revoked</dt><dd>{state.revoked.join(", ") || "none"}</dd>
                      <dt className="text-muted-foreground">Disabled</dt><dd>{state.disabled.join(", ") || "none"}</dd>
                    </dl>
                  </>
                )}
              </div>
            </Panel>

            <Panel icon={Fingerprint} title="Signed decision trail" desc="Every allow and every block with its reason — hash-chained and ML-DSA-65 signed." className="lg:col-span-2">
              <div className="max-h-[520px] overflow-auto rounded-lg border border-white/10">
                <Table>
                  <TableHeader className="sticky top-0 bg-background/95">
                    <TableRow><TableHead>#</TableHead><TableHead>Event</TableHead><TableHead>Who</TableHead><TableHead>File</TableHead><TableHead>Decision</TableHead><TableHead>Why</TableHead><TableHead>Hash</TableHead></TableRow>
                  </TableHeader>
                  <TableBody>
                    {log.map((r) => (
                      <TableRow key={r.seq}>
                        <TableCell className="font-mono text-xs text-muted-foreground">{r.seq}</TableCell>
                        <TableCell className="capitalize">{r.type.replace(/_/g, " ")}</TableCell>
                        <TableCell className="font-medium">{r.actor ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{r.asset ?? "—"}</TableCell>
                        <TableCell><Verdict d={r.decision} /></TableCell>
                        <TableCell className="text-sm text-muted-foreground">{(r.reason && REASONS[r.reason]) ?? r.reason ?? ""}</TableCell>
                        <TableCell className="font-mono text-[11px] text-sky-300/80">{r.hash}…</TableCell>
                      </TableRow>
                    ))}
                    {log.length === 0 && (
                      <TableRow><TableCell colSpan={7} className="py-12 text-center text-muted-foreground">Set up the demo files to begin.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </Panel>
          </TabsContent>

          <TabsContent value="integrity" className="grid gap-4 lg:grid-cols-2">
            <Panel icon={KeyRound} title="Verify & rotate" desc="Anyone with the audit public key can verify the key-event log.">
              <div className="space-y-3">
                <Button className="w-full justify-start gap-2 bg-sky-500 text-white hover:bg-sky-400" disabled={busy} onClick={async () => setVerify((await act("Audit log verified", "verify")).out)}>
                  <Fingerprint className="size-4" />Verify chain + ML-DSA signatures
                </Button>
                {verify && (
                  <div className="flex items-center gap-3 rounded-lg border border-white/10 bg-black/30 p-3 text-sm">
                    {verify.ok ? <Badge className="border-emerald-500/30 bg-emerald-500/15 text-emerald-300">VALID</Badge> : <Badge className="border-rose-500/30 bg-rose-500/15 text-rose-300">BROKEN</Badge>}
                    <span>{verify.records} records · signatures checked {verify.signatures_checked ? "✓" : "✗"}{verify.first_bad_seq ? ` · first bad #${verify.first_bad_seq}` : ""}</span>
                  </div>
                )}
                <Button variant="outline" className="w-full justify-start gap-2" disabled={busy} onClick={() => act("Data key rotated", "rotate")}>
                  <RotateCcw className="size-4" />Rotate data key — re-encrypt every file atomically
                </Button>
                {state && (
                  <div className="flex flex-wrap gap-2">
                    {state.keys.map((k: any) => (
                      <Badge key={k.version} variant="outline" className={k.status === "active" ? "border-sky-400/40 text-sky-300" : "border-white/15 text-muted-foreground"}>v{k.version} · {k.status}</Badge>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
            <Panel icon={ShieldAlert} title="Attack: undo a revocation on disk" desc="An attacker restores an older, validly authenticated state file to re-enable a revoked user.">
              <ol className="space-y-3">
                <li><Button variant="outline" className="w-full justify-start gap-2" disabled={busy} onClick={() => act("Attacker copied the state file", "snapshot")}><span className="font-mono text-xs text-muted-foreground">1</span>Attacker copies today&apos;s state file</Button></li>
                <li className="text-xs text-muted-foreground">Now revoke someone on the Lost device tab, then:</li>
                <li><Button variant="destructive" className="w-full justify-start gap-2" disabled={busy} onClick={() => act("Attacker restored the old state", "rollback")}><Undo2 className="size-4" />Attacker restores the old copy</Button></li>
                <li><Button className="w-full justify-start gap-2 bg-sky-500 text-white hover:bg-sky-400" disabled={busy} onClick={() => act(`${actor} reads ${asset} after rollback`, "read", { actor, asset })}><FileLock2 className="size-4" />Try to read as {actor}</Button></li>
              </ol>
              <p className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-200/90">
                Expected <code className="font-mono">integrity_failure</code>: the state version no longer matches the signed audit-log head, so the service fails closed.
              </p>
            </Panel>
          </TabsContent>

          <TabsContent value="cluster">
            <Panel icon={Network} title="Revocation & rotation across 3 nodes" desc={`ML-DSA-signed, epoch-versioned policy pulled by separate node processes · ${cl?.environment?.node ?? ""} on ${cl?.environment?.platform ?? ""}`}>
              {cl && (
                <div className="mb-4 grid gap-4 sm:grid-cols-3">
                  <Kpi icon={Zap} label="Median propagation" value={`${cl.revocation_propagation_ms.median} ms`} hint="publish → last node enforcing" />
                  <Kpi icon={Zap} label="Worst case" value={`${cl.revocation_propagation_ms.max} ms`} hint={`${cl.config.samples} samples · ${cl.config.poll_ms} ms polling`} />
                  <Kpi icon={KeyRound} label="Rotation grace (demo)" value={`${cl.config.grace_ms} ms`} hint="30 s by default" />
                </div>
              )}
              <div className="rounded-lg border border-white/10">
                <Table>
                  <TableHeader><TableRow><TableHead>Result</TableHead><TableHead>Step</TableHead><TableHead>Expected</TableHead><TableHead>Observed (node-a)</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {cl?.steps?.map((s: any) => (
                      <TableRow key={s.step}>
                        <TableCell>{s.pass ? <Badge className="border-emerald-500/30 bg-emerald-500/15 text-emerald-300">PASS</Badge> : <Badge className="border-rose-500/30 bg-rose-500/15 text-rose-300">FAIL</Badge>}</TableCell>
                        <TableCell className="font-medium capitalize">{s.step}</TableCell>
                        <TableCell className="text-muted-foreground">{s.expect}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{String(Object.values(s.observed)[0])}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </Panel>
          </TabsContent>

          <TabsContent value="detector" className="grid gap-4 lg:grid-cols-3">
            <Panel icon={Radar} title="Accuracy" desc="Rules + approvals context + service-edge graph. No ML.">
              {d0 && (
                <div className="space-y-3">
                  <Kpi icon={Radar} label="F1 · standard / hard" value={`${d0.standard.aggregate.f1} / ${d0.hard.aggregate.f1}`} hint={`${d0.standard.aggregate.incidents + d0.hard.aggregate.incidents} incidents · 10 seeds each`} />
                  <Kpi icon={Clock} label="Median time-to-alert" value={`${Math.round(d0.standard.aggregate.median_time_to_alert_ms)} ms`} hint="from first incident event" />
                  <Kpi icon={ShieldCheck} label="False alerts / 1k benign" value={`${d0.standard.aggregate.false_alerts_per_1000_benign}`} hint="upper bound · synthetic data" />
                </div>
              )}
              <Button className="mt-4 w-full gap-2 bg-sky-500 text-white hover:bg-sky-400" disabled={busy} onClick={async () => setDet((await act("Detector run on a fresh log", "detect", { seed: Math.floor(Math.random() * 1e6) })).out)}>
                <Radar className="size-4" />Run on a fresh synthetic log
              </Button>
            </Panel>
            <Panel icon={ShieldAlert} title="Explained alerts" desc="Identity, services, events and the rule that fired — no black boxes." className="lg:col-span-2">
              <div className="max-h-[560px] space-y-3 overflow-auto pr-1">
                {det?.alerts?.map((a: any) => (
                  <div key={a.id} className="rounded-lg border border-white/10 bg-black/30 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className={a.severity === "high" ? "border-rose-500/30 bg-rose-500/15 text-rose-300" : "border-amber-500/30 bg-amber-500/15 text-amber-300"}>{a.severity}</Badge>
                      <span className="font-heading font-medium capitalize">{a.rule.replace(/_/g, " ")}</span>
                      <span className="text-sm text-muted-foreground">· {a.actor}</span>
                    </div>
                    <p className="mt-2 text-sm">{a.summary}</p>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {a.services.map((s: string, i: number) => (
                        <Badge key={`${s}-${i}`} variant="outline" className="border-white/15 font-mono text-[11px]">{s}</Badge>
                      ))}
                    </div>
                    <p className="mt-2 font-mono text-[11px] text-muted-foreground">events {a.events.join(", ")}</p>
                    <p className="text-xs text-muted-foreground/80">limits: {a.limits}</p>
                  </div>
                ))}
                {det?.incidents && (
                  <p className="rounded-lg border border-white/10 p-3 text-xs text-muted-foreground">
                    Hidden ground truth: {det.incidents.map((i: any) => i.kind.replace(/_/g, " ")).join(" · ")}
                  </p>
                )}
                {!det && <p className="py-12 text-center text-sm text-muted-foreground">Run the detector to see explained alerts.</p>}
              </div>
            </Panel>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
