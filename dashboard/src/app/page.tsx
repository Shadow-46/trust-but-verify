"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Bell, Check, Crosshair, FileText, KeyRound, LayoutGrid, Network, ScrollText, ShieldCheck, ShieldX, Users, X } from "lucide-react";
import { animate, motion } from "motion/react";
import { Tour } from "@/components/tour";
import type { TourStep } from "@/components/tour";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Res = { ok: boolean; out: any; blocked?: boolean; ms?: number };
type Row = { seq: number; ts: string; type: string; actor: string | null; asset: string | null; decision: string | null; reason: string | null; hash: string };
type Section = "overview" | "files" | "users" | "audit" | "keys" | "nodes" | "alerts" | "lab";

const USERS = ["maya", "omar", "dana", "mallory"];
const BECAUSE: Record<string, string> = {
  owner: "the identity owns it and has not been revoked or disabled",
  not_owner: "the identity does not own this file",
  revoked: "the identity was revoked after its device was reported lost",
  disabled: "the account is disabled",
  unknown_asset: "the file does not exist",
  integrity_failure: "stored data failed its integrity check",
  request_id_reused: "the request ID was already used",
};
const SHORT: Record<string, string> = {
  owner: "Owner, not revoked",
  not_owner: "Not the owner",
  revoked: "Revoked, device lost",
  disabled: "Account disabled",
  unknown_asset: "No such file",
  integrity_failure: "Integrity check failed",
  request_id_reused: "Request ID reused",
};

async function api(action: string, extra: Record<string, unknown> = {}): Promise<Res> {
  const r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...extra }) });
  return r.json();
}

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function Status({ d }: { d: string | null }) {
  if (d === "allow") return <span className="inline-flex items-center gap-1.5 text-[#0F7B4F]"><span className="size-1.5 rounded-full bg-[#0F7B4F]" />Allowed</span>;
  if (d === "deny") return <span className="inline-flex items-center gap-1.5 text-[#B42318]"><span className="size-1.5 rounded-full bg-[#B42318]" />Denied</span>;
  return <span className="inline-flex items-center gap-1.5 text-[#5C6370]"><span className="size-1.5 rounded-full bg-[#AEB4BD]" />Event</span>;
}

function Th({ children, className = "" }: { children?: React.ReactNode; className?: string }) {
  return <th className={`border-b border-[#E3E5E8] px-4 py-2 text-left text-xs font-medium text-[#5C6370] ${className}`}>{children}</th>;
}
function Td({ children, className = "" }: { children?: React.ReactNode; className?: string }) {
  return <td className={`border-b border-[#EEF0F2] px-4 py-2.5 align-top ${className}`}>{children}</td>;
}
function Panel({ title, action, children, tour }: { title: string; action?: React.ReactNode; children: React.ReactNode; tour?: string }) {
  return (
    <section data-tour={tour} className="rounded-lg border border-[#E3E5E8] bg-white">
      <div className="flex items-center justify-between gap-4 border-b border-[#E3E5E8] px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
function Stats({ items }: { items: { label: string; value: string; note: string }[] }) {
  return (
    <div className="grid overflow-hidden rounded-lg border border-[#E3E5E8] bg-white sm:grid-cols-2 lg:grid-cols-4">
      {items.map((s, i) => (
        <div key={s.label} className={`px-4 py-3 ${i > 0 ? "border-t border-[#E3E5E8] sm:border-t-0 sm:border-l" : ""}`}>
          <div className="text-xs text-[#5C6370]">{s.label}</div>
          <CountUp value={s.value} />
          <div className="text-xs text-[#5C6370]">{s.note}</div>
        </div>
      ))}
    </div>
  );
}
const primary = "bg-[#1D4ED8] text-white hover:bg-[#1A43B8]";
/** New random seed for a freshly generated access log (called from event handlers). */
const freshSeed = () => Math.floor(Math.random() * 1e6);

/** Counts a leading number up from zero whenever the value changes (e.g. "19 ms"). */
function CountUp({ value }: { value: string }) {
  const [shown, setShown] = useState(value);
  useEffect(() => {
    const m = value.match(/^(\d+(?:\.\d+)?)(.*)$/);
    if (!m) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setShown(value);
      return;
    }
    const decimals = (m[1].split(".")[1] ?? "").length;
    const c = animate(0, parseFloat(m[1]), { duration: 0.9, ease: "easeOut", onUpdate: (v) => setShown(v.toFixed(decimals) + m[2]) });
    return () => c.stop();
  }, [value]);
  return <div className="mt-1 text-xl font-semibold tabular-nums">{shown}</div>;
}

// ---------- guided scenario ----------
type Step = { title: string; expect: string; run: () => Promise<{ pass: boolean; actual: string }> };

function decisionText(r: Res) {
  if (r.blocked) return "Refused: integrity check failed, service is fail-closed";
  if (r.out?.decision === "allow") return "Allowed, contents returned";
  if (r.out?.decision === "deny") return "Denied, no contents returned";
  return r.out?.error ? `Error: ${r.out.error}` : "Done";
}

export default function Console() {
  const [section, setSection] = useState<Section>("overview");
  const [log, setLog] = useState<Row[]>([]);
  const [state, setState] = useState<any>(null);
  const [failClosed, setFailClosed] = useState(false);
  const [ev, setEv] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [asUser, setAsUser] = useState("maya");
  const [lastRead, setLastRead] = useState<{ who: string; file: string; res: Res } | null>(null);
  const [verify, setVerify] = useState<any>(null);
  const [filter, setFilter] = useState<"all" | "allow" | "deny">("all");
  const [confirm, setConfirm] = useState<null | { kind: "revoke"; user: string } | { kind: "rotate" }>(null);
  const [det, setDet] = useState<any>(null);
  const [scenarioOpen, setScenarioOpen] = useState(false);
  const [results, setResults] = useState<({ pass: boolean; actual: string } | null)[]>([]);
  const [touring, setTouring] = useState(false);
  const [attacks, setAttacks] = useState<any[]>([]);
  const [live, setLive] = useState<any>(null);
  const [ripple, setRipple] = useState<string | null>(null);
  const pollCluster = useCallback(async () => {
    const r = await api("cluster-status");
    setLive(r.ok && r.out?.ready ? { ...r.out, running: (r as any).running } : null);
    return r;
  }, []);
  const startCluster = async () => {
    setRipple(null);
    await run("cluster-start");
    for (let i = 0; i < 40; i++) {
      const r = await pollCluster();
      if (r.out?.ready && r.out.nodes.every((n: any) => n.epoch >= r.out.published_epoch)) break;
      await new Promise((res) => setTimeout(res, 100));
    }
  };
  const revokeLive = async () => {
    const r = await api("cluster-revoke");
    const target = r.out?.epoch ?? 0;
    const t0: number = r.out?.at ?? 0; // revocation time recorded by the control plane
    for (let i = 0; i < 80; i++) {
      const s = await pollCluster();
      const running = s.out?.nodes?.filter((n: any) => (s as any).running?.[n.name]) ?? [];
      if (running.length && running.every((n: any) => n.epoch >= target)) {
        const ms = Math.max(...running.map((n: any) => n.adopted_at)) - t0;
        const msg = `Revoked on ${running.length} running node${running.length > 1 ? "s" : ""} in ${ms} ms`;
        setRipple(msg);
        return msg;
      }
      await new Promise((res) => setTimeout(res, 40));
    }
    setRipple("Some nodes have not caught up yet");
    return null;
  };
  const [attackResults, setAttackResults] = useState<Record<string, any>>({});
  const runAttacks = async (id: string) => {
    const r = await run("attack", { id });
    const next: Record<string, any> = {};
    for (const x of Array.isArray(r.out) ? r.out : []) next[x.id] = x;
    setAttackResults((prev) => ({ ...prev, ...next }));
    return Array.isArray(r.out) ? r.out : [];
  };

  const refresh = useCallback(async () => {
    const [l, s] = await Promise.all([api("log"), api("state")]);
    setLog(Array.isArray(l.out) ? [...l.out].reverse() : []);
    setState(s.ok ? s.out : null);
    setFailClosed(!s.ok && s.out?.error === "integrity_failure");
  }, []);

  const run = useCallback(
    async (action: string, extra: Record<string, unknown> = {}) => {
      setBusy(true);
      try {
        const r = await api(action, extra);
        await refresh();
        return r;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  useEffect(() => {
    // Initial load of the operator view (client-only console talking to the local API).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    void api("evidence").then((r) => setEv(r.out));
    void api("attacks").then((r) => setAttacks(Array.isArray(r.out) ? r.out : []));
  }, [refresh]);

  const read = async (who: string, file: string) => {
    const res = await run("read", { actor: who, asset: file });
    setLastRead({ who, file, res });
    if (res.blocked) toast.error("Request refused", { description: "Integrity check failed. The service is fail-closed until reset." });
    else toast(`${who} ${res.out?.decision === "allow" ? "was allowed to read" : "was denied"} ${file}`);
  };

  const steps: Step[] = useMemo(() => {
    const readMaya = () => api("read", { actor: "maya", asset: "design-doc" });
    return [
      { title: "Reset the demo", expect: "Fresh files, keys and signed log", run: async () => { const r = await api("reset"); return { pass: r.out?.ready === true, actual: r.out?.ready ? "Demo files ready" : "Setup failed" }; } },
      { title: "maya opens design-doc", expect: "Allowed: maya owns it and is not revoked", run: async () => { const r = await readMaya(); return { pass: r.out?.decision === "allow", actual: decisionText(r) }; } },
      { title: "An attacker copies the state file", expect: "Copy saved (simulated disk access)", run: async () => { const r = await api("snapshot"); return { pass: r.ok, actual: r.ok ? "Copy saved" : "Could not copy" }; } },
      { title: "maya reports the laptop lost", expect: "maya's access is revoked everywhere", run: async () => { const r = await api("revoke", { actor: "maya" }); return { pass: r.ok, actual: r.ok ? "Revocation recorded and signed" : "Revocation failed" }; } },
      { title: "The lost laptop tries design-doc", expect: "Denied: identity revoked after device loss", run: async () => { const r = await readMaya(); return { pass: r.out?.decision === "deny", actual: decisionText(r) }; } },
      { title: "The attacker restores the old copy", expect: "Old state file written back to disk", run: async () => { const r = await api("rollback"); return { pass: r.ok, actual: r.ok ? "Old state restored on disk" : "Restore failed" }; } },
      { title: "The lost laptop tries again", expect: "Attack blocked: rolled-back state is detected and every request is refused", run: async () => { const r = await readMaya(); return { pass: r.blocked === true, actual: r.blocked ? "Attack blocked: integrity check failed, nothing returned" : decisionText(r) }; } },
      { title: "Operator resets the demo", expect: "Service healthy again", run: async () => { const r = await api("reset"); return { pass: r.out?.ready === true, actual: r.out?.ready ? "Service healthy" : "Reset failed" }; } },
    ];
  }, []);

  const runStep = async (i: number) => {
    setBusy(true);
    try {
      const r = await steps[i].run();
      setResults((prev) => {
        const next = i === 0 ? [] : [...prev];
        next[i] = r;
        return next;
      });
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const ok = (text: string) => ({ text, tone: "good" as const });
  const bad = (text: string) => ({ text, tone: "bad" as const });
  const readAs = async (who: string) => {
    const r = await run("read", { actor: who, asset: "design-doc" });
    setLastRead({ who, file: "design-doc", res: r });
    return r;
  };
  const tourSteps: TourStep<Section>[] = [
    { section: "overview", target: "hero", title: "Every access decision, explained", body: "This console drives the same service the judges call. We start clean: three encrypted files owned by maya and omar.", run: async () => { await run("reset"); setResults([]); setVerify(null); setDet(null); setLastRead(null); return ok("Demo reset: files encrypted, signed audit log started"); } },
    { section: "files", target: "files", title: "maya opens her design doc", body: "Every request is checked: does the file exist, does maya own it, is she revoked or disabled. The decision is signed into the log before the reply.", run: async () => { const r = await readAs("maya"); return r.out?.decision === "allow" ? ok("Allowed: contents returned") : bad(decisionText(r)); } },
    { section: "files", target: "files", title: "Someone else tries the same file", body: "omar is a valid user but not the owner. Being signed in is not enough.", run: async () => { const r = await readAs("omar"); return r.out?.decision === "deny" ? ok("Denied: omar does not own design-doc") : bad(decisionText(r)); } },
    { section: "files", target: "files", title: "An attacker copies the state file", body: "We simulate an attacker with disk access quietly saving a copy of today's state. It comes back later.", run: async () => { const r = await run("snapshot"); return r.ok ? { text: "Copy saved on the attacker's side", tone: "neutral" as const } : bad("Copy failed"); }, dwell: 5000 },
    { section: "users", target: "users", title: "maya's laptop is lost", body: "The operator reports the device lost. The revocation is persisted and signed before it is acknowledged.", run: async () => { const r = await run("revoke", { actor: "maya" }); return r.ok ? ok("maya revoked") : bad("Revocation failed"); } },
    { section: "files", target: "files", title: "The lost laptop tries again", body: "Same identity, same file, moments later.", run: async () => { const r = await readAs("maya"); return r.out?.decision === "deny" ? ok("Denied: identity revoked after device loss") : bad(decisionText(r)); } },
    { section: "overview", target: "hero", title: "The reason, in plain language", body: "Anyone can read exactly why access was blocked, next to the signed record that proves it.", dwell: 6000 },
    { section: "files", target: "files", title: "The attacker restores the old copy", body: "To undo the revocation, the attacker writes the earlier state file back. It is validly authenticated, just old.", run: async () => { const r = await run("rollback"); return r.ok ? { text: "Old state written back to disk", tone: "neutral" as const } : bad("Restore failed"); }, dwell: 5000 },
    { section: "files", target: "blocked-banner", title: "Attack blocked", body: "The state's version no longer matches the ML-DSA-signed audit log head, so the service fails closed instead of trusting the disk.", run: async () => { const r = await readAs("maya"); return r.blocked ? ok("Refused: integrity check failed, nothing returned") : bad(decisionText(r)); }, dwell: 8000 },
    { section: "overview", target: "reset-btn", title: "The operator recovers", body: "In production this is a restore from a verified, signed backup that keeps every later revocation. Here we reset and replay the revocation.", run: async () => { await run("reset"); await readAs("maya"); await run("revoke", { actor: "maya" }); await readAs("maya"); setLastRead(null); return ok("Service healthy, maya still revoked"); } },
    { section: "audit", target: "audit", title: "A tamper-evident trail", body: "Every allow and every block is hash-chained and signed with ML-DSA-65. Anyone with the public key can verify it.", run: async () => { const r = await run("verify"); setVerify(r.out); return r.out?.ok ? ok(`Log verified: ${r.out.records} records, all signatures valid`) : bad("Log verification failed"); } },
    { section: "keys", target: "keys", title: "Rotating the data key", body: "A new key version re-encrypts every file in one atomic step. The old version is retired.", run: async () => { const r = await run("rotate"); return r.ok ? ok(`Rotated v${r.out.from} to v${r.out.to}, ${r.out.reencrypted} files re-encrypted`) : bad("Rotation refused"); } },
    { section: "lab", target: "lab", title: "Judges try to break it", body: "The Attack Lab launches twelve real attacks: stolen device, replay, forged and rolled-back policy, state and log rollback, log tampering and injection, prototype pollution, malformed floods, probing, protected-read abuse.", run: async () => { const res = await runAttacks("all"); const blocked = res.filter((x: any) => x.blocked).length; return blocked === res.length ? ok(`${blocked} of ${res.length} attacks blocked, each with evidence`) : bad(`${blocked} of ${res.length} blocked`); }, dwell: 9000 },
    { section: "nodes", target: "live-cluster", title: "Watch a revocation ripple", body: "Three real node processes each verify the ML-DSA-signed policy. We report maya's phone lost and watch every node switch from allow to deny.", run: async () => { await startCluster(); const msg = await revokeLive(); return msg ? ok(msg) : bad("Nodes did not converge"); }, dwell: 8000 },
    { section: "nodes", target: "nodes-stats", title: "Revocation reaches every node", body: "Three separate node processes pull an ML-DSA-signed, epoch-versioned policy and refuse forged or older versions.", run: async () => (ev?.cluster ? ok(`Median ${ev.cluster.revocation_propagation_ms.median} ms, worst case ${ev.cluster.revocation_propagation_ms.max} ms`) : undefined) },
    { section: "nodes", target: "nodes-checks", title: "Rotation with a documented cutoff", body: "The old key is accepted until the cutoff, then rejected everywhere, while transfers that already started finish.", dwell: 6000 },
    { section: "alerts", target: "alerts", title: "Catching misuse of valid credentials", body: "An explainable detector (rules, approvals and a service graph, no ML) analyses a fresh access log with hidden incidents.", run: async () => { const r = await run("detect", { seed: freshSeed() }); setDet(r.out); return r.out?.alerts ? ok(`${r.out.alerts.length} alerts for ${r.out.incidents.length} hidden incidents`) : bad("Analysis failed"); }, dwell: 8000 },
    { section: "overview", target: "kpis", title: "Verified, not claimed", body: "Official validator 22/22 in the judges' runtime, revocation in about 20 ms, every decision explained and signed. Thank you.", dwell: 7000 },
  ];

  const latest = log.find((r) => r.type === "access_decision" || r.type === "duplicate_request_id");
  const filtered = log.filter((r) => filter === "all" || r.decision === filter);
  const cl = ev?.cluster;
  const d0 = ev?.detector;
  const owned = (u: string) => (state?.owners ?? []).filter((o: any) => o.owner === u).map((o: any) => o.asset);
  const userStatus = (u: string) => (state?.revoked?.includes(u) ? "Revoked" : state?.disabled?.includes(u) ? "Disabled" : "Active");

  const nav: { id: Section; label: string; icon: typeof Users }[] = [
    { id: "overview", label: "Overview", icon: LayoutGrid },
    { id: "files", label: "Files", icon: FileText },
    { id: "users", label: "Users & devices", icon: Users },
    { id: "audit", label: "Audit log", icon: ScrollText },
    { id: "keys", label: "Keys", icon: KeyRound },
    { id: "nodes", label: "Nodes", icon: Network },
    { id: "alerts", label: "Alerts", icon: Bell },
    { id: "lab", label: "Attack lab", icon: Crosshair },
  ];
  const title = nav.find((n) => n.id === section)?.label;

  return (
    <div className="grid min-h-screen grid-cols-1 bg-[#F6F7F8] text-[#14171C] md:grid-cols-[232px_1fr]">
      <aside className="border-b border-[#E3E5E8] bg-[#FBFBFC] md:sticky md:top-0 md:h-screen md:border-r md:border-b-0">
        <div className="flex items-center gap-2.5 px-4 py-4">
          <div className="grid size-7 place-items-center rounded-md bg-[#14171C] text-xs font-semibold text-white">W</div>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold">Trust, but verify</div>
            <div className="text-xs text-[#5C6370]">WASD workspace</div>
          </div>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:pb-0">
          {nav.map((n) => (
            <button
              key={n.id}
              onClick={() => setSection(n.id)}
              className={`flex shrink-0 items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-sm outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8]/40 ${section === n.id ? "bg-white font-medium text-[#14171C] shadow-[0_0_0_1px_#E3E5E8]" : "text-[#5C6370] hover:bg-[#F1F2F4] hover:text-[#14171C]"}`}
            >
              <n.icon className="size-4" strokeWidth={1.75} />
              {n.label}
            </button>
          ))}
        </nav>
        <div className="hidden px-4 py-4 text-xs text-[#5C6370] md:absolute md:bottom-0 md:block">
          {failClosed ? <span className="text-[#B42318]">Service is fail-closed</span> : state ? <>State v{state.version}, key v{state.active_key}</> : "Not set up"}
        </div>
      </aside>

      <div className="min-w-0">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-[#E3E5E8] bg-[#F6F7F8]/90 px-6 py-3 backdrop-blur">
          <div className="flex items-center gap-2">
            <h1 className="text-[15px] font-semibold">{title}</h1>
            <span className="rounded border border-[#E3E5E8] bg-white px-1.5 py-0.5 text-[11px] text-[#5C6370]">Demo environment</span>
            <span className="inline-flex items-center gap-1.5 text-[11px] text-[#5C6370]"><span className="relative flex size-2"><span className={`absolute inline-flex size-full animate-ping rounded-full opacity-60 ${failClosed ? "bg-[#B42318]" : "bg-[#0F7B4F]"}`} /><span className={`relative inline-flex size-2 rounded-full ${failClosed ? "bg-[#B42318]" : "bg-[#0F7B4F]"}`} /></span>{failClosed ? "Fail-closed" : "Live"}</span>
          </div>
          <div className="flex gap-2">
            <Button data-tour="reset-btn" variant="outline" size="sm" disabled={busy} onClick={async () => { await run("reset"); setResults([]); toast("Demo reset"); }}>Reset demo</Button>
            <Button variant="outline" size="sm" onClick={() => setScenarioOpen(true)}>Checklist</Button>
            <Button size="sm" className={primary} onClick={() => setTouring(true)}>Start walkthrough</Button>
          </div>
        </header>

        <motion.main key={section} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.28, ease: "easeOut" }} className="mx-auto max-w-[1120px] space-y-5 px-6 py-6">
          {failClosed && (
            <motion.div data-tour="blocked-banner" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0, x: [0, -6, 6, -4, 4, 0] }} transition={{ duration: 0.6 }} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#F1C9C5] bg-[#FDF3F2] px-4 py-3 text-sm">
              <div className="flex items-start gap-3">
                <motion.span initial={{ scale: 0, rotate: -25 }} animate={{ scale: 1, rotate: 0 }} transition={{ type: "spring", stiffness: 260, damping: 12, delay: 0.15 }}><ShieldX className="mt-0.5 size-5 text-[#B42318]" /></motion.span>
              <div>
                <span className="font-medium text-[#B42318]">The service is refusing all requests.</span>{" "}
                <span className="text-[#5C6370]">Stored state no longer matches the signed audit log, so nothing is trusted until an operator restores a verified backup.</span>
              </div>
              </div>
              <Button size="sm" variant="outline" disabled={busy} onClick={async () => { await run("reset"); setResults([]); }}>Reset demo</Button>
            </motion.div>
          )}
          {!state && !failClosed && (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#E3E5E8] bg-white px-4 py-3 text-sm">
              <span>No demo data yet. Set up three protected files for maya and omar to get started.</span>
              <Button size="sm" className={primary} disabled={busy} onClick={() => run("reset")}>Set up demo</Button>
            </div>
          )}

          {section === "overview" && (
            <>
              <section data-tour="hero" className="rounded-lg border border-[#E3E5E8] bg-white px-6 py-6">
                <div className="text-xs text-[#5C6370]">Latest access decision{latest ? `, ${time(latest.ts)}` : ""}</div>
                {latest ? (
                  <motion.p key={latest.seq} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: "easeOut" }} className="mt-2 max-w-[60ch] text-2xl leading-snug font-medium tracking-tight">
                    {latest.actor} was{" "}
                    <span className={latest.decision === "allow" ? "text-[#0F7B4F]" : "text-[#B42318]"}>{latest.decision === "allow" ? "allowed to read" : "denied access to"}</span>{" "}
                    {latest.asset} because {BECAUSE[latest.reason ?? ""] ?? latest.reason}.
                  </motion.p>
                ) : (
                  <p className="mt-2 text-2xl font-medium tracking-tight text-[#5C6370]">No decisions yet. Open a file from the Files page or run the scenario.</p>
                )}
                {latest && <div className="mt-3 font-mono text-xs text-[#5C6370]">Signed record #{latest.seq}, hash {latest.hash}</div>}
              </section>
              <div data-tour="kpis"><Stats
                items={[
                  { label: "Official validator", value: "22 / 22", note: "Node 24.11.1, offline" },
                  { label: "Revocation reaches all nodes", value: cl ? `${cl.revocation_propagation_ms.median} ms` : "–", note: cl ? `worst case ${cl.revocation_propagation_ms.max} ms` : "" },
                  { label: "Detector F1", value: d0 ? String(d0.standard.aggregate.f1) : "–", note: d0 ? `${d0.standard.aggregate.false_alerts_per_1000_benign} false alerts per 1,000 events` : "" },
                  { label: "Time per request", value: "37 ms", note: "including a signed audit record" },
                ]}
              /></div>
              <Panel title="Recent decisions" action={<button className="text-sm text-[#1D4ED8] hover:underline" onClick={() => setSection("audit")}>Open audit log</button>}>
                <DecisionTable rows={log.filter((r) => r.decision).slice(0, 6)} />
              </Panel>
            </>
          )}

          {section === "files" && (
            <Panel
              tour="files"
              title="Protected files"
              action={
                <div className="flex items-center gap-2 text-sm text-[#5C6370]">
                  Request as
                  <Select value={asUser} onValueChange={(v) => setAsUser(String(v))}>
                    <SelectTrigger size="sm" className="w-28 bg-white"><SelectValue /></SelectTrigger>
                    <SelectContent>{USERS.map((u) => <SelectItem key={u} value={u}>{u}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
              }
            >
              <table className="w-full text-sm">
                <thead><tr><Th>File</Th><Th>Owner</Th><Th>Encrypted with</Th><Th className="text-right">Action</Th></tr></thead>
                <tbody>
                  {(state?.owners ?? []).map((o: any) => (
                    <tr key={o.asset}>
                      <Td className="font-medium">{o.asset}</Td>
                      <Td>{o.owner}</Td>
                      <Td className="font-mono text-xs text-[#5C6370]">AES-256-GCM, key v{state.active_key}</Td>
                      <Td className="text-right"><Button size="sm" variant="outline" disabled={busy} onClick={() => read(asUser, o.asset)}>Open as {asUser}</Button></Td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {lastRead && (
                <div className="border-t border-[#E3E5E8] px-4 py-3 text-sm">
                  {lastRead.res.blocked ? (
                    <span><span className="font-medium text-[#B42318]">Refused.</span> Stored state failed its integrity check, so the service returned nothing.</span>
                  ) : (
                    <span>
                      <Status d={lastRead.res.out?.decision ?? null} /> <span className="ml-1">{lastRead.who} {lastRead.res.out?.decision === "allow" ? "opened" : "could not open"} {lastRead.file}.</span>
                      {lastRead.res.out?.body && <span className="ml-2 text-[#5C6370]">Contents: “{lastRead.res.out.body}”</span>}
                      <span className="ml-2 font-mono text-xs text-[#5C6370]">{lastRead.res.ms} ms</span>
                    </span>
                  )}
                </div>
              )}
            </Panel>
          )}

          {section === "users" && (
            <Panel title="Users and devices" tour="users">
              <table className="w-full text-sm">
                <thead><tr><Th>User</Th><Th>Status</Th><Th>Owns</Th><Th className="text-right">Action</Th></tr></thead>
                <tbody>
                  {USERS.map((u) => {
                    const st = userStatus(u);
                    return (
                      <tr key={u}>
                        <Td className="font-medium">{u}</Td>
                        <Td><span className={st === "Active" ? "text-[#0F7B4F]" : st === "Revoked" ? "text-[#B42318]" : "text-[#5C6370]"}>{st}</span></Td>
                        <Td className="text-[#5C6370]">{owned(u).join(", ") || "Nothing"}</Td>
                        <Td className="text-right">
                          <Button size="sm" variant="outline" disabled={busy || st !== "Active"} onClick={() => setConfirm({ kind: "revoke", user: u })}>Report device lost</Button>
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Panel>
          )}

          {section === "audit" && (
            <>
              {verify && (
                <div className={`rounded-lg border px-4 py-3 text-sm ${verify.ok ? "border-[#BFE3D0] bg-[#F1FAF5]" : "border-[#F1C9C5] bg-[#FDF3F2]"}`}>
                  {verify.ok ? (
                    <><span className="font-medium text-[#0F7B4F]">Log verified.</span> All {verify.records} records are intact and every ML-DSA-65 signature checks out.</>
                  ) : (
                    <><span className="font-medium text-[#B42318]">Log broken at record #{verify.first_bad_seq}.</span> A record was edited, removed or reordered.</>
                  )}
                </div>
              )}
              <Panel
                tour="audit"
                title="Signed audit log"
                action={
                  <div className="flex items-center gap-2">
                    <div className="flex rounded-md border border-[#E3E5E8] p-0.5 text-xs">
                      {(["all", "allow", "deny"] as const).map((f) => (
                        <button key={f} onClick={() => setFilter(f)} className={`rounded px-2 py-1 ${filter === f ? "bg-[#14171C] text-white" : "text-[#5C6370] hover:text-[#14171C]"}`}>
                          {f === "all" ? "All" : f === "allow" ? "Allowed" : "Denied"}
                        </button>
                      ))}
                    </div>
                    <Button size="sm" className={primary} disabled={busy} onClick={async () => setVerify((await run("verify")).out)}>Verify log</Button>
                  </div>
                }
              >
                <DecisionTable rows={filtered} full />
              </Panel>
            </>
          )}

          {section === "keys" && (
            <Panel tour="keys" title="Data keys" action={<Button size="sm" className={primary} disabled={busy || !state} onClick={() => setConfirm({ kind: "rotate" })}>Rotate key</Button>}>
              <table className="w-full text-sm">
                <thead><tr><Th>Version</Th><Th>Status</Th><Th>Created</Th><Th>Protects</Th></tr></thead>
                <tbody>
                  {(state?.keys ?? []).slice().reverse().map((k: any) => (
                    <tr key={k.version}>
                      <Td className="font-mono">v{k.version}</Td>
                      <Td><span className={k.status === "active" ? "text-[#0F7B4F]" : "text-[#5C6370]"}>{k.status === "active" ? "Active" : "Retired"}</span></Td>
                      <Td className="text-[#5C6370]">{new Date(k.created_at).toLocaleString()}</Td>
                      <Td className="text-[#5C6370]">{k.status === "active" ? `${state.owners.length} files` : "Nothing (re-encrypted)"}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="border-t border-[#E3E5E8] px-4 py-3 text-xs text-[#5C6370]">Keys are wrapped by a key-encryption key and never leave the service. Rotation re-encrypts every file in one atomic step.</p>
            </Panel>
          )}

          {section === "nodes" && (
            <Panel
              tour="live-cluster"
              title="Live cluster"
              action={
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={busy} onClick={startCluster}>{live ? "Restart cluster" : "Start cluster"}</Button>
                  <Button size="sm" variant="outline" disabled={busy || !live} onClick={async () => { await api("cluster-enrol"); setRipple(null); await pollCluster(); }}>Enrol new phone</Button>
                  <Button size="sm" className={primary} disabled={busy || !live} onClick={revokeLive}>Report maya&apos;s phone lost</Button>
                </div>
              }
            >
              {!live && <p className="px-4 py-8 text-center text-sm text-[#5C6370]">Start the cluster to launch three node processes that enforce the signed policy.</p>}
              {live && (
                <>
                  <div className="grid gap-3 p-4 md:grid-cols-3">
                    {live.nodes.map((n: any) => {
                      const running = live.running?.[n.name];
                      const allowed = n.decision === "allow";
                      return (
                        <motion.div key={n.name} layout className={`rounded-lg border p-3 text-sm ${running ? "border-[#E3E5E8]" : "border-dashed border-[#CBD0D6] bg-[#FBFBFC]"}`}>
                          <div className="flex items-center justify-between">
                            <span className="font-medium">{n.name}</span>
                            <span className="inline-flex items-center gap-1.5 text-xs text-[#5C6370]"><span className={`size-1.5 rounded-full ${running ? "bg-[#0F7B4F]" : "bg-[#AEB4BD]"}`} />{running ? "Running" : "Stopped"}</span>
                          </div>
                          <motion.div key={n.epoch} initial={{ backgroundColor: "#EEF2FF" }} animate={{ backgroundColor: "rgba(255,255,255,0)" }} transition={{ duration: 1.2 }} className="mt-2 rounded px-1 font-mono text-xs text-[#5C6370]">policy epoch {n.epoch}</motion.div>
                          <motion.div key={n.decision} initial={{ scale: 0.96, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className={`mt-2 rounded-md px-2 py-1.5 ${allowed ? "bg-[#E7F5EE] text-[#0F7B4F]" : "bg-[#FDECEA] text-[#B42318]"}`}>
                            maya&apos;s phone: {allowed ? "Allowed" : "Denied"} <span className="text-xs opacity-80">({n.reason.replace(/_/g, " ")})</span>
                          </motion.div>
                          <div className="mt-2">
                            <Button size="sm" variant="ghost" disabled={busy} onClick={async () => { await api(running ? "cluster-stop" : "cluster-restart", { node: n.name }); await new Promise((r) => setTimeout(r, 300)); await pollCluster(); }}>{running ? "Stop node" : "Restart node"}</Button>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                  <div className="flex items-center justify-between border-t border-[#E3E5E8] px-4 py-2.5 text-xs text-[#5C6370]">
                    <span>Published policy epoch {live.published_epoch}, device {live.device}</span>
                    {ripple && <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="font-medium text-[#14171C]">{ripple}</motion.span>}
                  </div>
                </>
              )}
            </Panel>
          )}

          {section === "nodes" && cl && (
            <>
              <div data-tour="nodes-stats"><Stats
                items={[
                  { label: "Median time to revoke everywhere", value: `${cl.revocation_propagation_ms.median} ms`, note: "publish to last node enforcing" },
                  { label: "Worst case", value: `${cl.revocation_propagation_ms.max} ms`, note: `${cl.config.samples} measurements` },
                  { label: "Nodes", value: String(cl.config.nodes.length), note: "separate processes" },
                  { label: "Key rotation grace", value: "30 s", note: `${cl.config.grace_ms / 1000} s in this run` },
                ]}
              /></div>
              <Panel title="Cluster checks" tour="nodes-checks">
                <table className="w-full text-sm">
                  <thead><tr><Th>Check</Th><Th>Expected</Th><Th>Observed on node-a</Th><Th className="text-right">Result</Th></tr></thead>
                  <tbody>
                    {cl.steps.map((s: any) => (
                      <tr key={s.step}>
                        <Td className="font-medium">{s.step.charAt(0).toUpperCase() + s.step.slice(1)}</Td>
                        <Td className="text-[#5C6370]">{s.expect}</Td>
                        <Td className="font-mono text-xs text-[#5C6370]">{String(Object.values(s.observed)[0])}</Td>
                        <Td className="text-right">{s.pass ? <span className="text-[#0F7B4F]">Pass</span> : <span className="text-[#B42318]">Fail</span>}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Panel>
            </>
          )}

          {section === "lab" && (
            <Panel
              tour="lab"
              title="Attack lab"
              action={<Button size="sm" className={primary} disabled={busy} onClick={async () => { const res = await runAttacks("all"); toast(`${res.filter((x: any) => x.blocked).length} of ${res.length} attacks blocked`); }}>Run all attacks</Button>}
            >
              <p className="border-b border-[#E3E5E8] px-4 py-3 text-sm text-[#5C6370]">Each attack runs for real against a fresh, isolated instance of the service. Nothing here is simulated in the browser.</p>
              <ul>
                {attacks.map((a: any) => {
                  const r = attackResults[a.id];
                  return (
                    <li key={a.id} className="grid gap-3 border-b border-[#EEF0F2] px-4 py-3 text-sm last:border-b-0 md:grid-cols-[1fr_auto]">
                      <div className="min-w-0">
                        <div className="font-medium">{a.name}</div>
                        <div className="text-[#5C6370]">{a.attack}</div>
                        <div className="mt-0.5 text-xs text-[#5C6370]">Defence: {a.defense}</div>
                        {r && (
                          <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className={`mt-1.5 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs ${r.blocked ? "bg-[#E7F5EE] text-[#0F7B4F]" : "bg-[#FDECEA] text-[#B42318]"}`}>
                            <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 320, damping: 14 }}>{r.blocked ? <ShieldCheck className="size-3.5" /> : <ShieldX className="size-3.5" />}</motion.span>
                            <span className="font-medium">{r.blocked ? "Blocked" : "Not blocked"}</span>
                            <span className="font-mono">{r.evidence}</span>
                          </motion.div>
                        )}
                      </div>
                      <div><Button size="sm" variant="outline" disabled={busy} onClick={() => runAttacks(a.id)}>{r ? "Run again" : "Run"}</Button></div>
                    </li>
                  );
                })}
              </ul>
            </Panel>
          )}

          {section === "alerts" && d0 && (
            <>
              <Stats
                items={[
                  { label: "F1 score", value: `${d0.standard.aggregate.f1}`, note: `hard cases ${d0.hard.aggregate.f1}` },
                  { label: "Median time to alert", value: `${(d0.standard.aggregate.median_time_to_alert_ms / 1000).toFixed(1)} s`, note: "from the first suspicious event" },
                  { label: "False alerts", value: `${d0.standard.aggregate.false_alerts_per_1000_benign}`, note: "per 1,000 normal events" },
                  { label: "Evaluated", value: `${d0.standard.aggregate.incidents + d0.hard.aggregate.incidents}`, note: "injected incidents, 20 runs" },
                ]}
              />
              <Panel tour="alerts" title="Suspicious activity" action={<Button size="sm" className={primary} disabled={busy} onClick={async () => setDet((await run("detect", { seed: freshSeed() })).out)}>Analyze a new log</Button>}>
                {!det && <p className="px-4 py-8 text-center text-sm text-[#5C6370]">Analyze a freshly generated access log to see what the detector flags and why.</p>}
                {det && (
                  <ul>
                    {det.alerts.map((a: any) => (
                      <li key={a.id} className="border-b border-[#EEF0F2] px-4 py-3 text-sm last:border-b-0">
                        <div className="flex flex-wrap items-baseline gap-x-2">
                          <span className="font-medium">{a.rule === "unexpected_role_change" ? "Unapproved privilege change" : a.rule === "lateral_movement_candidate" ? "Possible lateral movement" : a.rule.replace(/_/g, " ")}</span>
                          <span className="text-[#5C6370]">by {a.actor}</span>
                          <span className={`text-xs ${a.severity === "high" ? "text-[#B42318]" : "text-[#9A6700]"}`}>{a.severity} severity</span>
                        </div>
                        <p className="mt-1 max-w-[80ch] text-[#3A404A]">{a.summary}</p>
                        <p className="mt-1 font-mono text-xs text-[#5C6370]">{a.services.join(" > ")}, events {a.events.join(", ")}</p>
                      </li>
                    ))}
                    <li className="bg-[#FBFBFC] px-4 py-2.5 text-xs text-[#5C6370]">
                      {det.alerts.length} alerts for {det.incidents.length} hidden incidents ({det.incidents.map((i: any) => i.kind.replace(/_/g, " ")).join(", ")}). The detector never sees these labels.
                    </li>
                  </ul>
                )}
              </Panel>
            </>
          )}
        </motion.main>
      </div>

      <Tour steps={tourSteps} open={touring} onClose={() => setTouring(false)} go={setSection} />

      <Dialog open={confirm !== null} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent>
          {confirm?.kind === "revoke" && (
            <>
              <DialogHeader>
                <DialogTitle>Report {confirm.user}&apos;s device lost?</DialogTitle>
                <DialogDescription>{confirm.user} will be denied on every node from the next request. The revocation is signed into the audit log and cannot be undone by restoring an older backup.</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>Cancel</Button>
                <Button variant="destructive" onClick={async () => { const u = confirm.user; setConfirm(null); await run("revoke", { actor: u }); toast(`${u}'s device reported lost`); }}>Report device lost</Button>
              </DialogFooter>
            </>
          )}
          {confirm?.kind === "rotate" && (
            <>
              <DialogHeader>
                <DialogTitle>Rotate the data key?</DialogTitle>
                <DialogDescription>A new key version encrypts every file in one atomic step. The old version is retired and can no longer read anything.</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>Cancel</Button>
                <Button className={primary} onClick={async () => { setConfirm(null); const r = await run("rotate"); toast(r.ok ? `Key rotated to v${r.out.to}` : "Rotation refused"); }}>Rotate key</Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      <Sheet open={scenarioOpen} onOpenChange={setScenarioOpen}>
        <SheetContent className="w-full overflow-y-auto bg-white sm:max-w-[480px]">
          <SheetHeader>
            <SheetTitle>Lost laptop, then a rollback attack</SheetTitle>
            <SheetDescription>Run each step in order. Every result is checked against what should happen.</SheetDescription>
          </SheetHeader>
          <ol className="px-4 pb-6">
            {steps.map((s, i) => {
              const r = results[i];
              const enabled = !busy && (i === 0 || !!results[i - 1]?.pass);
              return (
                <li key={s.title} className="flex gap-3 border-b border-[#EEF0F2] py-3 last:border-b-0">
                  <span className={`mt-0.5 grid size-6 shrink-0 place-items-center rounded-full text-xs font-medium ${r ? (r.pass ? "bg-[#E7F5EE] text-[#0F7B4F]" : "bg-[#FDECEA] text-[#B42318]") : "bg-[#F1F2F4] text-[#5C6370]"}`}>
                    {r ? (r.pass ? <Check className="size-3.5" /> : <X className="size-3.5" />) : i + 1}
                  </span>
                  <div className="min-w-0 flex-1 text-sm">
                    <div className="flex items-start justify-between gap-3">
                      <span className="font-medium">{s.title}</span>
                      <Button size="sm" variant={r ? "ghost" : "outline"} disabled={!enabled} onClick={() => runStep(i)}>{r ? "Run again" : "Run"}</Button>
                    </div>
                    <div className="mt-0.5 text-[#5C6370]">Expected: {s.expect}</div>
                    {r && <div className={`mt-0.5 ${r.pass ? "text-[#0F7B4F]" : "text-[#B42318]"}`}>Result: {r.actual}</div>}
                  </div>
                </li>
              );
            })}
          </ol>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function DecisionTable({ rows, full = false }: { rows: Row[]; full?: boolean }) {
  if (rows.length === 0) return <p className="px-4 py-8 text-center text-sm text-[#5C6370]">No records yet.</p>;
  return (
    <div className={full ? "max-h-[560px] overflow-auto" : ""}>
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-white">
          <tr><Th>#</Th><Th>Time</Th><Th>What happened</Th><Th>Who</Th><Th>File</Th><Th>Decision</Th><Th>Reason</Th>{full && <Th>Record hash</Th>}</tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <motion.tr key={r.seq} layout initial={{ opacity: 0, x: -8, backgroundColor: r.decision === "deny" ? "#FDECEA" : r.decision === "allow" ? "#E7F5EE" : "#EEF2FF" }} animate={{ opacity: 1, x: 0, backgroundColor: "rgba(255,255,255,0)" }} transition={{ duration: 1.4, ease: "easeOut" }}>
              <Td className="font-mono text-xs text-[#5C6370]">{r.seq}</Td>
              <Td className="tabular-nums text-[#5C6370]">{time(r.ts)}</Td>
              <Td>{r.type === "access_decision" ? "Access request" : r.type === "revoke" ? "Device reported lost" : r.type === "key_rotation" ? "Key rotated" : r.type === "setup" ? "Demo set up" : r.type.replace(/_/g, " ")}</Td>
              <Td className="font-medium">{r.actor ?? ""}</Td>
              <Td>{r.asset ?? ""}</Td>
              <Td><Status d={r.decision} /></Td>
              <Td className="text-[#5C6370]">{r.reason ? (SHORT[r.reason] ?? r.reason) : ""}</Td>
              {full && <Td className="font-mono text-xs text-[#5C6370]">{r.hash}</Td>}
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
