"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowLeft, ArrowRight, Check, Monitor, RotateCcw, ShieldCheck, ShieldX, Skull, User, UserCog, X } from "lucide-react";
import { api } from "@/lib/demo";

/**
 * Live Attack Lab (laptop A). Pick an attack, press Space for each step: every
 * step is a real action against the live service, so the Live Monitor on the
 * other laptop changes at the same moment. The stage shows who acts, the
 * request travelling to the service, each security check in the order the code
 * runs it, and the evidence.
 */

type Check = { name: string; pass: boolean };
type Ev = { step: number; actor: "attacker" | "operator" | "user" | "service"; title: string; caption: string; checks: Check[]; evidence: string; tone: "good" | "bad" | "alarm" | "neutral"; audit_seq: number | null };
type Attack = { id: string; name: string; summary: string; impact: string; defense: string; live: boolean; needs_cluster: boolean; steps: { actor: Ev["actor"]; title: string; caption: string }[] };

const ACTOR = {
  attacker: { label: "Attacker", icon: Skull, color: "#B42318", bg: "#FDECEA" },
  user: { label: "User", icon: User, color: "#1D4ED8", bg: "#EEF2FF" },
  operator: { label: "Operator", icon: UserCog, color: "#14171C", bg: "#F1F2F4" },
  service: { label: "Service", icon: ShieldCheck, color: "#0F7B4F", bg: "#E7F5EE" },
} as const;

const toneColor = (t: Ev["tone"]) => (t === "good" ? "#0F7B4F" : t === "alarm" ? "#B42318" : t === "bad" ? "#B42318" : "#5C6370");

export default function Lab() {
  const [catalog, setCatalog] = useState<Attack[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [run, setRun] = useState<{ id: string; events: Ev[]; done: boolean } | null>(null);
  const [view, setView] = useState(0); // which executed step is on stage (1-based; 0 = intro)
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const attack = useMemo(() => catalog.find((a) => a.id === sel) ?? null, [catalog, sel]);

  useEffect(() => {
    void api("lab-catalog").then((r) => setCatalog(Array.isArray(r.out) ? r.out : []));
    // Resume an unfinished run after a refresh.
    void api("lab-runs").then((r) => {
      const last = Array.isArray(r.out) ? r.out[0] : null;
      if (last && !last.done) {
        setSel(last.attack);
        setRun({ id: last.id, events: last.events ?? [], done: false });
        setView(last.events?.length ?? 0);
      }
    });
  }, []);

  const choose = (id: string) => {
    if (busy) return;
    setSel(id);
    setRun(null);
    setView(0);
    setError(null);
  };

  const launch = async () => {
    if (!attack || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api("lab-start", { id: attack.id });
      if (r.out?.run_id) {
        setRun({ id: r.out.run_id, events: [], done: false });
        setView(0);
      } else setError(r.out?.message ?? r.out?.error ?? "Could not start");
    } finally {
      setBusy(false);
    }
  };

  const next = useCallback(async () => {
    if (!run || busy) return;
    if (view < run.events.length) return setView((v) => v + 1); // replaying already-run steps
    if (run.done) return;
    setBusy(true);
    try {
      const r = await api("lab-step", { run: run.id });
      if (r.out?.event) {
        setRun((cur) => (cur ? { ...cur, events: [...cur.events, r.out.event], done: r.out.done } : cur));
        setView((v) => v + 1);
      } else setError(r.out?.error ?? "Step failed");
    } finally {
      setBusy(false);
    }
  }, [run, busy, view]);

  const reset = async () => {
    setBusy(true);
    try {
      await api("reset");
      setRun(null);
      setView(0);
      setError(null);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === "INPUT") return;
      if (e.key === " " || e.key === "ArrowRight") {
        e.preventDefault();
        if (!run && attack) void launch();
        else void next();
      } else if (e.key === "ArrowLeft") setView((v) => Math.max(0, v - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const ev = run && view > 0 ? run.events[view - 1] : null;
  // Service status on stage, from the events seen so far.
  const serviceState = useMemo(() => {
    let s: "live" | "closed" = "live";
    for (const e of run?.events.slice(0, view) ?? []) {
      if (e.tone === "alarm" && e.checks.some((c) => !c.pass && /State and audit|head|Verification key/.test(c.name))) s = "closed";
      if (e.actor === "operator" && e.tone === "good" && s === "closed") s = "live";
    }
    return s;
  }, [run, view]);
  const finished = run?.done && view === run.events.length;
  const outcome = finished ? run!.events.at(-1)!.tone : null;

  return (
    <main className="flex min-h-screen bg-[#F6F7F8] text-[#14171C]">
      {/* attack list */}
      <aside className="w-80 shrink-0 border-r border-[#E3E5E8] bg-white">
        <div className="border-b border-[#E3E5E8] px-5 py-4">
          <h1 className="text-base font-semibold">Attack Lab</h1>
          <p className="mt-0.5 text-xs text-[#5C6370]">Real attacks on the live service. Press Space for each step.</p>
          <div className="mt-3 flex gap-2">
            <a href="/monitor" target="_blank" className="inline-flex items-center gap-1.5 rounded-md border border-[#E3E5E8] px-2.5 py-1.5 text-xs hover:bg-[#F6F7F8]"><Monitor className="size-3.5" />Open monitor</a>
            <button onClick={reset} disabled={busy} className="inline-flex items-center gap-1.5 rounded-md border border-[#E3E5E8] px-2.5 py-1.5 text-xs hover:bg-[#F6F7F8] disabled:opacity-50"><RotateCcw className="size-3.5" />Reset demo</button>
          </div>
        </div>
        {[true, false].map((live) => (
          <div key={String(live)} className="py-2">
            <div className="px-5 py-1.5 text-xs font-medium text-[#5C6370]">{live ? "Live on the running service" : "Sandboxed (isolated instance)"}</div>
            {catalog.filter((a) => a.live === live).map((a) => (
              <button key={a.id} onClick={() => choose(a.id)} className={`block w-full px-5 py-2.5 text-left transition-colors ${sel === a.id ? "bg-[#EEF2FF]" : "hover:bg-[#F6F7F8]"}`}>
                <div className="flex items-center gap-2 text-sm font-medium">
                  {a.live && <span className="relative flex size-1.5"><span className="absolute inline-flex size-full animate-ping rounded-full bg-[#B42318] opacity-60" /><span className="relative inline-flex size-1.5 rounded-full bg-[#B42318]" /></span>}
                  {a.name}
                </div>
                <div className="mt-0.5 line-clamp-2 text-xs text-[#5C6370]">{a.summary}</div>
              </button>
            ))}
          </div>
        ))}
      </aside>

      {/* stage */}
      <section className="flex-1 px-8 py-6">
        {!attack && <div className="flex h-full items-center justify-center text-sm text-[#5C6370]">Pick an attack on the left.</div>}
        {attack && (
          <div className="mx-auto max-w-5xl">
            <div className="flex items-start justify-between gap-6">
              <div>
                <div className="text-xs font-medium text-[#5C6370]">{attack.live ? "Live attack · changes the monitor in real time" : "Sandboxed attack · isolated instance"}</div>
                <h2 className="mt-1 text-2xl font-semibold tracking-tight">{attack.name}</h2>
                <p className="mt-1 max-w-2xl text-[15px] text-[#3A404A]">{attack.summary}</p>
              </div>
              {!run && (
                <button onClick={launch} disabled={busy} className="shrink-0 rounded-lg bg-[#B42318] px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-[#9A1E14] disabled:opacity-60">
                  {busy ? "Preparing…" : "Launch attack"}
                </button>
              )}
            </div>

            {error && (
              <div className="mt-4 flex items-center justify-between rounded-lg border border-[#F1C9C5] bg-[#FDECEA] px-4 py-3 text-sm text-[#B42318]">
                {error}
                <button onClick={reset} className="rounded-md border border-[#F1C9C5] bg-white px-2.5 py-1 text-xs">Reset demo</button>
              </div>
            )}

            {!run && (
              <div className="mt-6 grid gap-4 md:grid-cols-3">
                <Info title="Why it matters">{attack.impact}</Info>
                <Info title="What stops it">{attack.defense}</Info>
                <Info title={`${attack.steps.length} steps`}>
                  <ol className="space-y-1">
                    {attack.steps.map((s, i) => (
                      <li key={i} className="flex gap-2"><span className="text-[#5C6370] tabular-nums">{i + 1}.</span><span>{s.title}</span></li>
                    ))}
                  </ol>
                </Info>
              </div>
            )}

            {run && (
              <>
                {/* progress */}
                <div className="mt-6 flex items-center gap-1.5">
                  {attack.steps.map((s, i) => {
                    const e = run.events[i];
                    const here = view === i + 1;
                    return (
                      <button key={i} onClick={() => e && setView(i + 1)} className="group flex-1" title={s.title}>
                        <div className={`h-1.5 rounded-full transition-colors ${here ? "bg-[#1D4ED8]" : e ? (e.tone === "alarm" ? "bg-[#F4A79F]" : "bg-[#9DB4F0]") : "bg-[#E3E5E8]"}`} />
                      </button>
                    );
                  })}
                </div>

                {/* lanes */}
                <Stage ev={ev} serviceState={serviceState} />

                {/* caption */}
                <AnimatePresence mode="wait">
                  <motion.div key={view} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }} className="mt-5 rounded-xl border border-[#E3E5E8] bg-white p-5">
                    {ev ? (
                      <>
                        <div className="text-xs text-[#5C6370]">Step {ev.step} of {attack.steps.length} · {ACTOR[ev.actor].label}</div>
                        <div className="mt-1 text-xl font-semibold">{ev.title}</div>
                        <p className="mt-1 text-[15px] leading-relaxed text-[#3A404A]">{ev.caption}</p>
                        {ev.checks.length > 0 && (
                          <ul className="mt-3 grid gap-1.5 sm:grid-cols-2">
                            {ev.checks.map((c, i) => (
                              <motion.li key={c.name} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + i * 0.18 }} className={`flex items-start gap-2 rounded-md px-2.5 py-1.5 text-sm ${c.pass ? "bg-[#E7F5EE] text-[#0F7B4F]" : "bg-[#FDECEA] font-medium text-[#B42318]"}`}>
                                {c.pass ? <Check className="mt-0.5 size-4 shrink-0" /> : <X className="mt-0.5 size-4 shrink-0" />}
                                {c.name}
                              </motion.li>
                            ))}
                          </ul>
                        )}
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 + ev.checks.length * 0.18 }} className="mt-3 flex flex-wrap items-center gap-2 font-mono text-xs text-[#3A404A]">
                          <span className="rounded bg-[#F6F7F8] px-2 py-1" style={{ color: toneColor(ev.tone) }}>{ev.evidence}</span>
                          {ev.audit_seq !== null && <span className="rounded bg-[#EEF2FF] px-2 py-1 text-[#1D4ED8]">signed audit record #{ev.audit_seq}</span>}
                        </motion.div>
                      </>
                    ) : (
                      <>
                        <div className="text-xs text-[#5C6370]">Ready · {attack.steps.length} steps</div>
                        <div className="mt-1 text-xl font-semibold">{attack.steps[0].title}</div>
                        <p className="mt-1 text-[15px] text-[#3A404A]">{attack.steps[0].caption}</p>
                      </>
                    )}
                  </motion.div>
                </AnimatePresence>

                {/* outcome */}
                <AnimatePresence>
                  {finished && (
                    <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} className={`mt-4 flex items-center gap-3 rounded-xl border px-5 py-4 ${outcome === "good" ? "border-[#CDE9DA] bg-[#E7F5EE]" : "border-[#F1C9C5] bg-[#FDECEA]"}`}>
                      {outcome === "good" ? <ShieldCheck className="size-7 text-[#0F7B4F]" /> : <ShieldX className="size-7 text-[#B42318]" />}
                      <div className="flex-1">
                        <div className={`text-lg font-semibold ${outcome === "good" ? "text-[#0F7B4F]" : "text-[#B42318]"}`}>{outcome === "good" ? "Blocked. The defence held." : "Not blocked"}</div>
                        <div className="text-sm text-[#3A404A]">{attack.defense}</div>
                      </div>
                      <button onClick={() => { setRun(null); setView(0); }} className="rounded-md border border-[#E3E5E8] bg-white px-3 py-1.5 text-sm">Run again</button>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* controls */}
                <div className="mt-4 flex items-center justify-between">
                  <button onClick={() => setView((v) => Math.max(0, v - 1))} disabled={view === 0} className="inline-flex items-center gap-1.5 rounded-md border border-[#E3E5E8] bg-white px-3 py-2 text-sm disabled:opacity-40"><ArrowLeft className="size-4" />Back</button>
                  <span className="text-xs text-[#5C6370]">Space or → for the next step · ← to look back</span>
                  <button onClick={() => void next()} disabled={busy || !!finished} className="inline-flex items-center gap-1.5 rounded-md bg-[#1D4ED8] px-4 py-2 text-sm font-medium text-white hover:bg-[#1A43B8] disabled:opacity-40">
                    {busy ? "Running…" : view < run.events.length ? "Next" : `Run step ${run.events.length + 1}`}
                    <ArrowRight className="size-4" />
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </section>
    </main>
  );
}

function Info({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[#E3E5E8] bg-white p-4 text-sm">
      <div className="text-xs font-medium text-[#5C6370]">{title}</div>
      <div className="mt-1.5 leading-relaxed text-[#3A404A]">{children}</div>
    </div>
  );
}

/** Actor → wire → service, with the step's request travelling across and the verdict at the service. */
function Stage({ ev, serviceState }: { ev: Ev | null; serviceState: "live" | "closed" }) {
  const actor = ev ? ACTOR[ev.actor] : ACTOR.attacker;
  const Icon = actor.icon;
  const travels = ev && ev.actor !== "service";
  const refused = ev && ev.actor === "attacker" && ev.checks.some((c) => !c.pass);
  const closed = serviceState === "closed";
  return (
    <div className="relative mt-5 h-44 overflow-hidden rounded-xl border border-[#E3E5E8] bg-white">
      {/* wire */}
      <div className="absolute left-[16%] right-[16%] top-1/2 h-0.5 -translate-y-1/2 bg-[repeating-linear-gradient(90deg,#C9CED6_0_10px,transparent_10px_18px)]" />
      <div className="absolute left-1/2 top-[calc(50%+14px)] -translate-x-1/2 text-[11px] text-[#5C6370]">network</div>

      {/* actor */}
      <AnimatePresence mode="wait">
        <motion.div key={ev?.actor ?? "none"} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="absolute left-[6%] top-1/2 flex -translate-y-1/2 flex-col items-center gap-1.5">
          <div className="flex size-16 items-center justify-center rounded-full" style={{ backgroundColor: actor.bg }}>
            <Icon className="size-8" style={{ color: actor.color }} />
          </div>
          <span className="text-xs font-medium">{ev ? actor.label : "Attacker"}</span>
        </motion.div>
      </AnimatePresence>

      {/* request packet */}
      <AnimatePresence>
        {travels && (
          <motion.div
            key={`pkt-${ev!.step}`}
            className="absolute top-1/2 -translate-y-1/2"
            initial={{ left: "16%", opacity: 0 }}
            animate={refused ? { left: ["16%", "74%", "66%"], opacity: [1, 1, 0.9] } : { left: ["16%", "78%"], opacity: [1, 1] }}
            transition={{ duration: refused ? 1.1 : 0.8, ease: [0.22, 1, 0.36, 1], times: refused ? [0, 0.7, 1] : undefined }}
          >
            <div className="flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium text-white shadow" style={{ backgroundColor: actor.color }}>
              {ev!.actor === "attacker" ? "malicious request" : ev!.actor === "operator" ? "operator action" : "request"}
            </div>
            {refused && (
              <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 0.75 }} className="absolute -right-3 -top-3 flex size-6 items-center justify-center rounded-full bg-white shadow ring-2 ring-[#B42318]">
                <X className="size-4 text-[#B42318]" />
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* service */}
      <motion.div
        className="absolute right-[6%] top-1/2 flex -translate-y-1/2 flex-col items-center gap-1.5"
        animate={closed ? { x: [0, -6, 6, -4, 4, 0] } : { x: 0 }}
        transition={{ duration: 0.5 }}
      >
        <motion.div className="flex size-16 items-center justify-center rounded-full" animate={{ backgroundColor: closed ? "#FDECEA" : "#E7F5EE" }}>
          {closed ? <ShieldX className="size-8 text-[#B42318]" /> : <ShieldCheck className="size-8 text-[#0F7B4F]" />}
        </motion.div>
        <span className="text-xs font-medium">{closed ? "Service: fail-closed" : "Service: live"}</span>
      </motion.div>
    </div>
  );
}
