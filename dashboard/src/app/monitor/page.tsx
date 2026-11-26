"use client";
/* eslint-disable @typescript-eslint/no-explicit-any -- operator API returns untyped JSON */

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { NetworkMap } from "@/components/network-map";
import { api, describe, ruleLabel, time } from "@/lib/demo";
import type { Row } from "@/lib/demo";

/**
 * Live Monitor (laptop B): a read-only, big-screen view of what the service is
 * doing right now — whether it is serving or fail-closed, every signed audit
 * record as it lands, security alerts, the cluster network, and the Attack Lab
 * step being shown on the other laptop. Polls once a second.
 */
export default function Monitor() {
  const [m, setM] = useState<any>(null);
  const [offline, setOffline] = useState(false);
  // Records newer than what was on screen at load get a highlight flash.
  const [baseline, setBaseline] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api("monitor");
        if (!alive) return;
        setM(r.out);
        setOffline(false);
        const seqs = Array.isArray(r.out?.log) ? r.out.log.map((x: Row) => x.seq) : [];
        setBaseline((b) => (b === null ? (seqs.length ? Math.max(...seqs) : 0) : b));
      } catch {
        if (alive) setOffline(true);
      }
    };
    void tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const log: Row[] = Array.isArray(m?.log) ? [...m.log].reverse().slice(0, 14) : [];
  const failClosed = m?.state?.error === "integrity_failure" || m?.log?.error === "integrity_failure";
  const alerts: any[] = Array.isArray(m?.alerts) ? [...m.alerts].reverse().slice(0, 6) : [];
  const lab = m?.lab;
  const cluster = m?.cluster && !m.cluster.error && m.cluster.ready ? m.cluster : null;
  const revoked: string[] = m?.state?.revoked ?? [];

  return (
    <main className="min-h-screen bg-[#F6F7F8] px-6 py-5 text-[#14171C]">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-lg bg-[#14171C] text-sm font-semibold text-white">W</div>
          <div>
            <h1 className="text-lg font-semibold leading-tight">Trust, but verify · Live monitor</h1>
            <p className="text-xs text-[#5C6370]">What the service is doing right now. Every line below is a signed audit record.</p>
          </div>
        </div>
        <div className="text-right text-xs text-[#5C6370]">
          {offline ? <span className="text-[#B42318]">Console unreachable — retrying</span> : m ? <>Updated {time(m.at)}</> : "Connecting…"}
        </div>
      </header>

      {/* Service status */}
      <AnimatePresence mode="wait">
        <motion.section
          key={failClosed ? "closed" : "live"}
          initial={{ opacity: 0, y: -8 }}
          animate={failClosed ? { opacity: 1, y: 0, x: [0, -10, 10, -6, 6, 0] } : { opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className={`mt-4 flex items-center gap-4 rounded-xl border px-5 py-4 ${failClosed ? "border-[#F1C9C5] bg-[#FDECEA]" : "border-[#CDE9DA] bg-[#E7F5EE]"}`}
        >
          {failClosed ? <ShieldX className="size-9 text-[#B42318]" /> : <ShieldCheck className="size-9 text-[#0F7B4F]" />}
          <div>
            <div className={`text-xl font-semibold ${failClosed ? "text-[#B42318]" : "text-[#0F7B4F]"}`}>
              {failClosed ? "Fail-closed: refusing every request" : "Live: every request checked and signed"}
            </div>
            <div className="text-sm text-[#3A404A]">
              {failClosed
                ? "Stored state or the audit log failed verification, so nothing is trusted until a verified backup is restored."
                : m?.state && !m.state.error
                  ? `State version ${m.state.version} · data key v${m.state.active_key} · revoked: ${revoked.length ? revoked.join(", ") : "nobody"}`
                  : "Waiting for the service…"}
            </div>
          </div>
        </motion.section>
      </AnimatePresence>

      {/* What just happened (mirrors the Attack Lab on the other laptop) */}
      <AnimatePresence mode="wait">
        {lab && (
          <motion.div
            key={`${lab.run_id}-${lab.step}`}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-3 flex items-start gap-3 rounded-xl border border-[#E3E5E8] bg-white px-5 py-3"
          >
            <ShieldAlert className="mt-0.5 size-5 shrink-0 text-[#1D4ED8]" />
            <div className="text-sm">
              <span className="font-semibold">Attack Lab · {lab.name}</span>
              <span className="text-[#5C6370]"> · step {lab.step} of {lab.total}: </span>
              <span className="font-medium">{lab.title}</span>
              <div className="text-[#3A404A]">{lab.caption}</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="mt-4 grid gap-4 lg:grid-cols-12">
        {/* Live audit stream */}
        <section className="rounded-xl border border-[#E3E5E8] bg-white lg:col-span-7">
          <div className="flex items-center justify-between border-b border-[#E3E5E8] px-5 py-3">
            <h2 className="text-sm font-semibold">Live audit log</h2>
            <span className="text-xs text-[#5C6370]">hash-chained · ML-DSA-65 signed</span>
          </div>
          <ul>
            <AnimatePresence initial={false}>
              {log.map((r) => {
                const d = describe(r);
                const fresh = baseline !== null && r.seq > baseline;
                const color = d.tone === "good" ? "#0F7B4F" : d.tone === "bad" ? "#B42318" : d.tone === "warn" ? "#B54708" : "#5C6370";
                return (
                  <motion.li
                    key={r.seq}
                    layout
                    initial={{ opacity: 0, y: -14, backgroundColor: "#EEF2FF" }}
                    animate={{ opacity: 1, y: 0, backgroundColor: fresh ? ["#EEF2FF", "#FFFFFF"] : "#FFFFFF" }}
                    transition={{ duration: 0.5, backgroundColor: { duration: 2.2 } }}
                    className="flex items-start gap-3 border-b border-[#EEF0F2] px-5 py-2.5 last:border-b-0"
                  >
                    <span className="mt-1.5 size-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[15px] leading-snug">{d.text}</div>
                      <div className="mt-0.5 font-mono text-[11px] text-[#5C6370]">#{r.seq} · {time(r.ts)} · hash {r.hash}</div>
                    </div>
                  </motion.li>
                );
              })}
            </AnimatePresence>
            {!log.length && <li className="px-5 py-10 text-center text-sm text-[#5C6370]">{failClosed ? "The log cannot be trusted right now." : "No records yet."}</li>}
          </ul>
        </section>

        <div className="flex flex-col gap-4 lg:col-span-5">
          <section className="rounded-xl border border-[#E3E5E8] bg-white">
            <div className="border-b border-[#E3E5E8] px-5 py-3 text-sm font-semibold">Cluster network</div>
            {cluster ? <NetworkMap live={cluster} running={m?.running} interactive={false} /> : <p className="px-5 py-8 text-center text-sm text-[#5C6370]">Cluster not started on the console.</p>}
          </section>
          <section className="rounded-xl border border-[#E3E5E8] bg-white">
            <div className="flex items-center justify-between border-b border-[#E3E5E8] px-5 py-3">
              <h2 className="text-sm font-semibold">Security alerts</h2>
              <span className="text-xs text-[#5C6370]">raised by the service itself</span>
            </div>
            <ul>
              <AnimatePresence initial={false}>
                {alerts.map((a) => (
                  <motion.li key={`${a.ts}-${a.rule}`} layout initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} className="border-b border-[#EEF0F2] px-5 py-2.5 text-sm last:border-b-0">
                    <div className="font-medium text-[#B42318]">{ruleLabel(a.rule)}</div>
                    <div className="text-[#3A404A]">{a.detail}</div>
                    <div className="mt-0.5 text-xs text-[#3A404A]"><span className="text-[#5C6370]">identity</span> {a.identity ?? a.actor ?? "unauthenticated caller"} · <span className="text-[#5C6370]">service</span> {a.service ?? "file-service adapter"} · <span className="text-[#5C6370]">event</span> {a.events ?? "-"}</div>
                    <div className="font-mono text-[11px] text-[#5C6370]">{time(a.ts)}{a.seq ? ` · audit #${a.seq}` : " · signed side log"}</div>
                  </motion.li>
                ))}
              </AnimatePresence>
              {!alerts.length && <li className="px-5 py-6 text-center text-sm text-[#5C6370]">No alerts.</li>}
            </ul>
          </section>
        </div>
      </div>
    </main>
  );
}
