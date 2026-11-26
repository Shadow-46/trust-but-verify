"use client";
/* eslint-disable @typescript-eslint/no-explicit-any -- cluster status is untyped JSON from the operator API */

import { useEffect, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";
import { AnimatePresence, motion } from "motion/react";

/**
 * Live cluster as a network: the control plane in the middle, node processes
 * around it, maya's phone outside. Packets show what really happened:
 * - a new signed policy epoch travels to every node (stopped at the cut if a link is partitioned),
 * - device requests (e.g. from the Attack Lab) travel to a node and bounce off when denied.
 * Nodes are draggable; clicking one opens its controls (cut/restore link, stop/start).
 */

type Pt = { x: number; y: number };
type Packet = { id: string; from: string; to: string; color: string; dropped: boolean; label?: string };

const W = 800;
const H = 420;
const INK = "#1D4ED8";
const OK = "#0F7B4F";
const BAD = "#B42318";
const MUTED = "#AEB4BD";

const DEFAULT_POS: Record<string, Pt> = {
  control: { x: 420, y: 210 },
  "node-a": { x: 420, y: 70 },
  "node-b": { x: 600, y: 320 },
  "node-c": { x: 240, y: 320 },
  phone: { x: 110, y: 120 },
};

export function NetworkMap({
  live,
  running,
  interactive = true,
  onAction,
}: {
  live: any | null;
  running?: Record<string, boolean>;
  interactive?: boolean;
  onAction?: (action: "cluster-partition" | "cluster-heal" | "cluster-stop" | "cluster-restart", node: string) => void;
}) {
  const [pos, setPos] = useState<Record<string, Pt>>(DEFAULT_POS);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [menu, setMenu] = useState<string | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ id: string; start: Pt; moved: boolean } | null>(null);
  const lastEpoch = useRef<number | null>(null);
  const lastAttempt = useRef<number | null>(null); // primed on the first status, so old attempts don't replay

  const nodes: any[] = live?.nodes ?? [];
  const blocked: string[] = live?.control?.blocked ?? [];
  const isRunning = (n: string) => running?.[n] ?? true;

  // New epoch published → a signed policy packet to every node (cut links drop it halfway).
  useEffect(() => {
    if (!live) return;
    const e = live.published_epoch as number;
    if (lastEpoch.current !== null && e > lastEpoch.current) {
      const fresh = nodes.map((n) => ({
        id: `p${e}-${n.name}`,
        from: "control",
        to: n.name,
        color: INK,
        dropped: blocked.includes(n.name) || !isRunning(n.name),
        label: `epoch ${e}`,
      }));
      setPackets((p) => [...p, ...fresh]);
    }
    lastEpoch.current = e;
    // Device requests that reached a node since the last poll.
    const all = (live.attempts ?? []) as any[];
    if (lastAttempt.current === null) {
      lastAttempt.current = all.length ? Math.max(...all.map((a) => a.at)) : 0;
      return;
    }
    const since = lastAttempt.current;
    const newer = all.filter((a) => a.at > since);
    if (newer.length) {
      lastAttempt.current = Math.max(...newer.map((a) => a.at));
      setPackets((p) => [
        ...p,
        ...newer.map((a) => ({ id: `a${a.at}-${a.node}`, from: "phone", to: a.node, color: a.decision === "allow" ? OK : BAD, dropped: a.decision !== "allow", label: a.label })),
      ]);
    }
  }, [live]); // eslint-disable-line react-hooks/exhaustive-deps

  const toSvg = (ev: ReactPointerEvent): Pt => {
    const m = svg.current?.getScreenCTM();
    if (!m) return { x: 0, y: 0 };
    const p = new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m.inverse());
    return { x: Math.max(40, Math.min(W - 40, p.x)), y: Math.max(40, Math.min(H - 40, p.y)) };
  };
  const onDown = (id: string) => (ev: ReactPointerEvent) => {
    if (!interactive) return;
    (ev.target as Element).setPointerCapture(ev.pointerId);
    drag.current = { id, start: toSvg(ev), moved: false };
  };
  const onMove = (ev: ReactPointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const p = toSvg(ev);
    if (Math.hypot(p.x - d.start.x, p.y - d.start.y) > 4) d.moved = true;
    if (d.moved) setPos((s) => ({ ...s, [d.id]: p }));
  };
  const onUp = () => {
    const d = drag.current;
    drag.current = null;
    if (d && !d.moved && d.id.startsWith("node-")) setMenu((m) => (m === d.id ? null : d.id));
  };

  const ackMs = (name: string) => {
    const t = live?.control?.acks?.[name]?.[String(live?.published_epoch)];
    return typeof t === "number" && live?.published_at ? Math.max(0, t - live.published_at) : null;
  };

  return (
    <div className="relative">
      <svg ref={svg} viewBox={`0 0 ${W} ${H}`} className="h-auto w-full touch-none select-none" onPointerMove={onMove} onPointerUp={onUp} role="img" aria-label="Cluster network map">
        {/* control plane → node links */}
        {nodes.map((n) => {
          const a = pos.control;
          const b = pos[n.name] ?? DEFAULT_POS[n.name];
          const cut = blocked.includes(n.name);
          const down = !isRunning(n.name);
          const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
          return (
            <g key={`l-${n.name}`}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={cut ? BAD : down ? MUTED : "#C9CED6"} strokeWidth={cut ? 2.5 : 2} strokeDasharray={cut ? "8 6" : down ? "2 6" : undefined} />
              {/* live polling heartbeat along healthy links */}
              {!cut && !down && (
                <motion.circle r={3} fill={INK} opacity={0.35} initial={false} animate={{ cx: [b.x, a.x], cy: [b.y, a.y] }} transition={{ duration: 1.6, repeat: Infinity, ease: "linear" }} />
              )}
              {cut && (
                <g transform={`translate(${mid.x} ${mid.y})`}>
                  <circle r={11} fill="white" stroke={BAD} strokeWidth={2} />
                  <path d="M-4 -4 L4 4 M4 -4 L-4 4" stroke={BAD} strokeWidth={2.2} strokeLinecap="round" />
                </g>
              )}
            </g>
          );
        })}
        {/* maya's phone → nodes (requests) */}
        {nodes.map((n) => {
          const a = pos.phone;
          const b = pos[n.name] ?? DEFAULT_POS[n.name];
          return <line key={`d-${n.name}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#E3E5E8" strokeWidth={1.5} strokeDasharray="3 5" />;
        })}

        {/* packets */}
        <AnimatePresence>
          {packets.map((p) => {
            const a = pos[p.from] ?? DEFAULT_POS[p.from];
            const b = pos[p.to] ?? DEFAULT_POS[p.to];
            const end = p.dropped && p.from === "control" ? { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } : b;
            const back = p.dropped && p.from !== "control";
            return (
              <motion.g
                key={p.id}
                initial={{ x: a.x, y: a.y, opacity: 1, scale: 1 }}
                animate={back ? { x: [a.x, b.x - (b.x - a.x) * 0.12, a.x + (b.x - a.x) * 0.55], y: [a.y, b.y - (b.y - a.y) * 0.12, a.y + (b.y - a.y) * 0.55], opacity: [1, 1, 0] } : { x: end.x, y: end.y, opacity: [1, 1, 0], scale: p.dropped ? [1, 1, 0.4] : [1, 1.5, 1] }}
                transition={{ duration: back ? 1.4 : 0.9, ease: [0.22, 1, 0.36, 1], times: [0, 0.7, 1] }}
                onAnimationComplete={() => setPackets((s) => s.filter((x) => x.id !== p.id))}
              >
                <circle r={7} fill={p.color} />
                <circle r={12} fill={p.color} opacity={0.18} />
              </motion.g>
            );
          })}
        </AnimatePresence>

        {/* control plane */}
        <g transform={`translate(${pos.control.x} ${pos.control.y})`}>
          <motion.circle key={`cp-${live?.published_epoch}`} r={48} fill="none" stroke={INK} initial={{ opacity: 0.5, scale: 0.9 }} animate={{ opacity: 0, scale: 1.5 }} transition={{ duration: 1.2 }} />
          <circle r={44} fill={INK} />
          <text textAnchor="middle" y={-4} className="fill-white text-[13px] font-semibold">Control plane</text>
          <text textAnchor="middle" y={14} className="fill-white/80 font-mono text-[11px]">epoch {live?.published_epoch ?? "–"}</text>
        </g>

        {/* phone */}
        <g transform={`translate(${pos.phone.x} ${pos.phone.y})`}>
          <rect x={-22} y={-32} width={44} height={64} rx={9} fill="white" stroke="#5C6370" strokeWidth={2} />
          <rect x={-8} y={22} width={16} height={3} rx={1.5} fill="#5C6370" />
          <text textAnchor="middle" y={52} className="fill-[#14171C] text-[12px] font-medium">maya&apos;s phone</text>
          <text textAnchor="middle" y={67} className="fill-[#5C6370] font-mono text-[10px]">{live?.device ?? ""}</text>
        </g>

        {/* nodes */}
        {nodes.map((n) => {
          const p = pos[n.name] ?? DEFAULT_POS[n.name];
          const down = !isRunning(n.name);
          const cut = blocked.includes(n.name);
          const allow = n.decision === "allow";
          const color = down ? MUTED : allow ? OK : BAD;
          const ms = ackMs(n.name);
          return (
            <g key={n.name} transform={`translate(${p.x} ${p.y})`} onPointerDown={onDown(n.name)} className={interactive ? "cursor-grab active:cursor-grabbing" : ""}>
              <motion.circle key={`pulse-${n.epoch}`} r={36} fill="none" stroke={color} initial={{ opacity: 0.6, scale: 1 }} animate={{ opacity: 0, scale: 1.6 }} transition={{ duration: 1 }} />
              <circle r={34} fill="white" stroke={color} strokeWidth={3} strokeDasharray={down ? "4 4" : undefined} />
              <text textAnchor="middle" y={-4} className="fill-[#14171C] text-[13px] font-semibold">{n.name}</text>
              <text textAnchor="middle" y={13} className="fill-[#5C6370] font-mono text-[11px]">epoch {n.epoch}</text>
              <g transform="translate(0 52)">
                <rect x={-62} y={-11} width={124} height={22} rx={11} fill={down ? "#F1F2F4" : allow ? "#E7F5EE" : "#FDECEA"} />
                <text textAnchor="middle" y={4} className="text-[11px] font-medium" fill={color}>
                  {down ? "offline" : cut ? `cut off · ${allow ? "allows" : "denies"}` : `phone ${allow ? "allowed" : "denied"}`}
                </text>
              </g>
              {ms !== null && !down && !cut && <text textAnchor="middle" y={80} className="fill-[#5C6370] font-mono text-[10px]">adopted in {ms} ms</text>}
            </g>
          );
        })}
      </svg>

      {/* node controls */}
      {interactive && menu && (() => {
        const p = pos[menu] ?? DEFAULT_POS[menu];
        const cut = blocked.includes(menu);
        const down = !isRunning(menu);
        return (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="absolute z-10 w-44 rounded-lg border border-[#E3E5E8] bg-white p-1.5 text-sm shadow-[0_12px_30px_-12px_rgba(15,18,24,0.35)]"
            style={{ left: `calc(${(p.x / W) * 100}% + 40px)`, top: `calc(${(p.y / H) * 100}% - 30px)` }}
          >
            <div className="px-2 py-1 text-xs text-[#5C6370]">{menu}</div>
            <button className="w-full rounded px-2 py-1.5 text-left hover:bg-[#F6F7F8]" onClick={() => { onAction?.(cut ? "cluster-heal" : "cluster-partition", menu); setMenu(null); }}>
              {cut ? "Restore network link" : "Cut network link"}
            </button>
            <button className="w-full rounded px-2 py-1.5 text-left hover:bg-[#F6F7F8]" onClick={() => { onAction?.(down ? "cluster-restart" : "cluster-stop", menu); setMenu(null); }}>
              {down ? "Start node process" : "Stop node process"}
            </button>
          </motion.div>
        );
      })()}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 pb-3 text-xs text-[#5C6370]">
        <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-full border-2 border-[#0F7B4F]" />allows maya&apos;s phone</span>
        <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-full border-2 border-[#B42318]" />denies it</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-0 w-5 border-t-2 border-dashed border-[#B42318]" />link cut</span>
        <span className="inline-flex items-center gap-1.5"><span className="size-2 rounded-full bg-[#1D4ED8]" />signed policy update</span>
        {interactive && <span>Drag nodes to rearrange · click a node for controls</span>}
      </div>
    </div>
  );
}
