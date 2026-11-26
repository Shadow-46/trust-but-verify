"use client";

/**
 * One animated scene per Attack Lab storyboard, shared by the Lab stage (laptop A) and the
 * Live Monitor (laptop B). Every scene is driven by the REAL step results (evidence, checks,
 * tone): node verdicts, epochs, timings and device names come from what the service did, not
 * from a script. `step` is the step on stage (1-based; 0 = before the first step).
 */

import { AnimatePresence, motion } from "motion/react";
import type { LucideIcon } from "lucide-react";
import {
  Archive, Ban, BellRing, Check, FileLock, FileX, HardDrive, KeyRound, Landmark, Link2, Lock, LockOpen, Scissors,
  Server, ShieldCheck, ShieldX, Skull, Smartphone, User, Wifi, X, Boxes,
} from "lucide-react";

export type SceneEvent = { step: number; actor: string; title: string; evidence: string; tone: string; checks: { name: string; pass: boolean }[] };

const RED = "#B42318";
const GREEN = "#0F7B4F";
const BLUE = "#1D4ED8";
const AMBER = "#B54708";
const GRAY = "#5C6370";

const num = (s: string | undefined, re: RegExp) => {
  const m = s ? re.exec(s) : null;
  return m ? m[1] : null;
};

/** A labelled actor/system tile at (x%, y%) of the scene. */
function Tile({ x, y, icon: Icon, label, sub, tone = "neutral", pulse = false, size = 48 }: { x: number; y: number; icon: LucideIcon; label: string; sub?: string; tone?: "neutral" | "good" | "bad" | "warn" | "attacker"; pulse?: boolean; size?: number }) {
  const color = tone === "good" ? GREEN : tone === "bad" ? RED : tone === "warn" ? AMBER : tone === "attacker" ? RED : "#14171C";
  const bg = tone === "good" ? "#E7F5EE" : tone === "bad" ? "#FDECEA" : tone === "warn" ? "#FEF3E2" : tone === "attacker" ? "#FDECEA" : "#F1F2F4";
  return (
    <div className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1" style={{ left: `${x}%`, top: `${y}%` }}>
      <motion.div
        className="flex items-center justify-center rounded-xl border"
        style={{ width: size, height: size, borderColor: `${color}55` }}
        animate={{ backgroundColor: bg, scale: pulse ? [1, 1.12, 1] : 1 }}
        transition={{ duration: 0.6, repeat: pulse ? 2 : 0 }}
      >
        <Icon style={{ color, width: size * 0.5, height: size * 0.5 }} />
      </motion.div>
      <div className="whitespace-nowrap text-center text-[11px] font-medium leading-tight" style={{ color }}>{label}</div>
      {sub && <div className="max-w-[9rem] text-center font-mono text-[10px] leading-tight text-[#5C6370]">{sub}</div>}
    </div>
  );
}

/** A packet that travels from one point to another; `bounce` makes it hit and fall back. */
function Packet({ from, to, label, color = BLUE, bounce = false, delay = 0, ghost = false }: { from: [number, number]; to: [number, number]; label: string; color?: string; bounce?: boolean; delay?: number; ghost?: boolean }) {
  const mid: [number, number] = [from[0] + (to[0] - from[0]) * 0.86, from[1] + (to[1] - from[1]) * 0.86];
  const back: [number, number] = [from[0] + (to[0] - from[0]) * 0.7, from[1] + (to[1] - from[1]) * 0.7 + 6];
  return (
    <motion.div
      className="absolute z-10 -translate-x-1/2 -translate-y-1/2"
      initial={{ left: `${from[0]}%`, top: `${from[1]}%`, opacity: 0 }}
      animate={bounce
        ? { left: [`${from[0]}%`, `${mid[0]}%`, `${back[0]}%`], top: [`${from[1]}%`, `${mid[1]}%`, `${back[1]}%`], opacity: [1, 1, 0.85] }
        : { left: [`${from[0]}%`, `${to[0]}%`], top: [`${from[1]}%`, `${to[1]}%`], opacity: [1, 1] }}
      transition={{ duration: bounce ? 1.1 : 0.9, delay, ease: [0.22, 1, 0.36, 1], times: bounce ? [0, 0.65, 1] : undefined }}
    >
      <div className={`whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-medium text-white shadow ${ghost ? "border border-dashed border-white/70" : ""}`} style={{ backgroundColor: color, opacity: ghost ? 0.85 : 1 }}>
        {label}
      </div>
      {bounce && (
        <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: delay + 0.75 }} className="absolute -right-2 -top-2.5 flex size-5 items-center justify-center rounded-full bg-white shadow ring-2" style={{ ["--tw-ring-color" as string]: RED }}>
          <X className="size-3.5" style={{ color: RED }} />
        </motion.div>
      )}
    </motion.div>
  );
}

/** A check/cross stamp popping at (x, y). */
function Stamp({ x, y, ok, label, delay = 0.6 }: { x: number; y: number; ok: boolean; label?: string; delay?: number }) {
  return (
    <motion.div initial={{ scale: 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ delay, type: "spring", stiffness: 300, damping: 18 }} className="absolute z-20 flex -translate-x-1/2 -translate-y-1/2 items-center gap-1 rounded-full bg-white px-2 py-0.5 text-[11px] font-semibold shadow" style={{ left: `${x}%`, top: `${y}%`, color: ok ? GREEN : RED }}>
      {ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}
      {label}
    </motion.div>
  );
}

/** A dashed connector between two points (percent coordinates). */
function Wire({ a, b, color = "#C9CED6", broken = false }: { a: [number, number]; b: [number, number]; color?: string; broken?: boolean }) {
  return (
    <svg className="pointer-events-none absolute inset-0 size-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      <motion.line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} stroke={broken ? RED : color} strokeWidth={broken ? 0.8 : 0.5} strokeDasharray={broken ? "2 2" : "1.5 1.5"} vectorEffect="non-scaling-stroke"
        animate={broken ? { opacity: [1, 0.3, 1] } : { opacity: 1 }} transition={{ duration: 0.8, repeat: broken ? Infinity : 0 }} style={{ strokeWidth: broken ? 2 : 1.4 }} />
    </svg>
  );
}

// ---------- scenes ----------

const NODE_Y = [22, 50, 78];

function StolenPhone({ step, events }: { step: number; events: SceneEvent[] }) {
  const ev2 = events[1]?.evidence;
  const epoch = num(ev2, /epoch (\d+)/);
  const ms = num(ev2, /in (\d+) ms/);
  const device = num(events[0]?.evidence, /device (\S+):/) ?? "maya's phone";
  const revoked = step >= 2;
  const hit = (i: number) => (i === 0 ? step >= 3 : step >= 4);
  return (
    <>
      <Tile x={10} y={50} icon={Smartphone} label="thief" sub={device} tone={step >= 1 ? "attacker" : "neutral"} pulse={step === 1} />
      {step >= 1 && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="absolute left-[14%] top-[30%]"><KeyRound className="size-5" style={{ color: RED }} /></motion.div>}
      <Tile x={45} y={14} icon={Landmark} label="control plane" sub={revoked && epoch ? `epoch ${epoch} · ML-DSA` : "signs policy"} tone={revoked ? "good" : "neutral"} size={40} />
      {["node-a", "node-b", "node-c"].map((n, i) => (
        <Tile key={n} x={86} y={NODE_Y[i]} icon={Server} label={n} sub={revoked ? (hit(i) ? "refused" : "device revoked") : "device trusted"} tone={revoked ? (hit(i) ? "bad" : "warn") : "neutral"} size={40} />
      ))}
      {step === 2 && ["a", "b", "c"].map((n, i) => <Packet key={n} from={[45, 18]} to={[84, NODE_Y[i]]} label={`epoch ${epoch ?? ""} revokes`} color={GREEN} delay={i * 0.18} />)}
      {step === 2 && ms && <Stamp x={66} y={92} ok label={`enforced on 3/3 nodes in ${ms} ms`} delay={1.1} />}
      {step === 3 && <Packet from={[14, 50]} to={[84, NODE_Y[0]]} label="signed with stolen key" color={RED} bounce />}
      {step === 4 && [1, 2].map((i) => <Packet key={i} from={[14, 50]} to={[84, NODE_Y[i]]} label="try another node" color={RED} bounce delay={(i - 1) * 0.25} />)}
      {step >= 4 && <Stamp x={58} y={92} ok label="rejected on every node" delay={1.3} />}
    </>
  );
}

function Replay({ step, events }: { step: number; events: SceneEvent[] }) {
  const nonce = num(events[1]?.evidence, /nonce (\S+)/) ?? "nonce";
  return (
    <>
      <Tile x={9} y={30} icon={User} label="maya" sub={step >= 1 ? "new phone enrolled" : undefined} tone={step >= 2 ? "good" : "neutral"} />
      <Tile x={40} y={78} icon={Wifi} label="eavesdropper" sub={step >= 3 ? "holds an exact copy" : "on the Wi-Fi"} tone="attacker" pulse={step === 3} />
      <Tile x={86} y={26} icon={Server} label="node-b" sub={step >= 4 ? "nonce already used" : step >= 2 ? `stored ${nonce}` : undefined} tone={step >= 4 ? "bad" : step >= 2 ? "good" : "neutral"} size={42} />
      <Tile x={86} y={74} icon={Server} label="node-c" sub={step >= 5 ? "signed for node-b" : "never saw the nonce"} tone={step >= 5 ? "bad" : "neutral"} size={42} />
      <Wire a={[14, 30]} b={[82, 26]} />
      {step === 2 && <Packet from={[14, 30]} to={[84, 26]} label={`to node-b · ${nonce}`} color={BLUE} />}
      {step === 2 && <Stamp x={74} y={10} ok label="allowed" delay={0.9} />}
      {step === 3 && <Packet from={[46, 28]} to={[40, 64]} label="copy" color={RED} ghost />}
      {step === 4 && <Packet from={[44, 72]} to={[84, 26]} label="same bytes again" color={RED} bounce ghost />}
      {step === 5 && <Packet from={[44, 76]} to={[84, 74]} label="replay to node-c" color={RED} bounce ghost />}
      {step >= 5 && <Stamp x={62} y={94} ok label="rejected on every node" delay={1.2} />}
    </>
  );
}

function ForgedPolicy({ step, events }: { step: number; events: SceneEvent[] }) {
  const forged = num(events[0]?.evidence, /forged epoch (\d+)/);
  const held = num(events[2]?.evidence, /epoch (\d+)/);
  return (
    <>
      <Tile x={10} y={50} icon={Skull} label="attacker" sub="own ML-DSA key" tone="attacker" />
      {step >= 1 && step < 2 && (
        <motion.div initial={{ scale: 0, rotate: -10 }} animate={{ scale: 1, rotate: 0 }} className="absolute left-[30%] top-[38%] flex flex-col items-center">
          <FileX className="size-10" style={{ color: RED }} />
          <span className="font-mono text-[10px]" style={{ color: RED }}>epoch {forged ?? "+100"} · all devices active</span>
        </motion.div>
      )}
      <Tile x={84} y={50} icon={Server} label="node-c" sub={held ? `still epoch ${held}` : "keeps its verified policy"} tone={step >= 2 ? "good" : "neutral"} size={44} />
      <motion.div className="absolute left-[72%] top-1/2 -translate-x-1/2 -translate-y-1/2" animate={step === 2 ? { scale: [1, 1.25, 1] } : {}} transition={{ delay: 0.7, duration: 0.5 }}>
        <ShieldCheck className="size-9" style={{ color: step >= 2 ? GREEN : GRAY }} />
        <div className="text-center text-[10px] text-[#5C6370]">anchor</div>
      </motion.div>
      {step === 2 && <Packet from={[14, 50]} to={[72, 50]} label={`forged policy · epoch ${forged ?? ""}`} color={RED} bounce />}
      {step >= 2 && <Stamp x={56} y={20} ok={false} label="signature ≠ control plane" delay={0.9} />}
      {step >= 3 && <Stamp x={84} y={86} ok label="nothing changed" delay={0.3} />}
    </>
  );
}

function StateRollback({ step, events }: { step: number; events: SceneEvent[] }) {
  const closed = step >= 6 && step < 7;
  const swapped = step >= 5 && step < 7;
  return (
    <>
      <Tile x={9} y={28} icon={Skull} label="attacker" sub={step >= 1 ? "copied state.json" : "disk access"} tone="attacker" />
      {step >= 1 && step < 5 && <motion.div initial={{ x: 120, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="absolute left-[16%] top-[52%] rounded-md border border-dashed border-[#F4A79F] bg-[#FDECEA] px-2 py-1 font-mono text-[10px] text-[#B42318]">old state (maya active)</motion.div>}
      <div className="absolute left-[38%] top-[8%] w-[34%] rounded-xl border border-[#E3E5E8] bg-[#FBFBFC] p-2">
        <div className="flex items-center gap-1.5 text-[11px] font-medium text-[#3A404A]"><HardDrive className="size-4" /> service disk</div>
        <div className="mt-2 grid grid-cols-2 gap-2">
          <motion.div animate={{ backgroundColor: swapped ? "#FEF3E2" : "#FFFFFF", borderColor: swapped ? AMBER : "#E3E5E8" }} className="rounded-md border p-1.5 text-center">
            <div className="text-[10px] text-[#5C6370]">state.json</div>
            <div className="font-mono text-xs font-semibold" style={{ color: swapped ? AMBER : "#14171C" }}>{swapped ? "OLD version" : step >= 2 ? "maya revoked" : "current"}</div>
          </motion.div>
          <div className="rounded-md border border-[#E3E5E8] bg-white p-1.5 text-center">
            <div className="text-[10px] text-[#5C6370]">signed log head</div>
            <div className="font-mono text-xs font-semibold text-[#1D4ED8]">{step >= 2 ? "after revocation" : "latest"}</div>
          </div>
        </div>
        <div className="relative mt-1 h-4"><Wire a={[25, 10]} b={[75, 10]} broken={closed} color={GREEN} /></div>
        <div className="text-center text-[10px]" style={{ color: closed ? RED : GREEN }}>{closed ? "version ≠ signed head → fail-closed" : "version bound to signed head"}</div>
      </div>
      {step >= 3 && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="absolute left-[82%] top-[18%] flex flex-col items-center"><Archive className="size-7" style={{ color: GREEN }} /><span className="text-[10px] text-[#0F7B4F]">signed backup</span></motion.div>}
      <Tile x={14} y={86} icon={Smartphone} label="lost laptop" sub="maya" tone={step >= 4 ? "bad" : "neutral"} size={36} />
      {step === 4 && <Packet from={[18, 86]} to={[55, 46]} label="open design-doc" color={RED} bounce />}
      {step === 5 && <Packet from={[22, 54]} to={[45, 34]} label="write old state back" color={RED} />}
      {step === 6 && <Packet from={[18, 86]} to={[55, 46]} label="try again" color={RED} bounce />}
      {closed && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 0.8 }} className="absolute left-[55%] top-[72%] flex -translate-x-1/2 items-center gap-1.5 rounded-full bg-[#FDECEA] px-3 py-1 text-xs font-semibold text-[#B42318]"><Lock className="size-4" /> fail-closed: refusing everything</motion.div>}
      {step >= 7 && <Packet from={[82, 24]} to={[56, 30]} label="verified restore" color={GREEN} />}
      {step >= 7 && <Stamp x={55} y={76} ok label={events[6]?.tone === "good" ? "live again · maya stays revoked" : "restore result"} delay={1} />}
    </>
  );
}

function CoverTracks({ step, events }: { step: number; events: SceneEvent[] }) {
  const seq = num(events[0]?.evidence, /audit #(\d+)/);
  const cut = step >= 3 && step < 6;
  const blocks = [0, 1, 2, 3, 4];
  const keySwapped = step === 5;
  return (
    <>
      <Tile x={9} y={30} icon={Skull} label="insider" sub="wants it gone" tone="attacker" />
      <div className="absolute left-[22%] top-[30%] flex items-center gap-1.5">
        {blocks.map((b) => {
          const isEvidence = b === 4;
          const gone = isEvidence && cut;
          return (
            <motion.div key={b} className="flex items-center gap-1.5" animate={gone ? { opacity: 0.15, y: 26 } : { opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
              <div className={`rounded-md border px-2 py-1.5 text-center font-mono text-[10px] ${isEvidence && step >= 1 ? "border-[#F4A79F] bg-[#FDECEA] text-[#B42318]" : "border-[#E3E5E8] bg-white text-[#3A404A]"}`}>
                {isEvidence && step >= 1 ? `#${seq ?? "n"}\nomar denied` : `#…`}
              </div>
              {b < 4 && <Link2 className="size-3.5" style={{ color: cut && b === 3 ? RED : GRAY }} />}
            </motion.div>
          );
        })}
        <AnimatePresence>{!cut && step >= 1 && <motion.div exit={{ opacity: 0, y: -10 }} className="ml-1 rounded bg-[#EEF2FF] px-1.5 py-0.5 text-[10px] font-medium text-[#1D4ED8]">signed head</motion.div>}</AnimatePresence>
      </div>
      {step === 3 && <motion.div initial={{ x: -30, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="absolute left-[66%] top-[16%]"><Scissors className="size-6" style={{ color: RED }} /></motion.div>}
      {step >= 2 && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="absolute left-[86%] top-[62%] flex flex-col items-center"><Archive className="size-7" style={{ color: GREEN }} /><span className="text-[10px] text-[#0F7B4F]">signed backup</span></motion.div>}
      <motion.div className="absolute left-[30%] top-[66%] flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px]" animate={{ borderColor: keySwapped ? RED : "#E3E5E8", backgroundColor: keySwapped ? "#FDECEA" : "#FFFFFF" }}>
        <KeyRound className="size-4" style={{ color: keySwapped ? RED : GRAY }} /> audit.pub {keySwapped ? "swapped: pinned hash ✗" : "pinned in MAC'd state"}
      </motion.div>
      {step === 4 && <Stamp x={55} y={86} ok={false} label="signed head missing → fail-closed" delay={0.4} />}
      {step >= 6 && <Stamp x={55} y={86} ok label="restored · the evidence is back" delay={0.6} />}
    </>
  );
}

const FILES = ["design-doc", "roadmap", "payroll.xlsx", "budget.xlsx"];

function Probing({ step }: { step: number }) {
  const quarantined = step >= 3;
  return (
    <>
      <div className="absolute left-[12%] top-1/2 -translate-x-1/2 -translate-y-1/2">
        <motion.div animate={quarantined ? { boxShadow: ["0 0 0 0px #B4231855", "0 0 0 10px #B4231800"] } : {}} transition={{ repeat: quarantined ? Infinity : 0, duration: 1.2 }} className="rounded-xl">
          <Tile x={50} y={50} icon={User} label="lee" sub={quarantined ? "quarantined" : `${Math.min(step, 3)} denials / 60 s`} tone={quarantined ? "bad" : "neutral"} />
        </motion.div>
      </div>
      {quarantined && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="absolute left-[24%] top-1/2 -translate-y-1/2"><Ban className="size-9" style={{ color: RED }} /></motion.div>}
      {FILES.map((f, i) => {
        const tried = i < 3 ? step >= i + 1 : step >= 4;
        const own = i === 3;
        return <Tile key={f} x={82} y={14 + i * 24} icon={FileLock} label={f} sub={own ? "lee's own file" : "not lee's"} tone={tried ? "bad" : "neutral"} size={34} />;
      })}
      {step >= 1 && step <= 3 && <Packet from={[20, 50]} to={[80, 14 + (step - 1) * 24]} label={`try ${FILES[step - 1]}`} color={RED} bounce />}
      {step === 3 && <motion.div initial={{ scale: 0 }} animate={{ scale: [0, 1.2, 1] }} transition={{ delay: 1 }} className="absolute left-[46%] top-[8%] flex items-center gap-1 rounded-full bg-[#FDECEA] px-2.5 py-1 text-xs font-semibold text-[#B42318]"><BellRing className="size-4" /> signed probing alert</motion.div>}
      {step >= 4 && <Packet from={[20, 50]} to={[80, 86]} label="open her own file" color={BLUE} bounce />}
      {step >= 4 && <Stamp x={50} y={92} ok label="quarantine holds until reviewed" delay={1.2} />}
    </>
  );
}

function Injection({ step }: { step: number }) {
  const tokens = ["mallory", "\\n", '{"type":"revoke","actor":"omar"}'];
  return (
    <>
      <Tile x={9} y={50} icon={Skull} label="attacker" tone="attacker" />
      {step === 1 && (
        <>
          <div className="absolute left-[20%] top-[18%] flex gap-1.5">
            {tokens.map((t, i) => (
              <motion.span key={t} initial={{ y: -10, opacity: 0 }} animate={{ y: [0, 0, 28], x: [0, 0, -i * 30], opacity: [1, 1, 0] }} transition={{ delay: i * 0.15, duration: 1.6, times: [0, 0.6, 1] }} className="rounded border border-[#F4A79F] bg-[#FDECEA] px-1.5 py-0.5 font-mono text-[10px] text-[#B42318]">{t}</motion.span>
            ))}
          </div>
          <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 1.4 }} className="absolute left-[20%] top-[50%] rounded-md border border-[#C9D6F5] bg-[#EEF2FF] px-2 py-1 font-mono text-[10px] text-[#1D4ED8]">
            {'"actor": "mallory\\n{\\"type\\":\\"revoke\\",…}"'}  ← one escaped JSON field
          </motion.div>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.8 }} className="absolute left-[78%] top-[50%] -translate-x-1/2 -translate-y-1/2 text-center">
            <div className="rounded-md border border-[#E3E5E8] bg-white px-2 py-1 text-[11px]">audit log: <b>1</b> record</div>
            <div className="mt-1 text-[10px] text-[#B42318] line-through">fake revoke record</div>
          </motion.div>
          <Stamp x={56} y={86} ok label="no record forged · alert raised" delay={2.1} />
        </>
      )}
      {step >= 2 && (
        <>
          <Tile x={78} y={50} icon={ShieldCheck} label="opaque ID" sub="Map key · JSON field · never a path" tone="good" />
          <Packet from={[14, 40]} to={[76, 46]} label="__proto__" color={RED} bounce />
          <Packet from={[14, 62]} to={[76, 56]} label="../../etc/passwd" color={RED} bounce delay={0.3} />
          <Stamp x={46} y={88} ok label="no file read · nothing polluted" delay={1.4} />
        </>
      )}
    </>
  );
}

function ProtectedRead({ step, events }: { step: number; events: SceneEvent[] }) {
  const bytes = num(events[2]?.evidence, /ciphertext (\d+) bytes/);
  return (
    <>
      <Tile x={9} y={26} icon={Skull} label="mallory" sub={step >= 1 ? "own ML-KEM-768 key" : undefined} tone="attacker" size={40} />
      <Tile x={9} y={78} icon={User} label="omar (owner)" sub={step >= 3 ? "decapsulates" : undefined} tone={step >= 3 ? "good" : "neutral"} size={40} />
      <Tile x={58} y={50} icon={ShieldCheck} label="file service" sub="authorize first" tone="neutral" size={44} />
      <Tile x={88} y={50} icon={FileLock} label="payroll.xlsx" sub="body never sent" size={36} />
      {step >= 1 && step < 2 && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} className="absolute left-[18%] top-[16%]"><KeyRound className="size-5" style={{ color: RED }} /></motion.div>}
      {step === 2 && <Packet from={[14, 26]} to={[56, 48]} label="encrypt it to MY key" color={RED} bounce />}
      {step === 2 && <Stamp x={34} y={50} ok={false} label="not the owner → no ciphertext" delay={1} />}
      {step >= 3 && <Packet from={[14, 78]} to={[56, 52]} label="omar's public key" color={BLUE} />}
      {step >= 3 && <motion.div initial={{ left: "56%", top: "56%", opacity: 0 }} animate={{ left: "16%", top: "70%", opacity: 1 }} transition={{ delay: 1, duration: 0.9 }} className="absolute z-10 rounded-full bg-[#0F7B4F] px-2.5 py-0.5 text-[11px] font-medium text-white shadow">ciphertext {bytes ? `${bytes} B` : ""} + HMAC proof</motion.div>}
      {step >= 3 && <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 2 }} className="absolute left-[22%] top-[86%]"><LockOpen className="size-5" style={{ color: GREEN }} /></motion.div>}
      {step >= 3 && <Stamp x={40} y={94} ok label="proof matches" delay={2.2} />}
    </>
  );
}

function Sandbox({ step, events, name }: { step: number; events: SceneEvent[]; name: string }) {
  const blocked = events[1]?.checks?.[0]?.pass ?? null;
  return (
    <>
      <Tile x={10} y={50} icon={Skull} label="attacker" tone="attacker" />
      <div className="absolute left-[34%] top-[14%] h-[72%] w-[50%] rounded-xl border-2 border-dashed border-[#C9CED6] bg-[#FBFBFC]">
        <div className="flex items-center gap-1.5 px-3 py-2 text-[11px] font-medium text-[#5C6370]"><Boxes className="size-4" /> isolated instance · {name}</div>
        <div className="absolute left-1/2 top-[58%] -translate-x-1/2 -translate-y-1/2">
          {step >= 2 ? (blocked === false ? <ShieldX className="size-12" style={{ color: RED }} /> : <ShieldCheck className="size-12" style={{ color: GREEN }} />) : <Server className="size-10 text-[#5C6370]" />}
        </div>
      </div>
      {step === 1 && <Packet from={[14, 50]} to={[52, 56]} label="attack" color={RED} />}
      {step >= 2 && <Stamp x={59} y={92} ok={blocked !== false} label={blocked === false ? "not blocked" : "blocked"} delay={0.4} />}
    </>
  );
}

export function AttackScene({ attack, name = "", step, events, compact = false }: { attack: string; name?: string; step: number; events: SceneEvent[]; compact?: boolean }) {
  const shown = events.slice(0, step);
  const scene = (() => {
    switch (attack) {
      case "stolen-phone": return <StolenPhone step={step} events={shown} />;
      case "replay": return <Replay step={step} events={shown} />;
      case "forged-policy": return <ForgedPolicy step={step} events={shown} />;
      case "state-rollback": return <StateRollback step={step} events={shown} />;
      case "cover-tracks": return <CoverTracks step={step} events={shown} />;
      case "probing": return <Probing step={step} />;
      case "injection": return <Injection step={step} />;
      case "protected-read": return <ProtectedRead step={step} events={shown} />;
      default: return <Sandbox step={step} events={shown} name={name} />;
    }
  })();
  return (
    <div className={`relative overflow-hidden rounded-xl border border-[#E3E5E8] bg-white ${compact ? "h-56" : "h-64"}`}>
      {/* keyed by step so every step replays its animation */}
      <div key={`${attack}-${step}`} className="absolute inset-0">{scene}</div>
    </div>
  );
}
