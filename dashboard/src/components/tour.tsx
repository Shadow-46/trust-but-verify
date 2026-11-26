"use client";
/* eslint-disable react-hooks/set-state-in-effect -- the tour is a timed state machine: entering a step resets its outcome and readiness by design. */

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChevronLeft, ChevronRight, Pause, Play, X } from "lucide-react";

/**
 * Autoplay product walkthrough. Each step switches to a section, spotlights the
 * element marked with data-tour="<target>", explains it, runs the real action
 * against the service, shows the outcome, then advances. Presenter controls:
 * pause/play (Space), back/next (arrow keys), exit (Esc).
 */
export type TourStep<S extends string = string> = {
  section: S;
  target: string;
  title: string;
  body: string;
  run?: () => Promise<{ text: string; tone?: "good" | "bad" | "neutral" } | void>;
  dwell?: number;
};

type Rect = { top: number; left: number; width: number; height: number };
const PAD = 8;

export function Tour<S extends string>({ steps, open, onClose, go }: { steps: TourStep<S>[]; open: boolean; onClose: () => void; go: (s: S) => void }) {
  const [idx, setIdx] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [rect, setRect] = useState<Rect | null>(null);
  const [outcome, setOutcome] = useState<{ text: string; tone?: "good" | "bad" | "neutral" } | null>(null);
  const [ready, setReady] = useState(false);
  const runToken = useRef(0);
  // Step actions run strictly one after another, even when the presenter skips ahead,
  // so actions against the live service never interleave.
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const step = steps[idx];

  const measure = useCallback(() => {
    const el = step ? document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`) : null;
    if (!el) return setRect(null);
    const r = el.getBoundingClientRect();
    setRect({ top: r.top - PAD, left: r.left - PAD, width: r.width + PAD * 2, height: r.height + PAD * 2 });
  }, [step]);

  // Enter a step: navigate, bring the target into view, run its action.
  useEffect(() => {
    if (!open || !step) return;
    const token = ++runToken.current;
    setOutcome(null);
    setReady(false);
    go(step.section);
    const t1 = setTimeout(() => {
      document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 350);
    const t2 = setTimeout(async () => {
      measure();
      const job = queue.current.then(() => (token === runToken.current && step.run ? step.run() : undefined));
      queue.current = job.catch(() => undefined);
      const r = await job;
      if (token !== runToken.current) return;
      if (r) setOutcome(r);
      setTimeout(() => {
        if (token === runToken.current) {
          measure();
          setReady(true);
        }
      }, 250);
    }, 800);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [open, idx]); // eslint-disable-line react-hooks/exhaustive-deps

  // Autoplay: advance after the dwell time once the step's action has finished.
  useEffect(() => {
    if (!open || !playing || !ready) return;
    const t = setTimeout(() => (idx < steps.length - 1 ? setIdx(idx + 1) : setPlaying(false)), step?.dwell ?? 6500);
    return () => clearTimeout(t);
  }, [open, playing, ready, idx, steps.length, step]);

  useEffect(() => {
    if (!open) return;
    const onMove = () => measure();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowRight") setIdx((i) => Math.min(i + 1, steps.length - 1));
      else if (e.key === "ArrowLeft") setIdx((i) => Math.max(i - 1, 0));
      else if (e.key === " ") {
        e.preventDefault();
        setPlaying((p) => !p);
      }
    };
    window.addEventListener("resize", onMove);
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("resize", onMove);
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [open, measure, onClose, steps.length]);

  useEffect(() => {
    if (open) {
      // Restart from the beginning each time the walkthrough is opened.
       
      setIdx(0);
      setPlaying(true);
    }
  }, [open]);

  if (!open || !step) return null;

  const vw = typeof window === "undefined" ? 1280 : window.innerWidth;
  const vh = typeof window === "undefined" ? 800 : window.innerHeight;
  const cardW = Math.min(400, vw - 32);
  const below = rect ? rect.top + rect.height + 260 < vh : true;
  const cardTop = rect ? (below ? rect.top + rect.height + 14 : Math.max(16, rect.top - 14 - 230)) : vh / 2 - 120;
  const cardLeft = rect ? Math.min(Math.max(16, rect.left), vw - cardW - 16) : vw / 2 - cardW / 2;
  const tone = outcome?.tone === "good" ? "text-[#0F7B4F]" : outcome?.tone === "bad" ? "text-[#B42318]" : "text-[#14171C]";

  return (
    <div className="pointer-events-none fixed inset-0 z-[60]" aria-live="polite">
      {/* Dimmed backdrop with a spotlight cut-out that glides between targets. */}
      <motion.div
        className="absolute rounded-xl ring-2 ring-[#1D4ED8]"
        style={{ boxShadow: "0 0 0 9999px rgba(15,18,24,0.52)" }}
        initial={false}
        animate={rect ? { top: rect.top, left: rect.left, width: rect.width, height: rect.height, opacity: 1 } : { top: vh / 2, left: vw / 2, width: 0, height: 0, opacity: 1 }}
        transition={{ type: "spring", stiffness: 170, damping: 24 }}
      >
        <motion.span
          className="absolute inset-0 rounded-xl ring-2 ring-[#1D4ED8]/60"
          animate={{ scale: [1, 1.04, 1], opacity: [0.9, 0, 0.9] }}
          transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut" }}
        />
      </motion.div>

      <AnimatePresence mode="wait">
        <motion.div
          key={idx}
          className="pointer-events-auto absolute rounded-xl border border-[#E3E5E8] bg-white p-4 shadow-[0_24px_60px_-20px_rgba(15,18,24,0.45)]"
          style={{ width: cardW, top: cardTop, left: cardLeft }}
          initial={{ opacity: 0, y: below ? 10 : -10, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, scale: 0.98 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
        >
          <div className="flex items-center justify-between text-xs text-[#5C6370]">
            <span>Step {idx + 1} of {steps.length}</span>
            <button className="rounded p-1 hover:bg-[#F1F2F4]" onClick={onClose} aria-label="Exit walkthrough"><X className="size-3.5" /></button>
          </div>
          <h3 className="mt-1 text-[15px] font-semibold text-[#14171C]">{step.title}</h3>
          <p className="mt-1 text-sm leading-relaxed text-[#3A404A]">{step.body}</p>
          <AnimatePresence>
            {outcome && (
              <motion.p
                className={`mt-2 rounded-md bg-[#F6F7F8] px-2.5 py-1.5 text-sm font-medium ${tone}`}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
              >
                {outcome.text}
              </motion.p>
            )}
          </AnimatePresence>
          <div className="mt-3 h-1 overflow-hidden rounded-full bg-[#EEF0F2]">
            {ready && playing && (
              <motion.div
                key={`bar-${idx}`}
                className="h-full bg-[#1D4ED8]"
                initial={{ width: "0%" }}
                animate={{ width: "100%" }}
                transition={{ duration: (step.dwell ?? 6500) / 1000, ease: "linear" }}
              />
            )}
          </div>
          <div className="mt-3 flex items-center justify-between">
            <div className="flex gap-1">
              <button className="rounded-md border border-[#E3E5E8] p-1.5 hover:bg-[#F6F7F8] disabled:opacity-40" disabled={idx === 0} onClick={() => setIdx(idx - 1)} aria-label="Previous step"><ChevronLeft className="size-4" /></button>
              <button className="rounded-md border border-[#E3E5E8] p-1.5 hover:bg-[#F6F7F8]" onClick={() => setPlaying(!playing)} aria-label={playing ? "Pause" : "Play"}>{playing ? <Pause className="size-4" /> : <Play className="size-4" />}</button>
              <button className="rounded-md border border-[#E3E5E8] p-1.5 hover:bg-[#F6F7F8] disabled:opacity-40" disabled={idx === steps.length - 1} onClick={() => setIdx(idx + 1)} aria-label="Next step"><ChevronRight className="size-4" /></button>
            </div>
            <span className="text-xs text-[#5C6370]">{playing ? "Playing" : "Paused"} · Space, arrows, Esc</span>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
