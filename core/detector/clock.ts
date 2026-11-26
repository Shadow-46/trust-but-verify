// Goal 8: clock differences. Raw timestamps are kept untouched; we add a
// corrected event time (event - known source offset) with an uncertainty, and
// flag order we cannot establish instead of guessing.

import { parseUtc } from "./ingest.ts";
import type { Flag, LogEvent, Policy, TimeInfo } from "./types.ts";

export function timeInfo(e: LogEvent, policy: Policy): { time: TimeInfo; flags: Flag[] } {
  const raw = parseUtc(e.event_time_utc, `${e.event_id} event_time_utc`);
  const received = parseUtc(e.received_time_utc, `${e.event_id} received_time_utc`);
  const corrected = raw - e.source_clock_offset_ms;
  const flags: Flag[] = [];
  if (e.source_clock_offset_ms !== 0) flags.push("clock_offset");
  if (received - raw < 0) flags.push("negative_raw_delay");
  if (Math.abs(e.source_clock_offset_ms) > policy.clock.maxSupportedSkewMs) {
    flags.push("unsupported_skew", "ambiguous_order");
  }
  return {
    time: {
      raw_event_ms: raw,
      received_ms: received,
      corrected_event_ms: corrected,
      corrected_event_utc: new Date(corrected).toISOString(),
      collector_delay_ms: received - corrected,
      uncertainty_ms: policy.clock.uncertaintyMs,
    },
    flags,
  };
}

export interface OrderInput {
  id: string;
  session_id: string;
  time: TimeInfo;
  flags: Flag[];
}

export interface DelayNote {
  /** the earlier-received event that occurred later than this one */
  arrivedAfter: string;
  /** how much earlier this event occurred, on the collector clock */
  occurredEarlierByMs: number;
}

/**
 * Adds `delayed_delivery` / `ambiguous_order` flags in place. `items` must be in
 * receipt order. Two corrected times closer than 2 x uncertainty cannot be ordered.
 */
export function markOrder(items: OrderInput[], uncertaintyMs: number): Map<string, DelayNote> {
  const delays = new Map<string, DelayNote>();
  const band = 2 * uncertaintyMs;
  const add = (it: OrderInput, f: Flag) => {
    if (!it.flags.includes(f)) it.flags.push(f);
  };
  const trusted = (it: OrderInput) => !it.flags.includes("unsupported_skew");

  // Receipt order vs event order: compare with the latest event time seen so far.
  let latest: OrderInput | undefined;
  for (const it of items) {
    if (!trusted(it)) continue;
    if (latest) {
      const gap = latest.time.corrected_event_ms - it.time.corrected_event_ms;
      if (gap > band) {
        add(it, "delayed_delivery");
        delays.set(it.id, { arrivedAfter: latest.id, occurredEarlierByMs: gap });
      } else if (gap > 0) {
        add(it, "ambiguous_order");
        add(latest, "ambiguous_order");
      }
    }
    if (!latest || it.time.corrected_event_ms > latest.time.corrected_event_ms) latest = it;
  }

  // Within a session, neighbours inside the uncertainty band have no reliable order.
  const bySession = new Map<string, OrderInput[]>();
  for (const it of items) {
    if (it.session_id === "" || !trusted(it)) continue;
    const list = bySession.get(it.session_id) ?? [];
    list.push(it);
    bySession.set(it.session_id, list);
  }
  for (const list of bySession.values()) {
    list.sort((a, b) => a.time.corrected_event_ms - b.time.corrected_event_ms);
    for (let k = 1; k < list.length; k++) {
      if (list[k].time.corrected_event_ms - list[k - 1].time.corrected_event_ms <= band) {
        add(list[k], "ambiguous_order");
        add(list[k - 1], "ambiguous_order");
      }
    }
  }
  return delays;
}
