import { reactive, computed, watch } from "vue";
import { state } from "./store.js";
import { IMPACT_ELEVATED } from "./format.js";

// The Signals view: early-warning items from CERTs, vendor PSIRTs, oss-security,
// GitHub advisories and exploitation research, often ahead of a CVE. Its tab
// counts elevated, signature-ready items this browser hasn't seen in the view;
// items that were new when the view was opened stay highlighted until reload.

const SEEN_KEY = "webcve.signals.seen";

export const signals = reactive({ items: [], feeds: [], queue: null, windowDays: 30, loaded: false, seen: loadSeen(), fresh: new Set() });

function loadSeen() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || "[]"));
  } catch {
    return new Set();
  }
}

function saveSeen() {
  try {
    const live = new Set(signals.items.map((s) => s.id));
    localStorage.setItem(SEEN_KEY, JSON.stringify([...signals.seen].filter((id) => live.has(id))));
  } catch {
    // Storage blocked: the counter resets next visit
  }
}

// Worth a reader's attention: rated high or severe, and something a signature can be built from
export const isNotable = (s) =>
  s.ai && IMPACT_ELEVATED.includes(s.ai.rating) && (s.ai.network ? s.ai.network === "new_signature" : s.readiness === "ready" && s.ai.tier !== "triage");

export const unseenSignals = computed(() => signals.items.filter((s) => isNotable(s) && !signals.seen.has(s.id)));
export const unseenSignalsSevere = computed(() => unseenSignals.value.some((s) => s.ai.rating === "severe"));

function markSeen() {
  let changed = false;
  for (const s of signals.items) {
    if (isNotable(s) && !signals.seen.has(s.id)) {
      signals.seen.add(s.id);
      signals.fresh.add(s.id);
      changed = true;
    }
  }
  if (changed) saveSeen();
}

export async function loadSignals() {
  try {
    const res = await fetch("/api/signals");
    if (!res.ok) return;
    const d = await res.json();
    signals.items = d.items || [];
    signals.feeds = d.feeds || [];
    signals.queue = d.queue || null;
    signals.windowDays = d.windowDays || 30;
    signals.loaded = true;
    if (state.view === "signals") markSeen();
  } catch {
    // Keep the previous list
  }
}

let started = false;
export function startSignals() {
  if (started) return;
  started = true;
  loadSignals();
  let tick = 0;
  setInterval(() => {
    tick++;
    if (state.view === "signals" || tick % 5 === 0) loadSignals();
  }, 60 * 1000);
  watch(
    () => state.view,
    (v) => {
      if (v !== "signals") return;
      markSeen();
      loadSignals();
    },
  );
}
