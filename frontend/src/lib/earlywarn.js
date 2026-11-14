import { reactive, computed, watch } from "vue";
import { state, stats } from "./store.js";
import { IMPACT_ELEVATED } from "./format.js";

// The Early warning view: critical CVEs the AI rates high or severe for global
// impact, published or added to KEV in the last EARLY_WINDOW_DAYS days. Its tab
// counts entries this browser hasn't seen in the view yet: red when any of them
// is severe, orange otherwise.

export const EARLY_WINDOW_DAYS = 30;
const SEEN_KEY = "webcve.earlyWarning.seen";

export function earlySince() {
  return new Date(Date.now() - EARLY_WINDOW_DAYS * 86400000).toISOString().slice(0, 10);
}

// fresh: entries that were unseen when the view was opened this page load.
// They stay highlighted until the page is reloaded.
export const early = reactive({ items: [], seen: loadSeen(), queue: null, fresh: new Set() });

function loadSeen() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || "[]"));
  } catch {
    return new Set();
  }
}

function saveSeen() {
  try {
    // Only IDs still in the window are worth keeping
    const live = new Set(early.items.map((c) => c.id));
    localStorage.setItem(SEEN_KEY, JSON.stringify([...early.seen].filter((id) => live.has(id))));
  } catch {
    // Storage blocked: the counter just resets next visit
  }
}

export const unseen = computed(() => early.items.filter((c) => !early.seen.has(c.id)));
export const unseenSevere = computed(() => unseen.value.some((c) => c.aiImpact === "severe"));

function markSeen() {
  let changed = false;
  for (const c of early.items) {
    if (!early.seen.has(c.id)) {
      early.seen.add(c.id);
      early.fresh.add(c.id);
      changed = true;
    }
  }
  if (changed) saveSeen();
}

async function load() {
  const req = { aiImpact: IMPACT_ELEVATED, changedSince: earlySince(), pageSize: 500 };
  try {
    const res = await fetch("/api/cves", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) });
    if (!res.ok) return;
    const d = await res.json();
    early.items = (d.cves || []).map((c) => ({ id: c.id, aiImpact: c.aiImpact }));
    if (state.view === "early") markSeen();
  } catch {
    // Keep the previous list
  }
}

// AI pipeline queue depth, refreshed often while the view is open
async function loadQueue() {
  try {
    const res = await fetch("/api/ai-impact/status");
    if (res.ok) early.queue = await res.json();
  } catch {
    // Keep the previous numbers
  }
}

let started = false;
export function startEarlyWarning() {
  if (started) return;
  started = true;
  load();
  // Assessments finish in the background, so also check periodically
  setInterval(load, 5 * 60 * 1000);
  loadQueue();
  setInterval(() => (state.view === "early" ? loadQueue() : null), 15 * 1000);
  watch(() => stats.value?.lastDataUpdate, load);
  watch(
    () => state.view,
    (v) => {
      if (v !== "early") return;
      markSeen();
      loadQueue();
    },
  );
}
