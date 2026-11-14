<script setup>
import { ref, computed, watch } from "vue";
import Icon from "./Icon.vue";
import ImpactBadge from "./ImpactBadge.vue";
import ImpactCard from "./ImpactCard.vue";
import { signals } from "../lib/signals.js";
import { fmtNum, fmtRelative, IMPACT_LABEL, SIG_LABEL } from "../lib/format.js";

// Early-warning items that aren't tied to a CVE record (yet). By default only
// actionable ones show: about a specific vulnerability or its exploitation, and
// with enough public detail to build a signature from.
const emit = defineEmits(["open"]);

const KINDS = { cert: "CERTs", vendor: "Vendors", research: "Research", community: "oss-security", advisory: "GitHub advisories" };
const RATINGS = ["severe", "high", "moderate", "low"];

// Sort and filters are remembered per browser
const PREFS_KEY = "webcve.signals.prefs";
let saved = {};
try {
  saved = JSON.parse(localStorage.getItem(PREFS_KEY) || "{}") || {};
} catch {}

const q = ref("");
const actionableOnly = ref(saved.actionableOnly ?? true);
const kinds = ref(Array.isArray(saved.kinds) ? saved.kinds : []);
const ratings = ref(Array.isArray(saved.ratings) ? saved.ratings : []);
const sortBy = ref(saved.sortBy === "date" ? "date" : "risk");

watch(
  [actionableOnly, kinds, ratings, sortBy],
  () => {
    try {
      localStorage.setItem(
        PREFS_KEY,
        JSON.stringify({ actionableOnly: actionableOnly.value, kinds: kinds.value, ratings: ratings.value, sortBy: sortBy.value }),
      );
    } catch {}
  },
  { deep: true },
);
const open = ref(null);
const showFeeds = ref(false);

const actionable = (s) => s.readiness === "ready" && s.report !== "other";
const rank = (s) => (s.ai ? { severe: 4, high: 3, moderate: 2, low: 1 }[s.ai.rating] || 0 : 0);

const hiddenCount = computed(() => signals.items.filter((s) => !actionable(s)).length);

const rows = computed(() => {
  const needle = q.value.trim().toLowerCase();
  const out = signals.items.filter((s) => {
    if (actionableOnly.value && !actionable(s)) return false;
    if (kinds.value.length && !kinds.value.includes(s.feedKind)) return false;
    if (ratings.value.length && !ratings.value.includes(s.ai?.rating || "unrated")) return false;
    if (needle && !`${s.title} ${s.summary} ${s.feedLabel} ${(s.cves || []).join(" ")}`.toLowerCase().includes(needle)) return false;
    return true;
  });
  if (sortBy.value === "risk") out.sort((a, b) => rank(b) - rank(a) || b.published.localeCompare(a.published));
  return out;
});

function toggle(list, v) {
  const i = list.value.indexOf(v);
  if (i >= 0) list.value.splice(i, 1);
  else list.value.push(v);
}

function linked(s, id) {
  return (s.linked || []).find((l) => l.id === id);
}

const failedFeeds = computed(() => signals.feeds.filter((f) => f.lastError));
</script>

<template>
  <section class="signals" aria-label="Early-warning signals">
    <div class="sg-head">
      <div>
        <h2>Signals</h2>
        <p class="muted">
          Alerts, advisories and research from {{ signals.feeds.length }} sources in the last {{ signals.windowDays }} days, often ahead of a CVE.
          Rated by the same AI as CVEs.
        </p>
      </div>
      <div v-if="signals.queue && (signals.queue.awaitingTriage || signals.queue.awaitingAnalysis)" class="sg-queue" role="status">
        <span class="aiq-dot busy" />
        {{ fmtNum(signals.queue.awaitingTriage) }} awaiting triage · {{ fmtNum(signals.queue.awaitingAnalysis) }} awaiting deep analysis
      </div>
    </div>

    <div class="sg-controls">
      <input v-model="q" class="input sg-search" type="search" placeholder="Search titles, text, CVE IDs" aria-label="Search signals" />
      <label class="sg-toggle">
        <input v-model="actionableOnly" type="checkbox" />
        Actionable only
        <span v-if="actionableOnly && hiddenCount" class="muted">({{ fmtNum(hiddenCount) }} hidden)</span>
      </label>
      <select v-model="sortBy" class="input sg-sort" aria-label="Sort">
        <option value="risk">Highest risk first</option>
        <option value="date">Newest first</option>
      </select>
    </div>
    <div class="sg-chips" role="group" aria-label="Filter by source">
      <span class="sg-label">Source</span>
      <button v-for="(label, k) in KINDS" :key="k" class="chip" :class="{ on: kinds.includes(k) }" :aria-pressed="kinds.includes(k)" @click="toggle(kinds, k)">
        {{ label }}
      </button>
      <button v-if="kinds.length" class="chip clear" @click="kinds = []">Any source</button>
    </div>
    <div class="sg-chips" role="group" aria-label="Filter by AI rating">
      <span class="sg-label">AI rating</span>
      <button v-for="r in RATINGS" :key="r" class="chip" :class="{ on: ratings.includes(r) }" :aria-pressed="ratings.includes(r)" @click="toggle(ratings, r)">
        {{ IMPACT_LABEL[r] }}
      </button>
      <button class="chip" :class="{ on: ratings.includes('unrated') }" :aria-pressed="ratings.includes('unrated')" @click="toggle(ratings, 'unrated')">Not rated</button>
      <button v-if="ratings.length" class="chip clear" @click="ratings = []">Any rating</button>
    </div>

    <div v-if="!signals.loaded" class="muted sg-empty">Loading signals…</div>
    <div v-else-if="!rows.length" class="muted sg-empty">
      Nothing matches.
      <template v-if="actionableOnly && hiddenCount">{{ fmtNum(hiddenCount) }} items aren't actionable yet; untick "Actionable only" to see them.</template>
    </div>

    <ul v-else class="sg-list">
      <li v-for="s in rows" :key="s.id" class="sg-item" :class="{ fresh: signals.fresh.has(s.id), [`ai-${s.ai?.rating}`]: s.ai }">
        <div class="sg-row" role="button" tabindex="0" :aria-expanded="open === s.id" @click="open = open === s.id ? null : s.id" @keydown.enter="open = open === s.id ? null : s.id">
          <div class="sg-badges">
            <ImpactBadge v-if="s.ai" :rating="s.ai.rating" :confidence="s.ai.confidence" compact />
            <span v-if="s.ai && !['severe', 'high'].includes(s.ai.rating)" class="badge" :class="`ai-${s.ai.rating}`">{{ IMPACT_LABEL[s.ai.rating] }}</span>
            <span v-if="!s.ai" class="badge ai-low">Not rated yet</span>
            <span v-tip="s.readyWhy" class="badge" :class="`sig-${s.readiness}`" tabindex="0">{{ SIG_LABEL[s.readiness] }}</span>
          </div>
          <div class="sg-main">
            <a class="sg-title" :href="s.url" target="_blank" rel="noopener noreferrer" @click.stop>{{ s.title }}</a>
            <div class="sg-meta muted">
              {{ s.feedLabel }} · {{ fmtRelative(s.published) }}
              <template v-if="s.alsoIn?.length"> · <b>also in {{ s.alsoIn.join(", ") }}</b></template>
            </div>
            <div v-if="s.cves?.length" class="sg-cves">
              <template v-for="id in s.cves.slice(0, 8)" :key="id">
                <button v-if="linked(s, id)" class="cve-chip mono" @click.stop="emit('open', id)">
                  {{ id }}
                  <span v-if="linked(s, id).score" class="num">{{ linked(s, id).score.toFixed(1) }}</span>
                  <span v-if="linked(s, id).inKEV" class="badge kev">KEV</span>
                </button>
                <span v-else v-tip="'Not in the CVE data yet'" class="cve-chip mono pending">{{ id }}</span>
              </template>
              <span v-if="s.cves.length > 8" class="muted">+{{ s.cves.length - 8 }}</span>
            </div>
            <p v-if="s.ai?.summary && open !== s.id" class="sg-summary">{{ s.ai.summary }}</p>
          </div>
          <Icon :name="open === s.id ? 'chevronUp' : 'chevronDown'" :size="14" class="muted" />
        </div>
        <div v-if="open === s.id" class="sg-detail">
          <ImpactCard v-if="s.ai && s.ai.tier !== 'triage'" :assessment="s.ai" />
          <p v-else-if="s.ai" class="sg-summary full">{{ s.ai.summary }}</p>
          <p class="sg-text">{{ s.summary }}</p>
          <a :href="s.url" target="_blank" rel="noopener noreferrer">Open the original <Icon name="external" :size="12" /></a>
        </div>
      </li>
    </ul>

    <div class="sg-feeds">
      <button class="btn ghost sm" @click="showFeeds = !showFeeds">
        {{ showFeeds ? "Hide" : "Show" }} sources
        <span v-if="failedFeeds.length" class="badge danger">{{ failedFeeds.length }} failing</span>
      </button>
      <table v-if="showFeeds" class="sg-feed-table">
        <tr v-for="f in signals.feeds" :key="f.name">
          <td><a :href="f.site" target="_blank" rel="noopener noreferrer">{{ f.label }}</a></td>
          <td class="muted">{{ KINDS[f.kind] }}</td>
          <td class="num">{{ fmtNum(f.items) }} items</td>
          <td :class="f.lastError ? 'danger' : 'muted'">{{ f.lastError || (f.lastOK ? `updated ${fmtRelative(f.lastOK)}` : "not fetched yet") }}</td>
        </tr>
      </table>
    </div>
  </section>
</template>

<style scoped>
.signals {
  display: grid;
  gap: 12px;
}
.sg-head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: 8px 16px;
}
.sg-head h2 {
  margin: 0;
  font-size: 18px;
}
.sg-head p {
  margin: 4px 0 0;
  font-size: 13px;
}
.sg-queue {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--text-2);
}
.aiq-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--sev-high);
}
.sg-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
  align-items: center;
}
.sg-search {
  flex: 1 1 240px;
  width: auto;
  min-width: 0;
}
.sg-sort {
  flex: 0 0 auto;
  width: auto;
}
.sg-label {
  min-width: 70px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.chip.clear {
  border-style: dashed;
}
.sg-toggle {
  flex: 0 0 auto;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
}
.sg-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}
.chip {
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-2);
  border-radius: 999px;
  padding: 3px 10px;
  font: inherit;
  font-size: 12.5px;
  cursor: pointer;
}
.chip.on {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent-text);
}
.sg-empty {
  padding: 24px 4px;
}
.sg-list {
  list-style: none;
  margin: 0;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  overflow: hidden;
}
.sg-item + .sg-item {
  border-top: 1px solid var(--border);
}
.sg-item.ai-severe {
  box-shadow: inset 4px 0 0 var(--sev-critical);
}
.sg-item.ai-high {
  box-shadow: inset 4px 0 0 var(--sev-high);
}
.sg-item.fresh {
  background: color-mix(in srgb, var(--sev-high) 10%, var(--surface));
}
.sg-row {
  display: grid;
  grid-template-columns: 170px 1fr auto;
  gap: 12px;
  padding: 10px 14px;
  cursor: pointer;
}
.sg-row:hover {
  background: var(--surface-hover);
}
.sg-badges {
  display: flex;
  flex-wrap: wrap;
  align-content: flex-start;
  gap: 4px;
}
.sg-main {
  min-width: 0;
  display: grid;
  gap: 3px;
}
.sg-title {
  font-weight: 600;
  color: var(--text);
  text-decoration: none;
  overflow-wrap: anywhere;
}
.sg-title:hover {
  text-decoration: underline;
}
.sg-meta {
  font-size: 12px;
}
.sg-cves {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}
.cve-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11.5px;
  padding: 1px 6px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--surface-hover);
  color: var(--text);
  cursor: pointer;
}
.cve-chip.pending {
  cursor: default;
  color: var(--text-3);
  background: transparent;
}
.sg-summary {
  margin: 2px 0 0;
  font-size: 12.5px;
  color: var(--text-2);
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.sg-summary.full {
  display: block;
}
.sg-detail {
  padding: 0 14px 14px calc(170px + 26px);
  display: grid;
  gap: 8px;
  font-size: 13px;
}
.sg-text {
  margin: 0;
  color: var(--text-2);
  white-space: pre-line;
}
.sg-feeds {
  display: grid;
  gap: 8px;
  justify-items: start;
}
.sg-feed-table {
  font-size: 12.5px;
  border-collapse: collapse;
}
.sg-feed-table td {
  padding: 3px 12px 3px 0;
}
.danger {
  color: var(--danger);
}
@media (max-width: 720px) {
  .sg-row {
    grid-template-columns: 1fr auto;
  }
  .sg-badges {
    grid-column: 1 / -1;
  }
  .sg-detail {
    padding-left: 14px;
  }
}
</style>
