<script setup>
import { ref, watch, onMounted, onBeforeUnmount } from "vue";
import Icon from "./Icon.vue";
import ImpactBadge from "./ImpactBadge.vue";
import { state, stats } from "../lib/store.js";
import { IMPACT_ELEVATED, fmtNum, fmtRelative, cleanName, summaryText } from "../lib/format.js";
import { explain } from "../lib/glossary.js";

// Critical CVEs the AI model rates high or severe for global impact, published or
// added to KEV in the last 30 days. Shown above the results so they can't be missed.
const emit = defineEmits(["open"]);

const WINDOW_DAYS = 30;
const LIMIT = 3;
const items = ref([]);
const total = ref(0);
const expanded = ref(false);
// Collapsed to its header line; remembered per browser
const COLLAPSE_KEY = "webcve.earlyWarning.collapsed";
const collapsed = ref(false);
try {
  collapsed.value = localStorage.getItem(COLLAPSE_KEY) === "1";
} catch {}
function toggleCollapsed() {
  collapsed.value = !collapsed.value;
  try {
    localStorage.setItem(COLLAPSE_KEY, collapsed.value ? "1" : "0");
  } catch {}
}

async function load() {
  const since = new Date(Date.now() - WINDOW_DAYS * 86400000).toISOString().slice(0, 10);
  const req = { aiImpact: IMPACT_ELEVATED, changedSince: since, sortBy: "datePublished", sortDesc: true, pageSize: 25 };
  try {
    const res = await fetch("/api/cves", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) });
    if (!res.ok) return;
    const d = await res.json();
    // Severe first, newest first within each rating
    const rank = (c) => (c.aiImpact === "severe" ? 0 : 1);
    items.value = (d.cves || []).sort((a, b) => rank(a) - rank(b));
    total.value = d.total;
  } catch {
    // Optional section: the table still shows ratings
  }
}

function showAll() {
  state.view = state.view === "vendors" ? "all" : state.view;
  state.filters.aiImpact = [...IMPACT_ELEVATED];
  state.filters.since = new Date(Date.now() - WINDOW_DAYS * 86400000).toISOString().slice(0, 10);
}

// Assessments finish in the background, so also check periodically
let timer;
onMounted(() => {
  load();
  timer = setInterval(load, 5 * 60 * 1000);
});
onBeforeUnmount(() => clearInterval(timer));
// New data (and new assessments) arrive with each dataset publish
watch(() => stats.value?.lastDataUpdate, load);
</script>

<template>
  <section v-if="items.length" class="early-warning" :class="{ severe: items[0].aiImpact === 'severe' }" aria-label="AI early warnings">
    <div class="ew-head">
      <span class="ew-title"><Icon name="alert" :size="16" /> Early warning</span>
      <span v-tip="explain('AI impact')" class="ew-sub" tabindex="0">
        {{ fmtNum(total) }} critical CVE{{ total === 1 ? "" : "s" }} rated <b>high or severe</b> global-impact risk by AI in the last {{ WINDOW_DAYS }} days
      </span>
      <span class="ew-actions">
        <button class="btn sm" @click="showAll">Show all</button>
        <button class="btn ghost sm" :aria-expanded="!collapsed" @click="toggleCollapsed">{{ collapsed ? "Expand" : "Collapse" }}</button>
      </span>
    </div>
    <ul v-if="!collapsed" class="ew-list">
      <li v-for="c in expanded ? items : items.slice(0, LIMIT)" :key="c.id">
        <button v-tip="c.aiSummary || ''" class="ew-item" @click="emit('open', c.id)">
          <ImpactBadge :rating="c.aiImpact" :confidence="c.aiConfidence" compact />
          <span class="ew-id mono">{{ c.id }}</span>
          <span class="ew-name">{{ summaryText(c) }}</span>
          <span class="ew-meta muted">
            <template v-if="cleanName(c.vendor)">{{ c.vendor }} · </template>{{ fmtRelative(c.datePublished) }}
          </span>
        </button>
      </li>
    </ul>
    <button v-if="!collapsed && items.length > LIMIT" class="btn ghost sm ew-more" @click="expanded = !expanded">
      {{ expanded ? "Show fewer" : `Show ${items.length - LIMIT} more` }}
    </button>
  </section>
</template>

<style scoped>
.early-warning {
  margin-bottom: 16px;
  padding: 8px 14px;
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--sev-high) 8%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--sev-high) 40%, transparent);
  box-shadow: inset 4px 0 0 var(--sev-high);
}
.early-warning.severe {
  background: color-mix(in srgb, var(--sev-critical) 9%, var(--surface));
  border-color: color-mix(in srgb, var(--sev-critical) 45%, transparent);
  box-shadow: inset 4px 0 0 var(--sev-critical);
}
.ew-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 12px;
}
.ew-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-weight: 750;
  font-size: 13px;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--sev-high);
}
.severe .ew-title {
  color: var(--sev-critical);
}
.ew-sub {
  font-size: 13px;
  color: var(--text-2);
}
.ew-actions {
  margin-left: auto;
  display: inline-flex;
  gap: 6px;
}
.ew-list {
  list-style: none;
  margin: 6px 0 0;
  padding: 0;
  display: grid;
  gap: 2px;
}
.ew-item {
  width: 100%;
  display: grid;
  grid-template-columns: auto auto 1fr auto;
  align-items: baseline;
  gap: 10px;
  padding: 4px 8px;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.ew-item:hover,
.ew-item:focus-visible {
  background: color-mix(in srgb, var(--surface) 70%, transparent);
}
.ew-id {
  font-size: 12.5px;
  font-weight: 600;
}
.ew-name {
  min-width: 0;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ew-meta {
  font-size: 12px;
  white-space: nowrap;
}
.ew-more {
  margin-top: 4px;
}
@media (max-width: 720px) {
  .ew-item {
    grid-template-columns: auto 1fr;
  }
  .ew-name {
    grid-column: 1 / -1;
  }
  .ew-meta {
    display: none;
  }
}
</style>
