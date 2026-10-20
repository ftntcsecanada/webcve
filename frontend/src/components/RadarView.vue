<script setup>
import { ref, watch, onMounted, computed } from "vue";
import Icon from "./Icon.vue";
import { state, radarRequest } from "../lib/store.js";
import { fmtDate, fmtRelative, fmtNum, fmtEpss, severityKey } from "../lib/format.js";
import { explain } from "../lib/glossary.js";

const emit = defineEmits(["open"]);

const data = ref(null);
const loading = ref(false);
const error = ref(null);
const typeFilter = ref(["kev", "exploit", "poc", "critical"]);
let inflight = null;
let timer = null;

async function load() {
  inflight?.abort();
  const ctrl = new AbortController();
  inflight = ctrl;
  loading.value = true;
  try {
    const res = await fetch("/api/radar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(radarRequest()),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data.value = await res.json();
    error.value = null;
  } catch (e) {
    if (e.name !== "AbortError") error.value = "Couldn't load recent activity.";
  } finally {
    if (inflight === ctrl) loading.value = false;
  }
}

onMounted(load);
watch(
  () => [state.filters.vendors, state.vendor.days],
  () => {
    clearTimeout(timer);
    timer = setTimeout(load, 80);
  },
  { deep: true }
);

const TYPES = [
  ["kev", "Added to KEV", "flame", "KEV"],
  ["exploit", "Exploit published", "bug", "Exploit-DB"],
  ["poc", "First GitHub PoC", "bug", "GitHub PoC"],
  ["critical", "Critical CVE", "alert", "CVSS"],
];
const TYPE_LABEL = Object.fromEntries(TYPES.map(([k, l]) => [k, l]));

const events = computed(() => (data.value?.events || []).filter((e) => typeFilter.value.includes(e.type)));

// Group by day for a timeline layout
const days = computed(() => {
  const out = [];
  for (const e of events.value) {
    const last = out[out.length - 1];
    if (last && last.date === e.date) last.events.push(e);
    else out.push({ date: e.date, events: [e] });
  }
  return out;
});

function toggle(t) {
  const i = typeFilter.value.indexOf(t);
  if (i >= 0) typeFilter.value.splice(i, 1);
  else typeFilter.value.push(t);
}

const maxKev = computed(() => Math.max(1, ...(data.value?.summary || []).map((s) => s.kev)));
</script>

<template>
  <section class="radar">
    <div class="controls">
      <div class="types" role="group" aria-label="Event types">
        <button
          v-for="[k, label, icon, term] in TYPES"
          :key="k"
          v-tip="explain(term)"
          :class="[k, { on: typeFilter.includes(k) }]"
          @click="toggle(k)"
        >
          <Icon :name="icon" :size="12" /> {{ label }}
          <span v-if="data" class="n num">{{ fmtNum((data.summary || []).reduce((a, s) => a + (s[k] || 0), 0)) }}</span>
        </button>
      </div>
      <div class="seg" role="group" aria-label="Time window">
        <span class="seg-label">Last</span>
        <button v-for="d in [30, 90, 365]" :key="d" :class="{ on: state.vendor.days === d }" @click="state.vendor.days = d">
          {{ d === 365 ? "12 mo" : `${d} days` }}
        </button>
      </div>
    </div>

    <p v-if="!state.filters.vendors.length" class="hint">
      <Icon name="alert" :size="13" /> Showing all vendors. Pick a peer group above, or vendors in the sidebar, to follow specific competitors.
    </p>
    <div v-if="error" class="error"><Icon name="alert" /> {{ error }}</div>

    <div class="layout">
      <!-- Per-vendor tally -->
      <aside v-if="data?.summary?.length" class="tally">
        <h4>By vendor</h4>
        <table>
          <thead>
            <tr>
              <th />
              <th v-tip="explain('KEV')">KEV</th>
              <th v-tip="'Exploit-DB exploits published in the window'">Expl.</th>
              <th v-tip="'CVEs whose first GitHub PoC appeared in the window'">PoC</th>
              <th v-tip="'Critical CVEs (CVSS 9+) published in the window'">Crit.</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in data.summary" :key="s.vendor">
              <td class="v">
                {{ s.vendor }}
                <span class="bar"><span :style="{ width: (s.kev / maxKev) * 100 + '%' }" /></span>
              </td>
              <td class="num" :class="{ zero: !s.kev }">{{ s.kev }}</td>
              <td class="num" :class="{ zero: !s.exploit }">{{ s.exploit }}</td>
              <td class="num" :class="{ zero: !s.poc }">{{ s.poc }}</td>
              <td class="num" :class="{ zero: !s.critical }">{{ s.critical }}</td>
            </tr>
          </tbody>
        </table>
      </aside>

      <!-- Timeline -->
      <div class="timeline" :class="{ stale: loading }">
        <div v-if="data && !events.length" class="empty">Nothing in this window for the selected vendors.</div>
        <div v-for="d in days" :key="d.date" class="day">
          <div class="day-head">
            <span class="d">{{ fmtDate(d.date) }}</span>
            <span class="muted">{{ fmtRelative(d.date) }}</span>
          </div>
          <ul>
            <li v-for="(e, i) in d.events" :key="e.cve + e.type + i" :class="e.type">
              <span class="type"><span class="dot" />{{ TYPE_LABEL[e.type] }}</span>
              <button class="ev" @click="emit('open', e.cve)">
                <span class="sev-pill sm" :class="severityKey(e.severity)">{{ e.score ? e.score.toFixed(1) : "—" }}</span>
                <span class="id mono">{{ e.cve }}</span>
                <span class="vendor">{{ e.vendor }}</span>
                <span class="title">{{ e.title }}</span>
                <span v-if="e.ransomware" v-tip="explain('Ransomware')" class="badge danger">Ransomware</span>
                <span v-if="e.epss >= 0.1" v-tip="explain('EPSS')" class="badge warn">EPSS {{ fmtEpss(e.epss) }}</span>
              </button>
              <div v-if="e.detail" class="detail">
                <a v-if="e.url" :href="e.url" target="_blank" rel="noopener noreferrer">{{ e.detail }}</a>
                <span v-else>{{ e.detail }}</span>
              </div>
            </li>
          </ul>
        </div>
        <div v-if="data && data.total > data.events.length" class="more muted">
          Showing the {{ data.events.length }} most recent of {{ fmtNum(data.total) }} events. Narrow the vendors or window to see the rest.
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 12px;
}
.types {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.types button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-3);
  font-size: 12.5px;
  font-weight: 500;
}
.types button.on {
  color: var(--text);
  border-color: var(--border-strong);
}
.types button.on.kev {
  background: var(--kev-soft);
  color: var(--kev-text);
  border-color: transparent;
}
.types button.on.exploit,
.types button.on.poc {
  background: var(--warn-soft);
  color: var(--warn);
  border-color: transparent;
}
.types button.on.critical {
  background: var(--danger-soft);
  color: var(--danger);
  border-color: transparent;
}
.n {
  font-size: 11px;
  font-weight: 650;
}
.seg {
  display: flex;
  align-items: center;
  padding: 2px;
  gap: 2px;
  border-radius: var(--radius-sm);
  background: var(--surface-hover);
}
.seg-label {
  padding: 0 6px;
  font-size: 12px;
  color: var(--text-3);
}
.seg button {
  height: 24px;
  padding: 0 8px;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--text-2);
  font-size: 12px;
}
.seg button.on {
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-sm), 0 0 0 1px var(--border);
}
.hint {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0 0 12px;
  font-size: 12.5px;
  color: var(--text-3);
}
.error {
  margin-bottom: 12px;
  padding: 10px 14px;
  border-radius: var(--radius);
  background: var(--danger-soft);
  color: var(--danger);
}
.layout {
  display: grid;
  grid-template-columns: minmax(240px, 300px) 1fr;
  gap: 16px;
  align-items: start;
}
.tally {
  position: sticky;
  top: 0;
  padding: 12px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
}
.tally h4 {
  margin: 0 0 8px;
  font-size: 11.5px;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-3);
}
.tally table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
.tally th {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--text-3);
  text-align: right;
  padding: 0 0 6px 6px;
  cursor: help;
}
.tally td {
  padding: 5px 0 5px 6px;
  border-top: 1px solid var(--border);
  text-align: right;
}
.tally td.v {
  text-align: left;
  padding-left: 0;
  font-weight: 500;
}
.tally .bar {
  display: block;
  height: 3px;
  margin-top: 3px;
  border-radius: 2px;
  background: var(--surface-hover);
  overflow: hidden;
}
.tally .bar span {
  display: block;
  height: 100%;
  background: var(--kev);
}
.zero {
  color: var(--text-3);
}
.timeline {
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  transition: opacity 0.15s;
}
.timeline.stale {
  opacity: 0.6;
}
.day + .day {
  border-top: 1px solid var(--border);
}
.day-head {
  display: flex;
  gap: 8px;
  align-items: baseline;
  padding: 10px 14px 4px;
  font-size: 12.5px;
}
.day-head .d {
  font-weight: 650;
}
.day ul {
  margin: 0;
  padding: 0 8px 8px;
  list-style: none;
}
.day li {
  display: grid;
  grid-template-columns: 130px 1fr;
  gap: 0 8px;
  padding: 4px 6px;
  border-radius: 6px;
}
.day li:hover {
  background: var(--surface-hover);
}
.type {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-2);
  grid-row: span 2;
  padding-top: 3px;
}
.type .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-3);
  flex-shrink: 0;
}
li.kev .dot {
  background: var(--kev);
}
li.exploit .dot,
li.poc .dot {
  background: var(--warn);
}
li.critical .dot {
  background: var(--danger);
}
.ev {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  padding: 0;
  border: 0;
  background: none;
  text-align: left;
}
.ev:hover .id {
  color: var(--accent-text);
  text-decoration: underline;
}
.sev-pill.sm {
  min-width: 32px;
  height: 18px;
  font-size: 11px;
}
.id {
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
}
.vendor {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-2);
  white-space: nowrap;
}
.title {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12.5px;
  color: var(--text-2);
}
.detail {
  font-size: 12px;
  color: var(--text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.empty,
.more {
  padding: 24px;
  text-align: center;
  color: var(--text-3);
  font-size: 13px;
}
@media (max-width: 900px) {
  .layout {
    grid-template-columns: 1fr;
  }
  .tally {
    position: static;
  }
  .day li {
    grid-template-columns: 1fr;
  }
  .type {
    grid-row: auto;
  }
  .vendor {
    display: none;
  }
}
</style>
