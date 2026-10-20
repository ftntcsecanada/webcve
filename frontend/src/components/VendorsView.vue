<script setup>
import { ref, watch, onMounted } from "vue";
import Icon from "./Icon.vue";
import { state, vendorRequest, setView, activeFilterCount } from "../lib/store.js";
import { fmtNum } from "../lib/format.js";
import { explain } from "../lib/glossary.js";

const data = ref(null);
const loading = ref(false);
const error = ref(null);
let inflight = null;
let timer = null;

async function load() {
  inflight?.abort();
  const ctrl = new AbortController();
  inflight = ctrl;
  loading.value = true;
  try {
    const res = await fetch("/api/vendors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(vendorRequest()),
      signal: ctrl.signal,
    });
    if (res.status === 503) {
      timer = setTimeout(load, 2000);
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data.value = await res.json();
    error.value = null;
  } catch (e) {
    if (e.name !== "AbortError") error.value = "Couldn't load the vendor comparison.";
  } finally {
    if (inflight === ctrl) loading.value = false;
  }
}

onMounted(load);
watch(
  () => [state.filters, state.vendor.sort, state.vendor.desc, state.vendor.min],
  () => {
    clearTimeout(timer);
    timer = setTimeout(load, 80);
  },
  { deep: true }
);
watch(
  () => state.vendor.query,
  () => {
    clearTimeout(timer);
    timer = setTimeout(load, 250);
  }
);

// Quick answers to common questions; each just sets the sort
const PRESETS = [
  ["kev", true, "Most exploited"],
  ["kevPct", true, "Highest exploited rate"],
  ["daysToKev", false, "Fastest to exploitation"],
  ["metasploit", true, "Most weaponized"],
  ["trend", true, "Fastest growing"],
  ["cves", true, "Most CVEs"],
];

const COLUMNS = [
  { key: "cves", label: "CVEs", term: "Vendor CVEs" },
  { key: "last12", label: "Last 12 mo", term: "Last 12 months" },
  { key: "avgScore", label: "Avg CVSS", term: "Avg CVSS" },
  { key: "critHighPct", label: "Crit/High", term: "Critical/High %" },
  { key: "kev", label: "KEV", term: "KEV count" },
  { key: "kevPct", label: "KEV rate", term: "KEV rate" },
  { key: "ransomware", label: "Ransomware", term: "Ransomware" },
  { key: "exploitPct", label: "Exploit rate", term: "Exploit rate" },
  { key: "metasploit", label: "Metasploit", term: "Metasploit" },
  { key: "epssHigh", label: "EPSS ≥10%", term: "EPSS ≥ 10%" },
  { key: "daysToKev", label: "Days to KEV", term: "Days to KEV" },
];

const MIN_OPTIONS = [1, 25, 100, 500];

function sortBy(key) {
  if (state.vendor.sort === key) state.vendor.desc = !state.vendor.desc;
  else {
    state.vendor.sort = key;
    // Faster exploitation is the interesting end for days-to-KEV
    state.vendor.desc = key !== "daysToKev" && key !== "name";
  }
}

function preset([key, desc]) {
  state.vendor.sort = key;
  state.vendor.desc = desc;
}

function openVendor(name) {
  state.filters.vendors = [name];
  setView("all");
}

function pct(v) {
  if (!v) return "0%";
  const p = v * 100;
  return p < 1 ? `${p.toFixed(1)}%` : `${Math.round(p)}%`;
}

function trendText(r) {
  if (!r.prev12 && !r.last12) return "";
  if (!r.prev12) return "new";
  const t = Math.round(r.trend * 100);
  return `${t > 0 ? "+" : ""}${t}%`;
}

function trendClass(r) {
  if (!r.prev12) return "";
  if (r.trend > 0.15) return "up";
  if (r.trend < -0.15) return "down";
  return "";
}

// Per-row sparkline of CVEs per year
function spark(years) {
  const W = 72, H = 20;
  const max = Math.max(1, ...years);
  const step = W / years.length;
  return years.map((n, i) => {
    const h = Math.max(n ? 1.5 : 0, (n / max) * H);
    return { x: i * step + 1, y: H - h, w: step - 2, h };
  });
}

// Column maxima for the inline bars
function colMax(key) {
  return Math.max(1e-9, ...(data.value?.vendors || []).map((r) => r[key] || 0));
}
</script>

<template>
  <section class="vendors">
    <div class="intro">
      <p>
        Compare vendors by how much is published about them and how often their flaws are exploited.
        <span class="muted">
          Counts follow product footprint and disclosure practice, so lean on the rates (KEV rate, exploit rate) and days to KEV
          when comparing vendors of different sizes.
          <template v-if="activeFilterCount()">Only CVEs matching your filters are counted.</template>
          <template v-else>Use the filters to narrow by year, severity or weakness; pick vendors in the Vendor filter to compare just those.</template>
        </span>
      </p>
    </div>

    <div class="controls">
      <div class="presets" role="group" aria-label="Sort presets">
        <button
          v-for="p in PRESETS"
          :key="p[0]"
          :class="{ on: state.vendor.sort === p[0] && state.vendor.desc === p[1] }"
          @click="preset(p)"
        >
          {{ p[2] }}
        </button>
      </div>
      <div class="right">
        <label class="search">
          <Icon name="search" :size="13" />
          <input v-model="state.vendor.query" class="input" placeholder="Find vendor" spellcheck="false" />
        </label>
        <div class="seg" role="group" aria-label="Minimum CVEs">
          <span v-tip="'Hide vendors with fewer CVEs than this. Rates for vendors with only a few CVEs are noisy.'" class="seg-label">Min CVEs</span>
          <button v-for="m in MIN_OPTIONS" :key="m" :class="{ on: state.vendor.min === m }" @click="state.vendor.min = m">{{ m }}</button>
        </div>
      </div>
    </div>

    <div v-if="error" class="error"><Icon name="alert" /> {{ error }}</div>

    <div class="table-card">
      <div class="meta-line">
        <span v-if="data">
          <b class="num">{{ fmtNum(data.total) }}</b> vendors
          <span class="muted">· {{ fmtNum(data.matched) }} CVEs counted · {{ data.tookMs.toFixed(0) }} ms</span>
          <span v-if="data.total > data.vendors.length" class="muted"> · showing top {{ data.vendors.length }}</span>
        </span>
        <span v-if="loading" class="spinner" />
      </div>
      <div class="scroll scroll-thin">
        <table :class="{ stale: loading }">
          <thead>
            <tr>
              <th class="c-vendor">
                <button :class="{ sorted: state.vendor.sort === 'name' }" @click="sortBy('name')">
                  Vendor <Icon v-if="state.vendor.sort === 'name'" :name="state.vendor.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
                </button>
              </th>
              <th v-for="c in COLUMNS" :key="c.key" class="num-col">
                <button v-tip="explain(c.term)" :class="{ sorted: state.vendor.sort === c.key }" @click="sortBy(c.key)">
                  {{ c.label }}
                  <Icon v-if="state.vendor.sort === c.key" :name="state.vendor.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
                </button>
              </th>
              <th class="c-cwe"><span v-tip="explain('Top weaknesses')" class="th-label">Top weaknesses</span></th>
            </tr>
          </thead>
          <tbody v-if="data">
            <tr v-for="r in data.vendors" :key="r.key">
              <td class="c-vendor">
                <button class="vname" :title="`Show ${r.name}'s CVEs`" @click="openVendor(r.name)">{{ r.name }}</button>
              </td>
              <td class="num-col">
                <div class="cell-cves">
                  <svg
                    v-tip="`CVEs per year, ${data.yearFrom}–${data.yearTo}: ${r.years.join(', ')}`"
                    class="yspark"
                    width="72"
                    height="20"
                    role="img"
                    :aria-label="`CVEs per year ${data.yearFrom} to ${data.yearTo}`"
                  >
                    <rect v-for="(b, i) in spark(r.years)" :key="i" :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="1" />
                  </svg>
                  <span class="num">{{ fmtNum(r.cves) }}</span>
                </div>
              </td>
              <td class="num-col num">
                {{ fmtNum(r.last12) }}
                <div class="sub" :class="trendClass(r)">{{ trendText(r) }}</div>
              </td>
              <td class="num-col num">{{ r.avgScore ? r.avgScore.toFixed(1) : "—" }}</td>
              <td class="num-col num">
                {{ pct(r.critHighPct) }}
                <span class="mini"><span :style="{ width: (r.critHighPct / colMax('critHighPct')) * 100 + '%' }" /></span>
              </td>
              <td class="num-col num" :class="{ zero: !r.kev }">{{ fmtNum(r.kev) }}</td>
              <td class="num-col num" :class="{ zero: !r.kev }">
                {{ pct(r.kevPct) }}
                <span class="mini kev"><span :style="{ width: (r.kevPct / colMax('kevPct')) * 100 + '%' }" /></span>
              </td>
              <td class="num-col num" :class="{ zero: !r.ransomware, danger: r.ransomware }">{{ fmtNum(r.ransomware) }}</td>
              <td class="num-col num">
                {{ pct(r.exploitPct) }}
                <span class="mini warn"><span :style="{ width: (r.exploitPct / colMax('exploitPct')) * 100 + '%' }" /></span>
              </td>
              <td class="num-col num" :class="{ zero: !r.metasploit }">{{ fmtNum(r.metasploit) }}</td>
              <td class="num-col num" :class="{ zero: !r.epssHigh }">{{ fmtNum(r.epssHigh) }}</td>
              <td class="num-col num" :class="{ zero: r.daysToKev < 0 }">
                <template v-if="r.daysToKev >= 0">{{ fmtNum(r.daysToKev) }}<span class="unit">d</span></template>
                <template v-else>—</template>
              </td>
              <td class="c-cwe">
                <button
                  v-for="w in r.topWeaknesses"
                  :key="w"
                  class="cwe mono"
                  :title="`Filter to ${w}`"
                  @click="state.filters.cwe = w"
                >
                  {{ w }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="data && !data.vendors.length" class="empty">
          No vendors with at least {{ state.vendor.min }} matching CVEs. Lower the minimum or clear some filters.
        </div>
        <div v-if="!data && !error" class="empty">Loading…</div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.intro p {
  margin: 0 0 14px;
  max-width: 900px;
  font-size: 13.5px;
  line-height: 1.55;
}
.controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 12px;
}
.presets {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.presets button {
  height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-2);
  font-size: 12.5px;
  font-weight: 500;
}
.presets button:hover {
  border-color: var(--border-strong);
  color: var(--text);
}
.presets button.on {
  background: var(--accent-soft);
  border-color: transparent;
  color: var(--accent-text);
  font-weight: 600;
}
.right {
  display: flex;
  align-items: center;
  gap: 10px;
}
.search {
  position: relative;
  display: flex;
  align-items: center;
}
.search .icon {
  position: absolute;
  left: 9px;
  color: var(--text-3);
}
.search .input {
  width: 180px;
  height: 28px;
  padding-left: 28px;
  font-size: 13px;
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
  cursor: help;
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
.error {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
  padding: 10px 14px;
  border-radius: var(--radius);
  background: var(--danger-soft);
  color: var(--danger);
}
.table-card {
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
}
.meta-line {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.spinner {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent);
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.scroll {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  transition: opacity 0.15s;
}
table.stale {
  opacity: 0.6;
}
th {
  position: sticky;
  top: 0;
  padding: 0 8px;
  height: 36px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  text-align: left;
  white-space: nowrap;
}
th button,
.th-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  height: 24px;
  padding: 0 6px;
  border: 0;
  border-radius: 5px;
  background: none;
  color: var(--text-3);
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
}
.th-label {
  cursor: help;
}
th button:hover {
  background: var(--surface-hover);
  color: var(--text);
}
th button.sorted {
  color: var(--text);
}
.num-col {
  text-align: right;
}
th.num-col button {
  margin-right: -6px;
}
td {
  padding: 8px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  vertical-align: middle;
}
tbody tr:hover td {
  background: var(--surface-hover);
}
.c-vendor {
  position: sticky;
  left: 0;
  z-index: 1;
  background: var(--surface);
  min-width: 170px;
  max-width: 240px;
  padding-left: 14px;
}
.vname {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 0;
  border: 0;
  background: none;
  font-weight: 600;
  text-align: left;
}
.vname:hover {
  color: var(--accent-text);
  text-decoration: underline;
}
.cell-cves {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
}
.yspark rect {
  fill: var(--border-strong);
}
tbody tr:hover .yspark rect {
  fill: var(--accent);
}
.sub {
  font-size: 11px;
  color: var(--text-3);
}
.sub.up {
  color: var(--danger);
}
.sub.down {
  color: var(--ok);
}
.mini {
  display: block;
  width: 56px;
  height: 3px;
  margin: 4px 0 0 auto;
  border-radius: 2px;
  background: var(--surface-hover);
  overflow: hidden;
}
.mini span {
  display: block;
  height: 100%;
  margin-left: auto;
  background: var(--text-3);
}
.mini.kev span {
  background: var(--kev);
}
.mini.warn span {
  background: var(--warn);
}
.zero {
  color: var(--text-3);
}
.danger {
  color: var(--danger);
  font-weight: 600;
}
.unit {
  margin-left: 1px;
  color: var(--text-3);
  font-size: 11px;
}
.c-cwe {
  white-space: nowrap;
}
.cwe {
  margin-right: 4px;
  padding: 1px 6px;
  border: 0;
  border-radius: 4px;
  background: var(--surface-hover);
  color: var(--text-2);
  font-size: 11px;
}
.cwe:hover {
  background: var(--accent-soft);
  color: var(--accent-text);
}
.empty {
  padding: 40px;
  text-align: center;
  color: var(--text-3);
}
@media (max-width: 720px) {
  .search .input {
    width: 140px;
  }
}
</style>
