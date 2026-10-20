<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from "vue";
import Icon from "./components/Icon.vue";
import FilterPanel from "./components/FilterPanel.vue";
import ResultsTable from "./components/ResultsTable.vue";
import CveDrawer from "./components/CveDrawer.vue";
import BarChart from "./components/BarChart.vue";
import SourcesPanel from "./components/SourcesPanel.vue";
import VendorsView from "./components/VendorsView.vue";
import {
  state,
  results,
  stats,
  VIEWS,
  SORTS,
  setView,
  resetFilters,
  activeFilterCount,
  fetchResults,
  fetchStats,
  exportResults,
  readURL,
  startSync,
  saved,
  saveCurrentSearch,
} from "./lib/store.js";
import { SEVERITY_LABEL, ATTACK_VECTOR_LABEL, EXPLOIT_SOURCE_LABEL, fmtNum, fmtRelative, fmtDate, fmtEpss } from "./lib/format.js";
import { explain } from "./lib/glossary.js";

const f = state.filters;
const isKev = computed(() => state.view === "kev");
const isVendors = computed(() => state.view === "vendors");

// ---- Theme ----
function storageGet(k) {
  try {
    return localStorage.getItem(k);
  } catch {
    return null;
  }
}
function storageSet(k, v) {
  try {
    localStorage.setItem(k, v);
  } catch {
    // Private mode etc.; preference just won't persist
  }
}
const theme = ref(storageGet("webcve.theme") || "system");
watch(
  theme,
  (t) => {
    if (t === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    storageSet("webcve.theme", t);
  },
  { immediate: true }
);
function cycleTheme() {
  theme.value = { system: "light", light: "dark", dark: "system" }[theme.value];
}
const themeIcon = computed(() => ({ system: "monitor", light: "sun", dark: "moon" })[theme.value]);

const showChart = ref(storageGet("webcve.chart") !== "0");
watch(showChart, (v) => storageSet("webcve.chart", v ? "1" : "0"));

const filtersOpen = ref(false);
const showHelp = ref(false);
const showSources = ref(new URLSearchParams(location.search).has("sources"));

// ---- Search ----
const searchEl = ref(null);
const cveIdPattern = /^\s*(cve-\d{4}-\d{4,})\s*$/i;
const directId = computed(() => f.q.match(cveIdPattern)?.[1].toUpperCase() ?? null);

function onSearchKey(e) {
  if (e.key === "Enter" && directId.value) {
    openCve(directId.value);
  } else if (e.key === "Escape") {
    if (f.q) f.q = "";
    else e.target.blur();
  } else if (e.key === "ArrowDown") {
    e.preventDefault();
    e.target.blur();
    cursor.value = 0;
  }
}

// ---- Selection / drawer ----
const cursor = ref(-1);

function openCve(id) {
  state.selectedId = id;
}
function closeCve() {
  state.selectedId = null;
}

const selectedIndex = computed(() => results.cves.findIndex((c) => c.id === state.selectedId));

function step(delta) {
  const n = results.cves.length;
  if (!n) return;
  const from = state.selectedId && selectedIndex.value >= 0 ? selectedIndex.value : cursor.value;
  const next = Math.max(0, Math.min(n - 1, (from < 0 ? -1 : from) + delta));
  cursor.value = next;
  if (state.selectedId) openCve(results.cves[next].id);
}

watch(
  () => results.cves,
  () => {
    cursor.value = Math.min(cursor.value, results.cves.length - 1);
  }
);

// ---- Pagination ----
const rangeText = computed(() => {
  if (!results.total) return "0";
  const start = (state.page - 1) * state.pageSize + 1;
  const end = Math.min(results.total, start + results.cves.length - 1);
  return `${fmtNum(start)}–${fmtNum(end)}`;
});
function goPage(p) {
  const next = Math.max(1, Math.min(results.totalPages || 1, p));
  if (next !== state.page) {
    state.page = next;
    cursor.value = 0;
    document.querySelector(".results-scroll")?.scrollTo({ top: 0 });
  }
}

// ---- Keyboard ----
function onKey(e) {
  const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName);
  if (e.key === "/" && !typing) {
    e.preventDefault();
    searchEl.value?.focus();
    searchEl.value?.select();
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  switch (e.key) {
    case "j":
    case "ArrowDown":
      e.preventDefault();
      step(1);
      break;
    case "k":
    case "ArrowUp":
      e.preventDefault();
      step(-1);
      break;
    case "Enter":
    case "o":
      if (cursor.value >= 0 && results.cves[cursor.value]) openCve(results.cves[cursor.value].id);
      break;
    case "Escape":
      if (showSources.value) showSources.value = false;
      else if (showHelp.value) showHelp.value = false;
      else if (state.selectedId) closeCve();
      else if (filtersOpen.value) filtersOpen.value = false;
      break;
    case "ArrowRight":
    case "]":
      goPage(state.page + 1);
      break;
    case "ArrowLeft":
    case "[":
      goPage(state.page - 1);
      break;
    case "1":
      setView("all");
      break;
    case "2":
      setView("kev");
      break;
    case "3":
      setView("vendors");
      break;
    case "f":
      filtersOpen.value = !filtersOpen.value;
      break;
    case "?":
      showHelp.value = !showHelp.value;
      break;
  }
}

// ---- Active filter chips ----
const chips = computed(() => {
  const out = [];
  if (f.q) out.push({ key: "q", label: `“${f.q}”`, remove: () => (f.q = "") });
  if (f.kevOnly && !isKev.value) out.push({ key: "kev", label: "Known exploited", cls: "kev", remove: () => (f.kevOnly = false) });
  if (f.ransomware) out.push({ key: "rw", label: "Ransomware", remove: () => (f.ransomware = false) });
  if (f.kevDays) out.push({ key: "kd", label: `Added ≤ ${f.kevDays}d`, remove: () => (f.kevDays = 0) });
  if (f.kevDue)
    out.push({ key: "due", label: f.kevDue === "overdue" ? "Overdue" : `Due ≤ ${f.kevDue}d`, remove: () => (f.kevDue = "") });
  if (f.exploit) out.push({ key: "x", label: "Exploit evidence", remove: () => (f.exploit = false) });
  f.exploitSources.forEach((k) =>
    out.push({ key: `xs-${k}`, label: EXPLOIT_SOURCE_LABEL[k] || k, remove: () => f.exploitSources.splice(f.exploitSources.indexOf(k), 1) })
  );
  if (f.epssMin != null) out.push({ key: "epss", label: `EPSS ≥ ${fmtEpss(f.epssMin)}`, remove: () => (f.epssMin = null) });
  if (f.since) out.push({ key: "since", label: `New since ${fmtDate(f.since)}`, cls: "accent", remove: () => (f.since = "") });
  f.severities.forEach((s) =>
    out.push({ key: `sev-${s}`, label: SEVERITY_LABEL[s], dot: s, remove: () => f.severities.splice(f.severities.indexOf(s), 1) })
  );
  f.attackVectors.forEach((a) =>
    out.push({ key: `av-${a}`, label: `${ATTACK_VECTOR_LABEL[a]} vector`, remove: () => f.attackVectors.splice(f.attackVectors.indexOf(a), 1) })
  );
  if (f.scoreMin != null || f.scoreMax != null)
    out.push({
      key: "score",
      label: f.scoreMax == null ? `CVSS ≥ ${f.scoreMin}` : `CVSS ${f.scoreMin ?? 0}–${f.scoreMax}`,
      remove: () => ((f.scoreMin = null), (f.scoreMax = null)),
    });
  if (f.yearFrom || f.yearTo)
    out.push({
      key: "year",
      label: f.yearFrom === f.yearTo ? `${f.yearFrom}` : `${f.yearFrom || "…"}–${f.yearTo || "now"}`,
      remove: () => ((f.yearFrom = null), (f.yearTo = null)),
    });
  f.vendors.forEach((v) => out.push({ key: `v-${v}`, label: v, prefix: "Vendor", remove: () => f.vendors.splice(f.vendors.indexOf(v), 1) }));
  f.products.forEach((p) => out.push({ key: `p-${p}`, label: p, prefix: "Product", remove: () => f.products.splice(f.products.indexOf(p), 1) }));
  if (f.cwe) out.push({ key: "cwe", label: f.cwe, prefix: "CWE", remove: () => (f.cwe = "") });
  return out;
});

// ---- Charts ----
const SEV_STACK = [
  ["CRITICAL", "var(--sev-critical)"],
  ["HIGH", "var(--sev-high)"],
  ["MEDIUM", "var(--sev-medium)"],
  ["LOW", "var(--sev-low)"],
  ["NONE", "var(--sev-none)"],
];

const yearBars = computed(() =>
  results.yearCounts
    .filter((y) => y.year >= 1999)
    .map((y) => ({
      key: y.year,
      label: String(y.year),
      tick: `'${String(y.year).slice(-2)}`,
      total: y.count,
      segments: SEV_STACK.map(([k, color]) => ({ key: k, label: SEVERITY_LABEL[k], value: y.severity?.[k] || 0, color })),
    }))
);

const monthFmt = new Intl.DateTimeFormat(undefined, { month: "short", year: "numeric" });
const kevBars = computed(() =>
  results.kevMonths.map((m, i) => {
    const [y, mo] = m.month.split("-").map(Number);
    const d = new Date(y, mo - 1, 1);
    return {
      key: i,
      label: monthFmt.format(d),
      tick: mo === 1 || i === 0 ? String(y) : d.toLocaleString(undefined, { month: "narrow" }),
      total: m.count,
      segments: [{ key: "kev", label: "Added", value: m.count, color: "var(--kev)" }],
    };
  })
);

const yearSelection = computed(() => (f.yearFrom || f.yearTo ? [f.yearFrom, f.yearTo] : null));
function onYearSelect(range) {
  f.yearFrom = range ? range[0] : null;
  f.yearTo = range ? range[1] : null;
}

const freshness = computed(() => {
  const d = stats.value?.lastDataUpdate;
  if (!d) return null;
  const days = (Date.now() - new Date(d)) / 86400000;
  const s = stats.value.sources || {};
  const fmt = (t) => (t && !t.startsWith("0001") ? new Date(t).toLocaleString() : "never");
  const title = [
    `CVE records: ${fmt(s.cve)}${s.cveDelta ? ` (${s.cveDelta})` : ""}`,
    `KEV catalog: ${fmt(s.kev)}`,
    `EPSS scores: ${fmt(s.epss)}${stats.value.epssDate ? ` (scores of ${stats.value.epssDate})` : ""}`,
    stats.value.nextUpdateIn ? `Next check in ${stats.value.nextUpdateIn}` : "",
  ]
    .filter(Boolean)
    .join("\n");
  const errors = stats.value.sourceErrors || [];
  return {
    text: errors.length ? `${errors.length} source${errors.length > 1 ? "s" : ""} failing` : `updated ${fmtRelative(d)}`,
    stale: days > 2,
    failing: errors.length > 0,
    title: (errors.length ? `Failing: ${errors.join(", ")}\n\n` : "") + title + "\n\nClick for all data sources",
  };
});

// ---- Export ----
const exporting = ref(false);
const exportOpen = ref(false);
async function doExport(format) {
  exportOpen.value = false;
  exporting.value = true;
  try {
    await exportResults(format);
  } catch {
    results.error = "Export failed.";
  } finally {
    exporting.value = false;
  }
}

// ---- Save search ----
const saveOpen = ref(false);
const saveName = ref("");
const saveInput = ref(null);
function startSave() {
  saveName.value = chips.value.map((c) => (c.prefix ? `${c.label}` : c.label)).join(" · ").slice(0, 60) || (isKev.value ? "Known exploited" : "All CVEs");
  saveOpen.value = true;
  setTimeout(() => saveInput.value?.select(), 0);
}
function confirmSave() {
  if (!saveName.value.trim()) return;
  saveCurrentSearch(saveName.value.trim());
  saveOpen.value = false;
}
const activeSaved = computed(() => (saved.active ? saved.list.find((s) => s.id === saved.active.id) : null));

const statusText = {
  starting: "Starting up…",
  downloading: "Downloading the CVE and KEV databases (first run can take several minutes)…",
  loading: "Loading the CVE database…",
  error: "The server couldn't load its data. Check the server logs.",
};

onMounted(() => {
  readURL();
  startSync();
  fetchResults();
  fetchStats();
  window.addEventListener("keydown", onKey);
  window.addEventListener("mousedown", closePopovers);
});
onBeforeUnmount(() => {
  window.removeEventListener("keydown", onKey);
  window.removeEventListener("mousedown", closePopovers);
});

function closePopovers(e) {
  if (!e.target.closest?.(".popover-anchor")) {
    exportOpen.value = false;
    saveOpen.value = false;
  }
  if (!e.target.closest?.(".help, .help-toggle")) showHelp.value = false;
}
</script>

<template>
  <div class="app" :class="{ 'drawer-open': !!state.selectedId }">
    <!-- Top bar -->
    <header class="topbar">
      <div class="brand">
        <span class="logo"><Icon name="shield" :size="16" /></span>
        <span class="brand-name">webcve</span>
      </div>

      <div class="search">
        <Icon name="search" :size="15" class="search-icon" />
        <input
          ref="searchEl"
          v-model="f.q"
          class="search-input"
          type="search"
          placeholder="Search CVEs — try log4j, vendor:fortinet sev:critical, &quot;remote code&quot;"
          aria-label="Search"
          spellcheck="false"
          @keydown="onSearchKey"
        />
        <span v-if="directId" class="search-hint">
          <span class="kbd">↵</span> open {{ directId }}
        </span>
        <span v-else-if="!f.q" class="kbd search-kbd">/</span>
        <button v-else class="btn ghost sm icon search-clear" aria-label="Clear search" @click="f.q = ''"><Icon name="x" :size="14" /></button>
      </div>

      <div class="top-right">
        <div v-if="stats" class="top-stats">
          <span><b class="num">{{ fmtNum(stats.totalCves) }}</b> <Term k="CVE">CVEs</Term></span>
          <button
            v-if="freshness"
            class="fresh"
            :class="{ stale: freshness.stale, failing: freshness.failing }"
            :title="freshness.title"
            @click="showSources = true"
          >
            <span class="fresh-dot" />{{ freshness.stale && !freshness.failing ? "Stale · " : "" }}{{ freshness.text }}
          </button>
        </div>
        <button class="btn ghost icon help-toggle" title="Keyboard shortcuts and search syntax (?)" @click="showHelp = !showHelp"><Icon name="keyboard" /></button>
        <button class="btn ghost icon" :title="`Theme: ${theme}`" @click="cycleTheme"><Icon :name="themeIcon" /></button>
      </div>
    </header>

    <div class="body">
      <div v-if="filtersOpen" class="scrim" @click="filtersOpen = false" />
      <FilterPanel class="sidebar" :class="{ open: filtersOpen }" @close="filtersOpen = false" />

      <main class="main results-scroll scroll-thin">
        <!-- View tabs -->
        <div class="tabs-row">
          <nav class="tabs" role="tablist">
            <button
              v-for="(v, key) in VIEWS"
              :key="key"
              role="tab"
              :aria-selected="state.view === key"
              :class="{ on: state.view === key, kev: key === 'kev' }"
              @click="setView(key)"
            >
              <Icon :name="key === 'kev' ? 'flame' : key === 'vendors' ? 'package' : 'list'" :size="14" />
              <span v-if="key === 'kev'" v-tip="explain('KEV')" class="tab-long">{{ v.label }}</span>
              <span v-else class="tab-long">{{ v.label }}</span>
              <span class="tab-short">{{ v.short }}</span>
              <span v-if="stats && key !== 'vendors'" class="tab-count num">{{ fmtNum(key === "kev" ? stats.totalKev : stats.totalCves) }}</span>
            </button>
          </nav>
          <button class="btn filters-btn" @click="filtersOpen = true">
            <Icon name="sliders" :size="14" /> Filters
            <span v-if="activeFilterCount()" class="filters-count">{{ activeFilterCount() }}</span>
          </button>
        </div>

        <!-- KEV overview tiles -->
        <section v-if="isKev && stats" class="tiles">
          <div class="tile">
            <div class="tile-label"><Term k="KEV">In catalog</Term></div>
            <div class="tile-value num">{{ fmtNum(stats.totalKev) }}</div>
            <div class="tile-sub">Released {{ fmtDate(stats.kevCatalogDate?.slice(0, 10)) }}</div>
          </div>
          <button class="tile clickable" :class="{ on: f.kevDays === 30 }" @click="f.kevDays = f.kevDays === 30 ? 0 : 30">
            <div class="tile-label">Added last 30 days</div>
            <div class="tile-value num">{{ fmtNum(stats.kevLast30Days) }}</div>
            <div class="tile-sub">{{ f.kevDays === 30 ? "Filtering · click to clear" : "Click to filter" }}</div>
          </button>
          <button class="tile clickable" :class="{ on: f.kevDue === '30' }" @click="f.kevDue = f.kevDue === '30' ? '' : '30'">
            <div class="tile-label"><Term k="Due date">Due next 30 days</Term></div>
            <div class="tile-value num">{{ fmtNum(stats.kevDueNext30) }}</div>
            <div class="tile-sub">{{ f.kevDue === "30" ? "Filtering · click to clear" : "Click to filter" }}</div>
          </button>
          <button class="tile clickable" :class="{ on: f.ransomware }" @click="f.ransomware = !f.ransomware">
            <div class="tile-label"><Term k="Ransomware">Ransomware-linked</Term></div>
            <div class="tile-value num danger">{{ fmtNum(stats.kevRansomware) }}</div>
            <div class="tile-sub">{{ f.ransomware ? "Filtering · click to clear" : "Click to filter" }}</div>
          </button>
          <div class="tile wide">
            <div class="tile-label">Added per month</div>
            <BarChart :bars="kevBars" :height="64" unit="added" />
          </div>
        </section>

        <!-- Year chart -->
        <section v-else-if="!isKev && !isVendors" class="chart-card" :class="{ collapsed: !showChart }">
          <div class="chart-head">
            <span class="chart-title">CVEs by publication year</span>
            <div v-if="showChart" class="legend">
              <span v-for="[k, c] in SEV_STACK" :key="k" class="legend-item">
                <span class="swatch" :style="{ background: c }" />{{ SEVERITY_LABEL[k] }}
              </span>
            </div>
            <button class="btn ghost sm" @click="showChart = !showChart">{{ showChart ? "Hide" : "Show" }}</button>
          </div>
          <BarChart
            v-if="showChart && yearBars.length"
            :bars="yearBars"
            :height="140"
            selectable
            :selection="yearSelection"
            @select="onYearSelect"
          />
        </section>

        <!-- Results header -->
        <div v-if="!isVendors" class="results-head">
          <div class="count-line">
            <span class="total num">{{ fmtNum(results.total) }}</span>
            <span class="muted">{{ isKev ? "known exploited" : "vulnerabilities" }}</span>
            <span v-if="results.loaded" class="took muted num">· {{ results.tookMs.toFixed(0) }} ms</span>
            <span v-if="results.loading" class="spinner" aria-label="Loading" />
          </div>
          <div class="head-actions">
            <label class="sort">
              <span class="muted">Sort</span>
              <select v-model="state.sort.by" class="select">
                <option v-for="[k, label] in SORTS[state.view]" :key="k" :value="k">{{ label }}</option>
                <option v-if="!SORTS[state.view].some(([k]) => k === state.sort.by)" :value="state.sort.by">{{ state.sort.by }}</option>
              </select>
              <button class="btn sm icon" :title="state.sort.desc ? 'Descending' : 'Ascending'" @click="state.sort.desc = !state.sort.desc">
                <Icon :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="13" />
              </button>
            </label>
            <div class="popover-anchor">
              <button class="btn sm" title="Save this search to the sidebar and track new matches" @click="saveOpen ? (saveOpen = false) : startSave()">
                <Icon name="check" :size="13" /> Save search
              </button>
              <form v-if="saveOpen" class="popover" @submit.prevent="confirmSave" @keydown.esc.stop="saveOpen = false">
                <label class="pop-label" for="save-name">Name</label>
                <input id="save-name" ref="saveInput" v-model="saveName" class="input" maxlength="80" autocomplete="off" data-1p-ignore data-lpignore="true" />
                <p class="pop-hint">Saved in this browser. The sidebar shows how many CVEs are new each time you come back.</p>
                <div class="pop-actions">
                  <button type="button" class="btn ghost sm" @click="saveOpen = false">Cancel</button>
                  <button type="submit" class="btn sm primary">Save</button>
                </div>
              </form>
            </div>
            <div class="popover-anchor">
              <button class="btn sm" :disabled="exporting || !results.total" :aria-expanded="exportOpen" @click="exportOpen = !exportOpen">
                <Icon name="download" :size="13" /> {{ exporting ? "Exporting…" : "Export" }} <Icon name="chevronDown" :size="12" />
              </button>
              <div v-if="exportOpen" class="popover menu" role="menu" @keydown.esc.stop="exportOpen = false">
                <button role="menuitem" @click="doExport('xlsx')">Excel (.xlsx)</button>
                <button role="menuitem" @click="doExport('csv')">CSV</button>
                <button role="menuitem" @click="doExport('json')">JSON (full records)</button>
                <div class="pop-hint">Up to 10,000 rows, in the current sort order.</div>
              </div>
            </div>
          </div>
        </div>

        <div v-if="chips.length" class="chips">
          <span v-for="c in chips" :key="c.key" class="fchip" :class="c.cls">
            <span v-if="c.dot" class="sev-dot" :class="c.dot" />
            <span v-if="c.prefix" class="fchip-prefix">{{ c.prefix }}</span>
            <span class="fchip-label">{{ c.label }}</span>
            <button :aria-label="`Remove ${c.label}`" @click="c.remove()"><Icon name="x" :size="12" /></button>
          </span>
          <button class="btn ghost sm" @click="resetFilters">Clear all</button>
        </div>

        <VendorsView v-if="isVendors" />

        <div v-if="activeSaved && saved.active.newCount && !f.since && !isVendors" class="new-banner">
          <b class="num">{{ fmtNum(saved.active.newCount) }}</b> new in “{{ activeSaved.name }}” since {{ fmtDate(saved.active.previousSeen) }}
          <button class="btn sm" @click="f.since = saved.active.previousSeen">Show only new</button>
        </div>

        <div v-if="results.error" class="error">
          <Icon name="alert" /> {{ results.error }}
          <button class="btn sm" @click="fetchResults">Retry</button>
        </div>

        <!-- Table -->
        <div v-if="!isVendors" class="table-card">
          <div v-if="results.warming && !results.loaded" class="warming">
            <span class="spinner big" />
            <h3>{{ statusText[results.warming] || "Loading…" }}</h3>
            <p class="muted">The page will fill in automatically when the data is ready.</p>
          </div>
          <ResultsTable v-else-if="results.cves.length" v-model:cursor="cursor" @open="openCve" />
          <div v-else-if="results.loaded && !results.loading" class="empty">
            <Icon name="search" :size="28" />
            <h3>No matching vulnerabilities</h3>
            <p class="muted">Try removing a filter or broadening your search.</p>
            <div class="empty-actions">
              <button v-if="chips.length" class="btn" @click="chips[chips.length - 1].remove()">Remove “{{ chips[chips.length - 1].label }}”</button>
              <button v-if="chips.length > 1" class="btn ghost" @click="resetFilters">Clear all filters</button>
            </div>
          </div>
          <div v-else class="table-skeleton">
            <div v-for="i in 10" :key="i" class="sk-row"><span class="sk a" /><span class="sk b" /><span class="sk c" /></div>
          </div>

          <footer v-if="results.total" class="pager">
            <span class="muted num">{{ rangeText }} of {{ fmtNum(results.total) }}</span>
            <span class="spacer" />
            <select v-model.number="state.pageSize" class="select sm" aria-label="Rows per page">
              <option v-for="n in [25, 50, 100, 200]" :key="n" :value="n">{{ n }} / page</option>
            </select>
            <button class="btn sm icon" :disabled="state.page <= 1" title="Previous page ([)" @click="goPage(state.page - 1)"><Icon name="chevronLeft" /></button>
            <span class="page num">Page {{ fmtNum(state.page) }} of {{ fmtNum(results.totalPages) }}</span>
            <button class="btn sm icon" :disabled="state.page >= results.totalPages" title="Next page (])" @click="goPage(state.page + 1)"><Icon name="chevronRight" /></button>
          </footer>
        </div>
      </main>
    </div>

    <!-- Drawer -->
    <Transition name="drawer">
      <div v-if="state.selectedId" class="drawer-wrap">
        <div class="drawer-scrim" @click="closeCve" />
        <CveDrawer
          class="drawer-panel"
          :id="state.selectedId"
          :has-prev="selectedIndex > 0"
          :has-next="selectedIndex >= 0 && selectedIndex < results.cves.length - 1"
          @close="closeCve"
          @prev="step(-1)"
          @next="step(1)"
        />
      </div>
    </Transition>

    <SourcesPanel v-if="showSources" @close="showSources = false" />

    <!-- Shortcuts -->
    <Transition name="fade">
      <div v-if="showHelp" class="help" role="dialog" aria-label="Keyboard shortcuts">
        <div class="help-head">
          <b>Keyboard shortcuts</b>
          <button class="btn ghost sm icon" aria-label="Close" @click="showHelp = false"><Icon name="x" /></button>
        </div>
        <dl>
          <div><dt><span class="kbd">/</span></dt><dd>Search</dd></div>
          <div><dt><span class="kbd">j</span> <span class="kbd">k</span></dt><dd>Next / previous row</dd></div>
          <div><dt><span class="kbd">↵</span></dt><dd>Open details</dd></div>
          <div><dt><span class="kbd">Esc</span></dt><dd>Close panel</dd></div>
          <div><dt><span class="kbd">[</span> <span class="kbd">]</span></dt><dd>Previous / next page</dd></div>
          <div><dt><span class="kbd">1</span> <span class="kbd">2</span> <span class="kbd">3</span></dt><dd>All CVEs / KEV / Vendors</dd></div>
          <div><dt><span class="kbd">f</span></dt><dd>Toggle filters (narrow screens)</dd></div>
        </dl>
        <button class="btn sm sources-link" @click="(showSources = true), (showHelp = false)">
          <Icon name="list" :size="13" /> Data sources and update status
        </button>
        <div class="help-head syntax-head"><b>Search syntax</b></div>
        <dl class="syntax">
          <div><dt><code>log4j rce</code></dt><dd>All words, any order</dd></div>
          <div><dt><code>"remote code"</code></dt><dd>Exact phrase</dd></div>
          <div><dt><code>vendor:fortinet</code></dt><dd>Vendor contains</dd></div>
          <div><dt><code>product:"pan-os"</code></dt><dd>Product contains</dd></div>
          <div><dt><code>cwe:79</code></dt><dd>Weakness</dd></div>
          <div><dt><code>sev:critical</code></dt><dd>Severity</dd></div>
          <div><dt><code>kev:yes</code> <code>exploit:yes</code></dt><dd>Exploited / PoC</dd></div>
          <div><dt><code>epss:>10%</code></dt><dd>EPSS minimum</dd></div>
          <div><dt><code>year:2024</code> <code>av:network</code></dt><dd>Year, attack vector</dd></div>
        </dl>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100vh;
  height: 100dvh;
}

/* ---- Top bar ---- */
.topbar {
  display: flex;
  align-items: center;
  gap: 16px;
  height: 56px;
  padding: 0 16px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  z-index: 10;
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 248px;
  flex-shrink: 0;
}
.logo {
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border-radius: 7px;
  background: var(--text);
  color: var(--surface);
}
.brand-name {
  font-weight: 700;
  font-size: 15px;
  letter-spacing: -0.01em;
}
.search {
  position: relative;
  flex: 1;
  max-width: 640px;
  display: flex;
  align-items: center;
}
.search-icon {
  position: absolute;
  left: 11px;
  color: var(--text-3);
  pointer-events: none;
}
.search-input {
  width: 100%;
  height: 36px;
  padding: 0 120px 0 34px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface-2);
  font-size: 14px;
}
.search-input::-webkit-search-cancel-button {
  display: none;
}
.search-input:hover {
  border-color: var(--border-strong);
}
.search-input:focus {
  outline: none;
  border-color: var(--accent);
  background: var(--surface);
  box-shadow: 0 0 0 3px var(--focus);
}
.search-kbd,
.search-hint,
.search-clear {
  position: absolute;
  right: 8px;
}
.search-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--accent-text);
  font-weight: 500;
}
.top-right {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-left: auto;
}
.top-stats {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-right: 8px;
  font-size: 12.5px;
  color: var(--text-2);
  white-space: nowrap;
}
.fresh {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 8px;
  margin: -3px -8px;
  border: 0;
  border-radius: 6px;
  background: none;
  color: inherit;
  font-size: inherit;
}
.fresh:hover {
  background: var(--surface-hover);
}
.fresh.failing {
  color: var(--danger);
  font-weight: 600;
}
.fresh.failing .fresh-dot {
  background: var(--danger);
}
.sources-link {
  margin-top: 10px;
}
.fresh-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--ok);
}
.fresh.stale {
  color: var(--warn);
}
.fresh.stale .fresh-dot {
  background: var(--warn);
}

/* ---- Body ---- */
.body {
  flex: 1;
  display: flex;
  min-height: 0;
}
.sidebar {
  width: 280px;
  flex-shrink: 0;
  background: var(--surface);
  border-right: 1px solid var(--border);
}
.main {
  flex: 1;
  min-width: 0;
  overflow-y: auto;
  padding: 16px 24px 40px;
}

.tabs-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}
.tabs {
  display: flex;
  gap: 4px;
  padding: 3px;
  border-radius: var(--radius);
  background: var(--surface-hover);
}
.tabs button {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 32px;
  padding: 0 12px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-2);
  font-weight: 550;
}
.tabs button:hover {
  color: var(--text);
}
.tabs button.on {
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-sm), 0 0 0 1px var(--border);
}
.tabs button.on.kev {
  color: var(--kev-text);
}
.tab-short {
  display: none;
}
.tab-count {
  font-size: 11.5px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 999px;
  background: var(--surface-hover);
  color: var(--text-3);
}
.tabs button.on.kev .tab-count {
  background: var(--kev-soft);
  color: var(--kev-text);
}
.filters-btn {
  display: none;
  margin-left: auto;
}
.filters-count {
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 999px;
  background: var(--accent);
  color: #fff;
  font-size: 11px;
  line-height: 18px;
  text-align: center;
}

/* KEV tiles */
.tiles {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr)) minmax(260px, 2fr);
  gap: 10px;
  margin-bottom: 16px;
}
.tile {
  display: flex;
  flex-direction: column;
  padding: 12px 14px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  text-align: left;
  min-width: 0;
}
.tile.clickable:hover {
  border-color: var(--border-strong);
  background: var(--surface-2);
}
.tile.on {
  border-color: var(--kev);
  box-shadow: 0 0 0 1px var(--kev);
}
.tile-label {
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-3);
}
.tile-value {
  margin-top: 4px;
  font-size: 26px;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.1;
}
.tile-value.danger {
  color: var(--danger);
}
.tile-sub {
  margin-top: auto;
  padding-top: 4px;
  font-size: 12px;
  color: var(--text-3);
}
.tile.wide {
  gap: 4px;
}

/* Year chart */
.chart-card {
  padding: 12px 16px 8px;
  margin-bottom: 16px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
}
.chart-card.collapsed {
  padding-bottom: 12px;
}
.chart-head {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 8px;
}
.chart-card.collapsed .chart-head {
  margin-bottom: 0;
}
.chart-title {
  font-weight: 600;
  font-size: 13px;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  flex: 1;
}
.chart-card.collapsed .chart-title {
  flex: 1;
}
.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--text-2);
}
.swatch {
  width: 9px;
  height: 9px;
  border-radius: 3px;
}

/* Results header */
.results-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 10px;
}
.count-line {
  display: flex;
  align-items: baseline;
  gap: 6px;
  flex: 1;
}
.total {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.took {
  font-size: 12px;
}
.spinner {
  align-self: center;
  width: 13px;
  height: 13px;
  border-radius: 50%;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent);
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
.head-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  align-items: center;
  gap: 8px;
}
.sort {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
}
.select {
  height: 26px;
  padding: 0 6px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 12.5px;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-bottom: 12px;
}
.fchip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 320px;
  height: 26px;
  padding-left: 9px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 12.5px;
}
.fchip.kev {
  background: var(--kev-soft);
  border-color: transparent;
  color: var(--kev-text);
}
.fchip-prefix {
  color: var(--text-3);
}
.fchip-label {
  font-weight: 550;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fchip button {
  display: grid;
  place-items: center;
  width: 24px;
  height: 24px;
  border: 0;
  border-radius: 50%;
  background: transparent;
  color: var(--text-3);
}
.fchip button:hover {
  color: var(--text);
}

.error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  margin-bottom: 12px;
  border-radius: var(--radius);
  background: var(--danger-soft);
  color: var(--danger);
  font-weight: 500;
}
.error .btn {
  margin-left: auto;
}

.table-card {
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  overflow: clip;
}
.pager {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  font-size: 12.5px;
}
.spacer {
  flex: 1;
}
.page {
  padding: 0 4px;
  color: var(--text-2);
}

.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 64px 24px;
  color: var(--text-3);
  text-align: center;
}
.empty h3 {
  margin: 12px 0 4px;
  color: var(--text);
  font-size: 15px;
}
.empty p {
  margin: 0;
}
.empty-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

.table-skeleton {
  padding: 8px 16px;
}
.sk-row {
  display: flex;
  gap: 16px;
  padding: 14px 0;
  border-bottom: 1px solid var(--border);
}
.sk {
  height: 12px;
  border-radius: 4px;
  background: var(--surface-hover);
}
.sk.a { width: 40px; }
.sk.b { width: 120px; }
.sk.c { flex: 1; }

/* ---- Drawer ---- */
.drawer-wrap {
  position: fixed;
  inset: 56px 0 0 0;
  z-index: 40;
  pointer-events: none;
}
.drawer-scrim {
  position: absolute;
  inset: 0;
  background: rgba(10, 12, 18, 0.25);
  pointer-events: auto;
}
.drawer-panel {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(640px, 100vw);
  box-shadow: var(--shadow-lg);
  pointer-events: auto;
}
.drawer-enter-active,
.drawer-leave-active {
  transition: opacity 0.18s ease;
}
.drawer-enter-active .drawer-panel,
.drawer-leave-active .drawer-panel {
  transition: transform 0.22s cubic-bezier(0.2, 0.8, 0.2, 1);
}
.drawer-enter-from,
.drawer-leave-to {
  opacity: 0;
}
.drawer-enter-from .drawer-panel,
.drawer-leave-to .drawer-panel {
  transform: translateX(40px);
}

/* Wide screens: no scrim, the list stays usable beside the drawer */
@media (min-width: 1760px) {
  .drawer-scrim {
    display: none;
  }
  .app.drawer-open .main {
    padding-right: calc(640px + 24px);
  }
}

.popover-anchor {
  position: relative;
}
.popover {
  position: absolute;
  right: 0;
  top: calc(100% + 6px);
  z-index: 30;
  width: 300px;
  padding: 12px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow-lg);
}
.popover.menu {
  width: 220px;
  padding: 4px;
}
.popover.menu button {
  display: block;
  width: 100%;
  padding: 7px 10px;
  border: 0;
  border-radius: 5px;
  background: none;
  text-align: left;
  font-size: 13px;
}
.popover.menu button:hover {
  background: var(--surface-hover);
}
.popover.menu .pop-hint {
  padding: 4px 10px 6px;
}
.pop-label {
  display: block;
  margin-bottom: 4px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
}
.pop-hint {
  margin: 8px 0 0;
  font-size: 11.5px;
  color: var(--text-3);
}
.pop-actions {
  display: flex;
  justify-content: flex-end;
  gap: 6px;
  margin-top: 10px;
}
.btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.btn.primary:hover {
  background: var(--accent);
  filter: brightness(1.08);
}
.fchip.accent {
  background: var(--accent-soft);
  border-color: transparent;
  color: var(--accent-text);
}
.new-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  margin-bottom: 12px;
  border-radius: var(--radius);
  background: var(--accent-soft);
  color: var(--accent-text);
  font-size: 13px;
}
.new-banner .btn {
  margin-left: auto;
}
.warming {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 72px 24px;
  text-align: center;
}
.warming h3 {
  margin: 16px 0 4px;
  font-size: 15px;
}
.warming p {
  margin: 0;
}
.spinner.big {
  width: 28px;
  height: 28px;
  border-width: 3px;
}
.syntax-head {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}
.syntax code {
  font-family: var(--mono);
  font-size: 11.5px;
  padding: 1px 5px;
  border-radius: 4px;
  background: var(--surface-hover);
}

/* ---- Help ---- */
.help {
  position: fixed;
  right: 16px;
  top: 64px;
  z-index: 50;
  width: 340px;
  max-height: calc(100vh - 80px);
  overflow-y: auto;
  padding: 12px 14px;
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow-lg);
}
.help-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.help dl {
  margin: 0;
}
.help dl div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 5px 0;
  font-size: 13px;
}
.help dd {
  margin: 0;
  color: var(--text-2);
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.12s;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* ---- Responsive ---- */
@media (max-width: 1180px) {
  .tiles {
    grid-template-columns: repeat(4, 1fr);
  }
  .tile.wide {
    grid-column: 1 / -1;
  }
  .top-stats {
    display: none;
  }
}
@media (max-width: 900px) {
  .brand {
    width: auto;
  }
  .brand-name {
    display: none;
  }
  .sidebar {
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    z-index: 45;
    width: min(320px, 88vw);
    transform: translateX(-100%);
    transition: transform 0.2s ease;
    box-shadow: var(--shadow-lg);
  }
  .sidebar.open {
    transform: none;
  }
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 44;
    background: rgba(10, 12, 18, 0.35);
  }
  .filters-btn {
    display: inline-flex;
  }
  .main {
    padding: 12px 16px 32px;
  }
}
@media (max-width: 600px) {
  .topbar {
    gap: 8px;
    padding: 0 12px;
  }
  .search-input {
    padding-right: 12px;
  }
  .search-kbd,
  .search-hint {
    display: none;
  }
  .tabs button {
    padding: 0 10px;
  }
  .tabs button .icon,
  .tab-long {
    display: none;
  }
  .tab-short {
    display: inline;
  }
  .tab-count {
    display: none;
  }
  .tiles {
    grid-template-columns: 1fr 1fr;
  }
  .head-actions {
    width: 100%;
    justify-content: flex-start;
  }
  .legend {
    display: none;
  }
  .pager .select,
  .page {
    display: none;
  }
}
</style>
