import { reactive, ref, watch, computed } from "vue";

// ---- Filter state ----

function emptyFilters() {
  return {
    q: "",
    severities: [],
    attackVectors: [],
    kevOnly: false,
    ransomware: false,
    kevDays: 0,
    yearFrom: null,
    yearTo: null,
    scoreMin: null,
    scoreMax: null,
    vendors: [],
    products: [],
    cwe: "",
  };
}

export const VIEWS = {
  all: { label: "All CVEs", defaultSort: { by: "datePublished", desc: true } },
  kev: { label: "Known Exploited", defaultSort: { by: "kevDateAdded", desc: true } },
};

export const SORTS = {
  all: [
    ["datePublished", "Published"],
    ["dateUpdated", "Updated"],
    ["baseScore", "CVSS score"],
    ["id", "CVE ID"],
    ["vendor", "Vendor"],
  ],
  kev: [
    ["kevDateAdded", "Date added to KEV"],
    ["kevDueDate", "Remediation due"],
    ["baseScore", "CVSS score"],
    ["datePublished", "Published"],
    ["id", "CVE ID"],
    ["vendor", "Vendor"],
  ],
};

export const state = reactive({
  view: "all",
  filters: emptyFilters(),
  sort: { ...VIEWS.all.defaultSort },
  page: 1,
  pageSize: 50,
  selectedId: null,
});

export const results = reactive({
  loading: false,
  error: null,
  cves: [],
  total: 0,
  totalPages: 0,
  facets: { severity: {}, attackVector: {}, kev: 0, ransomware: 0 },
  yearCounts: [],
  kevMonths: [],
  tookMs: 0,
  loaded: false,
});

export const stats = ref(null);

export function activeFilterCount() {
  const f = state.filters;
  let n = 0;
  if (f.q) n++;
  n += f.severities.length + f.attackVectors.length + f.vendors.length + f.products.length;
  if (f.kevOnly && state.view !== "kev") n++;
  if (f.ransomware) n++;
  if (f.kevDays) n++;
  if (f.yearFrom || f.yearTo) n++;
  if (f.scoreMin != null || f.scoreMax != null) n++;
  if (f.cwe) n++;
  return n;
}

export function resetFilters() {
  Object.assign(state.filters, emptyFilters());
}

export function setView(view) {
  if (state.view === view) return;
  state.view = view;
  state.sort = { ...VIEWS[view].defaultSort };
  if (view !== "kev") {
    state.filters.ransomware = false;
    state.filters.kevDays = 0;
  }
}

export function toggleIn(list, value) {
  const i = list.indexOf(value);
  if (i >= 0) list.splice(i, 1);
  else list.push(value);
}

export function addUnique(list, value) {
  if (value && !list.some((v) => v.toLowerCase() === value.toLowerCase())) list.push(value);
}

// ---- API ----

function buildRequest() {
  const f = state.filters;
  const req = {
    page: state.page,
    pageSize: state.pageSize,
    sortBy: state.sort.by,
    sortDesc: state.sort.desc,
  };
  if (f.q.trim()) req.search = f.q.trim();
  if (f.severities.length) req.severities = f.severities;
  if (f.attackVectors.length) req.attackVectors = f.attackVectors;
  if (f.vendors.length) req.vendors = f.vendors;
  if (f.products.length) req.products = f.products;
  if (f.cwe) req.cwe = f.cwe;
  if (f.yearFrom) req.yearFrom = f.yearFrom;
  if (f.yearTo) req.yearTo = f.yearTo;
  if (f.scoreMin != null) req.scoreMin = f.scoreMin;
  if (f.scoreMax != null) req.scoreMax = f.scoreMax;
  if (state.view === "kev" || f.kevOnly) req.inKEV = true;
  if (f.ransomware) req.ransomware = true;
  if (f.kevDays) req.kevAddedDays = f.kevDays;
  return req;
}

let inflight = null;

export async function fetchResults() {
  inflight?.abort();
  const ctrl = new AbortController();
  inflight = ctrl;
  results.loading = true;
  try {
    const res = await fetch("/api/cves", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildRequest()),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    Object.assign(results, {
      cves: data.cves || [],
      total: data.total,
      totalPages: data.totalPages,
      facets: data.facets,
      yearCounts: data.yearCounts || [],
      kevMonths: data.kevMonths || [],
      tookMs: data.tookMs,
      error: null,
      loaded: true,
    });
  } catch (e) {
    if (e.name === "AbortError") return;
    results.error = "Couldn't load results. Is the server running?";
  } finally {
    if (inflight === ctrl) {
      results.loading = false;
      inflight = null;
    }
  }
}

export async function fetchStats() {
  try {
    const res = await fetch("/api/stats");
    if (res.ok) stats.value = await res.json();
  } catch {
    // Header stats are decorative; the results error banner covers outages
  }
}

const detailCache = new Map();

export async function fetchCve(id) {
  if (detailCache.has(id)) return detailCache.get(id);
  const res = await fetch(`/api/cves/${encodeURIComponent(id)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const cve = await res.json();
  detailCache.set(id, cve);
  return cve;
}

export async function searchOptions(field, search, extra = {}) {
  const res = await fetch("/api/options/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ field, search, limit: 50, ...extra }),
  });
  if (!res.ok) return [];
  return (await res.json()) || [];
}

export async function exportXlsx() {
  const req = buildRequest();
  delete req.page;
  delete req.pageSize;
  const res = await fetch("/api/export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `${state.view === "kev" ? "kev" : "cve"}_export_${new Date().toISOString().slice(0, 10)}.xlsx`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- URL sync ----
// Lists use repeated params (v=a&v=b) because vendor/product names can contain commas.

export function writeURL() {
  const f = state.filters;
  const p = new URLSearchParams();
  if (state.view !== "all") p.set("view", state.view);
  if (f.q) p.set("q", f.q);
  f.severities.forEach((v) => p.append("sev", v));
  f.attackVectors.forEach((v) => p.append("av", v));
  f.vendors.forEach((v) => p.append("v", v));
  f.products.forEach((v) => p.append("p", v));
  if (f.cwe) p.set("cwe", f.cwe);
  if (f.kevOnly) p.set("kev", "1");
  if (f.ransomware) p.set("rw", "1");
  if (f.kevDays) p.set("kd", f.kevDays);
  if (f.yearFrom) p.set("yf", f.yearFrom);
  if (f.yearTo) p.set("yt", f.yearTo);
  if (f.scoreMin != null) p.set("smin", f.scoreMin);
  if (f.scoreMax != null) p.set("smax", f.scoreMax);
  const def = VIEWS[state.view].defaultSort;
  if (state.sort.by !== def.by || state.sort.desc !== def.desc) {
    p.set("sort", state.sort.by);
    p.set("dir", state.sort.desc ? "desc" : "asc");
  }
  if (state.page > 1) p.set("page", state.page);
  if (state.selectedId) p.set("cve", state.selectedId);
  const qs = p.toString();
  history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
}

export function readURL() {
  const p = new URLSearchParams(location.search);
  const f = state.filters;
  const num = (k) => (p.has(k) && !isNaN(parseFloat(p.get(k))) ? parseFloat(p.get(k)) : null);
  state.view = p.get("view") === "kev" ? "kev" : "all";
  state.sort = { ...VIEWS[state.view].defaultSort };
  f.q = p.get("q") || "";
  f.severities = p.getAll("sev");
  f.attackVectors = p.getAll("av");
  f.vendors = p.getAll("v");
  f.products = p.getAll("p");
  f.cwe = p.get("cwe") || "";
  f.kevOnly = p.get("kev") === "1";
  f.ransomware = p.get("rw") === "1";
  f.kevDays = num("kd") || 0;
  f.yearFrom = num("yf");
  f.yearTo = num("yt");
  f.scoreMin = num("smin");
  f.scoreMax = num("smax");
  if (p.has("sort")) state.sort = { by: p.get("sort"), desc: p.get("dir") !== "asc" };
  state.page = num("page") || 1;
  state.selectedId = p.get("cve");
}

// ---- Wiring ----

export function startSync() {
  let timer = null;
  let lastQ = state.filters.q;
  const schedule = (resetPage) => {
    if (resetPage) state.page = 1;
    clearTimeout(timer);
    // Typing gets a longer debounce than clicks
    const typing = state.filters.q !== lastQ;
    lastQ = state.filters.q;
    timer = setTimeout(fetchResults, typing ? 250 : 60);
  };
  watch(() => [state.filters, state.view], () => schedule(true), { deep: true });
  watch(() => [state.sort.by, state.sort.desc, state.pageSize], () => schedule(true));
  watch(() => state.page, () => schedule(false));
  watch(() => [state, state.filters], writeURL, { deep: true });
}

export const isKevView = computed(() => state.view === "kev");
