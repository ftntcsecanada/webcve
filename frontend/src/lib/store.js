import { reactive, ref, watch } from "vue";

// ---- Filter state ----

export function emptyFilters() {
  return {
    q: "",
    severities: [],
    attackVectors: [],
    kevOnly: false,
    ransomware: false,
    kevDays: 0,
    kevDue: "",
    yearFrom: null,
    yearTo: null,
    scoreMin: null,
    scoreMax: null,
    epssMin: null,
    exploit: false,
    exploitSources: [],
    vendors: [],
    products: [],
    cwe: "",
    since: "",
  };
}

export const VIEWS = {
  all: { label: "All CVEs", short: "All", defaultSort: { by: "datePublished", desc: true } },
  kev: { label: "Known Exploited", short: "KEV", defaultSort: { by: "kevDateAdded", desc: true } },
  vendors: { label: "Vendors", short: "Vendors", defaultSort: { by: "datePublished", desc: true } },
};

export const SORTS = {
  all: [
    ["datePublished", "Published"],
    ["dateUpdated", "Updated"],
    ["baseScore", "CVSS score"],
    ["epss", "EPSS (exploit likelihood)"],
    ["id", "CVE ID"],
    ["vendor", "Vendor"],
  ],
  kev: [
    ["kevDateAdded", "Date added to KEV"],
    ["kevDueDate", "Remediation due"],
    ["baseScore", "CVSS score"],
    ["epss", "EPSS (exploit likelihood)"],
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
  // Vendor comparison view
  vendor: { sort: "kev", desc: true, min: 25, query: "" },
});

export function vendorRequest() {
  return {
    ...buildRequest(state.view, state.filters),
    sort: state.vendor.sort,
    desc: state.vendor.desc,
    minCves: state.vendor.min,
    query: state.vendor.query,
    limit: 200,
  };
}

export const results = reactive({
  loading: false,
  error: null,
  warming: null, // server status while the dataset loads
  cves: [],
  total: 0,
  totalPages: 0,
  facets: { severity: {}, attackVector: {}, kev: 0, ransomware: 0, exploit: 0, exploitSources: {} },
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
  n += f.severities.length + f.attackVectors.length + f.vendors.length + f.products.length + f.exploitSources.length;
  if (f.kevOnly && state.view !== "kev") n++;
  for (const k of ["ransomware", "kevDays", "kevDue", "cwe", "exploit", "since"]) if (f[k]) n++;
  if (f.yearFrom || f.yearTo) n++;
  if (f.scoreMin != null || f.scoreMax != null) n++;
  if (f.epssMin != null) n++;
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
    state.filters.kevDue = "";
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

function buildRequest(view, f) {
  const req = {};
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
  if (f.epssMin != null) req.epssMin = f.epssMin;
  if (f.exploit) req.publicExploit = true;
  if (f.exploitSources.length) req.exploitSources = f.exploitSources;
  if (view === "kev" || f.kevOnly) req.inKEV = true;
  if (view === "kev" && f.ransomware) req.ransomware = true;
  if (view === "kev" && f.kevDays) req.kevAddedDays = f.kevDays;
  if (view === "kev" && f.kevDue) req.kevDue = f.kevDue;
  if (f.since) req.changedSince = f.since;
  return req;
}

function currentRequest() {
  return {
    ...buildRequest(state.view, state.filters),
    page: state.page,
    pageSize: state.pageSize,
    sortBy: state.sort.by,
    sortDesc: state.sort.desc,
  };
}

async function postJSON(url, body, signal) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  return res;
}

let inflight = null;
let warmTimer = null;

export async function fetchResults() {
  inflight?.abort();
  const ctrl = new AbortController();
  inflight = ctrl;
  results.loading = true;
  try {
    const res = await postJSON("/api/cves", currentRequest(), ctrl.signal);
    if (res.status === 503) {
      // Dataset still loading: show progress and retry
      const body = await res.json().catch(() => ({}));
      results.warming = body.status || "loading";
      clearTimeout(warmTimer);
      warmTimer = setTimeout(() => {
        fetchResults();
        fetchStats();
      }, 2000);
      return;
    }
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
      warming: null,
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

export async function fetchRelated(id) {
  const res = await fetch(`/api/cves/${encodeURIComponent(id)}/related`);
  if (!res.ok) return null;
  return res.json();
}

export async function searchOptions(field, search, extra = {}) {
  const res = await postJSON("/api/options/search", { field, search, limit: 50, ...extra });
  if (!res.ok) return [];
  return (await res.json()) || [];
}

export async function exportResults(format) {
  const req = { ...buildRequest(state.view, state.filters), sortBy: state.sort.by, sortDesc: state.sort.desc };
  const res = await postJSON(`/api/export?format=${format}`, req);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `${state.view === "kev" ? "kev" : "cve"}_export_${new Date().toISOString().slice(0, 10)}.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- URL (de)serialization ----
// Lists use repeated params (v=a&v=b) because vendor/product names can contain commas.

function toQuery(view, f, sort, extra = {}) {
  const p = new URLSearchParams();
  if (view !== "all") p.set("view", view);
  if (f.q) p.set("q", f.q);
  f.severities.forEach((v) => p.append("sev", v));
  f.attackVectors.forEach((v) => p.append("av", v));
  f.vendors.forEach((v) => p.append("v", v));
  f.products.forEach((v) => p.append("p", v));
  if (f.cwe) p.set("cwe", f.cwe);
  if (f.kevOnly) p.set("kev", "1");
  if (f.ransomware) p.set("rw", "1");
  if (f.kevDays) p.set("kd", f.kevDays);
  if (f.kevDue) p.set("due", f.kevDue);
  if (f.yearFrom) p.set("yf", f.yearFrom);
  if (f.yearTo) p.set("yt", f.yearTo);
  if (f.scoreMin != null) p.set("smin", f.scoreMin);
  if (f.scoreMax != null) p.set("smax", f.scoreMax);
  if (f.epssMin != null) p.set("epss", f.epssMin);
  if (f.exploit) p.set("x", "1");
  f.exploitSources.forEach((v) => p.append("xs", v));
  if (f.since) p.set("since", f.since);
  if (sort) {
    const def = VIEWS[view].defaultSort;
    if (sort.by !== def.by || sort.desc !== def.desc) {
      p.set("sort", sort.by);
      p.set("dir", sort.desc ? "desc" : "asc");
    }
  }
  for (const [k, v] of Object.entries(extra)) if (v) p.set(k, v);
  if (view === "vendors") {
    const vv = state.vendor;
    if (vv.sort !== "kev" || !vv.desc) {
      p.set("vs", vv.sort);
      p.set("vd", vv.desc ? "desc" : "asc");
    }
    if (vv.min !== 25) p.set("vmin", vv.min);
    if (vv.query) p.set("vq", vv.query);
  }
  return p.toString();
}

export function fromQuery(qs) {
  const p = new URLSearchParams(qs);
  const f = emptyFilters();
  const num = (k) => (p.has(k) && !isNaN(parseFloat(p.get(k))) ? parseFloat(p.get(k)) : null);
  const view = ["kev", "vendors"].includes(p.get("view")) ? p.get("view") : "all";
  if (view === "vendors") {
    state.vendor.sort = p.get("vs") || "kev";
    state.vendor.desc = p.get("vd") !== "asc";
    state.vendor.min = parseInt(p.get("vmin")) || 25;
    state.vendor.query = p.get("vq") || "";
  }
  f.q = p.get("q") || "";
  f.severities = p.getAll("sev");
  f.attackVectors = p.getAll("av");
  f.vendors = p.getAll("v");
  f.products = p.getAll("p");
  f.cwe = p.get("cwe") || "";
  f.kevOnly = p.get("kev") === "1";
  f.ransomware = p.get("rw") === "1";
  f.kevDays = num("kd") || 0;
  f.kevDue = p.get("due") || "";
  f.yearFrom = num("yf");
  f.yearTo = num("yt");
  f.scoreMin = num("smin");
  f.scoreMax = num("smax");
  f.epssMin = num("epss");
  f.exploit = p.get("x") === "1";
  f.exploitSources = p.getAll("xs");
  f.since = p.get("since") || "";
  const sort = p.has("sort") ? { by: p.get("sort"), desc: p.get("dir") !== "asc" } : { ...VIEWS[view].defaultSort };
  return { view, filters: f, sort, page: num("page") || 1, cve: p.get("cve") };
}

export function currentQuery({ withSort = true } = {}) {
  return toQuery(state.view, state.filters, withSort ? state.sort : null);
}

export function writeURL() {
  const qs = toQuery(state.view, state.filters, state.sort, {
    page: state.page > 1 ? state.page : "",
    cve: state.selectedId || "",
  });
  history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
}

export function applyQuery(qs) {
  const q = fromQuery(qs);
  state.view = q.view;
  Object.assign(state.filters, q.filters);
  state.sort = q.sort;
  state.page = q.page;
  if (q.cve !== undefined) state.selectedId = q.cve;
}

export function readURL() {
  applyQuery(location.search);
}

// ---- Saved searches ----
// Kept in localStorage per browser. Each remembers when it was last opened so
// it can show how many CVEs were published or added to KEV since.

const SAVED_KEY = "webcve.saved";

function loadSaved() {
  try {
    const v = JSON.parse(localStorage.getItem(SAVED_KEY) || "[]");
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

export const saved = reactive({ list: loadSaved(), counts: {}, active: null });

function persistSaved() {
  try {
    localStorage.setItem(SAVED_KEY, JSON.stringify(saved.list));
  } catch {
    // Private mode: saved searches last for this session only
  }
}

export function saveCurrentSearch(name) {
  const entry = { id: crypto.randomUUID?.() || String(Date.now()), name, query: currentQuery(), lastSeen: new Date().toISOString() };
  saved.list.push(entry);
  persistSaved();
  saved.active = { id: entry.id, previousSeen: entry.lastSeen };
  saved.counts[entry.id] = 0;
}

export function removeSaved(id) {
  saved.list = saved.list.filter((s) => s.id !== id);
  delete saved.counts[id];
  if (saved.active?.id === id) saved.active = null;
  persistSaved();
}

export function openSaved(entry) {
  applyQuery(entry.query);
  state.filters.since = "";
  state.selectedId = null;
  saved.active = { id: entry.id, previousSeen: entry.lastSeen, newCount: saved.counts[entry.id] || 0 };
  entry.lastSeen = new Date().toISOString();
  saved.counts[entry.id] = 0;
  persistSaved();
}

export async function refreshSavedCounts() {
  await Promise.all(
    saved.list.map(async (s) => {
      const { view, filters } = fromQuery(s.query);
      const req = { ...buildRequest(view, { ...filters, since: s.lastSeen }), countOnly: true };
      try {
        const res = await postJSON("/api/cves", req);
        if (res.ok) saved.counts[s.id] = (await res.json()).total;
      } catch {
        // Leave the previous count
      }
    })
  );
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
  watch(() => [state, state.filters, state.vendor], writeURL, { deep: true });

  // Saved search badges follow data refreshes
  watch(
    () => stats.value?.sources?.cve,
    (v) => v && refreshSavedCounts()
  );
  // Leaving a saved search's exact query ends its "new since" context
  watch(
    () => currentQuery({ withSort: false }),
    (qs) => {
      const a = saved.active;
      if (!a) return;
      const entry = saved.list.find((s) => s.id === a.id);
      const base = fromQuery(entry?.query || "");
      if (!entry || qs.replace(/&?since=[^&]*/, "") !== toQuery(base.view, base.filters, null)) saved.active = null;
    }
  );
}
