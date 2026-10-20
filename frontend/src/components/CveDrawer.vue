<script setup>
import { ref, watch, computed } from "vue";
import Icon from "./Icon.vue";
import { state, fetchCve, addUnique } from "../lib/store.js";
import {
  SEVERITY_LABEL,
  severityKey,
  fmtDate,
  fmtRelative,
  daysFromToday,
  cleanName,
  parseCvssVector,
  groupReferences,
  splitUrl,
} from "../lib/format.js";

const props = defineProps({
  id: { type: String, default: null },
  hasPrev: Boolean,
  hasNext: Boolean,
});
const emit = defineEmits(["close", "prev", "next"]);

const cve = ref(null);
const loading = ref(false);
const error = ref(null);
const copied = ref("");
const scroller = ref(null);
const showAllProducts = ref(false);

watch(
  () => props.id,
  async (id) => {
    if (!id) return;
    loading.value = true;
    error.value = null;
    showAllProducts.value = false;
    try {
      const data = await fetchCve(id);
      if (props.id !== id) return;
      cve.value = data;
      if (!data) error.value = `${id} isn't in the local database.`;
      scroller.value?.scrollTo({ top: 0 });
    } catch {
      error.value = "Couldn't load this CVE.";
    } finally {
      loading.value = false;
    }
  },
  { immediate: true }
);

const sev = computed(() => severityKey(cve.value?.baseSeverity));
const metrics = computed(() => parseCvssVector(cve.value?.vectorString));
const refGroups = computed(() => groupReferences(cve.value?.references));
const kevNotes = computed(() =>
  (cve.value?.kevNotes || "")
    .split(/\s*;\s*/)
    .map((s) => s.trim())
    .filter(Boolean)
);
const products = computed(() => {
  const list = (cve.value?.affectedProducts || []).filter((p) => cleanName(p.vendor) || cleanName(p.product));
  return showAllProducts.value ? list : list.slice(0, 8);
});
const productCount = computed(
  () => (cve.value?.affectedProducts || []).filter((p) => cleanName(p.vendor) || cleanName(p.product)).length
);

const due = computed(() => {
  const d = daysFromToday(cve.value?.kevDueDate);
  if (d == null) return null;
  if (d < 0) return { cls: "danger", text: `Overdue by ${-d} day${d === -1 ? "" : "s"}` };
  if (d === 0) return { cls: "danger", text: "Due today" };
  return { cls: d <= 14 ? "warn" : "", text: `Due in ${d} day${d === 1 ? "" : "s"}` };
});

const cweNumber = computed(() => cve.value?.cwe?.match(/CWE-(\d+)/)?.[1]);

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    copied.value = what;
    setTimeout(() => (copied.value = ""), 1400);
  } catch {
    // Clipboard can be unavailable on plain-http origins; nothing useful to do
  }
}

function currentUrl() {
  return window.location.href;
}

function filterBy(vendor, product) {
  if (cleanName(vendor)) addUnique(state.filters.vendors, vendor);
  if (product && cleanName(product)) addUnique(state.filters.products, product);
}

const riskLabel = ["", "low", "med", "high"];
</script>

<template>
  <aside class="drawer" role="dialog" aria-modal="false" :aria-label="id ? `Details for ${id}` : 'CVE details'">
    <header class="d-head">
      <div class="nav">
        <button class="btn ghost sm icon" :disabled="!hasPrev" title="Previous (k)" @click="emit('prev')"><Icon name="chevronUp" /></button>
        <button class="btn ghost sm icon" :disabled="!hasNext" title="Next (j)" @click="emit('next')"><Icon name="chevronDown" /></button>
      </div>
      <h2 class="d-id mono">{{ id }}</h2>
      <button class="btn ghost sm icon" :title="copied === 'id' ? 'Copied' : 'Copy ID'" @click="copy(id, 'id')">
        <Icon :name="copied === 'id' ? 'check' : 'copy'" :size="14" />
      </button>
      <button class="btn ghost sm icon" :title="copied === 'link' ? 'Copied' : 'Copy link'" @click="copy(currentUrl(), 'link')">
        <Icon :name="copied === 'link' ? 'check' : 'link'" :size="14" />
      </button>
      <span class="spacer" />
      <button class="btn ghost sm icon" title="Close (Esc)" @click="emit('close')"><Icon name="x" /></button>
    </header>

    <div ref="scroller" class="d-body scroll-thin">
      <div v-if="error" class="d-error">{{ error }}</div>
      <div v-else-if="!cve" class="d-skeleton">
        <div class="sk w60" /><div class="sk w90" /><div class="sk w80" /><div class="sk w40" />
      </div>
      <template v-else>
        <!-- Score + headline -->
        <section class="hero" :class="{ loading }">
          <div class="score" :class="sev">
            <div class="score-val num">{{ cve.baseScore ? cve.baseScore.toFixed(1) : "—" }}</div>
            <div class="score-lbl">{{ SEVERITY_LABEL[sev] }}</div>
          </div>
          <div class="headline">
            <h3>{{ cve.title || cve.kevName || "Untitled vulnerability" }}</h3>
            <div class="hl-meta">
              <span v-if="cve.inKEV" class="badge kev"><Icon name="flame" :size="11" />Known exploited</span>
              <span v-if="cve.kevKnownRansomwareCampaign === 'Known'" class="badge danger"><Icon name="lock" :size="11" />Ransomware</span>
              <span v-if="cve.cvssVersion" class="badge">CVSS {{ cve.cvssVersion }}</span>
              <span v-if="cve.state && cve.state !== 'PUBLISHED'" class="badge warn">{{ cve.state }}</span>
            </div>
          </div>
        </section>

        <!-- KEV callout -->
        <section v-if="cve.inKEV" class="kev-card">
          <div class="kev-title"><Icon name="flame" :size="15" /> CISA Known Exploited Vulnerability</div>
          <div v-if="cve.kevName" class="kev-name">{{ cve.kevName }}</div>
          <dl class="kev-grid">
            <div>
              <dt>Added</dt>
              <dd>{{ fmtDate(cve.kevDateAdded) }} <span class="muted">· {{ fmtRelative(cve.kevDateAdded) }}</span></dd>
            </div>
            <div>
              <dt>Remediation due</dt>
              <dd>
                {{ fmtDate(cve.kevDueDate) }}
                <span v-if="due" class="due" :class="due.cls">{{ due.text }}</span>
              </dd>
            </div>
            <div>
              <dt>Ransomware use</dt>
              <dd :class="{ danger: cve.kevKnownRansomwareCampaign === 'Known' }">{{ cve.kevKnownRansomwareCampaign || "Unknown" }}</dd>
            </div>
          </dl>
          <div v-if="cve.kevRequiredAction" class="kev-action">
            <dt>Required action</dt>
            <dd>{{ cve.kevRequiredAction }}</dd>
          </div>
          <ul v-if="kevNotes.length" class="kev-notes">
            <li v-for="n in kevNotes" :key="n">
              <a v-if="/^https?:/.test(n)" :href="n" target="_blank" rel="noopener noreferrer">{{ splitUrl(n).host }}<span class="muted">{{ splitUrl(n).path }}</span></a>
              <span v-else>{{ n }}</span>
            </li>
          </ul>
        </section>

        <!-- Description -->
        <section class="block">
          <p class="desc">{{ cve.description || "No description provided." }}</p>
        </section>

        <!-- CVSS -->
        <section v-if="cve.vectorString" class="block">
          <h4>Exploitability &amp; impact</h4>
          <div class="metrics">
            <div v-for="m in metrics" :key="m.key" class="metric" :class="riskLabel[m.risk]" :title="`${m.key}: ${m.value}`">
              <span class="m-label">{{ m.label }}</span>
              <span class="m-value">{{ m.value }}</span>
            </div>
          </div>
          <button class="vector mono" :title="copied === 'vec' ? 'Copied' : 'Copy vector'" @click="copy(cve.vectorString, 'vec')">
            {{ cve.vectorString }}
            <Icon :name="copied === 'vec' ? 'check' : 'copy'" :size="12" />
          </button>
        </section>

        <!-- Weakness -->
        <section v-if="cve.cwe" class="block">
          <h4>Weakness</h4>
          <div class="cwe">
            <button class="cwe-id mono" title="Filter by this CWE" @click="state.filters.cwe = cve.cwe">{{ cve.cwe }}</button>
            <span class="cwe-desc">{{ (cve.cweDescription || "").replace(/^CWE-\d+:?\s*/, "") }}</span>
            <a v-if="cweNumber" class="ext" :href="`https://cwe.mitre.org/data/definitions/${cweNumber}.html`" target="_blank" rel="noopener noreferrer" title="Open on MITRE">
              <Icon name="external" :size="13" />
            </a>
          </div>
        </section>

        <!-- Affected -->
        <section v-if="productCount" class="block">
          <h4>Affected products <span class="count">{{ productCount }}</span></h4>
          <ul class="products">
            <li v-for="(p, i) in products" :key="i">
              <button class="prod" title="Filter by this product" @click="filterBy(p.vendor, p.product)">
                <span class="p-vendor">{{ cleanName(p.vendor) || "—" }}</span>
                <span class="p-name">{{ cleanName(p.product) || "—" }}</span>
              </button>
              <div v-if="p.versions" class="p-ver mono" :title="p.versions">{{ p.versions }}</div>
            </li>
          </ul>
          <button v-if="productCount > 8 && !showAllProducts" class="btn sm show-more" @click="showAllProducts = true">
            Show all {{ productCount }}
          </button>
        </section>

        <!-- References -->
        <section v-if="refGroups.length" class="block">
          <h4>References <span class="count">{{ cve.references.length }}</span></h4>
          <div v-for="g in refGroups" :key="g.key" class="ref-group">
            <div class="ref-label" :class="g.key">{{ g.label }}</div>
            <ul class="refs">
              <li v-for="r in g.refs" :key="r.url">
                <a :href="r.url" target="_blank" rel="noopener noreferrer" :title="r.url">
                  <span class="r-host">{{ splitUrl(r.url).host }}</span><span class="r-path">{{ splitUrl(r.url).path }}</span>
                </a>
              </li>
            </ul>
          </div>
        </section>

        <!-- Timeline + external -->
        <section class="block">
          <h4>Record</h4>
          <dl class="record">
            <div><dt>Published</dt><dd>{{ fmtDate(cve.datePublished) }}</dd></div>
            <div><dt>Updated</dt><dd>{{ fmtDate(cve.dateUpdated) }}</dd></div>
            <div><dt>Reserved</dt><dd>{{ fmtDate(cve.dateReserved) }}</dd></div>
            <div><dt>Assigner</dt><dd>{{ cve.assignerOrg || "—" }}</dd></div>
          </dl>
          <div class="ext-links">
            <a class="btn sm" :href="`https://nvd.nist.gov/vuln/detail/${cve.id}`" target="_blank" rel="noopener noreferrer">NVD <Icon name="external" :size="12" /></a>
            <a class="btn sm" :href="`https://www.cve.org/CVERecord?id=${cve.id}`" target="_blank" rel="noopener noreferrer">CVE.org <Icon name="external" :size="12" /></a>
            <a
              v-if="cve.inKEV"
              class="btn sm"
              :href="`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve.id}`"
              target="_blank"
              rel="noopener noreferrer"
            >
              CISA KEV <Icon name="external" :size="12" />
            </a>
          </div>
        </section>
      </template>
    </div>
  </aside>
</template>

<style scoped>
.drawer {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--surface);
}
.d-head {
  display: flex;
  align-items: center;
  gap: 4px;
  height: 52px;
  padding: 0 10px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.nav {
  display: flex;
  gap: 2px;
  margin-right: 6px;
}
.d-id {
  margin: 0 4px 0 0;
  font-size: 15px;
  font-weight: 650;
  white-space: nowrap;
}
.spacer {
  flex: 1;
}
.d-body {
  flex: 1;
  overflow-y: auto;
  padding: 20px 22px 48px;
}
.d-error {
  padding: 24px;
  border-radius: var(--radius);
  background: var(--surface-2);
  color: var(--text-2);
  text-align: center;
}
.d-skeleton .sk {
  height: 14px;
  margin: 12px 0;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--surface-hover), var(--surface-2), var(--surface-hover));
  background-size: 200% 100%;
  animation: shimmer 1.2s infinite;
}
.sk.w40 { width: 40%; }
.sk.w60 { width: 60%; }
.sk.w80 { width: 80%; }
.sk.w90 { width: 90%; }
@keyframes shimmer {
  to { background-position: -200% 0; }
}

.hero {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  transition: opacity 0.15s;
}
.hero.loading {
  opacity: 0.5;
}
.score {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 72px;
  height: 72px;
  border-radius: 12px;
  flex-shrink: 0;
  background: var(--sev-none);
  color: var(--on-sev);
}
.score.CRITICAL { background: var(--sev-critical); color: #fff; }
.score.HIGH { background: var(--sev-high); color: #fff; }
.score.MEDIUM { background: var(--sev-medium); color: var(--on-sev); }
.score.LOW { background: var(--sev-low); color: var(--on-sev-low); }
.score.NONE { background: var(--surface-hover); color: var(--text-3); }
.score-val {
  font-size: 26px;
  font-weight: 700;
  line-height: 1;
}
.score-lbl {
  margin-top: 4px;
  font-size: 10.5px;
  font-weight: 650;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.headline h3 {
  margin: 2px 0 8px;
  font-size: 16px;
  line-height: 1.35;
  font-weight: 650;
}
.hl-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.kev-card {
  margin-top: 20px;
  padding: 14px 16px;
  border-radius: var(--radius);
  background: var(--kev-soft);
  border: 1px solid color-mix(in srgb, var(--kev) 30%, transparent);
}
.kev-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--kev-text);
}
.kev-name {
  margin-top: 6px;
  font-weight: 600;
}
.kev-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px 16px;
  margin: 12px 0 0;
}
dt {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-3);
}
dd {
  margin: 2px 0 0;
}
dd.danger {
  color: var(--danger);
  font-weight: 600;
}
.due {
  display: block;
  font-size: 12px;
  color: var(--text-2);
}
.due.danger {
  color: var(--danger);
  font-weight: 600;
}
.due.warn {
  color: var(--warn);
  font-weight: 600;
}
.kev-action {
  margin-top: 12px;
}
.kev-action dd {
  color: var(--text-2);
  font-size: 13px;
}
.kev-notes {
  margin: 10px 0 0;
  padding: 0;
  list-style: none;
  font-size: 12.5px;
}
.kev-notes li {
  line-height: 1.7;
  color: var(--text-2);
}
.kev-notes a {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.block {
  margin-top: 24px;
}
h4 {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0 0 10px;
  font-size: 11.5px;
  font-weight: 650;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-3);
}
h4 .count {
  font-weight: 600;
  color: var(--text-3);
  background: var(--surface-hover);
  border-radius: 4px;
  padding: 0 5px;
  letter-spacing: 0;
}
.desc {
  margin: 0;
  white-space: pre-wrap;
  line-height: 1.6;
  color: var(--text);
}

.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 6px;
}
.metric {
  display: flex;
  flex-direction: column;
  padding: 7px 10px;
  border-radius: var(--radius-sm);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border-strong);
}
.metric.high {
  border-left-color: var(--sev-high);
}
.metric.med {
  border-left-color: var(--sev-low);
}
.m-label {
  font-size: 11px;
  color: var(--text-3);
}
.m-value {
  font-weight: 600;
  font-size: 13px;
}
.vector {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  padding: 3px 8px;
  border: 1px dashed var(--border-strong);
  border-radius: 5px;
  background: transparent;
  font-size: 11.5px;
  color: var(--text-2);
  word-break: break-all;
  text-align: left;
}
.vector:hover {
  color: var(--text);
  border-style: solid;
}

.cwe {
  display: flex;
  align-items: center;
  gap: 10px;
}
.cwe-id {
  padding: 3px 8px;
  border-radius: 5px;
  border: 0;
  background: var(--accent-soft);
  color: var(--accent-text);
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
}
.cwe-desc {
  flex: 1;
  color: var(--text-2);
}
.ext {
  color: var(--text-3);
}

.products {
  margin: 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.products li {
  padding: 8px 12px;
  border-top: 1px solid var(--border);
}
.products li:first-child {
  border-top: 0;
}
.prod {
  display: flex;
  gap: 8px;
  align-items: baseline;
  padding: 0;
  border: 0;
  background: none;
  text-align: left;
}
.prod:hover .p-name {
  color: var(--accent-text);
  text-decoration: underline;
}
.p-vendor {
  color: var(--text-3);
  font-size: 12.5px;
}
.p-name {
  font-weight: 600;
}
.p-ver {
  margin-top: 3px;
  font-size: 11.5px;
  color: var(--text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.show-more {
  margin-top: 8px;
}

.ref-group + .ref-group {
  margin-top: 12px;
}
.ref-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
  margin-bottom: 4px;
}
.ref-label.exploit {
  color: var(--danger);
}
.ref-label.patch {
  color: var(--ok);
}
.refs {
  margin: 0;
  padding: 0;
  list-style: none;
}
.refs li {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1.75;
  font-size: 13px;
}
.r-host {
  font-weight: 500;
}
.r-path {
  color: var(--text-3);
}

.record {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px 16px;
  margin: 0;
}
.ext-links {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 16px;
}
.ext-links a:hover {
  text-decoration: none;
}
</style>
