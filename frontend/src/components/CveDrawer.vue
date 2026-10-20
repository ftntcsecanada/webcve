<script setup>
import { ref, watch, computed } from "vue";
import Icon from "./Icon.vue";
import { state, fetchCve, fetchRelated, addUnique } from "../lib/store.js";
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
  fmtEpss,
  fmtPercentile,
  epssLevel,
  summaryText,
  SSVC_LABEL,
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
const related = ref(null);

watch(
  () => props.id,
  async (id) => {
    if (!id) return;
    loading.value = true;
    error.value = null;
    showAllProducts.value = false;
    related.value = null;
    fetchRelated(id).then((r) => {
      if (props.id === id) related.value = r;
    });
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
  // Long-past deadlines are the norm for older entries; only flag recent misses
  if (d < -30) return { cls: "", text: `Past due (${-d} days ago)` };
  if (d < 0) return { cls: "danger", text: `Overdue by ${-d} day${d === -1 ? "" : "s"}` };
  if (d === 0) return { cls: "danger", text: "Due today" };
  return { cls: d <= 14 ? "warn" : "", text: `Due in ${d} day${d === 1 ? "" : "s"}` };
});

const ssvc = computed(() => {
  const c = cve.value;
  if (!c?.ssvcExploitation && !c?.ssvcAutomatable && !c?.ssvcTechnicalImpact) return null;
  return [
    ["Exploitation", SSVC_LABEL.exploitation[c.ssvcExploitation] || c.ssvcExploitation, c.ssvcExploitation === "active" ? "high" : c.ssvcExploitation === "poc" ? "med" : ""],
    ["Automatable", SSVC_LABEL.automatable[c.ssvcAutomatable] || c.ssvcAutomatable, c.ssvcAutomatable === "yes" ? "med" : ""],
    ["Technical impact", SSVC_LABEL.technicalImpact[c.ssvcTechnicalImpact] || c.ssvcTechnicalImpact, c.ssvcTechnicalImpact === "total" ? "med" : ""],
  ].filter(([, v]) => v);
});

const v4Metrics = computed(() => parseCvssVector(cve.value?.cvssV4Vector));

function openRelated(id) {
  state.selectedId = id;
}

function showAllForProduct() {
  const p = (cve.value?.affectedProducts || []).find((x) => cleanName(x.product));
  if (p) filterBy(p.vendor, p.product);
}

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
              <span v-if="cve.publicExploit && !cve.inKEV" class="badge warn"><Icon name="bug" :size="11" />Exploit evidence</span>
              <span v-if="cve.cvssVersion" class="badge">CVSS {{ cve.cvssVersion }}</span>
              <span v-if="cve.state && cve.state !== 'PUBLISHED'" class="badge warn">{{ cve.state }}</span>
            </div>
          </div>
        </section>

        <p v-if="cve.kevOnly" class="kev-only-note">
          <Icon name="alert" :size="14" /> CISA lists this CVE as exploited, but its record hasn't reached the CVE list this server mirrors yet.
          Details below come from the KEV catalog and fill in automatically when the record arrives.
        </p>

        <!-- Risk signals -->
        <section class="signals">
          <div class="signal" :title="cve.epss ? 'Probability of exploitation activity in the next 30 days (FIRST EPSS)' : 'No EPSS score published'">
            <div class="sig-label">EPSS · 30-day exploit likelihood</div>
            <div class="sig-value num" :class="epssLevel(cve.epss)">{{ fmtEpss(cve.epss) }}</div>
            <template v-if="cve.epss">
              <div class="pct-bar"><span :class="epssLevel(cve.epss)" :style="{ width: cve.epssPercentile * 100 + '%' }" /></div>
              <div class="sig-sub">{{ fmtPercentile(cve.epssPercentile) }}</div>
            </template>
          </div>
          <div v-if="ssvc" class="signal">
            <div class="sig-label">CISA SSVC</div>
            <ul class="ssvc">
              <li v-for="[k, v, lvl] in ssvc" :key="k" :class="lvl"><span class="muted">{{ k }}</span> {{ v }}</li>
            </ul>
          </div>
          <div v-if="cve.cvssV4Score" class="signal">
            <div class="sig-label">CVSS 4.0</div>
            <div class="sig-value num">
              <span class="sev-pill" :class="severityKey(cve.cvssV4Severity)">{{ cve.cvssV4Score.toFixed(1) }}</span>
              <span class="sig-sev">{{ SEVERITY_LABEL[severityKey(cve.cvssV4Severity)] }}</span>
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
          <details v-if="v4Metrics.length" class="v4">
            <summary>CVSS 4.0 metrics</summary>
            <div class="metrics">
              <div v-for="m in v4Metrics" :key="m.key" class="metric" :class="riskLabel[m.risk]" :title="`${m.key}: ${m.value}`">
                <span class="m-label">{{ m.label }}</span>
                <span class="m-value">{{ m.value }}</span>
              </div>
            </div>
            <button class="vector mono" @click="copy(cve.cvssV4Vector, 'vec4')">
              {{ cve.cvssV4Vector }}
              <Icon :name="copied === 'vec4' ? 'check' : 'copy'" :size="12" />
            </button>
          </details>
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

        <!-- Related -->
        <section v-if="related && (related.sameProduct.length || related.sameWeakness.length)" class="block">
          <h4>Related</h4>
          <div v-if="related.sameProduct.length" class="rel-group">
            <div class="rel-head">
              <span>Same product <span class="count num">{{ related.sameProductTotal }}</span></span>
              <button v-if="related.sameProductTotal > related.sameProduct.length" class="link-btn" @click="showAllForProduct">Show all in list</button>
            </div>
            <ul class="rel-list">
              <li v-for="r in related.sameProduct" :key="r.id">
                <button @click="openRelated(r.id)">
                  <span class="sev-pill sm" :class="severityKey(r.baseSeverity)">{{ r.baseScore ? r.baseScore.toFixed(1) : "—" }}</span>
                  <span class="rel-id mono">{{ r.id }}</span>
                  <span class="rel-title">{{ summaryText(r) }}</span>
                  <span v-if="r.inKEV" class="badge kev">KEV</span>
                </button>
              </li>
            </ul>
          </div>
          <div v-if="related.sameWeakness.length" class="rel-group">
            <div class="rel-head">
              <span>Same weakness ({{ cve.cwe }}) from this vendor <span class="count num">{{ related.sameWeaknessTotal }}</span></span>
            </div>
            <ul class="rel-list">
              <li v-for="r in related.sameWeakness" :key="r.id">
                <button @click="openRelated(r.id)">
                  <span class="sev-pill sm" :class="severityKey(r.baseSeverity)">{{ r.baseScore ? r.baseScore.toFixed(1) : "—" }}</span>
                  <span class="rel-id mono">{{ r.id }}</span>
                  <span class="rel-title">{{ summaryText(r) }}</span>
                  <span v-if="r.inKEV" class="badge kev">KEV</span>
                </button>
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

.kev-only-note {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  margin: 16px 0 0;
  padding: 10px 12px;
  border-radius: var(--radius);
  background: var(--warn-soft);
  color: var(--warn);
  font-size: 12.5px;
  line-height: 1.5;
}
.kev-only-note .icon {
  margin-top: 2px;
}
.signals {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 8px;
  margin-top: 16px;
}
.signal {
  padding: 10px 12px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface-2);
}
.sig-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--text-3);
}
.sig-value {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
  font-size: 20px;
  font-weight: 700;
  color: var(--text-2);
}
.sig-value.med {
  color: var(--warn);
}
.sig-value.high {
  color: var(--danger);
}
.sig-sev {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-2);
}
.sig-sub {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-3);
}
.pct-bar {
  height: 4px;
  margin-top: 6px;
  border-radius: 2px;
  background: var(--surface-hover);
  overflow: hidden;
}
.pct-bar span {
  display: block;
  height: 100%;
  background: var(--text-3);
}
.pct-bar span.med {
  background: var(--warn);
}
.pct-bar span.high {
  background: var(--danger);
}
.ssvc {
  margin: 6px 0 0;
  padding: 0;
  list-style: none;
  font-size: 12.5px;
  line-height: 1.6;
}
.ssvc li.med {
  color: var(--warn);
  font-weight: 600;
}
.ssvc li.high {
  color: var(--danger);
  font-weight: 600;
}
.ssvc .muted {
  font-weight: 400;
}
.v4 {
  margin-top: 12px;
}
.v4 summary {
  cursor: pointer;
  font-size: 12.5px;
  color: var(--text-2);
  margin-bottom: 8px;
}
.rel-group + .rel-group {
  margin-top: 14px;
}
.rel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-2);
}
.rel-head .count {
  font-weight: 500;
  color: var(--text-3);
}
.link-btn {
  padding: 0;
  border: 0;
  background: none;
  color: var(--accent-text);
  font-size: 12.5px;
}
.link-btn:hover {
  text-decoration: underline;
}
.rel-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.rel-list button {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 5px 6px;
  border: 0;
  border-radius: 5px;
  background: none;
  text-align: left;
}
.rel-list button:hover {
  background: var(--surface-hover);
}
.sev-pill.sm {
  min-width: 32px;
  height: 18px;
  font-size: 11px;
}
.rel-id {
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}
.rel-title {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12.5px;
  color: var(--text-2);
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
