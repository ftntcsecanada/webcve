<script setup>
import { ref, computed, onMounted } from "vue";
import Icon from "./Icon.vue";
import { fmtDate, fmtEpss, fmtPercentile, severityKey, SEVERITY_LABEL, cleanName, EVIDENCE_LABEL } from "../lib/format.js";
import { PEER_GROUPS } from "../lib/peers.js";

// One-page summary of a CVE for customer conversations: what it is, whether
// it's exploited, how to fix it, and how it compares with peers.
const props = defineProps({ cve: { type: Object, required: true } });
const emit = defineEmits(["close"]);

const c = computed(() => props.cve);
const sev = computed(() => severityKey(c.value.baseSeverity));
const copied = ref(false);
const peerContext = ref(null);

// The peer group containing this CVE's vendor, if any
const group = computed(() => {
  const vendors = [c.value.vendor, ...(c.value.affectedProducts || []).map((p) => p.vendor)].map((v) => (v || "").toLowerCase());
  return PEER_GROUPS.find((g) => g.vendors.some((gv) => vendors.some((v) => v && (v.startsWith(gv.toLowerCase()) || gv.toLowerCase().startsWith(v)))));
});

onMounted(async () => {
  if (!c.value.cwe) return;
  const req = { cwe: c.value.cwe, inKEV: true, pageSize: 6, sortBy: "kevDateAdded", sortDesc: true };
  if (group.value) req.vendors = group.value.vendors;
  try {
    const res = await fetch("/api/cves", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) });
    if (res.ok) {
      const d = await res.json();
      const others = (d.cves || []).filter((x) => x.id !== c.value.id);
      // The total includes this CVE when it matches its own query
      peerContext.value = { total: d.total - (c.value.inKEV ? 1 : 0), cves: others.slice(0, 5) };
    }
  } catch {
    // Optional section
  }
});

const products = computed(() => {
  const list = (c.value.affectedProducts || []).filter((p) => cleanName(p.vendor) || cleanName(p.product));
  return list.length ? list : c.value.nvdProducts || [];
});

const evidence = computed(() => {
  const kinds = new Map();
  for (const e of c.value.exploitEvidence || []) kinds.set(e.kind, (kinds.get(e.kind) || 0) + 1);
  return [...kinds].map(([k, n]) => `${EVIDENCE_LABEL[k] || k}${n > 1 ? ` (${n})` : ""}`);
});

const status = computed(() => {
  if (c.value.inKEV) return { cls: "kev", text: "Known exploited (CISA KEV)" };
  if (c.value.ssvcExploitation === "active" || c.value.euvdExploitedSince || c.value.msrc?.exploited) return { cls: "kev", text: "Exploitation reported" };
  if (evidence.value.length) return { cls: "warn", text: "Public exploit evidence" };
  return { cls: "", text: "No known exploitation" };
});

function asText() {
  const x = c.value;
  const lines = [
    `${x.id}: ${x.title || x.kevName || ""}`,
    `Severity: ${x.baseScore ? `${x.baseScore.toFixed(1)} ${SEVERITY_LABEL[sev.value]} (CVSS ${x.cvssVersion})` : "unscored"} · EPSS ${fmtEpss(x.epss)} · ${status.value.text}`,
    "",
    x.description || "",
    "",
    products.value.length ? `Affected: ${products.value.slice(0, 6).map((p) => `${p.vendor} ${p.product}`).join("; ")}` : "",
    x.inKEV ? `CISA KEV: added ${x.kevDateAdded}, remediation due ${x.kevDueDate}${x.kevKnownRansomwareCampaign === "Known" ? ", used in ransomware" : ""}` : "",
    evidence.value.length ? `Exploit evidence: ${evidence.value.join(", ")}` : "",
    (x.packages || []).length ? `Fixed in: ${x.packages.slice(0, 6).map((p) => `${p.name} ${p.fixed?.join("/") || "(see advisory)"}`).join("; ")}` : "",
    "",
    `https://nvd.nist.gov/vuln/detail/${x.id}`,
  ];
  return lines.filter((l, i, a) => l !== "" || a[i - 1] !== "").join("\n");
}

// "Cisco Small Business RV" rather than "Cisco Cisco Small Business RV"
function productLabel(p) {
  const v = cleanName(p.vendor), prod = cleanName(p.product);
  if (!prod) return v;
  return v && !prod.toLowerCase().startsWith(v.toLowerCase()) ? `${v} ${prod}` : prod;
}

function print() {
  window.print();
}

async function copyText() {
  try {
    await navigator.clipboard.writeText(asText());
    copied.value = true;
    setTimeout(() => (copied.value = false), 1500);
  } catch {
    // Clipboard unavailable on plain-http origins
  }
}
</script>

<template>
  <div class="brief-overlay" @mousedown.self="emit('close')" @keydown.esc="emit('close')">
    <div class="toolbar no-print">
      <span class="muted">CVE brief · print or save as PDF to share</span>
      <span class="spacer" />
      <button class="btn sm" @click="copyText"><Icon :name="copied ? 'check' : 'copy'" :size="13" /> {{ copied ? "Copied" : "Copy as text" }}</button>
      <button class="btn sm primary" @click="print"><Icon name="download" :size="13" /> Print / PDF</button>
      <button class="btn ghost sm icon" aria-label="Close" @click="emit('close')"><Icon name="x" /></button>
    </div>

    <article class="page">
      <div class="kicker">CVE brief · {{ fmtDate(new Date().toISOString().slice(0, 10)) }}</div>
      <div class="head">
        <div class="score" :class="sev">
          <div class="v">{{ c.baseScore ? c.baseScore.toFixed(1) : "—" }}</div>
          <div class="l">{{ SEVERITY_LABEL[sev] }}</div>
        </div>
        <div>
          <h1>{{ c.id }}</h1>
          <p class="title">{{ c.title || c.kevName }}</p>
          <span class="status" :class="status.cls">{{ status.text }}</span>
        </div>
      </div>

      <div class="facts">
        <div><span>CVSS</span><b>{{ c.baseScore ? `${c.baseScore.toFixed(1)} (v${c.cvssVersion}${c.scoreSource === "nvd" ? ", NVD" : ""})` : "Unscored" }}</b></div>
        <div><span>EPSS (30-day)</span><b>{{ fmtEpss(c.epss) }}</b><small v-if="c.epss">{{ fmtPercentile(c.epssPercentile) }}</small></div>
        <div><span>Published</span><b>{{ fmtDate(c.datePublished) }}</b></div>
        <div v-if="c.inKEV"><span>Added to KEV</span><b>{{ fmtDate(c.kevDateAdded) }}</b><small>due {{ fmtDate(c.kevDueDate) }}</small></div>
        <div v-if="c.cwe"><span>Weakness</span><b>{{ c.cwe }}</b><small>{{ c.cweName }}</small></div>
      </div>

      <p class="desc">{{ c.description }}</p>

      <section v-if="products.length">
        <h2>Affected</h2>
        <p>{{ products.slice(0, 8).map((p) => `${p.vendor} ${p.product}${p.versions ? ` (${p.versions})` : ""}`).join("; ") }}</p>
      </section>

      <section v-if="c.inKEV || evidence.length">
        <h2>Exploitation</h2>
        <ul>
          <li v-if="c.inKEV">
            CISA lists it as exploited in the wild since {{ fmtDate(c.kevDateAdded) }}<template v-if="c.kevKnownRansomwareCampaign === 'Known'">, including use in ransomware campaigns</template>.
          </li>
          <li v-if="evidence.length">Evidence: {{ evidence.join(", ") }}.</li>
          <li v-if="c.kevRequiredAction">Required action: {{ c.kevRequiredAction }}</li>
        </ul>
      </section>

      <section v-if="(c.packages || []).length">
        <h2>Fixed versions</h2>
        <p>{{ c.packages.slice(0, 8).map((p) => `${p.name}: ${p.fixed?.join(", ") || "see advisory"}`).join("; ") }}</p>
      </section>

      <section v-if="peerContext?.cves.length">
        <h2>Context: other exploited {{ c.cwe }} flaws{{ group ? ` in ${group.label.toLowerCase()}` : "" }}</h2>
        <p class="muted-p">{{ peerContext.total }} other KEV entries share this weakness{{ group ? " across this peer group" : "" }}. Most recent:</p>
        <ul>
          <li v-for="p in peerContext.cves" :key="p.id">
            <b>{{ p.id }}</b> {{ productLabel(p) }}: {{ p.kevName || p.title }} (KEV {{ fmtDate(p.kevDateAdded) }})
          </li>
        </ul>
      </section>

      <footer>
        Sources: CVE record, CISA KEV, FIRST EPSS, NVD, Exploit-DB, Metasploit, OSV. Details: nvd.nist.gov/vuln/detail/{{ c.id }}
      </footer>
    </article>
  </div>
</template>

<style scoped>
.brief-overlay {
  position: fixed;
  inset: 0;
  z-index: 70;
  overflow-y: auto;
  padding: 0 16px 48px;
  background: rgba(10, 12, 18, 0.55);
}
.toolbar {
  position: sticky;
  top: 0;
  z-index: 1;
  display: flex;
  align-items: center;
  gap: 8px;
  max-width: 820px;
  margin: 16px auto 0;
  padding: 8px 12px;
  border-radius: 10px 10px 0 0;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.spacer {
  flex: 1;
}
.btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.brief-overlay {
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}
.page {
  max-width: 820px;
  margin: 0 auto;
  padding: 32px 40px 32px;
  border-radius: 0 0 10px 10px;
  background: #fff;
  color: #14171f;
  font-size: 13px;
  line-height: 1.55;
}
.kicker {
  font-size: 11px;
  font-weight: 650;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #5b6475;
}
.head {
  display: flex;
  gap: 16px;
  align-items: center;
  margin: 10px 0 16px;
}
.score {
  display: grid;
  place-items: center;
  width: 70px;
  height: 70px;
  border-radius: 10px;
  background: #a3a8b3;
  color: #fff;
  flex-shrink: 0;
}
.score.CRITICAL { background: #7e1828; }
.score.HIGH { background: #c2302a; }
.score.MEDIUM { background: #e0682a; }
.score.LOW { background: #d4a02c; color: #2b1d00; }
.score .v {
  font-size: 24px;
  font-weight: 700;
  line-height: 1;
}
.score .l {
  font-size: 10px;
  font-weight: 650;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-family: var(--mono);
  font-size: 20px;
}
.title {
  margin: 2px 0 6px;
  font-weight: 600;
}
.status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  background: #eef0f3;
  font-size: 11.5px;
  font-weight: 650;
}
.status.kev {
  background: #f1eaff;
  color: #5b21b6;
}
.status.warn {
  background: #fff4e0;
  color: #9a5b00;
}
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
  padding: 12px 0;
  border-top: 1px solid #e3e6eb;
  border-bottom: 1px solid #e3e6eb;
}
.facts span {
  display: block;
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #6b7280;
}
.facts small {
  display: block;
  color: #6b7280;
}
.desc {
  margin: 14px 0;
}
section {
  margin-top: 14px;
}
h2 {
  margin: 0 0 4px;
  font-size: 13px;
}
section p,
section ul {
  margin: 0;
}
section ul {
  padding-left: 18px;
}
.muted-p {
  color: #6b7280;
}
footer {
  margin-top: 20px;
  padding-top: 10px;
  border-top: 1px solid #e3e6eb;
  font-size: 11px;
  color: #7a8293;
}
</style>
