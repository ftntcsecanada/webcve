<script setup>
import { ref, computed, onMounted } from "vue";
import Icon from "./Icon.vue";
import { fmtNum, fmtDate } from "../lib/format.js";

// A one-page, print-ready summary of the current vendor comparison, with the
// methodology and caveats attached so the numbers hold up when shared.
const props = defineProps({
  rows: { type: Array, required: true },
  title: { type: String, required: true },
  scope: { type: String, default: "" },
  groupBy: { type: String, default: "vendor" },
  yearFrom: Number,
  yearTo: Number,
});
const emit = defineEmits(["close"]);

const sources = ref([]);
const copied = ref(false);

onMounted(async () => {
  try {
    const res = await fetch("/api/sources");
    if (res.ok) sources.value = (await res.json()).sources || [];
  } catch {
    // The brief still works without source timestamps
  }
});

const rows = computed(() => props.rows.slice(0, 15));
const today = new Date().toISOString().slice(0, 10);

function pct(v) {
  if (!v) return "0%";
  const p = v * 100;
  return p < 1 ? `${p.toFixed(1)}%` : `${Math.round(p)}%`;
}
function days(v) {
  return v >= 0 ? `${v}d` : "—";
}
function delta(r) {
  if (!r.nvdCompared) return "—";
  return `${r.nvdDelta > 0 ? "+" : ""}${r.nvdDelta.toFixed(1)}`;
}

// Plain-text version for email or chat
function asText() {
  const head = ["Vendor", "CVEs", "Crit/High", "KEV", "KEV rate", "Exploited at disclosure", "Days to KEV", "Exploit rate", "Self-published"];
  const lines = [
    props.title,
    `${props.scope}. Generated ${today} from public CVE, CISA KEV, NVD, EPSS and exploit-database data.`,
    "",
    head.join(" | "),
    head.map(() => "---").join(" | "),
    ...rows.value.map((r) =>
      [r.name, fmtNum(r.cves), pct(r.critHighPct), fmtNum(r.kev), pct(r.kevPct) + (r.kev < 5 ? "†" : ""), r.kev ? `${r.zeroDay} (${pct(r.zeroDayPct)})` : "—", days(r.daysToKev), pct(r.exploitPct), pct(r.selfPubPct)].join(" | ")
    ),
    "",
    "† Fewer than 5 KEV entries: exploitation rates are unstable at this sample size.",
    "Read rates, not counts: CVE volume reflects product footprint and how actively a vendor discloses its own flaws.",
  ];
  return lines.join("\n");
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

function print() {
  window.print();
}

function when(t) {
  return t && !t.startsWith("0001") ? fmtDate(t) : "—";
}
</script>

<template>
  <div class="brief-overlay" @mousedown.self="emit('close')" @keydown.esc="emit('close')">
    <div class="toolbar no-print">
      <span class="muted">Comparison brief · print or save as PDF to share</span>
      <span class="spacer" />
      <button class="btn sm" @click="copyText"><Icon :name="copied ? 'check' : 'copy'" :size="13" /> {{ copied ? "Copied" : "Copy as text" }}</button>
      <button class="btn sm primary" @click="print"><Icon name="download" :size="13" /> Print / PDF</button>
      <button class="btn ghost sm icon" aria-label="Close" @click="emit('close')"><Icon name="x" /></button>
    </div>

    <article class="page">
      <header>
        <div class="kicker">CVE landscape brief · {{ fmtDate(today) }}</div>
        <h1>{{ title }}</h1>
        <p class="scope">{{ scope }}</p>
      </header>

      <table class="t">
        <thead>
          <tr>
            <th>{{ groupBy === "product" ? "Product" : "Vendor" }}</th>
            <th class="r">CVEs</th>
            <th class="r">Crit/High</th>
            <th class="r">KEV</th>
            <th class="r">KEV rate</th>
            <th class="r">Exploited at disclosure</th>
            <th class="r">Median days to KEV</th>
            <th class="r">Exploit rate</th>
            <th class="r">Self-published</th>
            <th class="r">CVSS vs NVD</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.key">
            <td class="name">{{ r.name }}</td>
            <td class="r">{{ fmtNum(r.cves) }}</td>
            <td class="r">{{ pct(r.critHighPct) }}</td>
            <td class="r">{{ fmtNum(r.kev) }}</td>
            <td class="r">
              {{ pct(r.kevPct) }}<sup v-if="r.kev < 5">†</sup>
              <span class="bar"><span :style="{ width: Math.min(100, (r.kevPct / Math.max(...rows.map((x) => x.kevPct), 1e-9)) * 100) + '%' }" /></span>
            </td>
            <td class="r">{{ r.kev ? `${r.zeroDay} (${pct(r.zeroDayPct)})` : "—" }}<sup v-if="r.kev && r.kev < 5">†</sup></td>
            <td class="r">{{ days(r.daysToKev) }}</td>
            <td class="r">{{ pct(r.exploitPct) }}</td>
            <td class="r">{{ pct(r.selfPubPct) }}</td>
            <td class="r">{{ delta(r) }}</td>
          </tr>
        </tbody>
      </table>
      <p class="note">
        <template v-if="props.rows.length > rows.length">Top {{ rows.length }} of {{ props.rows.length }} shown, in the current sort order. </template>
        <template v-if="rows.some((r) => r.kev < 5)">† Fewer than 5 KEV entries: exploitation rates are unstable at this sample size.</template>
      </p>

      <section class="method">
        <h2>How to read this</h2>
        <ul>
          <li>
            <b>Read rates, not counts.</b> CVE volume reflects product footprint and disclosure practice. Vendors with mature
            security teams publish more of their own flaws (see Self-published), which raises their counts without meaning
            their products are less secure.
          </li>
          <li><b>KEV rate</b> is the share of a vendor's CVEs that CISA lists as exploited in the wild: where attackers actually focus.</li>
          <li>
            <b>Exploited at disclosure</b> counts KEV entries listed within a day of the CVE's publication. These are often
            flaws disclosed because attacks were already under way, so this reflects attacker targeting as well as how fast
            a vendor publishes once exploitation is found.
          </li>
          <li><b>Median days to KEV</b> is the typical time from publication to CISA listing; lower means faster exploitation after disclosure.</li>
          <li><b>Exploit rate</b> is the share with any public exploit evidence (exploit code, PoCs, scanner templates, or reported exploitation).</li>
          <li><b>CVSS vs NVD</b> is the average gap between the vendor's own scores and NVD's for the same CVEs (negative = vendor scores lower).</li>
          <li>
            Vendor names are merged across spellings. CVEs listing several vendors count for each. CVE records rarely say who
            found a flaw consistently across vendors, so "found internally" isn't compared.
          </li>
        </ul>
      </section>

      <section v-if="sources.length" class="sources">
        <h2>Data</h2>
        <p>
          <template v-for="(s, i) in sources.filter((x) => ['cve', 'kev', 'nvd', 'epss', 'exploitdb', 'metasploit', 'github-poc'].includes(x.name))" :key="s.name">
            {{ s.label }} ({{ when(s.lastChange) }})<template v-if="i < 6">, </template>
          </template>.
          Years shown: {{ yearFrom }}–{{ yearTo }}.
        </p>
      </section>
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
  max-width: 1000px;
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
/* The page is always light, like paper */
.page {
  max-width: 1000px;
  margin: 0 auto;
  padding: 36px 40px 40px;
  border-radius: 0 0 10px 10px;
  background: #fff;
  color: #14171f;
  font-size: 12.5px;
  line-height: 1.5;
}
.kicker {
  font-size: 11px;
  font-weight: 650;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #5b6475;
}
h1 {
  margin: 4px 0 4px;
  font-size: 22px;
  letter-spacing: -0.01em;
}
.scope {
  margin: 0 0 18px;
  color: #4b5363;
}
.t {
  width: 100%;
  border-collapse: collapse;
}
.t th {
  padding: 6px 8px;
  border-bottom: 2px solid #14171f;
  font-size: 10.5px;
  font-weight: 650;
  text-align: left;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: #4b5363;
  vertical-align: bottom;
}
.t td {
  padding: 6px 8px;
  border-bottom: 1px solid #e3e6eb;
  font-variant-numeric: tabular-nums;
}
.t .name {
  font-weight: 600;
}
.r {
  text-align: right;
}
.bar {
  display: block;
  width: 60px;
  height: 3px;
  margin: 3px 0 0 auto;
  background: #eef0f3;
}
.bar span {
  display: block;
  height: 100%;
  margin-left: auto;
  background: #7c3aed;
}
.note {
  margin: 6px 0 0;
  font-size: 11px;
  color: #7a8293;
}
.method,
.sources {
  margin-top: 22px;
}
h2 {
  margin: 0 0 6px;
  font-size: 13px;
}
.method ul {
  margin: 0;
  padding-left: 18px;
  color: #303746;
}
.method li + li {
  margin-top: 4px;
}
.sources p {
  margin: 0;
  color: #4b5363;
  font-size: 11.5px;
}
</style>
