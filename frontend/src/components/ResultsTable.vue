<script setup>
import { computed, watch, nextTick } from "vue";
import Icon from "./Icon.vue";
import { state, results, addUnique } from "../lib/store.js";
import { SEVERITY_LABEL, severityKey, fmtDate, fmtRelative, daysFromToday, cleanName, summaryText, fmtEpss, epssLevel } from "../lib/format.js";

const props = defineProps({ cursor: { type: Number, default: -1 } });
const emit = defineEmits(["open", "update:cursor"]);

const isKev = computed(() => state.view === "kev");

function dueStatus(cve) {
  const d = daysFromToday(cve.kevDueDate);
  if (d == null) return null;
  // Long-past deadlines are the norm for older entries; only flag recent misses
  if (d < -30) return { cls: "", text: "Past due" };
  if (d < 0) return { cls: "danger", text: `${-d}d overdue` };
  if (d === 0) return { cls: "danger", text: "Due today" };
  if (d <= 14) return { cls: "warn", text: `Due in ${d}d` };
  return { cls: "", text: `Due in ${d}d` };
}

function epssTitle(cve) {
  if (!cve.epss) return "No EPSS score";
  return `EPSS: ${fmtEpss(cve.epss)} chance of exploitation in the next 30 days · ${Math.round(cve.epssPercentile * 100)}th percentile`;
}

function sortBy(key) {
  if (state.sort.by === key) state.sort.desc = !state.sort.desc;
  else state.sort = { by: key, desc: key !== "id" && key !== "vendor" && key !== "kevDueDate" };
}

function filterVendor(v) {
  addUnique(state.filters.vendors, v);
}
function filterProduct(v, p) {
  addUnique(state.filters.vendors, v);
  addUnique(state.filters.products, p);
}
function filterCwe(c) {
  state.filters.cwe = c;
}

// Keep the keyboard cursor row in view
watch(
  () => props.cursor,
  async (i) => {
    await nextTick();
    document.querySelector(`[data-row="${i}"]`)?.scrollIntoView({ block: "nearest" });
  }
);
</script>

<template>
  <div class="table-wrap">
    <table class="results" :class="{ kev: isKev, stale: results.loading }">
      <thead>
        <tr>
          <th class="c-score">
            <button :class="{ sorted: state.sort.by === 'baseScore' }" @click="sortBy('baseScore')">
              CVSS
              <Icon v-if="state.sort.by === 'baseScore'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
            </button>
          </th>
          <th class="c-epss">
            <button :class="{ sorted: state.sort.by === 'epss' }" title="Exploit Prediction Scoring System: probability of exploitation in the next 30 days" @click="sortBy('epss')">
              EPSS
              <Icon v-if="state.sort.by === 'epss'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
            </button>
          </th>
          <th class="c-id">
            <button :class="{ sorted: state.sort.by === 'id' }" @click="sortBy('id')">
              CVE
              <Icon v-if="state.sort.by === 'id'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
            </button>
          </th>
          <th class="c-summary">
            <button :class="{ sorted: state.sort.by === 'vendor' }" @click="sortBy('vendor')">
              Vulnerability
              <Icon v-if="state.sort.by === 'vendor'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
            </button>
          </th>
          <template v-if="isKev">
            <th class="c-date">
              <button :class="{ sorted: state.sort.by === 'kevDateAdded' }" @click="sortBy('kevDateAdded')">
                Added
                <Icon v-if="state.sort.by === 'kevDateAdded'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
              </button>
            </th>
            <th class="c-due">
              <button :class="{ sorted: state.sort.by === 'kevDueDate' }" @click="sortBy('kevDueDate')">
                Due
                <Icon v-if="state.sort.by === 'kevDueDate'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
              </button>
            </th>
          </template>
          <th v-else class="c-date">
            <button :class="{ sorted: state.sort.by === 'datePublished' }" @click="sortBy('datePublished')">
              Published
              <Icon v-if="state.sort.by === 'datePublished'" :name="state.sort.desc ? 'arrowDown' : 'arrowUp'" :size="12" />
            </button>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(cve, i) in results.cves"
          :key="cve.id"
          :data-row="i"
          :class="{ cursor: i === cursor, selected: state.selectedId === cve.id }"
          @click="emit('update:cursor', i), emit('open', cve.id)"
        >
          <td class="c-score">
            <span
              class="sev-pill"
              :class="severityKey(cve.baseSeverity)"
              :title="cve.baseScore ? `${SEVERITY_LABEL[severityKey(cve.baseSeverity)]} · CVSS ${cve.cvssVersion}` : 'No CVSS score'"
            >
              {{ cve.baseScore ? cve.baseScore.toFixed(1) : "—" }}
            </span>
            <span class="sev-text">{{ SEVERITY_LABEL[severityKey(cve.baseSeverity)] }}</span>
          </td>
          <td class="c-epss num" :title="epssTitle(cve)">
            <span class="epss" :class="epssLevel(cve.epss)">{{ fmtEpss(cve.epss) }}</span>
            <span v-if="cve.epss" class="epss-bar"><span :style="{ width: cve.epssPercentile * 100 + '%' }" :class="epssLevel(cve.epss)" /></span>
          </td>
          <td class="c-id">
            <a class="id mono" :href="`?cve=${cve.id}`" @click.prevent>{{ cve.id }}</a>
            <div class="id-badges">
              <span v-if="cve.inKEV && !isKev" class="badge kev" title="In CISA Known Exploited Vulnerabilities catalog">KEV</span>
              <span v-if="cve.kevKnownRansomwareCampaign === 'Known'" class="badge danger" title="Known use in ransomware campaigns">
                <Icon name="lock" :size="11" />Ransomware
              </span>
              <span v-if="cve.publicExploit && !cve.inKEV" class="badge warn" title="Public exploit, proof of concept, or active exploitation reported">
                <Icon name="bug" :size="11" />Exploit
              </span>
            </div>
          </td>
          <td class="c-summary">
            <div class="title">{{ isKev ? cve.kevName || summaryText(cve) : summaryText(cve) }}</div>
            <div class="meta">
              <template v-if="cleanName(cve.vendor)">
                <button class="link" :title="`Filter by vendor ${cve.vendor}`" @click.stop="filterVendor(cve.vendor)">{{ cve.vendor }}</button>
              </template>
              <template v-if="cleanName(cve.product)">
                <span v-if="cleanName(cve.vendor)" class="sep">/</span>
                <button class="link" :title="`Filter by product ${cve.product}`" @click.stop="filterProduct(cve.vendor, cve.product)">{{ cve.product }}</button>
              </template>
              <span v-if="cve.affectedCount > 1" class="more" :title="`${cve.affectedCount} affected products`">+{{ cve.affectedCount - 1 }}</span>
              <template v-if="cve.cwe">
                <span class="dot">·</span>
                <button class="link mono cwe" :title="`Filter by ${cve.cwe}`" @click.stop="filterCwe(cve.cwe)">{{ cve.cwe }}</button>
              </template>
              <template v-if="cve.attackVector">
                <span class="dot">·</span>
                <span class="av">{{ cve.attackVector.toLowerCase() }}</span>
              </template>
            </div>
          </td>
          <template v-if="isKev">
            <td class="c-date num" :title="fmtDate(cve.kevDateAdded)">
              {{ fmtDate(cve.kevDateAdded) }}
              <div class="sub">{{ fmtRelative(cve.kevDateAdded) }}</div>
            </td>
            <td class="c-due num">
              {{ fmtDate(cve.kevDueDate) }}
              <div v-if="dueStatus(cve)" class="sub" :class="dueStatus(cve).cls">{{ dueStatus(cve).text }}</div>
            </td>
          </template>
          <td v-else class="c-date num">
            {{ fmtDate(cve.datePublished) }}
            <div class="sub">{{ fmtRelative(cve.datePublished) }}</div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.table-wrap {
  width: 100%;
}
.results {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  table-layout: fixed;
  transition: opacity 0.15s;
}
.results.stale {
  opacity: 0.6;
}
th {
  position: sticky;
  top: 0;
  z-index: 2;
  height: 34px;
  padding: 0 8px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-weight: 500;
}
th button {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  height: 24px;
  padding: 0 6px;
  margin-left: -6px;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--text-3);
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
th button:hover {
  background: var(--surface-hover);
  color: var(--text);
}
th button.sorted {
  color: var(--text);
}
td {
  padding: 9px 8px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tbody tr {
  cursor: pointer;
}
tbody tr:hover td {
  background: var(--surface-hover);
}
tbody tr.cursor td {
  background: var(--surface-hover);
}
tbody tr.cursor td:first-child {
  box-shadow: inset 2px 0 0 var(--accent);
}
tbody tr.selected td {
  background: var(--surface-active);
}

.c-score {
  width: 76px;
  padding-left: 16px;
}
.c-id {
  width: 160px;
}
.c-epss {
  width: 70px;
}
.epss {
  display: block;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-3);
}
.epss.low {
  color: var(--text-2);
}
.epss.med {
  color: var(--warn);
}
.epss.high {
  color: var(--danger);
}
.epss-bar {
  display: block;
  width: 44px;
  height: 3px;
  margin-top: 5px;
  border-radius: 2px;
  background: var(--surface-hover);
  overflow: hidden;
}
.epss-bar span {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: var(--border-strong);
}
.epss-bar span.med {
  background: var(--warn);
}
.epss-bar span.high {
  background: var(--danger);
}
.c-date {
  width: 118px;
  text-align: right;
}
.c-due {
  width: 118px;
  text-align: right;
}
th.c-date,
th.c-due {
  text-align: right;
}
th.c-date button,
th.c-due button {
  margin-left: 0;
  margin-right: -6px;
}
.sev-text {
  display: block;
  margin-top: 3px;
  font-size: 11px;
  color: var(--text-3);
}
.id {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
}
.id:hover {
  color: var(--accent-text);
  text-decoration: none;
}
.id-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 4px;
}
.id-badges:empty {
  display: none;
}
.title {
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.meta {
  display: flex;
  align-items: baseline;
  gap: 4px;
  margin-top: 2px;
  font-size: 12.5px;
  color: var(--text-3);
  white-space: nowrap;
  overflow: hidden;
}
.link {
  padding: 0;
  border: 0;
  background: none;
  color: var(--text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 40%;
  flex-shrink: 1;
}
.link:hover {
  color: var(--accent-text);
  text-decoration: underline;
}
.cwe {
  font-size: 11.5px;
  flex-shrink: 0;
}
.more {
  font-size: 11px;
  font-weight: 600;
  padding: 0 5px;
  border-radius: 4px;
  background: var(--surface-hover);
  color: var(--text-2);
}
.sep,
.dot {
  color: var(--border-strong);
}
.av {
  text-transform: capitalize;
}
.sub {
  font-size: 11.5px;
  color: var(--text-3);
  margin-top: 2px;
}
.sub.danger {
  color: var(--danger);
  font-weight: 600;
}
.sub.warn {
  color: var(--warn);
  font-weight: 600;
}

@media (max-width: 720px) {
  .c-id {
    width: 132px;
  }
  .c-date,
  .c-due,
  .c-epss {
    display: none;
  }
  .c-score {
    width: 56px;
    padding-left: 12px;
  }
  .sev-text {
    display: none;
  }
  .meta .cwe,
  .meta .av,
  .meta .dot {
    display: none;
  }
  .link {
    max-width: 60%;
  }
}
</style>
