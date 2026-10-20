<script setup>
import { computed } from "vue";
import Icon from "./Icon.vue";
import Combobox from "./Combobox.vue";
import { state, results, saved, toggleIn, resetFilters, activeFilterCount, openSaved, removeSaved } from "../lib/store.js";
import { SEVERITIES, SEVERITY_LABEL, ATTACK_VECTORS, ATTACK_VECTOR_LABEL, EXPLOIT_SOURCES, fmtNum } from "../lib/format.js";
import { explain } from "../lib/glossary.js";

defineEmits(["close"]);

const f = state.filters;
const isKev = computed(() => state.view === "kev");
const thisYear = new Date().getFullYear();

const yearPresets = [
  ["This year", thisYear, null],
  ["2 yrs", thisYear - 1, null],
  ["5 yrs", thisYear - 4, null],
  ["Any", null, null],
];

const kevDayOptions = [
  [0, "Any time"],
  [7, "7 days"],
  [30, "30 days"],
  [90, "90 days"],
  [365, "1 year"],
];

const epssPresets = [
  [null, "Any"],
  [0.01, "≥1%"],
  [0.1, "≥10%"],
  [0.5, "≥50%"],
];

const duePresets = [
  ["", "Any"],
  ["overdue", "Overdue"],
  ["7", "≤ 7 days"],
  ["30", "≤ 30 days"],
];

const scorePresets = [
  ["9+", 9, null],
  ["7+", 7, null],
  ["4+", 4, null],
  ["Any", null, null],
];

function yearPresetActive(from, to) {
  return f.yearFrom === from && f.yearTo === to;
}

function setYears(from, to) {
  f.yearFrom = from;
  f.yearTo = to;
}

function setScore(min, max) {
  f.scoreMin = min;
  f.scoreMax = max;
}

const maxSev = computed(() => Math.max(1, ...SEVERITIES.map((s) => results.facets.severity?.[s] || 0)));
const maxEx = computed(() => Math.max(1, ...EXPLOIT_SOURCES.map(([k]) => results.facets.exploitSources?.[k] || 0)));
const maxAv = computed(() => Math.max(1, ...ATTACK_VECTORS.map((a) => results.facets.attackVector?.[a] || 0)));

function onNumber(key, e) {
  const v = e.target.value === "" ? null : Number(e.target.value);
  f[key] = Number.isFinite(v) ? v : null;
}
</script>

<template>
  <aside class="panel scroll-thin" aria-label="Filters">
    <div class="panel-head">
      <span class="panel-title">Filters</span>
      <button v-if="activeFilterCount()" class="btn ghost sm" @click="resetFilters">Clear all</button>
      <button class="btn ghost sm icon close" aria-label="Close filters" @click="$emit('close')"><Icon name="x" /></button>
    </div>

    <section v-if="saved.list.length" class="group saved">
      <h3>Saved searches</h3>
      <ul class="saved-list">
        <li v-for="s in saved.list" :key="s.id" :class="{ on: saved.active?.id === s.id }">
          <button class="saved-open" :title="`Open “${s.name}”`" @click="openSaved(s)">
            <Icon name="search" :size="13" />
            <span class="saved-name">{{ s.name }}</span>
            <span v-if="saved.counts[s.id]" class="saved-new num" :title="`${saved.counts[s.id]} published or added to KEV since you last opened it`">
              {{ fmtNum(saved.counts[s.id]) }} new
            </span>
          </button>
          <button class="saved-x" :aria-label="`Delete saved search ${s.name}`" @click="removeSaved(s.id)"><Icon name="x" :size="12" /></button>
        </li>
      </ul>
    </section>

    <section v-if="!isKev" class="group">
      <label class="switch-row">
        <span class="switch-label">
          <span v-tip="explain('KEV')" class="badge kev" tabindex="0">KEV</span>
          Known exploited only
        </span>
        <span class="count num">{{ fmtNum(results.facets.kev) }}</span>
        <input v-model="f.kevOnly" type="checkbox" class="switch" />
      </label>
    </section>

    <template v-else>
      <section class="group">
        <h3><Term k="Due date">Remediation due</Term></h3>
        <div class="seg">
          <button v-for="[v, label] in duePresets" :key="v" :class="{ on: f.kevDue === v }" @click="f.kevDue = v">{{ label }}</button>
        </div>
      </section>
      <section class="group">
        <h3>Added to catalog</h3>
        <div class="seg">
          <button
            v-for="[d, label] in kevDayOptions"
            :key="d"
            :class="{ on: f.kevDays === d }"
            @click="f.kevDays = d"
          >
            {{ label }}
          </button>
        </div>
      </section>
      <section class="group">
        <label class="switch-row">
          <span class="switch-label"><Icon name="lock" :size="14" /> <Term k="Ransomware">Used in ransomware</Term></span>
          <span class="count num">{{ fmtNum(results.facets.ransomware) }}</span>
          <input v-model="f.ransomware" type="checkbox" class="switch" />
        </label>
      </section>
    </template>

    <section class="group">
      <h3>Severity</h3>
      <div class="facets">
        <button
          v-for="s in SEVERITIES"
          :key="s"
          class="facet"
          :class="{ on: f.severities.includes(s) }"
          :aria-pressed="f.severities.includes(s)"
          @click="toggleIn(f.severities, s)"
        >
          <span class="check"><Icon v-if="f.severities.includes(s)" name="check" :size="11" /></span>
          <span class="sev-dot" :class="s" />
          <span v-if="s === 'NONE'" v-tip="explain('Unscored')" class="facet-label">{{ SEVERITY_LABEL[s] }}</span>
          <span v-else class="facet-label">{{ SEVERITY_LABEL[s] }}</span>
          <span class="count num">{{ fmtNum(results.facets.severity?.[s]) }}</span>
          <span class="bar" :style="{ width: ((results.facets.severity?.[s] || 0) / maxSev) * 100 + '%' }" />
        </button>
      </div>
    </section>

    <section class="group">
      <h3><Term k="Exploit evidence" /></h3>
      <div class="facets">
        <button class="facet" :class="{ on: f.exploit }" :aria-pressed="f.exploit" @click="f.exploit = !f.exploit">
          <span class="check"><Icon v-if="f.exploit" name="check" :size="11" /></span>
          <span class="facet-label">Any evidence</span>
          <span class="count num">{{ fmtNum(results.facets.exploit) }}</span>
        </button>
        <button
          v-for="[k, label, term] in EXPLOIT_SOURCES"
          :key="k"
          v-tip="term ? explain(term) : 'An exploit link in the CVE references that isn\'t from one of the sources above.'"
          class="facet sub"
          :class="{ on: f.exploitSources.includes(k) }"
          :aria-pressed="f.exploitSources.includes(k)"
          @click="toggleIn(f.exploitSources, k)"
        >
          <span class="check"><Icon v-if="f.exploitSources.includes(k)" name="check" :size="11" /></span>
          <span class="facet-label">{{ label }}</span>
          <span class="count num">{{ fmtNum(results.facets.exploitSources?.[k]) }}</span>
          <span class="bar neutral" :style="{ width: ((results.facets.exploitSources?.[k] || 0) / maxEx) * 100 + '%' }" />
        </button>
      </div>
    </section>

    <section class="group">
      <h3>Exploit likelihood (<Term k="EPSS" />)</h3>
      <div class="seg">
        <button v-for="[v, label] in epssPresets" :key="label" :class="{ on: f.epssMin === v }" @click="f.epssMin = v">{{ label }}</button>
      </div>
    </section>

    <section class="group">
      <h3><Term k="CVSS" /> score</h3>
      <div class="seg">
        <button
          v-for="[label, min, max] in scorePresets"
          :key="label"
          :class="{ on: f.scoreMin === min && f.scoreMax === max }"
          @click="setScore(min, max)"
        >
          {{ label }}
        </button>
      </div>
      <div class="range">
        <input class="input sm" type="number" min="0" max="10" step="0.1" placeholder="Min" :value="f.scoreMin ?? ''" @change="onNumber('scoreMin', $event)" />
        <span class="muted">–</span>
        <input class="input sm" type="number" min="0" max="10" step="0.1" placeholder="Max" :value="f.scoreMax ?? ''" @change="onNumber('scoreMax', $event)" />
      </div>
    </section>

    <section class="group">
      <h3><Term k="Attack vector">Attack vector</Term></h3>
      <div class="facets">
        <button
          v-for="a in ATTACK_VECTORS"
          :key="a"
          class="facet"
          :class="{ on: f.attackVectors.includes(a) }"
          :aria-pressed="f.attackVectors.includes(a)"
          @click="toggleIn(f.attackVectors, a)"
        >
          <span class="check"><Icon v-if="f.attackVectors.includes(a)" name="check" :size="11" /></span>
          <span class="facet-label">{{ ATTACK_VECTOR_LABEL[a] }}</span>
          <span class="count num">{{ fmtNum(results.facets.attackVector?.[a]) }}</span>
          <span class="bar neutral" :style="{ width: ((results.facets.attackVector?.[a] || 0) / maxAv) * 100 + '%' }" />
        </button>
      </div>
    </section>

    <section class="group">
      <h3>Published</h3>
      <div class="seg">
        <button
          v-for="[label, from, to] in yearPresets"
          :key="label"
          :class="{ on: yearPresetActive(from, to) }"
          @click="setYears(from, to)"
        >
          {{ label }}
        </button>
      </div>
      <div class="range">
        <input class="input sm" type="number" min="1999" :max="thisYear" placeholder="From" :value="f.yearFrom ?? ''" @change="onNumber('yearFrom', $event)" />
        <span class="muted">–</span>
        <input class="input sm" type="number" min="1999" :max="thisYear" placeholder="To" :value="f.yearTo ?? ''" @change="onNumber('yearTo', $event)" />
      </div>
    </section>

    <section class="group">
      <h3>Vendor</h3>
      <Combobox v-model="f.vendors" field="vendor" placeholder="Any vendor" />
    </section>

    <section class="group">
      <h3>Product</h3>
      <Combobox
        v-model="f.products"
        field="product"
        :placeholder="f.vendors.length ? 'Products of selected vendors' : 'Any product'"
        :extra="() => (f.vendors.length ? { vendors: f.vendors } : {})"
      />
    </section>

    <section class="group">
      <h3>Weakness (<Term k="CWE" />)</h3>
      <Combobox v-model="f.cwe" field="cwe" placeholder="e.g. CWE-79" />
    </section>
  </aside>
</template>

<style scoped>
.panel {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 12px 14px 32px;
  overflow-y: auto;
}
.panel-head {
  display: flex;
  align-items: center;
  gap: 4px;
  height: 32px;
  margin-bottom: 4px;
}
.panel-title {
  flex: 1;
  font-weight: 650;
  font-size: 13px;
}
.close {
  display: none;
}
.group {
  padding: 10px 0;
  border-top: 1px solid var(--border);
}
.group:first-of-type {
  border-top: 0;
}
h3 {
  margin: 0 0 8px;
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-3);
}
.facets {
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.facet {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding: 0 8px;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  text-align: left;
  overflow: hidden;
}
.facet:hover {
  background: var(--surface-hover);
}
.facet.sub {
  padding-left: 22px;
}
.facet .bar {
  position: absolute;
  left: 0;
  bottom: 0;
  height: 2px;
  border-radius: 2px;
  background: var(--border-strong);
  transition: width 0.25s ease;
}
.facet.on .bar {
  background: var(--accent);
}
.check {
  display: grid;
  place-items: center;
  width: 15px;
  height: 15px;
  border-radius: 4px;
  border: 1.5px solid var(--border-strong);
  color: #fff;
  flex-shrink: 0;
}
.facet.on .check {
  background: var(--accent);
  border-color: var(--accent);
}
.facet-label {
  flex: 1;
  font-size: 13px;
}
.count {
  font-size: 12px;
  color: var(--text-3);
}
.facet.on .facet-label {
  font-weight: 600;
}

.switch-row {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 13px;
}
.switch-label {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 6px;
}
.switch {
  appearance: none;
  position: relative;
  width: 30px;
  height: 18px;
  margin: 0;
  border-radius: 999px;
  background: var(--border-strong);
  cursor: pointer;
  transition: background 0.15s;
  flex-shrink: 0;
}
.switch::after {
  content: "";
  position: absolute;
  top: 2px;
  left: 2px;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
  transition: transform 0.15s;
}
.switch:checked {
  background: var(--kev);
}
.switch:checked::after {
  transform: translateX(12px);
}

.seg {
  display: flex;
  padding: 2px;
  gap: 2px;
  border-radius: var(--radius-sm);
  background: var(--surface-hover);
}
.seg button {
  flex: 1;
  height: 26px;
  padding: 0 4px;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--text-2);
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}
.seg button:hover {
  color: var(--text);
}
.seg button.on {
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-sm), 0 0 0 1px var(--border);
}
.hint {
  margin: 6px 0 0;
  font-size: 11.5px;
  color: var(--text-3);
}
.saved-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.saved-list li {
  display: flex;
  align-items: center;
  border-radius: var(--radius-sm);
}
.saved-list li:hover,
.saved-list li.on {
  background: var(--surface-hover);
}
.saved-list li.on .saved-name {
  font-weight: 600;
}
.saved-open {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding: 0 8px;
  border: 0;
  background: none;
  text-align: left;
  color: var(--text-2);
}
.saved-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text);
  font-size: 13px;
}
.saved-new {
  flex-shrink: 0;
  padding: 0 6px;
  border-radius: 999px;
  background: var(--accent);
  color: #fff;
  font-size: 11px;
  font-weight: 600;
  line-height: 18px;
}
.saved-x {
  display: grid;
  place-items: center;
  width: 26px;
  height: 26px;
  margin-right: 2px;
  border: 0;
  border-radius: 5px;
  background: none;
  color: var(--text-3);
  opacity: 0;
}
.saved-list li:hover .saved-x,
.saved-x:focus-visible {
  opacity: 1;
}
.saved-x:hover {
  color: var(--text);
}
.range {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
}
.input.sm {
  height: 28px;
  font-size: 13px;
}

@media (max-width: 900px) {
  .close {
    display: inline-flex;
  }
}
</style>
