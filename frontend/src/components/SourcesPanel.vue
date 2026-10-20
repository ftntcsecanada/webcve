<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from "vue";
import Icon from "./Icon.vue";
import { fmtNum, fmtRelative } from "../lib/format.js";

const emit = defineEmits(["close"]);

const data = ref(null);
const error = ref(null);
let timer = null;

async function load() {
  try {
    const res = await fetch("/api/sources");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data.value = await res.json();
    error.value = null;
  } catch {
    error.value = "Couldn't reach the server.";
  }
}

onMounted(() => {
  load();
  timer = setInterval(load, 10000);
});
onBeforeUnmount(() => clearInterval(timer));

const summary = computed(() => {
  const list = data.value?.sources || [];
  return {
    errors: list.filter((s) => s.state === "error").length,
    syncing: list.filter((s) => s.state === "syncing").length,
    total: list.length,
  };
});

function when(t) {
  return t && !t.startsWith("0001") ? fmtRelative(t) : "never";
}

function full(t) {
  return t && !t.startsWith("0001") ? new Date(t).toLocaleString() : "";
}

function until(t) {
  if (!t || t.startsWith("0001")) return "—";
  const s = (new Date(t) - Date.now()) / 1000;
  if (s <= 60) return "any moment";
  if (s < 3600) return `in ${Math.round(s / 60)}m`;
  if (s < 86400) return `in ${Math.round(s / 3600)}h`;
  return `in ${Math.round(s / 86400)}d`;
}

function size(b) {
  if (!b) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) {
    b /= 1024;
    i++;
  }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

const STATE_LABEL = { ok: "Up to date", syncing: "Updating", error: "Failing", pending: "Not loaded yet" };
</script>

<template>
  <div class="overlay" @mousedown.self="emit('close')">
    <section class="panel" role="dialog" aria-label="Data sources" @keydown.esc="emit('close')">
      <header class="head">
        <div>
          <h2>Data sources</h2>
          <p class="muted">
            Everything this browser pulls in, when it last changed and when it's checked next. Refreshes every 10 seconds.
          </p>
        </div>
        <button class="btn ghost icon" aria-label="Close" @click="emit('close')"><Icon name="x" /></button>
      </header>

      <div v-if="error" class="banner danger"><Icon name="alert" :size="14" /> {{ error }}</div>
      <div v-else-if="summary.errors" class="banner danger">
        <Icon name="alert" :size="14" /> {{ summary.errors }} source{{ summary.errors > 1 ? "s are" : " is" }} failing to update. Their last good data is still in use.
      </div>

      <div class="table-scroll scroll-thin">
        <table v-if="data">
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th v-tip="'When new data last arrived from this source'">Data updated</th>
              <th v-tip="'Last time the source was checked successfully, even if nothing had changed'">Last checked</th>
              <th>Next check</th>
              <th class="r">Records</th>
              <th class="r" v-tip="'Size of the downloaded data on the server'">Size</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="s in data.sources" :key="s.name">
              <tr :class="s.state">
                <td class="src">
                  <a :href="s.url" target="_blank" rel="noopener noreferrer" class="src-name">{{ s.label }}</a>
                  <div class="src-desc">{{ s.description }}</div>
                  <div class="src-int">Checked {{ s.interval }}</div>
                </td>
                <td>
                  <span class="state" :class="s.state">
                    <span v-if="s.state === 'syncing'" class="spin" />
                    <span v-else class="dot" />
                    {{ STATE_LABEL[s.state] || s.state }}
                  </span>
                  <div v-if="s.detail" class="detail">{{ s.detail }}</div>
                </td>
                <td :title="full(s.lastChange)">{{ when(s.lastChange) }}</td>
                <td :title="full(s.lastSuccess)">{{ when(s.lastSuccess) }}</td>
                <td :title="full(s.nextCheck)">{{ until(s.nextCheck) }}</td>
                <td class="r num">
                  {{ s.records ? fmtNum(s.records) : "—" }}
                  <div v-if="s.recordUnit" class="unit">{{ s.recordUnit }}</div>
                </td>
                <td class="r num">{{ size(s.bytes) }}</td>
              </tr>
              <tr v-if="s.error" class="err-row">
                <td colspan="7">
                  <Icon name="alert" :size="13" />
                  <span>Last error {{ when(s.errorAt) }}:</span>
                  <code>{{ s.error }}</code>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
        <div v-else-if="!error" class="loading">Loading…</div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.overlay {
  position: fixed;
  inset: 0;
  z-index: 60;
  display: grid;
  place-items: start center;
  padding: 48px 16px;
  background: rgba(10, 12, 18, 0.45);
  overflow-y: auto;
}
.panel {
  width: min(1100px, 100%);
  border-radius: 12px;
  background: var(--surface);
  box-shadow: var(--shadow-lg);
}
.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 20px 12px;
}
h2 {
  margin: 0;
  font-size: 17px;
}
.head p {
  margin: 4px 0 0;
  font-size: 13px;
}
.banner {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0 20px 12px;
  padding: 8px 12px;
  border-radius: var(--radius);
  font-size: 13px;
}
.banner.danger {
  background: var(--danger-soft);
  color: var(--danger);
}
.table-scroll {
  overflow-x: auto;
  padding: 0 8px 12px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-3);
  white-space: nowrap;
}
td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  white-space: nowrap;
}
.r {
  text-align: right;
}
.src {
  white-space: normal;
  min-width: 260px;
}
.src-name {
  font-weight: 600;
  color: var(--text);
}
.src-desc {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
  max-width: 420px;
}
.src-int {
  margin-top: 2px;
  font-size: 11.5px;
  color: var(--text-3);
}
.state {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
}
.state .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-3);
}
.state.ok .dot {
  background: var(--ok);
}
.state.error {
  color: var(--danger);
}
.state.error .dot {
  background: var(--danger);
}
.state.syncing {
  color: var(--accent-text);
}
.spin {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent);
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.detail,
.unit {
  margin-top: 2px;
  font-size: 11.5px;
  font-weight: 400;
  color: var(--text-3);
  white-space: normal;
}
.err-row td {
  padding-top: 0;
  color: var(--danger);
  font-size: 12px;
  white-space: normal;
}
tr:has(+ .err-row) td {
  border-bottom: 0;
}
.err-row td > * {
  vertical-align: middle;
}
.err-row span {
  margin: 0 6px;
}
.err-row code {
  font-family: var(--mono);
  font-size: 11.5px;
  word-break: break-word;
}
.loading {
  padding: 32px;
  text-align: center;
  color: var(--text-3);
}
</style>
