<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import Icon from "./Icon.vue";

const emit = defineEmits(["close", "open"]);
const lab = ref(null);
const jobs = ref([]);
const error = ref("");
const filter = ref("all");
const busy = ref("");
let timer = null;

const activeStates = new Set(["queued", "running", "needs_input", "cancelling"]);
const counts = computed(() => ({
  all: jobs.value.length,
  active: jobs.value.filter((j) => activeStates.has(j.status)).length,
  failed: jobs.value.filter((j) => j.status === "failed").length,
  succeeded: jobs.value.filter((j) => j.status === "succeeded").length,
}));
const visible = computed(() => jobs.value.filter((job) => {
  if (filter.value === "active") return activeStates.has(job.status);
  if (filter.value === "all") return true;
  return job.status === filter.value;
}));

async function jsonFetch(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.error || `Request failed (${response.status})`);
  return body;
}

async function load() {
  try {
    lab.value = await jsonFetch("/api/siglab/status");
    if (!lab.value.configured || !lab.value.reachable) {
      jobs.value = [];
      error.value = lab.value.detail || "Signature Lab is not reachable.";
      return;
    }
    const result = await jsonFetch("/api/siglab/jobs?limit=100");
    jobs.value = result.jobs || [];
    error.value = "";
  } catch (e) {
    error.value = e.message || "Could not load Signature Lab runs.";
  }
}

async function cancel(job) {
  if (!activeStates.has(job.status)) return;
  busy.value = job.id;
  try {
    await jsonFetch(`/api/siglab/jobs/${encodeURIComponent(job.id)}/cancel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Cancelled from the WebCVE runs view" }),
    });
    await load();
  } catch (e) {
    error.value = e.message || "Cancellation failed.";
  } finally {
    busy.value = "";
  }
}

function when(value) {
  return value ? new Date(value).toLocaleString() : "—";
}
function label(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

onMounted(() => {
  load();
  timer = setInterval(load, 5000);
});
onBeforeUnmount(() => clearInterval(timer));
</script>

<template>
  <div class="overlay" @mousedown.self="emit('close')">
    <section class="panel" role="dialog" aria-label="Signature Lab runs" @keydown.esc="emit('close')">
      <header class="head">
        <div>
          <h2>FortiGate Signature Lab runs</h2>
          <p class="muted">All queued, running, failed, and completed jobs. Refreshes every five seconds.</p>
        </div>
        <div class="head-actions">
          <button class="btn sm" @click="load"><Icon name="refresh" :size="13" /> Refresh</button>
          <button class="btn ghost icon" aria-label="Close" @click="emit('close')"><Icon name="x" /></button>
        </div>
      </header>

      <div class="summary">
        <button v-for="key in ['all', 'active', 'failed', 'succeeded']" :key="key" :class="{ on: filter === key }" @click="filter = key">
          <span>{{ label(key) }}</span><b class="num">{{ counts[key] }}</b>
        </button>
        <span class="lab-state" :class="{ ok: lab?.reachable, bad: lab && !lab.reachable }">
          <span class="dot" />{{ lab?.reachable ? "Lab reachable" : "Lab unavailable" }}
        </span>
      </div>

      <div v-if="error" class="banner"><Icon name="alert" :size="14" /> {{ error }}</div>

      <div class="table-scroll scroll-thin">
        <table v-if="visible.length">
          <thead><tr><th>CVE</th><th>Status</th><th>Stage</th><th>Progress</th><th>Updated</th><th>Outcome / error</th><th /></tr></thead>
          <tbody>
            <tr v-for="job in visible" :key="job.id">
              <td><button class="cve" @click="emit('open', job.cve_id)">{{ job.cve_id }}</button><div class="job mono">{{ job.id }}</div></td>
              <td><span class="status" :class="job.status"><span class="dot" />{{ label(job.status) }}</span></td>
              <td class="capitalize">{{ label(job.stage) }}</td>
              <td><div class="progress"><span :style="{ width: Math.round((job.progress || 0) * 100) + '%' }" /></div><span class="pct num">{{ Math.round((job.progress || 0) * 100) }}%</span></td>
              <td :title="job.updated_at">{{ when(job.updated_at) }}</td>
              <td class="detail">
                <span v-if="job.error" class="failure">{{ job.error.code }} · {{ job.error.message }}</span>
                <span v-else-if="job.result">{{ label(job.result.outcome) }} · {{ job.result.summary }}</span>
                <span v-else class="muted">{{ job.client_ref }}</span>
              </td>
              <td><button v-if="activeStates.has(job.status)" class="btn ghost sm" :disabled="busy === job.id" @click="cancel(job)">{{ busy === job.id ? "Cancelling…" : "Cancel" }}</button></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">{{ error ? "No run data available." : `No ${filter === 'all' ? '' : filter + ' '}runs.` }}</div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; z-index: 60; display: grid; place-items: start center; padding: 48px 16px; background: #0a0c1273; overflow-y: auto; }
.panel { width: min(1320px, 100%); border-radius: 12px; background: var(--surface); box-shadow: var(--shadow-lg); }
.head { display: flex; justify-content: space-between; gap: 16px; padding: 18px 20px 12px; }
.head h2 { margin: 0; font-size: 17px; }
.head p { margin: 4px 0 0; font-size: 13px; }
.head-actions, .summary { display: flex; align-items: center; gap: 8px; }
.summary { padding: 0 20px 14px; flex-wrap: wrap; }
.summary button { display: flex; gap: 12px; align-items: center; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); padding: 5px 10px; text-transform: capitalize; }
.summary button.on { color: var(--accent-text); border-color: var(--accent); background: var(--accent-soft); }
.lab-state { margin-left: auto; display: inline-flex; align-items: center; gap: 6px; color: var(--text-3); }
.dot { width: 8px; height: 8px; display: inline-block; border-radius: 50%; background: var(--text-3); }
.lab-state.ok .dot, .status.succeeded .dot { background: var(--ok); }
.lab-state.bad, .failure, .status.failed { color: var(--danger); }
.lab-state.bad .dot, .status.failed .dot { background: var(--danger); }
.status.running .dot, .status.queued .dot, .status.cancelling .dot { background: var(--warn); }
.status { display: inline-flex; align-items: center; gap: 6px; text-transform: capitalize; font-weight: 600; }
.banner { margin: 0 20px 12px; padding: 8px 12px; display: flex; gap: 8px; align-items: center; border-radius: var(--radius); color: var(--danger); background: var(--danger-soft); }
.table-scroll { overflow-x: auto; padding: 0 8px 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; color: var(--text-3); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
td { padding: 10px; border-bottom: 1px solid var(--border); vertical-align: top; white-space: nowrap; }
.cve { padding: 0; border: 0; background: none; color: var(--accent-text); font: inherit; font-weight: 650; }
.job { margin-top: 2px; color: var(--text-3); font-size: 10.5px; }
.capitalize { text-transform: capitalize; }
.detail { min-width: 300px; max-width: 520px; white-space: normal; }
.progress { display: inline-block; width: 72px; height: 5px; margin-right: 6px; border-radius: 3px; overflow: hidden; background: var(--surface-hover); vertical-align: middle; }
.progress span { display: block; height: 100%; background: var(--accent); }
.pct { color: var(--text-3); font-size: 11px; }
.empty { padding: 48px; text-align: center; color: var(--text-3); }
@media (max-width: 700px) { .overlay { padding: 12px; } .lab-state { width: 100%; margin-left: 0; } }
</style>
