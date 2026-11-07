<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import Icon from "./Icon.vue";

const emit = defineEmits(["close", "open"]);
const lab = ref(null);
const jobs = ref([]);
const error = ref("");
const filter = ref("all");
const busy = ref("");
const selected = ref(null);
const events = ref([]);
const artifacts = ref([]);
const detailError = ref("");
const detailLoading = ref(false);
const copied = ref("");
let timer = null;
let detailGeneration = 0;

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
const signatures = computed(() => selected.value?.result?.signatures || []);

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
    if (selected.value) await loadDetail(selected.value.id, false);
    error.value = "";
  } catch (e) {
    error.value = e.message || "Could not load Signature Lab runs.";
  }
}

async function loadDetail(id, showLoading = true) {
  const current = ++detailGeneration;
  if (showLoading) detailLoading.value = true;
  try {
    const [job, stream, artifactList] = await Promise.all([
      jsonFetch(`/api/siglab/jobs/${encodeURIComponent(id)}`),
      jsonFetch(`/api/siglab/jobs/${encodeURIComponent(id)}/events?after=0`),
      jsonFetch(`/api/siglab/jobs/${encodeURIComponent(id)}/artifacts`),
    ]);
    if (current !== detailGeneration) return;
    selected.value = job;
    events.value = stream.events || [];
    artifacts.value = artifactList.artifacts || [];
    detailError.value = "";
  } catch (e) {
    if (current !== detailGeneration) return;
    detailError.value = e.message || "Could not load run details.";
  } finally {
    if (current === detailGeneration) detailLoading.value = false;
  }
}

function selectJob(job) {
  selected.value = job;
  events.value = [];
  artifacts.value = [];
  detailError.value = "";
  loadDetail(job.id);
}

function closeDetail() {
  detailGeneration++;
  selected.value = null;
  events.value = [];
  artifacts.value = [];
  detailLoading.value = false;
  detailError.value = "";
}

async function copyValue(value, key) {
  try {
    await navigator.clipboard.writeText(value || "");
    copied.value = key;
    setTimeout(() => { if (copied.value === key) copied.value = ""; }, 1600);
  } catch {
    detailError.value = "Clipboard access was denied.";
  }
}

function artifactURL(artifact) {
  return `/api/siglab/jobs/${encodeURIComponent(selected.value.id)}/artifacts/${encodeURIComponent(artifact.name)}`;
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
    <section class="panel" role="dialog" aria-label="Signature Lab runs" @keydown.esc.stop="selected ? closeDetail() : emit('close')">
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
            <tr v-for="job in visible" :key="job.id" :class="{ selected: selected?.id === job.id }" @click="selectJob(job)">
              <td><button class="cve" @click.stop="emit('open', job.cve_id)">{{ job.cve_id }}</button><button class="job mono" @click.stop="selectJob(job)">{{ job.id }}</button></td>
              <td><span class="status" :class="job.status"><span class="dot" />{{ label(job.status) }}</span></td>
              <td class="capitalize">{{ label(job.stage) }}</td>
              <td><div class="progress"><span :style="{ width: Math.round((job.progress || 0) * 100) + '%' }" /></div><span class="pct num">{{ Math.round((job.progress || 0) * 100) }}%</span></td>
              <td :title="job.updated_at">{{ when(job.updated_at) }}</td>
              <td class="detail">
                <span v-if="job.error" class="failure">{{ job.error.code }} · {{ job.error.message }}</span>
                <span v-else-if="job.result">{{ label(job.result.outcome) }} · {{ job.result.summary }}</span>
                <span v-else class="muted">{{ job.client_ref }}</span>
              </td>
              <td><button v-if="activeStates.has(job.status)" class="btn ghost sm" :disabled="busy === job.id" @click.stop="cancel(job)">{{ busy === job.id ? "Cancelling…" : "Cancel" }}</button><button v-else class="btn ghost sm" @click.stop="selectJob(job)">View</button></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">{{ error ? "No run data available." : `No ${filter === 'all' ? '' : filter + ' '}runs.` }}</div>
      </div>

      <div v-if="selected || detailLoading" class="detail-overlay" @mousedown.self="closeDetail">
      <section class="run-detail" role="dialog" aria-modal="true" aria-label="Signature Lab run details">
        <div v-if="detailLoading && !selected" class="empty">Loading run details…</div>
        <template v-else-if="selected">
          <header class="detail-head">
            <div>
              <div class="eyebrow">{{ selected.cve_id }} · <span class="mono">{{ selected.id }}</span></div>
              <h3>{{ selected.result?.summary || selected.error?.message || `Signature Lab ${label(selected.status)}` }}</h3>
            </div>
            <button class="btn ghost icon" aria-label="Close run details" @click="closeDetail"><Icon name="x" /></button>
          </header>

          <div class="detail-meta">
            <div><span>Status</span><b class="capitalize">{{ label(selected.status) }}</b></div>
            <div><span>Stage</span><b class="capitalize">{{ label(selected.stage) }}</b></div>
            <div><span>Iteration</span><b class="num">{{ selected.iteration }} / {{ selected.max_iterations }}</b></div>
            <div><span>Updated</span><b>{{ when(selected.updated_at) }}</b></div>
            <div v-if="selected.result?.outcome"><span>Outcome</span><b class="capitalize">{{ label(selected.result.outcome) }}</b></div>
          </div>

          <div v-if="selected.error" class="banner detail-banner">
            <Icon name="alert" :size="14" />
            <div><b>{{ selected.error.code }}</b><div>{{ selected.error.message || selected.error.detail }}</div></div>
          </div>
          <div v-if="detailError" class="banner detail-banner"><Icon name="alert" :size="14" /> {{ detailError }}</div>

          <div v-if="signatures.length" class="detail-section">
            <h4>Generated signatures</h4>
            <article v-for="(signature, index) in signatures" :key="signature.name" class="signature-card">
              <div class="signature-head">
                <div><b>{{ signature.name }}</b><span class="muted">{{ signature.confidence }} confidence · {{ signature.recommended_action }}</span></div>
                <div class="head-actions">
                  <button class="btn ghost sm" @click="copyValue(signature.rule, `rule-${index}`)"><Icon :name="copied === `rule-${index}` ? 'check' : 'copy'" :size="12" /> {{ copied === `rule-${index}` ? "Copied" : "Copy rule" }}</button>
                  <button class="btn ghost sm" @click="copyValue(signature.cli, `cli-${index}`)"><Icon :name="copied === `cli-${index}` ? 'check' : 'copy'" :size="12" /> {{ copied === `cli-${index}` ? "Copied" : "Copy CLI" }}</button>
                </div>
              </div>
              <pre>{{ signature.rule }}</pre>
              <p v-if="signature.rationale">{{ signature.rationale }}</p>
              <div v-if="signature.tests?.matrix?.length" class="matrix">
                <div v-for="row in signature.tests.matrix" :key="row.fortios_version">
                  <b>FortiOS {{ row.fortios_version }}</b>
                  <span>Positive {{ row.positive?.passed }}/{{ row.positive?.total }}</span>
                  <span>Benign {{ row.negative?.passed }}/{{ row.negative?.total }}</span>
                  <strong :class="row.result">{{ row.result }}</strong>
                </div>
              </div>
            </article>
          </div>

          <div class="detail-grid">
            <div class="detail-section">
              <h4>Stage history</h4>
              <ol class="timeline">
                <li v-for="stage in selected.stages" :key="stage.name" :class="stage.status">
                  <span class="dot" /><div><b class="capitalize">{{ label(stage.name) }}</b><p>{{ stage.summary || label(stage.status) }}</p></div>
                </li>
              </ol>
            </div>
            <div class="detail-section">
              <h4>Artifacts</h4>
              <div v-if="artifacts.length" class="artifact-list">
                <a v-for="artifact in artifacts" :key="artifact.name" :href="artifact.sensitive ? undefined : artifactURL(artifact)" :class="{ disabled: artifact.sensitive }" target="_blank">
                  <Icon name="download" :size="13" /><span><b>{{ artifact.name }}</b><small>{{ label(artifact.kind) }} · {{ artifact.size }} bytes<span v-if="artifact.sensitive"> · restricted</span></small></span>
                </a>
              </div>
              <p v-else class="muted">No downloadable artifacts were recorded.</p>
            </div>
          </div>

          <div class="detail-section">
            <h4>Event log</h4>
            <ol class="event-log">
              <li v-for="event in events" :key="event.seq"><span class="num">{{ event.seq }}</span><time>{{ when(event.ts) }}</time><b class="capitalize">{{ label(event.stage) }}</b><p>{{ event.message }}</p></li>
            </ol>
          </div>
        </template>
      </section>
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
tbody tr { cursor: pointer; }
tbody tr:hover, tbody tr.selected { background: var(--surface-hover); }
.cve { padding: 0; border: 0; background: none; color: var(--accent-text); font: inherit; font-weight: 650; }
.job { display: block; margin-top: 2px; padding: 0; border: 0; background: none; color: var(--text-3); font-size: 10.5px; }
.capitalize { text-transform: capitalize; }
.detail { min-width: 300px; max-width: 520px; white-space: normal; }
.progress { display: inline-block; width: 72px; height: 5px; margin-right: 6px; border-radius: 3px; overflow: hidden; background: var(--surface-hover); vertical-align: middle; }
.progress span { display: block; height: 100%; background: var(--accent); }
.pct { color: var(--text-3); font-size: 11px; }
.empty { padding: 48px; text-align: center; color: var(--text-3); }
.detail-overlay { position: fixed; inset: 0; z-index: 70; display: grid; place-items: start center; padding: 64px 18px; overflow-y: auto; background: #0a0c12a6; }
.run-detail { width: min(1280px, 100%); max-height: calc(100vh - 128px); overflow-y: auto; padding: 18px; border: 1px solid var(--border); border-radius: 9px; background: var(--surface); box-shadow: var(--shadow-lg); }
.detail-head, .signature-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; }
.detail-head h3 { margin: 4px 0 0; font-size: 16px; }
.eyebrow { color: var(--text-3); font-size: 11px; }
.detail-meta { display: flex; flex-wrap: wrap; gap: 20px; margin: 16px 0; }
.detail-meta div { display: grid; gap: 3px; }
.detail-meta span { color: var(--text-3); font-size: 10px; text-transform: uppercase; letter-spacing: .05em; }
.detail-meta b { font-size: 12px; }
.detail-banner { margin: 10px 0; }
.detail-section { margin-top: 18px; min-width: 0; }
.detail-section h4 { margin: 0 0 9px; font-size: 12px; text-transform: uppercase; color: var(--text-2); letter-spacing: .04em; }
.signature-card { padding: 13px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface); }
.signature-head > div:first-child { display: grid; gap: 3px; }
.signature-card pre { overflow-x: auto; margin: 11px 0 8px; padding: 11px; border-radius: 6px; background: var(--code-bg, #11151d); color: var(--code-text, #e5e7eb); font-size: 11px; white-space: pre-wrap; word-break: break-word; }
.signature-card p { margin: 6px 0; color: var(--text-2); font-size: 12px; }
.matrix { display: grid; gap: 5px; margin-top: 10px; }
.matrix > div { display: flex; gap: 14px; align-items: center; padding: 7px 9px; border-radius: 5px; background: var(--surface-hover); font-size: 11px; }
.matrix strong { margin-left: auto; text-transform: uppercase; }
.matrix strong.pass { color: var(--ok); }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
.timeline, .event-log { margin: 0; padding: 0; list-style: none; }
.timeline li { display: flex; gap: 8px; padding: 5px 0; }
.timeline li.completed .dot { background: var(--ok); }
.timeline li.failed .dot { background: var(--danger); }
.timeline b { font-size: 11px; }
.timeline p { margin: 1px 0 0; color: var(--text-3); font-size: 11px; }
.artifact-list { display: grid; gap: 5px; }
.artifact-list a { display: flex; gap: 8px; align-items: center; padding: 7px 9px; border: 1px solid var(--border); border-radius: 5px; color: var(--text); text-decoration: none; }
.artifact-list a:hover { background: var(--surface-hover); }
.artifact-list a.disabled { opacity: .55; pointer-events: none; }
.artifact-list span { display: grid; }
.artifact-list small { color: var(--text-3); }
.event-log { max-height: 280px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; }
.event-log li { display: grid; grid-template-columns: 28px 150px 80px 1fr; gap: 8px; padding: 7px 9px; border-bottom: 1px solid var(--border); font-size: 11px; }
.event-log li:last-child { border-bottom: 0; }
.event-log time, .event-log > li > span { color: var(--text-3); }
.event-log p { margin: 0; }
@media (max-width: 700px) { .overlay { padding: 12px; } .lab-state { width: 100%; margin-left: 0; } .detail-overlay { padding: 12px; } .run-detail { max-height: calc(100vh - 24px); } }
@media (max-width: 850px) { .detail-grid { grid-template-columns: 1fr; } .event-log li { grid-template-columns: 25px 1fr; } .event-log time { display: none; } .event-log p { grid-column: 2; } }
</style>
