<script setup>
import { computed, onBeforeUnmount, ref, watch } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({ cve: { type: Object, required: true } });

const lab = ref({ configured: false, reachable: false, status: "checking" });
const job = ref(null);
const events = ref([]);
const error = ref("");
const actionBusy = ref(false);
let pollTimer = null;
let generation = 0;

const active = computed(() => ["queued", "running", "needs_input", "cancelling"].includes(job.value?.status));
const terminal = computed(() => ["succeeded", "failed", "cancelled"].includes(job.value?.status));
const progress = computed(() => Math.round((job.value?.progress || 0) * 100));
const lastEvent = computed(() => events.value.at(-1));
const stateLabel = computed(() => {
  if (lab.value.status === "checking") return "Checking lab";
  if (!lab.value.configured) return "Not configured";
  if (!lab.value.reachable) return "Lab unreachable";
  if (!job.value) return "Ready";
  return String(job.value.status || "unknown").replaceAll("_", " ");
});

function schedule(ms) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(refresh, ms);
}

async function jsonFetch(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.error || `Request failed (${response.status})`);
  return body;
}

async function refresh() {
  const current = ++generation;
  clearTimeout(pollTimer);
  try {
    const status = await jsonFetch("/api/siglab/status");
    if (current !== generation) return;
    lab.value = status;
    if (!status.configured || !status.reachable) {
      schedule(15000);
      return;
    }
    const listing = await jsonFetch(`/api/siglab/jobs?cve_id=${encodeURIComponent(props.cve.id)}&limit=10`);
    if (current !== generation) return;
    const latest = listing.jobs?.[0] || null;
    if (!latest) {
      job.value = null;
      events.value = [];
      error.value = "";
      schedule(15000);
      return;
    }
    job.value = await jsonFetch(`/api/siglab/jobs/${encodeURIComponent(latest.id)}`);
    const stream = await jsonFetch(`/api/siglab/jobs/${encodeURIComponent(latest.id)}/events?after=0`);
    if (current !== generation) return;
    events.value = stream.events || [];
    error.value = "";
    schedule(active.value ? 3000 : 15000);
  } catch (e) {
    if (current !== generation) return;
    error.value = e.message || "Signature Lab status failed";
    schedule(10000);
  }
}

async function startJob() {
  actionBusy.value = true;
  error.value = "";
  try {
    const key = `webcve-${props.cve.id.toLowerCase()}-${Date.now()}`;
    job.value = await jsonFetch(`/api/cves/${encodeURIComponent(props.cve.id)}/siglab/jobs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": key },
      body: JSON.stringify({
        actionPreference: "block",
        maxIterations: 3,
        freshResearch: terminal.value,
        analystNotes: "Submitted from WebCVE. Require live differential and false-positive validation.",
      }),
    });
    events.value = [];
    schedule(500);
  } catch (e) {
    error.value = e.message || "Could not start Signature Lab job";
  } finally {
    actionBusy.value = false;
  }
}

async function cancelJob() {
  if (!job.value?.id || !active.value) return;
  actionBusy.value = true;
  error.value = "";
  try {
    job.value = await jsonFetch(`/api/siglab/jobs/${encodeURIComponent(job.value.id)}/cancel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Cancelled by an analyst in WebCVE" }),
    });
    schedule(500);
  } catch (e) {
    error.value = e.message || "Could not cancel Signature Lab job";
  } finally {
    actionBusy.value = false;
  }
}

watch(
  () => props.cve.id,
  () => {
    generation++;
    job.value = null;
    events.value = [];
    error.value = "";
    lab.value = { configured: false, reachable: false, status: "checking" };
    schedule(0);
  },
  { immediate: true }
);

onBeforeUnmount(() => {
  generation++;
  clearTimeout(pollTimer);
});
</script>

<template>
  <section class="siglab block" :class="{ active }">
    <div class="lab-head">
      <div>
        <h4>FortiGate Signature Lab</h4>
        <div class="lab-state">
          <span class="status-dot" :class="{ ready: lab.reachable && !active, running: active, bad: error || !lab.configured || !lab.reachable }" />
          <span class="capitalize">{{ stateLabel }}</span>
          <template v-if="job"> · {{ job.stage }} · {{ progress }}%</template>
        </div>
      </div>
      <div class="lab-actions">
        <button v-if="active" class="btn sm ghost" :disabled="actionBusy || job.status === 'cancelling'" @click="cancelJob">
          <Icon name="x" :size="12" /> {{ job.status === "cancelling" ? "Cancelling" : "Cancel" }}
        </button>
        <button v-else class="btn sm" :disabled="actionBusy || !lab.reachable" @click="startJob">
          <Icon name="shield" :size="12" /> {{ terminal ? "Run again" : "Build signature" }}
        </button>
      </div>
    </div>

    <div v-if="active" class="lab-progress"><span :style="{ width: progress + '%' }" /></div>
    <p v-if="lastEvent" class="lab-event">{{ lastEvent.message }}</p>
    <p v-else-if="!lab.configured" class="lab-event">Set WEBCVE_SIGLAB_URL and WEBCVE_SIGLAB_TOKEN when provisioning this container.</p>
    <p v-else-if="!job && lab.reachable" class="lab-event">The lab is reachable. No run has been submitted for this CVE.</p>
    <p v-if="job?.error" class="lab-error">{{ job.error.detail || job.error.code || "Validation failed" }}</p>
    <p v-if="error" class="lab-error">{{ error }}</p>

    <dl v-if="job" class="lab-meta">
      <div><dt>Job</dt><dd class="mono">{{ job.id }}</dd></div>
      <div><dt>Updated</dt><dd>{{ job.updated_at ? new Date(job.updated_at).toLocaleString() : "—" }}</dd></div>
      <div v-if="job.result?.outcome"><dt>Outcome</dt><dd>{{ job.result.outcome.replaceAll("_", " ") }}</dd></div>
    </dl>
  </section>
</template>

<style scoped>
.siglab {
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 7px;
  padding: 12px 14px;
}
.siglab.active { border-left-color: var(--warn); }
.lab-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.lab-head h4 { margin: 0 0 4px; }
.lab-actions { display: flex; gap: 6px; }
.lab-state { color: var(--text-2); font-size: 12px; }
.capitalize { text-transform: capitalize; }
.status-dot { display: inline-block; width: 7px; height: 7px; margin-right: 5px; border-radius: 50%; background: var(--text-3); }
.status-dot.ready { background: var(--ok); }
.status-dot.running { background: var(--warn); box-shadow: 0 0 0 3px color-mix(in srgb, var(--warn) 18%, transparent); }
.status-dot.bad { background: var(--danger); }
.lab-progress { height: 4px; margin: 10px 0 7px; overflow: hidden; border-radius: 3px; background: var(--surface-hover); }
.lab-progress span { display: block; height: 100%; transition: width .25s ease; background: var(--accent); }
.lab-event, .lab-error { margin: 8px 0 0; font-size: 12.5px; color: var(--text-2); }
.lab-error { color: var(--danger); }
.lab-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 7px 14px; margin: 10px 0 0; }
.lab-meta div { min-width: 0; }
.lab-meta dt { color: var(--text-3); font-size: 11px; text-transform: uppercase; }
.lab-meta dd { margin: 2px 0 0; overflow: hidden; text-overflow: ellipsis; font-size: 12px; text-transform: capitalize; }
</style>
