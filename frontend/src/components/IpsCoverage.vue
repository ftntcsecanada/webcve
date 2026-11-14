<script setup>
import { ref, computed, nextTick, onBeforeUnmount } from "vue";
import Icon from "./Icon.vue";

// "IPS covered" tag that opens the FortiGuard IPS signatures covering a CVE,
// each linked to its FortiGuard encyclopedia page
const props = defineProps({
  rules: { type: Array, required: true }, // [{name, ruleId, action, severity, date}]
  label: { type: String, default: "IPS covered" },
  cve: { type: String, default: "" },
});

const open = ref(false);
const root = ref(null);
const pop = ref(null);
// Fixed to the viewport so scrolling tables don't clip it
const pos = ref({});

const detectOnly = computed(() => props.rules.length > 0 && props.rules.every((r) => r.action !== "block"));
const ruleURL = (r) => `https://www.fortiguard.com/encyclopedia/ips/${r.ruleId}`;

function onDocDown(e) {
  if (root.value && !root.value.contains(e.target)) close();
}
function onKey(e) {
  if (e.key === "Escape") close();
}
function close() {
  open.value = false;
  document.removeEventListener("mousedown", onDocDown, true);
  document.removeEventListener("keydown", onKey, true);
  window.removeEventListener("scroll", close, true);
  window.removeEventListener("resize", close);
}
async function toggle() {
  if (open.value) return close();
  open.value = true;
  document.addEventListener("mousedown", onDocDown, true);
  document.addEventListener("keydown", onKey, true);
  window.addEventListener("scroll", close, true);
  window.addEventListener("resize", close);
  await nextTick();
  const r = root.value?.getBoundingClientRect();
  if (!r || !pop.value) return;
  const w = pop.value.offsetWidth, h = pop.value.offsetHeight;
  const left = Math.max(16, Math.min(r.left, window.innerWidth - w - 16));
  // Below the tag, or above it when there's no room below
  const top = r.bottom + h + 12 > window.innerHeight && r.top > h + 12 ? r.top - h - 6 : r.bottom + 6;
  pos.value = { left: left + "px", top: top + "px" };
}
onBeforeUnmount(close);
</script>

<template>
  <span ref="root" class="ipscov" @click.stop>
    <button
      type="button"
      class="badge ips-covered ipscov-btn"
      :class="{ detect: detectOnly }"
      :aria-expanded="open"
      aria-haspopup="dialog"
      :title="detectOnly ? 'Covered for detection only: the signatures default to pass, not block' : 'Covered by FortiGuard IPS'"
      @click="toggle"
    >
      <Icon name="shield" :size="11" />{{ label }}<template v-if="rules.length > 1"> ({{ rules.length }})</template>
    </button>
    <div v-if="open" ref="pop" class="ipscov-pop" :style="pos" role="dialog" :aria-label="`FortiGuard IPS coverage${cve ? ' for ' + cve : ''}`">
      <div class="ipscov-head">
        <b>FortiGuard IPS coverage</b>
        <span v-if="cve" class="muted mono">{{ cve }}</span>
        <button type="button" class="ipscov-x" aria-label="Close" @click="close"><Icon name="x" :size="13" /></button>
      </div>
      <ul>
        <li v-for="r in rules" :key="r.ruleId">
          <a :href="ruleURL(r)" target="_blank" rel="noopener noreferrer" class="mono ipscov-name">{{ r.name }} <Icon name="external" :size="11" /></a>
          <div class="ipscov-meta">
            <span>Rule {{ r.ruleId }}</span>
            <span v-if="r.severity" class="sev">{{ r.severity }}</span>
            <span :class="r.action === 'block' ? 'ok' : 'warn'">default {{ r.action }}</span>
            <span v-if="r.date">released {{ r.date }}</span>
          </div>
        </li>
      </ul>
      <p v-if="detectOnly" class="ipscov-note">These signatures default to <b>pass</b>: they detect and log, but don't block unless a sensor overrides the action.</p>
      <a class="ipscov-more" href="https://www.fortiguard.com/encyclopedia?type=ips" target="_blank" rel="noopener noreferrer">
        FortiGuard IPS encyclopedia <Icon name="external" :size="11" />
      </a>
    </div>
  </span>
</template>

<style scoped>
.ipscov {
  position: relative;
  display: inline-flex;
}
/* A button, but it must look exactly like the other badges: inherit the
   family only, keep the badge's size and weight */
.ipscov-btn {
  border: 0;
  margin: 0;
  font-family: inherit;
  line-height: inherit;
  cursor: pointer;
}
.ipscov-btn:hover,
.ipscov-btn[aria-expanded="true"] {
  background: color-mix(in srgb, var(--accent) 82%, #000);
}
.ipscov-btn.detect {
  color: var(--warn);
  background: var(--warn-soft);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--warn) 40%, transparent);
}
.ipscov-pop {
  position: fixed;
  z-index: 200;
  width: min(420px, calc(100vw - 32px));
  padding: 10px 12px;
  border-radius: var(--radius);
  background: var(--surface);
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow-lg);
  font-size: 12.5px;
  font-weight: 400;
  text-align: left;
  white-space: normal;
  cursor: default;
  color: var(--text);
}
.ipscov-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.ipscov-x {
  margin-left: auto;
  border: 0;
  background: transparent;
  color: var(--text-3);
  cursor: pointer;
  padding: 2px;
  border-radius: var(--radius-sm);
}
.ipscov-x:hover {
  background: var(--surface-hover);
}
.ipscov-pop ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 8px;
}
.ipscov-name {
  color: var(--accent-text);
  text-decoration: none;
  overflow-wrap: anywhere;
}
.ipscov-name:hover {
  text-decoration: underline;
}
.ipscov-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 10px;
  margin-top: 2px;
  color: var(--text-3);
}
.ipscov-meta .sev {
  text-transform: capitalize;
}
.ipscov-meta .ok {
  color: var(--ok);
}
.ipscov-meta .warn {
  color: var(--warn);
}
.ipscov-note {
  margin: 8px 0 0;
  color: var(--text-2);
}
.ipscov-more {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: 8px;
  font-size: 12px;
  color: var(--text-2);
}
</style>
