<script setup>
import { ref, computed, watch, nextTick } from "vue";
import Icon from "./Icon.vue";
import { searchOptions } from "../lib/store.js";

// Remote-search token input. Multi-select keeps chips; single-select stores a string.
const props = defineProps({
  modelValue: { type: [Array, String], required: true },
  field: { type: String, required: true },
  placeholder: { type: String, default: "" },
  extra: { type: Function, default: () => ({}) },
});
const emit = defineEmits(["update:modelValue"]);

const multiple = computed(() => Array.isArray(props.modelValue));
const selected = computed(() => (multiple.value ? props.modelValue : props.modelValue ? [props.modelValue] : []));

const query = ref("");
const open = ref(false);
const options = ref([]);
const loading = ref(false);
const active = ref(0);
const inputEl = ref(null);
let timer = null;
let seq = 0;

const visible = computed(() =>
  options.value.filter((o) => !selected.value.some((s) => s.toLowerCase() === o.toLowerCase()))
);

async function load() {
  const mine = ++seq;
  loading.value = true;
  const res = await searchOptions(props.field, query.value, props.extra());
  if (mine !== seq) return;
  options.value = res;
  active.value = 0;
  loading.value = false;
}

watch(query, () => {
  clearTimeout(timer);
  timer = setTimeout(load, 150);
});

function onFocus() {
  open.value = true;
  load();
}

function onBlur() {
  // Delay so a click on an option lands before the menu disappears
  setTimeout(() => (open.value = false), 120);
}

function pick(value) {
  if (!value) return;
  if (multiple.value) emit("update:modelValue", [...props.modelValue, value]);
  else emit("update:modelValue", value);
  query.value = "";
  if (!multiple.value) inputEl.value?.blur();
  nextTick(load);
}

function remove(value) {
  if (multiple.value) emit("update:modelValue", props.modelValue.filter((v) => v !== value));
  else emit("update:modelValue", "");
}

function onKey(e) {
  const list = visible.value;
  if (e.key === "ArrowDown") {
    e.preventDefault();
    open.value = true;
    active.value = Math.min(active.value + 1, list.length - 1);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    active.value = Math.max(active.value - 1, 0);
  } else if (e.key === "Enter") {
    e.preventDefault();
    // Free text is allowed for CWE (substring match server-side)
    pick(list[active.value] ?? (props.field === "cwe" ? query.value.trim() : null));
  } else if (e.key === "Backspace" && !query.value && selected.value.length) {
    remove(selected.value[selected.value.length - 1]);
  } else if (e.key === "Escape") {
    open.value = false;
    inputEl.value?.blur();
  }
  e.stopPropagation();
}
</script>

<template>
  <div class="combo" :class="{ open: open && (visible.length || loading) }">
    <div class="field" @click="inputEl?.focus()">
      <span v-for="v in selected" :key="v" class="chip">
        <span class="chip-text" :title="v">{{ v }}</span>
        <button class="chip-x" :aria-label="`Remove ${v}`" @click.stop="remove(v)"><Icon name="x" :size="12" /></button>
      </span>
      <input
        ref="inputEl"
        v-model="query"
        class="combo-input"
        :placeholder="selected.length ? '' : placeholder"
        role="combobox"
        :aria-expanded="open"
        autocomplete="off"
        spellcheck="false"
        @focus="onFocus"
        @blur="onBlur"
        @keydown="onKey"
      />
    </div>
    <ul v-if="open && (visible.length || loading)" class="menu scroll-thin" role="listbox">
      <li v-if="loading && !visible.length" class="empty">Searching…</li>
      <li
        v-for="(o, i) in visible"
        :key="o"
        role="option"
        :aria-selected="i === active"
        :class="{ active: i === active }"
        @mousedown.prevent="pick(o)"
        @mouseenter="active = i"
      >
        {{ o }}
      </li>
    </ul>
  </div>
</template>

<style scoped>
.combo {
  position: relative;
}
.field {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  min-height: 32px;
  padding: 3px 6px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--surface);
  cursor: text;
}
.field:hover {
  border-color: var(--border-strong);
}
.field:focus-within {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--focus);
}
.combo-input {
  flex: 1;
  min-width: 60px;
  border: 0;
  outline: 0;
  background: transparent;
  padding: 2px 4px;
  font-size: 13px;
}
.combo-input::placeholder {
  color: var(--text-3);
}
.chip {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  height: 24px;
  padding-left: 8px;
  border-radius: 5px;
  background: var(--accent-soft);
  color: var(--accent-text);
  font-size: 12.5px;
  font-weight: 500;
}
.chip-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chip-x {
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  border: 0;
  background: transparent;
  color: inherit;
  opacity: 0.7;
}
.chip-x:hover {
  opacity: 1;
}
.menu {
  position: absolute;
  z-index: 30;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  max-height: 260px;
  overflow-y: auto;
  margin: 0;
  padding: 4px;
  list-style: none;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow-lg);
}
.menu li {
  padding: 6px 8px;
  border-radius: 5px;
  font-size: 13px;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.menu li.active {
  background: var(--surface-hover);
}
.menu li.empty {
  color: var(--text-3);
  cursor: default;
}
</style>
