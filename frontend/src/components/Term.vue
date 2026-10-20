<script setup>
import { computed } from "vue";
import { explain } from "../lib/glossary.js";

// An acronym or term with a hover/focus explanation from the glossary.
// <Term k="EPSS" /> shows "EPSS"; pass slot content to show different text.
const props = defineProps({ k: { type: String, required: true }, text: { type: String, default: "" } });
const tip = computed(() => props.text || explain(props.k));
</script>

<template>
  <span v-if="tip" v-tip="tip" class="term" tabindex="0"><slot>{{ k }}</slot></span>
  <span v-else><slot>{{ k }}</slot></span>
</template>

<style scoped>
.term {
  text-decoration: underline dotted;
  text-decoration-color: color-mix(in srgb, currentColor 45%, transparent);
  text-underline-offset: 3px;
  cursor: help;
}
.term:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 1px;
  border-radius: 2px;
}
</style>
