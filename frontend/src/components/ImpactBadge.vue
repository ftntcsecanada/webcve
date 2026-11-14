<script setup>
import { computed } from "vue";
import Icon from "./Icon.vue";
import { IMPACT_LABEL, IMPACT_ELEVATED } from "../lib/format.js";
import { explain } from "../lib/glossary.js";

// AI global-impact rating chip. `compact` shows only elevated ratings (for dense tables).
const props = defineProps({
  rating: { type: String, default: "" },
  confidence: { type: String, default: "" },
  compact: { type: Boolean, default: false },
});

const elevated = computed(() => IMPACT_ELEVATED.includes(props.rating));
const show = computed(() => props.rating && (!props.compact || elevated.value));
const tip = computed(() => {
  const conf = props.confidence ? ` (${props.confidence} confidence)` : "";
  return `AI global-impact risk: ${IMPACT_LABEL[props.rating]}${conf}. ${explain("AI impact")}`;
});
</script>

<template>
  <span v-if="show" v-tip="tip" class="badge" :class="`ai-${rating}`" tabindex="0">
    <Icon v-if="elevated" name="alert" :size="11" />
    {{ compact ? "Global risk" : "AI global risk" }}: {{ IMPACT_LABEL[rating] }}
  </span>
</template>
