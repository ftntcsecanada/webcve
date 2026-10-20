<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from "vue";

// Generic stacked bar chart with hover tooltips and optional click/drag range selection.
// bars: [{ key, label, tick, total, segments: [{ key, label, value, color }] }]
const props = defineProps({
  bars: { type: Array, required: true },
  height: { type: Number, default: 132 },
  selectable: { type: Boolean, default: false },
  selection: { type: Array, default: null }, // [fromKey, toKey] inclusive, keys are numbers
  unit: { type: String, default: "CVEs" },
});
const emit = defineEmits(["select"]);

const root = ref(null);
const width = ref(600);
let ro = null;
onMounted(() => {
  ro = new ResizeObserver(([e]) => (width.value = Math.max(200, e.contentRect.width)));
  ro.observe(root.value);
});
onBeforeUnmount(() => ro?.disconnect());

const PAD = { top: 8, right: 4, bottom: 20, left: 36 };
const GAP = 2;

const max = computed(() => Math.max(1, ...props.bars.map((b) => b.total)));

const ticks = computed(() => {
  const m = max.value;
  const raw = m / 3;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((s) => s * pow).find((s) => s >= raw) || raw;
  const out = [];
  for (let v = step; v <= m; v += step) out.push(v);
  return out;
});

const plotW = computed(() => width.value - PAD.left - PAD.right);
const plotH = computed(() => props.height - PAD.top - PAD.bottom);
const slot = computed(() => plotW.value / Math.max(1, props.bars.length));
const barW = computed(() => Math.max(3, Math.min(28, slot.value - Math.max(2, slot.value * 0.28))));

function y(v) {
  return PAD.top + plotH.value - (v / max.value) * plotH.value;
}

function topRoundedRect(x, yTop, w, h, r) {
  r = Math.min(r, w / 2, h);
  if (h <= 0) return "";
  return `M${x},${yTop + h}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + w - r}Q${x + w},${yTop} ${x + w},${yTop + r}V${yTop + h}Z`;
}

// Stack bottom-up; a 2px surface gap separates segments, the top segment gets rounded corners
const geometry = computed(() =>
  props.bars.map((b, i) => {
    const x = PAD.left + i * slot.value + (slot.value - barW.value) / 2;
    const visible = b.segments.filter((s) => s.value > 0);
    let acc = 0;
    const segs = visible.map((s, j) => {
      const y0 = y(acc);
      acc += s.value;
      const y1 = y(acc);
      const isTop = j === visible.length - 1;
      const gap = j > 0 ? GAP : 0;
      const h = Math.max(0, y0 - y1 - gap);
      const d = isTop ? topRoundedRect(x, y1, barW.value, Math.max(h, 1.5), 3) : `M${x},${y1}h${barW.value}v${h}h${-barW.value}Z`;
      return { key: s.key, color: s.color, d };
    });
    return { bar: b, x, segs, cx: x + barW.value / 2 };
  })
);

const tickEvery = computed(() => {
  const labelW = 34;
  return Math.max(1, Math.ceil(labelW / slot.value));
});

// ---- Hover + selection ----
const hover = ref(-1);
const dragFrom = ref(null);
const dragTo = ref(null);

function indexAt(e) {
  const rect = root.value.getBoundingClientRect();
  const x = e.clientX - rect.left - PAD.left;
  return Math.max(0, Math.min(props.bars.length - 1, Math.floor(x / slot.value)));
}

function onMove(e) {
  hover.value = indexAt(e);
  if (dragFrom.value != null) dragTo.value = hover.value;
}

function onDown(e) {
  if (!props.selectable) return;
  dragFrom.value = indexAt(e);
  dragTo.value = dragFrom.value;
  // Finish the drag even if the pointer is released outside the chart
  window.addEventListener("mouseup", onUp, { once: true });
}

function onUp(e) {
  if (dragFrom.value == null) return;
  const a = Math.min(dragFrom.value, dragTo.value);
  const b = Math.max(dragFrom.value, dragTo.value);
  dragFrom.value = dragTo.value = null;
  const ka = props.bars[a].key;
  const kb = props.bars[b].key;
  const sel = props.selection;
  if (e.shiftKey && sel) {
    emit("select", [Math.min(sel[0] ?? ka, ka), Math.max(sel[1] ?? kb, kb)]);
  } else if (a === b && sel && sel[0] === ka && sel[1] === ka) {
    emit("select", null); // clicking the sole selected bar clears
  } else {
    emit("select", [ka, kb]);
  }
}

function inSelection(i) {
  if (dragFrom.value != null) {
    return i >= Math.min(dragFrom.value, dragTo.value) && i <= Math.max(dragFrom.value, dragTo.value);
  }
  const sel = props.selection;
  if (!sel || (sel[0] == null && sel[1] == null)) return true;
  const k = props.bars[i].key;
  return (sel[0] == null || k >= sel[0]) && (sel[1] == null || k <= sel[1]);
}

const hasSelection = computed(
  () => dragFrom.value != null || (props.selection && (props.selection[0] != null || props.selection[1] != null))
);

const tip = computed(() => {
  const g = geometry.value[hover.value];
  if (!g) return null;
  const left = Math.min(Math.max(g.cx, 80), width.value - 80);
  return { g, left };
});

function fmt(n) {
  return n.toLocaleString();
}
function fmtTick(n) {
  return n >= 1000 ? `${+(n / 1000).toFixed(1)}k` : String(n);
}
</script>

<template>
  <div ref="root" class="chart" :style="{ height: height + 'px' }">
    <svg
      :width="width"
      :height="height"
      :class="{ selectable }"
      role="img"
      :aria-label="`Bar chart of ${unit}`"
      @mousemove="onMove"
      @mouseleave="hover = -1"
      @mousedown.prevent="onDown"
    >
      <g class="grid">
        <template v-for="t in ticks" :key="t">
          <line :x1="PAD.left" :x2="width - PAD.right" :y1="y(t)" :y2="y(t)" />
          <text :x="PAD.left - 6" :y="y(t) + 3.5" text-anchor="end">{{ fmtTick(t) }}</text>
        </template>
        <line class="base" :x1="PAD.left" :x2="width - PAD.right" :y1="y(0)" :y2="y(0)" />
      </g>
      <rect
        v-if="hover >= 0"
        class="hover-band"
        :x="PAD.left + hover * slot"
        :y="PAD.top"
        :width="slot"
        :height="plotH"
        rx="4"
      />
      <g v-for="(g, i) in geometry" :key="g.bar.key" :class="{ dim: hasSelection && !inSelection(i) }" class="bar">
        <path v-for="s in g.segs" :key="s.key" :d="s.d" :style="{ fill: s.color }" />
      </g>
      <g class="axis">
        <template v-for="(g, i) in geometry" :key="g.bar.key">
          <text v-if="(bars.length - 1 - i) % tickEvery === 0" :x="g.cx" :y="height - 5" text-anchor="middle">
            {{ g.bar.tick }}
          </text>
        </template>
      </g>
    </svg>
    <div v-if="tip && dragFrom == null" class="tip" :style="{ left: tip.left + 'px' }">
      <div class="tip-title">{{ tip.g.bar.label }}</div>
      <div v-for="s in [...tip.g.bar.segments].reverse()" v-show="tip.g.bar.segments.length > 1" :key="s.key" class="tip-row">
        <span class="swatch" :style="{ background: s.color }" />
        <span class="tip-label">{{ s.label }}</span>
        <span class="num">{{ fmt(s.value) }}</span>
      </div>
      <div class="tip-total">
        <span>Total</span><span class="num">{{ fmt(tip.g.bar.total) }} {{ unit }}</span>
      </div>
      <div v-if="selectable" class="tip-hint">Click or drag to filter · shift-click extends</div>
    </div>
  </div>
</template>

<style scoped>
.chart {
  position: relative;
  width: 100%;
}
svg {
  display: block;
  overflow: visible;
}
svg.selectable {
  cursor: pointer;
}
.grid line {
  stroke: var(--border);
  stroke-dasharray: 2 3;
}
.grid line.base {
  stroke: var(--border-strong);
  stroke-dasharray: none;
}
.grid text,
.axis text {
  fill: var(--text-3);
  font-size: 10.5px;
  font-variant-numeric: tabular-nums;
}
.hover-band {
  fill: var(--surface-hover);
}
.bar {
  transition: opacity 0.15s;
}
.bar.dim {
  opacity: 0.22;
}
.bar path {
  transition: d 0.3s ease;
}
.tip {
  position: absolute;
  bottom: calc(100% - 4px);
  transform: translateX(-50%);
  z-index: 20;
  min-width: 160px;
  padding: 8px 10px;
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow-lg);
  font-size: 12px;
  pointer-events: none;
}
.tip-title {
  font-weight: 650;
  margin-bottom: 4px;
}
.tip-row,
.tip-total {
  display: flex;
  align-items: center;
  gap: 6px;
  line-height: 1.6;
}
.tip-label {
  flex: 1;
  color: var(--text-2);
}
.tip-total {
  justify-content: space-between;
  margin-top: 4px;
  padding-top: 4px;
  border-top: 1px solid var(--border);
  font-weight: 600;
}
.swatch {
  width: 9px;
  height: 9px;
  border-radius: 3px;
}
.tip-hint {
  margin-top: 6px;
  color: var(--text-3);
  font-size: 11px;
}
</style>
