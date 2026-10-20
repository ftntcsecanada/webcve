// v-tip: a single shared tooltip for hover and keyboard focus.
// Usage: <span v-tip="'Explanation'">…</span>. Positions itself below the
// element, or above when there's no room, and stays inside the viewport.

let tipEl = null;
let current = null;

function ensureTip() {
  if (tipEl) return tipEl;
  tipEl = document.createElement("div");
  tipEl.className = "v-tip";
  tipEl.setAttribute("role", "tooltip");
  tipEl.id = "v-tip";
  document.body.appendChild(tipEl);
  return tipEl;
}

function show(el) {
  const text = el._tipText;
  if (!text) return;
  const tip = ensureTip();
  current = el;
  tip.textContent = text;
  tip.style.visibility = "hidden";
  tip.classList.add("on");
  el.setAttribute("aria-describedby", "v-tip");
  const r = el.getBoundingClientRect();
  const t = tip.getBoundingClientRect();
  const m = 8;
  let top = r.bottom + 6;
  if (top + t.height > innerHeight - m) top = r.top - t.height - 6;
  let left = r.left + r.width / 2 - t.width / 2;
  left = Math.max(m, Math.min(left, innerWidth - t.width - m));
  tip.style.top = `${Math.max(m, top)}px`;
  tip.style.left = `${left}px`;
  tip.style.visibility = "visible";
}

function hide(el) {
  if (current !== el || !tipEl) return;
  tipEl.classList.remove("on");
  el.removeAttribute("aria-describedby");
  current = null;
}

export const vTip = {
  mounted(el, binding) {
    el._tipText = binding.value;
    el._tipShow = () => show(el);
    el._tipHide = () => hide(el);
    el.addEventListener("mouseenter", el._tipShow);
    el.addEventListener("mouseleave", el._tipHide);
    el.addEventListener("focus", el._tipShow);
    el.addEventListener("blur", el._tipHide);
  },
  updated(el, binding) {
    el._tipText = binding.value;
  },
  beforeUnmount(el) {
    hide(el);
    el.removeEventListener("mouseenter", el._tipShow);
    el.removeEventListener("mouseleave", el._tipHide);
    el.removeEventListener("focus", el._tipShow);
    el.removeEventListener("blur", el._tipHide);
  },
};
