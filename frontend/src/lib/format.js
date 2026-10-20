export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

export const SEVERITY_LABEL = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  NONE: "Unscored",
};

export const ATTACK_VECTORS = ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"];

export const ATTACK_VECTOR_LABEL = {
  NETWORK: "Network",
  ADJACENT: "Adjacent",
  LOCAL: "Local",
  PHYSICAL: "Physical",
};

export function severityKey(s) {
  return s ? s.toUpperCase() : "NONE";
}

export function fmtNum(n) {
  return (n ?? 0).toLocaleString();
}

export function fmtCompact(n) {
  if (n == null) return "0";
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

const dateFmt = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });

// Dates like "2026-02-03" are calendar dates; parse them as local so they don't shift a day
function toDate(d) {
  if (!d) return null;
  if (typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d)) {
    const [y, m, day] = d.split("-").map(Number);
    return new Date(y, m - 1, day);
  }
  const date = new Date(d);
  return isNaN(date) || date.getFullYear() < 1990 ? null : date;
}

export function fmtDate(d) {
  const date = toDate(d);
  return date ? dateFmt.format(date) : "—";
}

export function daysFromToday(d) {
  const date = toDate(d);
  if (!date) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.round((date - today) / 86400000);
}

export function fmtRelative(d) {
  const date = toDate(d);
  if (!date) return "—";
  const diff = (Date.now() - date) / 1000;
  if (diff < 3600) return `${Math.max(1, Math.round(diff / 60))}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  const days = Math.round(diff / 86400);
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${Math.round(days / 365)}y ago`;
}

// "n/a", "unknown" and friends carry no information in the CVE corpus
export function cleanName(s) {
  if (!s) return "";
  const t = s.trim();
  return /^(n\/a|na|unknown|unspecified|-|\*)$/i.test(t) ? "" : t;
}

export function summaryText(cve) {
  return cve.title || cve.kevName || firstSentence(cve.description) || "No description";
}

function firstSentence(s) {
  if (!s) return "";
  const m = s.match(/^(.{20,180}?[.!?])(\s|$)/);
  return m ? m[1] : s;
}

// ---- CVSS vector decoding ----

const V3_METRICS = {
  AV: ["Attack Vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }, { N: 3, A: 2, L: 1, P: 0 }],
  AC: ["Attack Complexity", { L: "Low", H: "High" }, { L: 3, H: 1 }],
  PR: ["Privileges Required", { N: "None", L: "Low", H: "High" }, { N: 3, L: 2, H: 1 }],
  UI: ["User Interaction", { N: "None", R: "Required" }, { N: 3, R: 1 }],
  S: ["Scope", { U: "Unchanged", C: "Changed" }, { C: 3, U: 1 }],
  C: ["Confidentiality", { H: "High", L: "Low", N: "None" }, { H: 3, L: 2, N: 0 }],
  I: ["Integrity", { H: "High", L: "Low", N: "None" }, { H: 3, L: 2, N: 0 }],
  A: ["Availability", { H: "High", L: "Low", N: "None" }, { H: 3, L: 2, N: 0 }],
};

const IMPACT = { H: "High", L: "Low", N: "None" };
const IMPACT_RISK = { H: 3, L: 2, N: 0 };

const V4_METRICS = {
  AV: V3_METRICS.AV,
  AC: V3_METRICS.AC,
  AT: ["Attack Requirements", { N: "None", P: "Present" }, { N: 3, P: 1 }],
  PR: V3_METRICS.PR,
  UI: ["User Interaction", { N: "None", P: "Passive", A: "Active" }, { N: 3, P: 2, A: 1 }],
  VC: ["Confidentiality (vuln)", IMPACT, IMPACT_RISK],
  VI: ["Integrity (vuln)", IMPACT, IMPACT_RISK],
  VA: ["Availability (vuln)", IMPACT, IMPACT_RISK],
  SC: ["Confidentiality (subseq.)", IMPACT, IMPACT_RISK],
  SI: ["Integrity (subseq.)", IMPACT, IMPACT_RISK],
  SA: ["Availability (subseq.)", IMPACT, IMPACT_RISK],
};

const V2_IMPACT = { N: "None", P: "Partial", C: "Complete" };
const V2_IMPACT_RISK = { C: 3, P: 2, N: 0 };
const V2_METRICS = {
  AV: ["Access Vector", { N: "Network", A: "Adjacent", L: "Local" }, { N: 3, A: 2, L: 1 }],
  AC: ["Access Complexity", { L: "Low", M: "Medium", H: "High" }, { L: 3, M: 2, H: 1 }],
  Au: ["Authentication", { N: "None", S: "Single", M: "Multiple" }, { N: 3, S: 2, M: 1 }],
  C: ["Confidentiality", V2_IMPACT, V2_IMPACT_RISK],
  I: ["Integrity", V2_IMPACT, V2_IMPACT_RISK],
  A: ["Availability", V2_IMPACT, V2_IMPACT_RISK],
};

// Returns [{ key, label, value, risk }] where risk 0..3 (3 = worst for defenders)
export function parseCvssVector(vector) {
  if (!vector) return [];
  const parts = vector.split("/");
  let table = V2_METRICS;
  if (parts[0].startsWith("CVSS:4")) table = V4_METRICS;
  else if (parts[0].startsWith("CVSS:3")) table = V3_METRICS;
  const out = [];
  for (const p of parts) {
    const [k, v] = p.split(":");
    const def = table[k];
    if (!def) continue;
    out.push({ key: k, label: def[0], value: def[1][v] ?? v, risk: def[2][v] ?? 0 });
  }
  return out;
}

// ---- References ----

const TAG_GROUPS = [
  ["exploit", "Exploit"],
  ["patch", "Patch"],
  ["vendor-advisory", "Vendor advisory"],
  ["mitigation", "Mitigation"],
  ["third-party-advisory", "Third-party advisory"],
  ["issue-tracking", "Issue tracking"],
  ["release-notes", "Release notes"],
  ["technical-description", "Technical description"],
];

export function normalizeTag(tag) {
  return tag.toLowerCase().replace(/^x_refsource_/, "").replace(/_/g, "-");
}

// exploitUrls: links the server identified as exploit evidence; they're grouped
// under "Exploit" even when the publisher tagged them as something else
export function groupReferences(refs, exploitUrls = new Set()) {
  const groups = new Map(TAG_GROUPS.map(([k, label]) => [k, { key: k, label, refs: [] }]));
  const other = { key: "other", label: "Other", refs: [] };
  for (const r of refs || []) {
    const tags = (r.tags || []).map(normalizeTag);
    const hit = exploitUrls.has(r.url) ? TAG_GROUPS[0] : TAG_GROUPS.find(([k]) => tags.includes(k));
    (hit ? groups.get(hit[0]) : other).refs.push({ ...r, tags });
  }
  return [...groups.values(), other].filter((g) => g.refs.length);
}

export function splitUrl(url) {
  try {
    const u = new URL(url);
    return { host: u.hostname.replace(/^www\./, ""), path: (u.pathname + u.search).replace(/\/$/, "") };
  } catch {
    return { host: url, path: "" };
  }
}

// EPSS is a probability (0..1); show it as a percentage with sensible precision
export function fmtEpss(p) {
  if (p == null || p <= 0) return "—";
  const pct = p * 100;
  if (pct >= 99.95) return ">99.9%";
  if (pct >= 10) return `${pct.toFixed(1).replace(/\.0$/, "")}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(2)}%`;
}

// EPSS bands used for emphasis: ≥10% is unusually likely to be exploited
export function epssLevel(p) {
  if (!p) return "none";
  if (p >= 0.5) return "high";
  if (p >= 0.1) return "med";
  return "low";
}

// EPSS percentile (0..1) as a phrase: "Top 0.1%" reads better than "higher than 100%"
export function fmtPercentile(p) {
  if (p == null) return "";
  if (p >= 0.999) return "Top 0.1% of CVEs";
  if (p >= 0.99) return "Top 1% of CVEs";
  return `Higher than ${Math.floor(p * 100)}% of CVEs`;
}

export const EVIDENCE_LABEL = {
  "ssvc-active": "CISA: actively exploited",
  "ssvc-poc": "CISA: proof of concept public",
  "euvd-exploited": "ENISA: exploited",
  "msrc-exploited": "Microsoft: exploited",
  metasploit: "Metasploit module",
  exploitdb: "Exploit-DB",
  nuclei: "Nuclei template",
  github: "GitHub PoC",
  tagged: "Exploit reference",
  "exploit-site": "Exploit archive",
  "github-poc": "Possible GitHub PoC",
};

// Glossary term explaining each evidence kind
export const EVIDENCE_TERM = {
  "ssvc-active": "SSVC",
  "ssvc-poc": "SSVC",
  "euvd-exploited": "EUVD",
  "msrc-exploited": "MSRC",
  metasploit: "Metasploit",
  exploitdb: "Exploit-DB",
  nuclei: "Nuclei",
  github: "GitHub PoC",
  "github-poc": "GitHub PoC",
};

// Exploit-evidence source filter values, strongest weaponization first
export const EXPLOIT_SOURCES = [
  ["metasploit", "Metasploit module", "Metasploit"],
  ["exploitdb", "Exploit-DB entry", "Exploit-DB"],
  ["nuclei", "Nuclei template", "Nuclei"],
  ["github", "GitHub PoC", "GitHub PoC"],
  ["cisa", "CISA: PoC or exploited", "SSVC"],
  ["euvd", "ENISA: exploited", "EUVD"],
  ["msrc", "Microsoft: exploited", "MSRC"],
  ["other", "Other exploit link", ""],
];

export const EXPLOIT_SOURCE_LABEL = Object.fromEntries(EXPLOIT_SOURCES.map(([k, label]) => [k, label]));

export const SSVC_LABEL = {
  exploitation: { none: "No known exploitation", poc: "Proof of concept public", active: "Actively exploited" },
  automatable: { yes: "Automatable", no: "Not automatable" },
  technicalImpact: { total: "Total impact", partial: "Partial impact" },
};
