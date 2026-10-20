// Plain-language explanations for the acronyms and jargon in the UI.
// Used by <Term> and the v-tip directive.
export const GLOSSARY = {
  CVE: "Common Vulnerabilities and Exposures: the public ID (CVE-YEAR-NUMBER) assigned to a specific vulnerability.",
  CVSS: "Common Vulnerability Scoring System: a 0–10 severity score based on how the flaw can be exploited and what it affects. It measures severity, not likelihood of attack.",
  "CVSS 4.0": "The newest version of CVSS (2023). Scores aren't directly comparable with CVSS 3.x.",
  EPSS: "Exploit Prediction Scoring System (FIRST): the estimated probability that this CVE is exploited in the next 30 days. Updated daily.",
  percentile: "How this CVE's EPSS score ranks against every other scored CVE. 95th percentile = higher than 95% of CVEs.",
  KEV: "Known Exploited Vulnerabilities: CISA's catalog of CVEs with reliable evidence of exploitation in the wild.",
  CISA: "Cybersecurity and Infrastructure Security Agency, the US agency that maintains the KEV catalog.",
  "BOD 22-01": "Binding Operational Directive 22-01: requires US federal agencies to fix KEV entries by their due date. Widely used as a benchmark elsewhere.",
  "Due date": "The remediation deadline CISA sets for US federal agencies when it adds a CVE to KEV.",
  Ransomware: "CISA reports this vulnerability has been used in ransomware campaigns.",
  CWE: "Common Weakness Enumeration (MITRE): the category of coding or design mistake behind the vulnerability, e.g. CWE-79 is cross-site scripting.",
  SSVC: "Stakeholder-Specific Vulnerability Categorization: CISA's decision points for this CVE: whether it's exploited, whether attacks can be automated, and how much control an attacker gains.",
  Exploitation: "SSVC: none (no evidence), poc (public proof of concept) or active (exploited in the wild).",
  Automatable: "SSVC: whether an attacker can reliably exploit it at scale without human interaction.",
  "Technical impact": "SSVC: partial or total control of the affected system if exploited.",
  NVD: "National Vulnerability Database (NIST): adds its own analysis to CVEs, including CVSS scores and CPE product identifiers.",
  CPE: "Common Platform Enumeration: NVD's standardized vendor/product names, used here to fill in products the CVE record leaves as n/a.",
  CNA: "CVE Numbering Authority: the organization (often the vendor) that published the CVE record.",
  ADP: "Authorized Data Publisher: an organization like CISA that adds data (scores, SSVC) to CVE records after publication.",
  OSV: "Open Source Vulnerabilities (osv.dev): fixed package versions from GitHub advisories, language package registries and Linux distributions.",
  GHSA: "GitHub Security Advisory ID.",
  EUVD: "EU Vulnerability Database, run by ENISA (the EU cybersecurity agency). It keeps its own list of exploited vulnerabilities.",
  ENISA: "European Union Agency for Cybersecurity, which runs the EU Vulnerability Database.",
  MSRC: "Microsoft Security Response Center. Each Patch Tuesday it rates how likely Microsoft CVEs are to be exploited.",
  PoC: "Proof of concept: public code or steps that demonstrate the vulnerability. Not always a working exploit.",
  "Exploit evidence":
    "Signals that exploit code exists or attacks have been seen: CISA, ENISA or Microsoft reports, exploit archives, Metasploit modules, Nuclei templates and GitHub PoCs. Open a CVE to see which.",
  Metasploit: "Rapid7's penetration-testing framework. A Metasploit module means a ready-to-use exploit or scanner exists.",
  "Exploit-DB": "Offensive Security's public archive of exploits.",
  Nuclei: "ProjectDiscovery's vulnerability scanner. A template means the CVE can be detected (and often probed) at scale.",
  "GitHub PoC": "Proof-of-concept repositories on GitHub, indexed by the PoC-in-GitHub project. Unvetted: some are fake or malicious.",
  Unscored: "Neither the CVE record nor NVD provides a CVSS score.",
  "Attack vector": "How an attacker reaches the vulnerable component: over the network, from an adjacent network, locally, or with physical access.",
  "Attack complexity": "Conditions beyond the attacker's control that must exist for the attack to work. Low means it works reliably.",
  "Attack requirements": "CVSS 4.0: deployment conditions that must be present for the attack to succeed.",
  "Privileges required": "The access level an attacker needs before exploiting it. None is worst.",
  "User interaction": "Whether a user other than the attacker must do something (click a link, open a file).",
  Scope: "CVSS 3.x: whether a successful attack can affect components beyond the vulnerable one.",
  Confidentiality: "Impact on keeping data secret.",
  Integrity: "Impact on the trustworthiness and correctness of data.",
  Availability: "Impact on the accessibility of the affected system.",
  Authentication: "CVSS 2.0: how many times an attacker must authenticate.",
  "Access vector": "CVSS 2.0 name for attack vector.",
  "Access complexity": "CVSS 2.0 name for attack complexity.",
  "Vector string": "The compact CVSS encoding of every metric (e.g. AV:N = network attack vector).",
  Assigner: "The CNA that assigned and published this CVE.",
  Reserved: "When the CVE ID was reserved, usually before the vulnerability was disclosed.",
  "Fixed versions": "Package versions that contain the fix, from OSV. Upgrade to one of these or later.",
};

// CVSS metric labels used by parseCvssVector map onto glossary entries
const METRIC_TERMS = {
  "Attack Vector": "Attack vector",
  "Attack Complexity": "Attack complexity",
  "Attack Requirements": "Attack requirements",
  "Privileges Required": "Privileges required",
  "User Interaction": "User interaction",
  Scope: "Scope",
  Confidentiality: "Confidentiality",
  Integrity: "Integrity",
  Availability: "Availability",
  "Confidentiality (vuln)": "Confidentiality",
  "Integrity (vuln)": "Integrity",
  "Availability (vuln)": "Availability",
  "Confidentiality (subseq.)": "Confidentiality",
  "Integrity (subseq.)": "Integrity",
  "Availability (subseq.)": "Availability",
  "Access Vector": "Access vector",
  "Access Complexity": "Access complexity",
  Authentication: "Authentication",
};

export function metricExplanation(label) {
  const t = METRIC_TERMS[label];
  let text = t ? GLOSSARY[t] : "";
  if (label.endsWith("(subseq.)")) text += " (on systems beyond the vulnerable one)";
  return text;
}

export function explain(term) {
  return GLOSSARY[term] || "";
}
