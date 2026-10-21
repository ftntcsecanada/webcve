// Competitive peer groups for the Vendors view. Names must match vendor
// spellings in the data; the server normalizes them ("Juniper" = "Juniper Networks").
export const PEER_GROUPS = [
  {
    id: "firewall",
    label: "Network firewalls",
    vendors: ["Fortinet", "Palo Alto Networks", "Cisco", "Check Point", "Juniper Networks", "SonicWall", "Sophos", "WatchGuard", "Barracuda", "Zyxel", "Hillstone Networks"],
  },
  {
    id: "sase",
    label: "SASE, SSE & remote access",
    vendors: ["Fortinet", "Palo Alto Networks", "Cisco", "Zscaler", "Netskope", "Cloudflare", "Ivanti", "Citrix", "NetScaler", "Cato Networks", "Versa Networks", "Check Point", "Akamai"],
  },
  {
    id: "adc",
    label: "Application delivery & WAF",
    vendors: ["Fortinet", "F5", "Citrix", "NetScaler", "Imperva", "Akamai", "Cloudflare", "Barracuda", "Radware"],
  },
  {
    id: "endpoint",
    label: "Endpoint security",
    vendors: ["Fortinet", "CrowdStrike", "SentinelOne", "Trend Micro", "Sophos", "Trellix", "McAfee", "Symantec", "Broadcom", "ESET", "Kaspersky", "Bitdefender"],
  },
  {
    id: "lan",
    label: "Switching & wireless",
    vendors: ["Fortinet", "Cisco", "Juniper Networks", "Arista Networks", "Hewlett Packard Enterprise", "Huawei", "Ubiquiti", "Extreme Networks", "Netgear", "TP-Link"],
  },
];

export function groupMatching(vendors) {
  const set = new Set(vendors.map((v) => v.toLowerCase()));
  return PEER_GROUPS.find((g) => g.vendors.length === set.size && g.vendors.every((v) => set.has(v.toLowerCase())));
}

// Mirror of the server's vendor normalization, enough to match peer names
const SUFFIXES = new Set(["corporation", "corp", "incorporated", "inc", "limited", "ltd", "llc", "gmbh", "co", "company", "plc", "ag", "sa", "networks", "systems", "technologies", "technology", "software", "labs", "lab"]);
function vendorKey(name) {
  const words = (name || "").toLowerCase().split(/[^a-z0-9&+]+/).filter(Boolean);
  while (words.length > 1 && SUFFIXES.has(words[words.length - 1])) words.pop();
  return words.join(" ");
}
const SHORT = new Map(PEER_GROUPS.flatMap((g) => g.vendors).map((v) => [vendorKey(v), v]));

// "Check Point Software Technologies Ltd." -> "Check Point" when it's a known peer
export function shortVendorName(name) {
  return SHORT.get(vendorKey(name)) || name;
}
