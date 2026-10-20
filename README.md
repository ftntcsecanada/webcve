# webcve

A fast browser for the CVE corpus, the CISA Known Exploited Vulnerabilities (KEV)
catalog, exploit availability and exploit-likelihood scores.

- **All CVEs / Known Exploited / Vendors views.** The KEV view sorts by date added
  and shows remediation due dates, ransomware use and monthly additions. The Vendors
  view compares vendors by volume, severity, KEV rate, exploit rate, Metasploit
  coverage, EPSS and median days from publication to exploitation.
- **Prioritization signals.** CVSS (3.x primary, 4.0 alongside, NVD as fallback),
  EPSS score, percentile and 30-day trend, CISA SSVC decision points, Microsoft
  exploitability ratings, and exploit evidence with sources and links (Metasploit,
  Exploit-DB, Nuclei, GitHub PoCs, CISA/ENISA/Microsoft exploitation reports).
- **Fixed versions** per package from OSV (GitHub advisories, language ecosystems,
  Debian, Red Hat, Alpine).
- **Faceted filters** with live counts: severity, exploit evidence, EPSS, CVSS
  score, attack vector, year, vendor, product, CWE, KEV due window.
- **Search** with prefix matching, `"exact phrases"` and field syntax:
  `vendor:fortinet sev:critical kev:yes epss:>10% cwe:79 year:2024`.
- **Saved searches** in the sidebar, with a count of CVEs published or added to
  KEV since you last opened each one.
- **Detail drawer** with CVSS vector breakdown, KEV callout, related CVEs, grouped
  references and deep links (`?cve=CVE-2021-44228`).
- Every filter is in the URL, so any view can be shared. Export to Excel, CSV or JSON.
- Hover any acronym or metric for a plain-language explanation.
- Keyboard: `/` search, `j`/`k` move, `Enter` open, `Esc` close, `[`/`]` page,
  `1`/`2`/`3` switch view, `?` help.

## Data

The server keeps itself current from free public sources, each on its own schedule,
and swaps in new data without downtime. The **Data sources** page (click "updated …"
in the header) shows each source's status, last update, errors, record count and size.

| Source | Adds | Refresh |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | CVE records | hourly deltas, weekly full |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known exploited, due dates, ransomware | 6 h |
| [FIRST EPSS](https://www.first.org/epss/) | exploit likelihood (+ history on demand) | 6 h |
| [NIST NVD](https://nvd.nist.gov/developers) | fallback CVSS, CWE, CPE products | 2 h (set `NVD_API_KEY` to sync ~10× faster) |
| [Exploit-DB](https://www.exploit-db.com/), [Metasploit](https://github.com/rapid7/metasploit-framework), [Nuclei](https://github.com/projectdiscovery/nuclei-templates), [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | exploit code and scanner templates | daily |
| [ENISA EUVD](https://euvd.enisa.europa.eu/) | EU exploited list | 6 h |
| [Microsoft MSRC](https://msrc.microsoft.com/update-guide) | exploitability ratings | 12 h |
| [OSV](https://osv.dev/) | fixed package versions | daily |
| [MITRE CWE](https://cwe.mitre.org/) | weakness names | weekly |

The first NVD sync takes about 50 minutes without an API key; everything else is
usable meanwhile.

Optional webhook alerts for new KEV entries and new critical CVEs from watched
vendors are configured with `WEBCVE_ALERT_*` environment variables; see
[deploy/README.md](deploy/README.md).

## Development

```sh
go run .                            # API + site on :3000 (downloads data on first run)
WEBCVE_NO_UPDATES=1 go run .        # use local data only: no downloads or updates
go test ./...
cd frontend && npm run dev          # Vite dev server, proxies /api to :3000
cd frontend && npm run build        # builds into ../site
```

`docker build .` builds a local image. Production deployment is described in
[deploy/README.md](deploy/README.md).
