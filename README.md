# webcve

A fast browser for the CVE corpus, the CISA Known Exploited Vulnerabilities (KEV)
catalog and FIRST EPSS exploit-likelihood scores.

- **All CVEs / Known Exploited views.** The KEV view sorts by date added and shows
  remediation due dates, ransomware use and monthly additions.
- **Prioritization signals.** CVSS (3.x primary, 4.0 alongside), EPSS score and
  percentile, CISA SSVC decision points, and exploit evidence (public PoC, exploit
  references, active exploitation).
- **Faceted filters** with live counts: severity, exploit evidence, EPSS, CVSS
  score, attack vector, year, vendor, product, CWE, KEV due window.
- **Search** with prefix matching, `"exact phrases"` and field syntax:
  `vendor:fortinet sev:critical kev:yes epss:>10% cwe:79 year:2024`.
- **Saved searches** in the sidebar, with a count of CVEs published or added to
  KEV since you last opened each one.
- **Detail drawer** with CVSS vector breakdown, KEV callout, related CVEs, grouped
  references and deep links (`?cve=CVE-2021-44228`).
- Every filter is in the URL, so any view can be shared. Export to Excel, CSV or JSON.
- Keyboard: `/` search, `j`/`k` move, `Enter` open, `Esc` close, `[`/`]` page,
  `1`/`2` switch view, `?` help.

## Data

The server keeps itself current: CVE records hourly from the
[cvelistV5](https://github.com/CVEProject/cvelistV5) delta releases (with a weekly
full snapshot), and the KEV catalog and EPSS scores every six hours. It answers
requests while it loads and swaps in new data without downtime.

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
