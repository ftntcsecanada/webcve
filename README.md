# webcve

A fast browser for the CVE corpus and the CISA Known Exploited Vulnerabilities (KEV) catalog.

- **All CVEs / Known Exploited views**: the KEV view sorts by date added and shows remediation due dates, ransomware use and monthly additions.
- **Faceted filters** with live counts (severity, attack vector, KEV, CVSS score, year, vendor, product, CWE).
- **Detail drawer** with CVSS vector breakdown, KEV callout, grouped references and deep links (`?cve=CVE-2021-44228`).
- Every filter is reflected in the URL, so any view can be shared.
- Keyboard: `/` search, `j`/`k` move, `Enter` open, `Esc` close, `[`/`]` page, `1`/`2` switch view, `?` help.

## Development

```sh
go run .                      # API + static site on :3000 (downloads data on first run)
cd frontend && npm run dev    # Vite dev server, proxies /api to :3000
cd frontend && npm run build  # builds into ../site
```

`docker compose up --build` builds and runs both.
