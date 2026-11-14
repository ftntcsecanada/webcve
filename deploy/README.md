# Deploying webcve on the fabriclab host

Production runs on `claude@10.160.12.103` as container `webcve`, published on
host port **12095**. Pushing to `main` on GitHub deploys automatically.

| What | Where |
|---|---|
| Build inputs (refreshed from this dir on every build) | `/data/projects/webcve/` |
| Data volumes | `/data/webcve/cves`, `/data/webcve/kev`, `/data/webcve/cve_cache.gob` |
| Image | `registry.fabriclab.ca:5000/webcve:<commit>` and `:latest` |
| Deploy log | `/data/projects/webcve/pull.log` |
| GitHub deploy key (read-only) | `/root/.ssh/id_ed25519` on the host |

## How a deploy happens

1. Root's crontab runs `pull.sh` every 5 minutes. When `main` has moved past
   `.last_hash`, it runs `build.sh <commit>` (one at a time, via `flock`).
2. `build.sh` fetches that commit, copies this directory's `Dockerfile`,
   `docker-compose.yml`, `build.sh` and `pull.sh` over the host copies, builds
   with BuildKit (`--no-cache`, `--ssh default=<key>`), pushes to the registry,
   runs `docker-compose up -d`, and checks `/app/.commit` in the running
   container matches.
3. A failed commit is recorded in `.failed_hash` and not retried until `main`
   moves again. Run `sudo sh /data/projects/webcve/build.sh` to retry by hand.

The Dockerfile clones the repo itself. The deploy key is only mounted into the
clone step (`RUN --mount=type=ssh`); it is never a build argument, so it never
reaches an image layer or the build cache.

## After a deploy

The server starts answering immediately and shows a loading screen while it
reads the CVE cache (a minute or two; a full reparse after a cache-format change
takes longer). Check with:

```sh
ssh -i ~/claude_ssh_key claude@10.160.12.103 \
  'sudo docker ps --filter name=webcve --format "{{.Status}}"; curl -s localhost:12095/api/health'
```

## Data updates (inside the app)

- CVE records: hourly deltas from the cvelistV5 GitHub releases, plus a weekly
  full snapshot. State is kept in `kev/webcve-state.json`.
- CISA KEV catalog and FIRST EPSS scores: every 6 hours.
- NVD, Exploit-DB, Metasploit, Nuclei, PoC-in-GitHub, ENISA EUVD, Microsoft MSRC,
  OSV and MITRE CWE on their own schedules. Their downloads live in the `kev`
  volume (about 700 MB, mostly OSV and NVD's yearly feeds).
- Per-source status, errors and sizes: the Data sources page in the UI, or
  `curl -s localhost:12095/api/sources`.

Optional settings go in a root-only `/data/projects/webcve/.env` (not in git):

```sh
WEBCVE_ALERT_WEBHOOK=https://hooks.slack.com/services/...   # enables alerts
WEBCVE_ALERT_VENDORS=Fortinet,Microsoft,Ivanti               # default: all vendors
WEBCVE_ALERT_MIN_SCORE=9.0                                   # new non-KEV CVEs at or above this CVSS
WEBCVE_PUBLIC_URL=https://webcve.fabriclab.ca                # links in alert messages
GITHUB_TOKEN=...                                             # optional: higher GitHub API rate limit
WEBCVE_SIGLAB_URL=http://10.160.12.103:16774                 # Signature Lab API base URL
WEBCVE_SIGLAB_TOKEN=...                                      # Signature Lab bearer token
```

The Signature Lab token is consumed only by the WebCVE backend. Browsers use
the `/api/siglab/*` proxy endpoints and never receive the bearer credential.
The proxy exposes lab readiness, durable job state, event cursors, submission,
and cancellation. After changing these values, recreate the container with
`docker-compose up -d`.

### AI early-warning assessments

Setting `BIFROST_URL` and `BIFROST_API_KEY` turns on AI global-impact
assessments. They run on the private Bifrost gateway, so CVE data stays on our
infrastructure. Each published CVE with CVSS 7.0 or higher, or no score yet,
that was published or added to KEV inside the window gets a rating of `severe`, `high`,
`moderate` or `low` for its likelihood of heavy global impact. There are two tiers:

1. **Triage** (`kev-8b`, `POST /v1/decisions`): every candidate gets one
   typed decision call, about 150 ms, answering two factual questions: how
   widely the affected product is deployed (ubiquitous / widespread / niche /
   obscure), and how exploitation reaches the target (network, web, file,
   endpoint, or nothing a security product can see). The input is short prose
   built from facts, not the raw record: CVSS components spelled out as delivery
   hints, the CWE, affected products, package ecosystems, exploitation evidence,
   and the product's and vendor's CVE and KEV counts in our own corpus as a reach
   signal. The model is never asked about Fortinet products; the delivery class
   maps to FortiGate IPS, FortiWeb, AV/FortiMail/FortiSandbox or FortiEDR in code.
2. **Deep analysis** (`flgpu-openai/qwen3.8-27b-openai`, chat completions): the
   standouts get a reasoned assessment (rating, summary, drivers, exposure, what
   to watch for, and which Fortinet controls could cover it and what a signature
   would key on) that replaces the triage result. Standouts are CVEs that are
   both widely deployed (P(widespread)+P(ubiquitous) of at least 0.7, or 0.9
   when CVSS is below 9.0 or missing) and coverable (P(none) under 0.5, and not
   confidently a vendor-operated cloud service), plus every Fortinet product CVE and every
   KEV-listed or actively exploited one. The prompt describes what each
   Fortinet control can see, so it doesn't depend on the model's own knowledge.

Everything else keeps its triage result (moderate or low, with the reason).
A CVE is re-run when it's added to KEV, a public exploit appears, its SSVC
exploitation status changes or its EPSS jumps a band. A triaged CVE is
re-triaged right away, and one that already had a deep analysis is reanalysed
(at most once a day). Results are kept in `/data/webcve/kev/ai-impact.json`, so
restarts and redeploys don't pay twice. Candidates are scanned at startup and
after every data refresh (hourly CVE deltas, and KEV/EPSS every 6 hours).
Progress and errors show on the Data sources page.

```sh
BIFROST_URL=http://10.160.20.209:8080          # internal gateway; the public edge returns 403 from this host
BIFROST_API_KEY=...                            # needs the kev and flgpu-openai providers
WEBCVE_AI_MODEL=flgpu-openai/qwen3.8-27b-openai  # deep-analysis model (default)
WEBCVE_AI_TRIAGE_MODEL=kev-8b                  # default; "off" sends every candidate to deep analysis
WEBCVE_AI_ESCALATE_AT=0.7                      # triage P(widespread)+P(ubiquitous) needed for deep analysis
WEBCVE_AI_MIN_SCORE=9.0                        # CVSS at which the 0.7 reach bar applies
WEBCVE_AI_TRIAGE_MIN_SCORE=7.0                 # lowest CVSS triaged; unscored CVEs are triaged too
WEBCVE_AI_WINDOW_DAYS=30                       # how far back to assess (the first start backfills this window)
WEBCVE_AI_DAILY_LIMIT=200                      # load cap: deep analyses per UTC day (triage is uncapped)
WEBCVE_AI_ASSESSMENTS=0                        # turn off without removing the key
```

The models work from the CVE record and this platform's enrichment (KEV, EPSS,
exploits, OSV packages, affected products) plus their own knowledge; they don't
browse the web. When alerts are on, a fresh critical CVE whose deep analysis
rates it high or severe, or an analysis that escalates to one of those, posts an
"AI early warning" to the webhook. Triage ratings never alert.

Alerts post Slack-compatible `{"text": ...}` JSON for new KEV entries and new
high-severity CVEs from watched vendors. Restart with `docker-compose up -d`
after changing `.env`.
