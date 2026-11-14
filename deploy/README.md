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
assessments. They run on the private Bifrost gateway (OpenAI-compatible API,
default model `flgpu-openai/qwen3.8-27b-openai`), so CVE data stays on our
infrastructure. Each published CVE with CVSS 9.0 or higher that was published,
or added to KEV, in the last 30 days gets an assessment: a rating of
`severe`, `high`, `moderate` or `low` for its likelihood of heavy global impact,
with the reasoning behind it. A CVE is reassessed when it's added to KEV, a public
exploit appears, its SSVC exploitation status changes or its EPSS jumps a band.
Results are kept in `/data/webcve/kev/ai-impact.json`, so restarts and redeploys
don't pay twice. Progress and errors show on the Data sources page.

```sh
BIFROST_URL=https://...                        # gateway base URL (the container must be able to reach it)
BIFROST_API_KEY=...                            # gateway key; both values together enable assessments
WEBCVE_AI_MODEL=flgpu-openai/qwen3.8-27b-openai  # default
WEBCVE_AI_MIN_SCORE=9.0                        # CVSS threshold
WEBCVE_AI_WINDOW_DAYS=30                       # how far back to assess (the first start backfills this window)
WEBCVE_AI_DAILY_LIMIT=200                      # load cap: assessments per UTC day
WEBCVE_AI_ASSESSMENTS=0                        # turn off without removing the key
```

Expect about 10 to 20 assessments a day, at roughly 10 to 30 seconds each, plus a
one-time backfill of roughly 300 to 500 on first start, which the daily limit
spreads over a couple of days. The model works from the CVE record and this
platform's enrichment (KEV, EPSS, exploits, OSV packages, affected products) plus
its own knowledge; it does not browse the web. When
alerts are on, a fresh critical CVE rated high or severe, or an existing rating
that escalates to one of those, posts an "AI early warning" to the webhook.

Alerts post Slack-compatible `{"text": ...}` JSON for new KEV entries and new
high-severity CVEs from watched vendors. Restart with `docker-compose up -d`
after changing `.env`.
