package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CacheVersion = 5 // Bump when parsed CVE fields change
	CachePath    = "cve_cache.gob"
	CVEDir       = "cves"
	// DataDir holds the KEV catalog, EPSS scores and update state. It is the
	// existing "kev" volume so deployments don't need a new mount.
	DataDir   = "kev"
	KEVPath   = DataDir + "/known_exploited_vulnerabilities.json"
	EPSSPath  = DataDir + "/epss_scores-current.csv.gz"
	StatePath = DataDir + "/webcve-state.json"

	KEVDownloadURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSDownloadURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	CVEReleasesAPI  = "https://api.github.com/repos/CVEProject/cvelistV5/releases"

	DeltaInterval = time.Hour
	KEVInterval   = 6 * time.Hour
	EPSSInterval  = 6 * time.Hour
	FullInterval  = 7 * 24 * time.Hour
	// Beyond this much lag, a full snapshot is cheaper than replaying daily deltas
	MaxDeltaCatchUp = 14 * 24 * time.Hour
)

// App holds the serving dataset and the update machinery
type App struct {
	ds     atomic.Pointer[Dataset]
	status atomic.Value // string: starting, downloading, loading, ready, error

	// updateMu serializes dataset rebuilds; the fields below it are guarded by it
	updateMu sync.Mutex
	enr      Enrichment
	state    UpdateState

	// sources is a snapshot of state times for /api/stats, readable without updateMu
	sources atomic.Pointer[SourceTimes]
	// fullRunning stops deltas from writing into the tree while a full refresh replaces it
	fullRunning atomic.Bool

	alerts *Alerter
	client *http.Client
}

// UpdateState is persisted so restarts resume incremental updates
type UpdateState struct {
	CVEAsOf   time.Time `json:"cveAsOf"`   // CVE data includes all changes up to here
	LastDelta string    `json:"lastDelta"` // Release tag of the last applied delta
	CVE       time.Time `json:"cve"`       // When CVE data last changed locally
	KEV       time.Time `json:"kev"`
	EPSS      time.Time `json:"epss"`
	EPSSDate  string    `json:"epssDate"`
}

func newApp() *App {
	app := &App{
		client: &http.Client{Timeout: 10 * time.Minute},
		alerts: newAlerterFromEnv(),
	}
	app.status.Store("starting")
	return app
}

func (app *App) dataset() *Dataset { return app.ds.Load() }

func (app *App) statusString() string { return app.status.Load().(string) }

func logf(format string, args ...any) {
	fmt.Printf(time.Now().Format("2006-01-02 15:04:05")+" "+format+"\n", args...)
}

// bootstrap loads (downloading if needed) all data, publishes the first
// dataset, then starts the update loops. It runs in the background so the
// HTTP server can answer health checks and show a loading state meanwhile.
func (app *App) bootstrap() {
	app.updateMu.Lock()
	app.loadState()

	if _, err := os.Stat(KEVPath); err != nil {
		app.status.Store("downloading")
		if err := app.downloadKEV(); err != nil {
			logf("KEV download failed: %v", err)
		}
	}
	if !hasCVEFiles() {
		app.status.Store("downloading")
		if asOf, err := app.downloadCVEs(); err != nil {
			logf("CVE download failed: %v", err)
		} else {
			app.state.CVEAsOf, app.state.CVE, app.state.LastDelta = asOf, time.Now(), ""
			app.saveState()
		}
	}
	if err := app.loadKEV(); err != nil {
		logf("Warning: could not load KEV catalog: %v", err)
	}
	if err := app.ensureEPSS(false); err != nil {
		logf("Warning: EPSS unavailable: %v", err)
	}

	app.status.Store("loading")
	cves, err := loadCVEs()
	if err != nil {
		logf("Error loading CVEs: %v", err)
		app.status.Store("error")
		app.updateMu.Unlock()
		return
	}
	ds := buildDataset(cves, &app.enr)
	if app.state.CVEAsOf.IsZero() {
		// Installs that predate the state file: newest record update is the best estimate
		app.state.CVEAsOf = ds.stats.LastUpdated
	}
	if app.state.CVE.IsZero() {
		if info, err := os.Stat(CachePath); err == nil {
			app.state.CVE = info.ModTime()
		}
	}
	app.publish(ds)
	app.saveState()
	app.updateMu.Unlock()

	logf("Ready: %d CVEs (%d KEV, %d with EPSS)", ds.stats.TotalCVEs, ds.stats.TotalKEV, ds.stats.WithEPSS)

	if os.Getenv("WEBCVE_NO_UPDATES") != "" {
		logf("WEBCVE_NO_UPDATES set: background updates disabled")
		return
	}
	go app.loop("cve-delta", DeltaInterval, app.updateCVEs)
	go app.loop("kev", KEVInterval, app.updateKEV)
	go app.loop("epss", EPSSInterval, app.updateEPSS)
}

// loop runs fn now and then every interval, logging failures
func (app *App) loop(name string, every time.Duration, fn func() error) {
	for {
		if err := fn(); err != nil {
			logf("%s update failed: %v", name, err)
		}
		time.Sleep(every)
	}
}

// publishSources snapshots update times for the stats endpoint. Caller holds updateMu.
func (app *App) publishSources() {
	app.sources.Store(&SourceTimes{CVE: app.state.CVE, CVEDelta: app.state.LastDelta, KEV: app.state.KEV, EPSS: app.state.EPSS})
}

func (app *App) publish(ds *Dataset) {
	ds.stats.EPSSDate = app.state.EPSSDate
	app.publishSources()
	prev := app.ds.Swap(ds)
	app.status.Store("ready")
	if prev != nil {
		app.alerts.notify(prev, ds)
	}
}

// rebuild republishes the current CVEs with fresh enrichment. Caller holds updateMu.
func (app *App) rebuild() {
	cur := app.dataset()
	if cur == nil {
		return
	}
	app.publish(buildDataset(slices.Clone(cur.CVEs), &app.enr))
}

// ---- State ----

func (app *App) loadState() {
	data, err := os.ReadFile(StatePath)
	if err == nil {
		json.Unmarshal(data, &app.state)
	}
}

func (app *App) saveState() {
	data, _ := json.MarshalIndent(app.state, "", "  ")
	if err := writeFileAtomic(StatePath, data); err != nil {
		logf("Warning: could not save update state: %v", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- HTTP helpers ----

func (app *App) get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "webcve")
	if strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Accept", "application/vnd.github+json")
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := app.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

func (app *App) download(url, path string) error {
	resp, err := app.get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, resp.Body)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ---- KEV ----

func (app *App) downloadKEV() error {
	logf("Downloading CISA KEV catalog...")
	return app.download(KEVDownloadURL, KEVPath)
}

// loadKEV reads the catalog into app.enr. Caller holds updateMu.
func (app *App) loadKEV() error {
	data, err := os.ReadFile(KEVPath)
	if err != nil {
		return err
	}
	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return err
	}
	index := make(map[string]*KEVEntry, len(catalog.Vulnerabilities))
	for i := range catalog.Vulnerabilities {
		entry := &catalog.Vulnerabilities[i]
		index[entry.CveID] = entry
	}
	app.enr.KEV = index
	app.enr.KEVCatalogDate = catalog.DateReleased
	if app.state.KEV.IsZero() {
		if info, err := os.Stat(KEVPath); err == nil {
			app.state.KEV = info.ModTime()
		}
	}
	logf("Loaded %d KEV entries (catalog %s)", len(index), catalog.DateReleased)
	return nil
}

func (app *App) updateKEV() error {
	if err := app.downloadKEV(); err != nil {
		return err
	}
	app.updateMu.Lock()
	defer app.updateMu.Unlock()
	prevDate := app.enr.KEVCatalogDate
	if err := app.loadKEV(); err != nil {
		return err
	}
	app.state.KEV = time.Now()
	app.saveState()
	if app.enr.KEVCatalogDate != prevDate {
		logf("KEV catalog changed (%s -> %s), rebuilding", prevDate, app.enr.KEVCatalogDate)
		app.rebuild()
	} else {
		app.publishSources()
	}
	return nil
}

// ---- EPSS ----

// ensureEPSS loads EPSS scores, downloading when missing, stale or forced. Caller holds updateMu.
func (app *App) ensureEPSS(force bool) error {
	info, err := os.Stat(EPSSPath)
	if force || err != nil || time.Since(info.ModTime()) > 20*time.Hour {
		logf("Downloading EPSS scores...")
		if derr := app.download(EPSSDownloadURL, EPSSPath); derr != nil {
			if err != nil {
				return derr // nothing usable on disk
			}
			logf("EPSS download failed, using cached copy: %v", derr)
		} else {
			app.state.EPSS = time.Now()
		}
	}
	scores, date, err := readEPSS(EPSSPath)
	if err != nil {
		return err
	}
	app.enr.EPSS = scores
	app.enr.EPSSDate = date
	app.state.EPSSDate = date
	if app.state.EPSS.IsZero() {
		if info, err := os.Stat(EPSSPath); err == nil {
			app.state.EPSS = info.ModTime()
		}
	}
	logf("Loaded %d EPSS scores (%s)", len(scores), date)
	return nil
}

var epssDateRe = regexp.MustCompile(`score_date:(\d{4}-\d{2}-\d{2})`)

// readEPSS parses the gzipped EPSS CSV: a "#model_version:...,score_date:..." line, a header, then rows
func readEPSS(path string) (map[string]EPSSScore, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, "", err
	}
	br := bufio.NewReader(gz)
	date := ""
	if first, _ := br.Peek(200); bytes.HasPrefix(first, []byte("#")) {
		line, _ := br.ReadString('\n')
		if m := epssDateRe.FindStringSubmatch(line); m != nil {
			date = m[1]
		}
	}
	r := csv.NewReader(br)
	r.ReuseRecord = true
	scores := make(map[string]EPSSScore, 320000)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if len(rec) < 3 || !strings.HasPrefix(rec[0], "CVE-") {
			continue
		}
		s, err1 := strconv.ParseFloat(rec[1], 32)
		p, err2 := strconv.ParseFloat(rec[2], 32)
		if err1 == nil && err2 == nil {
			scores[strings.Clone(rec[0])] = EPSSScore{Score: float32(s), Percentile: float32(p)}
		}
	}
	return scores, date, nil
}

func (app *App) updateEPSS() error {
	app.updateMu.Lock()
	defer app.updateMu.Unlock()
	prev := app.enr.EPSSDate
	if err := app.ensureEPSS(false); err != nil {
		return err
	}
	app.saveState()
	if app.enr.EPSSDate != prev {
		logf("EPSS scores changed (%s -> %s), rebuilding", prev, app.enr.EPSSDate)
		app.rebuild()
	}
	return nil
}

// ---- CVE releases ----

type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func (r *GitHubRelease) asset(contains string) (url string, size int64) {
	for _, a := range r.Assets {
		if strings.Contains(a.Name, contains) && strings.HasSuffix(a.Name, ".zip") {
			return a.BrowserDownloadURL, a.Size
		}
	}
	return "", 0
}

// releaseDay extracts "2026-10-20" from tags like cve_2026-10-20_1900Z / cve_2026-10-19_at_end_of_day
func releaseDay(tag string) string {
	if len(tag) >= 14 && strings.HasPrefix(tag, "cve_") {
		return tag[4:14]
	}
	return ""
}

// listReleases returns releases newest first, paging back until one is older than since
func (app *App) listReleases(since time.Time) ([]GitHubRelease, error) {
	var all []GitHubRelease
	for page := 1; page <= 10; page++ {
		resp, err := app.get(fmt.Sprintf("%s?per_page=100&page=%d", CVEReleasesAPI, page))
		if err != nil {
			return nil, err
		}
		var batch []GitHubRelease
		err = json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) == 0 || batch[len(batch)-1].PublishedAt.Before(since) {
			break
		}
	}
	return all, nil
}

// planDeltas picks, oldest first, the deltas that bring data current from asOf:
// each later day's end-of-day delta (cumulative for that day) and the newest
// delta of the current day. Already-applied tags are skipped.
func planDeltas(releases []GitHubRelease, asOf time.Time, lastDelta string) []GitHubRelease {
	startDay := asOf.UTC().Format("2006-01-02")
	best := map[string]GitHubRelease{}
	for _, r := range releases {
		day := releaseDay(r.TagName)
		if day == "" || day < startDay {
			continue
		}
		if url, _ := r.asset("_delta_CVEs_at_"); url == "" {
			continue
		}
		// "at_end_of_day" sorts after "2300Z", so the max tag is the most complete
		if cur, ok := best[day]; !ok || r.TagName > cur.TagName {
			best[day] = r
		}
	}
	var plan []GitHubRelease
	for _, r := range best {
		if r.TagName > lastDelta {
			plan = append(plan, r)
		}
	}
	slices.SortFunc(plan, func(a, b GitHubRelease) int { return strings.Compare(a.TagName, b.TagName) })
	return plan
}

// updateCVEs applies new delta releases, or a full snapshot when too far behind or weekly
func (app *App) updateCVEs() error {
	app.updateMu.Lock()
	asOf, lastDelta, lastFull := app.state.CVEAsOf, app.state.LastDelta, app.state.CVE
	app.updateMu.Unlock()

	if app.fullRunning.Load() {
		return nil
	}
	if asOf.IsZero() || time.Since(asOf) > MaxDeltaCatchUp {
		return app.fullRefresh()
	}

	releases, err := app.listReleases(asOf)
	if err != nil {
		return err
	}
	plan := planDeltas(releases, asOf, lastDelta)
	if len(plan) == 0 {
		return nil
	}

	changed := map[string]CVE{}
	for _, r := range plan {
		url, size := r.asset("_delta_CVEs_at_")
		logf("Applying CVE delta %s (%.1f MB)", r.TagName, float64(size)/(1<<20))
		recs, err := app.fetchDelta(url)
		if err != nil {
			return fmt.Errorf("delta %s: %w", r.TagName, err)
		}
		for _, c := range recs {
			changed[c.ID] = c
		}
	}

	app.updateMu.Lock()
	defer app.updateMu.Unlock()
	cur := app.dataset()
	if cur == nil {
		return nil
	}
	cves := slices.Clone(cur.CVEs)
	added := 0
	for id, c := range changed {
		if i, ok := cur.byID[id]; ok {
			cves[i] = c
		} else {
			cves = append(cves, c)
			added++
		}
	}
	last := plan[len(plan)-1]
	app.state.LastDelta = last.TagName
	app.state.CVEAsOf = last.PublishedAt
	app.state.CVE = time.Now()
	ds := buildDataset(cves, &app.enr)
	app.publish(ds)
	app.saveState()
	logf("Applied %d changed CVEs (%d new) through %s", len(changed), added, last.TagName)

	if err := saveCache(ds.CVEs); err != nil {
		logf("Warning: could not save cache: %v", err)
	}
	if time.Since(lastFull) > FullInterval {
		go func() {
			if err := app.fullRefresh(); err != nil {
				logf("Full refresh failed: %v", err)
			}
		}()
	}
	return nil
}

// fetchDelta downloads a delta zip and parses each record, writing it into
// the CVE tree when possible so restarts and the cache stay consistent
func (app *App) fetchDelta(url string) ([]CVE, error) {
	resp, err := app.get(url)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var out []CVE
	writeFailed := false
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if f.FileInfo().IsDir() || !strings.HasPrefix(name, "CVE-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		path := cvePath(strings.TrimSuffix(name, ".json"))
		if path == "" {
			continue
		}
		cve, err := parseCVEJSON(body, path)
		if err != nil || cve.ID == "" {
			continue
		}
		if !writeFailed {
			if err := writeFileAtomic(path, body); err != nil {
				logf("Warning: CVE tree is read-only, keeping delta in memory only: %v", err)
				writeFailed = true
			}
		}
		out = append(out, cve)
	}
	return out, nil
}

var cveIDRe = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

// cvePath maps CVE-2024-12345 to cves/2024/12xxx/CVE-2024-12345.json (cvelistV5 layout)
func cvePath(id string) string {
	m := cveIDRe.FindStringSubmatch(id)
	if m == nil {
		return ""
	}
	n, _ := strconv.Atoi(m[2])
	return filepath.Join(CVEDir, m[1], fmt.Sprintf("%dxxx", n/1000), id+".json")
}

// fullRefresh downloads the latest full snapshot and reparses everything
func (app *App) fullRefresh() error {
	if !app.fullRunning.CompareAndSwap(false, true) {
		return nil
	}
	defer app.fullRunning.Store(false)
	asOf, err := app.downloadCVEs()
	if err != nil {
		return err
	}
	cves, err := loadCVEs()
	if err != nil {
		return err
	}
	app.updateMu.Lock()
	defer app.updateMu.Unlock()
	app.state.CVEAsOf, app.state.LastDelta, app.state.CVE = asOf, "", time.Now()
	app.publish(buildDataset(cves, &app.enr))
	app.saveState()
	return nil
}

// downloadCVEs replaces the CVE tree with the latest full snapshot, returning its timestamp
func (app *App) downloadCVEs() (time.Time, error) {
	logf("Downloading full CVE snapshot from GitHub...")
	resp, err := app.get(CVEReleasesAPI + "/latest")
	if err != nil {
		return time.Time{}, err
	}
	var release GitHubRelease
	err = json.NewDecoder(resp.Body).Decode(&release)
	resp.Body.Close()
	if err != nil {
		return time.Time{}, fmt.Errorf("parse release: %w", err)
	}
	url, size := release.asset("all_CVEs")
	if url == "" {
		return time.Time{}, fmt.Errorf("no full CVE zip in release %s", release.TagName)
	}
	logf("Release %s: downloading %.0f MB...", release.TagName, float64(size)/(1<<20))

	tmpDir, err := os.MkdirTemp("", "webcve-full-")
	if err != nil {
		return time.Time{}, err
	}
	defer os.RemoveAll(tmpDir)
	zipPath := filepath.Join(tmpDir, "cves.zip")
	if err := app.download(url, zipPath); err != nil {
		return time.Time{}, err
	}

	// all_CVEs_at_midnight.zip.zip wraps the real archive in another zip
	if strings.HasSuffix(url, ".zip.zip") {
		inner, err := extractInnerZip(zipPath, tmpDir)
		if err != nil {
			return time.Time{}, err
		}
		zipPath = inner
	}

	// Clear the tree's contents but not the dir itself, which may be a mount point
	if entries, err := os.ReadDir(CVEDir); err == nil {
		for _, e := range entries {
			os.RemoveAll(filepath.Join(CVEDir, e.Name()))
		}
	}
	if err := os.MkdirAll(CVEDir, 0755); err != nil {
		return time.Time{}, err
	}
	if err := extractZip(zipPath, CVEDir); err != nil {
		return time.Time{}, err
	}
	// The snapshot is taken at midnight UTC of its release day
	asOf := release.PublishedAt
	if d, err := time.Parse("2006-01-02", releaseDay(release.TagName)); err == nil {
		asOf = d
	}
	logf("CVE snapshot %s extracted", release.TagName)
	return asOf, nil
}

func extractInnerZip(outer, dir string) (string, error) {
	zr, err := zip.OpenReader(outer)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".zip") {
			continue
		}
		dest := filepath.Join(dir, "inner.zip")
		src, err := f.Open()
		if err != nil {
			return "", err
		}
		out, err := os.Create(dest)
		if err != nil {
			src.Close()
			return "", err
		}
		_, err = io.Copy(out, src)
		src.Close()
		out.Close()
		return dest, err
	}
	return "", fmt.Errorf("no inner zip found in nested archive")
}

// extractZip extracts a zip into destDir, dropping the archive's top-level folder
func extractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	root := filepath.Clean(destDir) + string(os.PathSeparator)
	extracted := 0
	for _, file := range reader.File {
		parts := strings.SplitN(file.Name, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		destPath := filepath.Join(destDir, parts[1])
		if !strings.HasPrefix(destPath, root) {
			continue // zip-slip guard
		}
		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		dst, err := os.Create(destPath)
		if err != nil {
			src.Close()
			return err
		}
		_, err = io.Copy(dst, src)
		src.Close()
		dst.Close()
		if err != nil {
			return err
		}
		if extracted++; extracted%50000 == 0 {
			logf("Extracted %d/%d files...", extracted, len(reader.File))
		}
	}
	logf("Extracted %d files", extracted)
	return nil
}

func hasCVEFiles() bool {
	found := false
	filepath.WalkDir(CVEDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasPrefix(d.Name(), "CVE-") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
