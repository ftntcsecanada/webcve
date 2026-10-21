package main

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Source is an external feed polled on its own schedule. Fetch downloads
// into DataDir and reports whether anything changed; Parse reads what's on
// disk (without holding updateMu) and returns a function that installs the
// result into the enrichment. Installs mark the dataset dirty and a single
// rebuilder coalesces bursts of changes into one rebuild.
type Source struct {
	Name  string
	Every time.Duration
	Fetch func(app *App) (changed bool, err error)
	Parse func(app *App) (install func(*Enrichment), err error)
}

func (app *App) sources() []*Source {
	return []*Source{
		{Name: "exploitdb", Every: 24 * time.Hour, Fetch: fetchFile(exploitDBURL, exploitDBPath), Parse: parseExploitDB},
		{Name: "metasploit", Every: 24 * time.Hour, Fetch: fetchFile(metasploitURL, metasploitPath), Parse: parseMetasploit},
		{Name: "nuclei", Every: 24 * time.Hour, Fetch: fetchFile(nucleiURL, nucleiPath), Parse: parseNuclei},
		{Name: "github-poc", Every: 24 * time.Hour, Fetch: fetchFile(pocGitHubURL, pocGitHubPath), Parse: parsePoCGitHub},
		{Name: "cwe", Every: 7 * 24 * time.Hour, Fetch: fetchFile(cweURL, cwePath), Parse: parseCWE},
		{Name: "euvd", Every: 6 * time.Hour, Fetch: fetchEUVD, Parse: parseEUVD},
		{Name: "msrc", Every: 12 * time.Hour, Fetch: fetchMSRC, Parse: parseMSRC},
		{Name: "osv", Every: 24 * time.Hour, Fetch: fetchOSV, Parse: parseOSV},
		{Name: "nvd", Every: 2 * time.Hour, Fetch: fetchNVD, Parse: parseNVD},
	}
}

// runSource installs what's already on disk, then fetches whenever the data is stale
func (app *App) runSource(s *Source) {
	app.installSource(s)
	for {
		app.updateMu.Lock()
		last := app.state.Fetched[s.Name]
		app.updateMu.Unlock()
		if wait := s.Every - time.Since(last); wait > 0 {
			time.Sleep(wait)
		}

		app.board.attempt(s.Name, "downloading")
		changed, err := s.Fetch(app)
		if err != nil {
			logf("%s: fetch failed: %v", s.Name, err)
			retry := min(s.Every, time.Hour) // retry sooner than a full interval
			app.board.fail(s.Name, err, retry)
			time.Sleep(retry)
			continue
		}
		app.board.success(s.Name, changed)
		app.updateMu.Lock()
		app.state.Fetched[s.Name] = time.Now()
		app.saveState()
		app.publishSources()
		app.updateMu.Unlock()
		if changed {
			app.installSource(s)
		}
	}
}

func (app *App) installSource(s *Source) {
	install, err := s.Parse(app)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("%s: parse failed: %v", s.Name, err)
			app.board.fail(s.Name, fmt.Errorf("parse: %w", err), s.Every)
		}
		return
	}
	app.updateMu.Lock()
	install(&app.enr)
	app.updateMu.Unlock()
	app.dirty.Store(true)
}

// rebuilder republishes the dataset when enrichment changed, at most every 15s
func (app *App) rebuilder() {
	for range time.Tick(15 * time.Second) {
		if !app.dirty.Swap(false) {
			continue
		}
		app.updateMu.Lock()
		app.rebuild()
		app.updateMu.Unlock()
	}
}

// ---- Conditional downloads ----

// fetchFile downloads url to path when the server's ETag changed
func fetchFile(url, path string) func(app *App) (bool, error) {
	return func(app *App) (bool, error) {
		return app.downloadIfChanged(url, path)
	}
}

func (app *App) downloadIfChanged(url, path string) (bool, error) {
	app.updateMu.Lock()
	etag := app.state.ETags[url]
	app.updateMu.Unlock()
	if _, err := os.Stat(path); err != nil {
		etag = "" // file missing: fetch unconditionally
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "webcve")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := app.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	tmp := path + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(out, resp.Body)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	if tag := resp.Header.Get("ETag"); tag != "" {
		app.updateMu.Lock()
		app.state.ETags[url] = tag
		app.updateMu.Unlock()
	}
	return true, nil
}

func (app *App) getJSON(url string, v any, header map[string]string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "webcve")
	req.Header.Set("Accept", "application/json")
	for k, val := range header {
		req.Header.Set(k, val)
	}
	resp, err := app.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func writeJSONAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func readJSONFile(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(bufio.NewReader(f)).Decode(v)
}

var cveRefRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// ---- Exploit-DB ----

const (
	exploitDBURL  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	exploitDBPath = DataDir + "/exploitdb.csv"
)

func parseExploitDB(app *App) (func(*Enrichment), error) {
	f, err := os.Open(exploitDBPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"id", "description", "date_published", "type", "verified", "codes"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("exploitdb: missing column %q", need)
		}
	}
	out := map[string][]ExploitRef{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) <= col["codes"] {
			continue
		}
		ids := cveRefRe.FindAllString(rec[col["codes"]], -1)
		if len(ids) == 0 {
			continue
		}
		note := rec[col["type"]]
		if rec[col["verified"]] == "1" {
			note += " · verified"
		}
		ref := ExploitRef{
			Source: "exploitdb",
			Title:  rec[col["description"]],
			URL:    "https://www.exploit-db.com/exploits/" + rec[col["id"]],
			Date:   rec[col["date_published"]],
			Note:   note,
		}
		for _, id := range ids {
			out[id] = append(out[id], ref)
		}
	}
	logf("exploitdb: %d CVEs with exploits", len(out))
	app.board.records("exploitdb", len(out), "CVEs with exploits")
	return func(e *Enrichment) { e.ExploitDB = out }, nil
}

// ---- Metasploit ----

const (
	metasploitURL  = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
	metasploitPath = DataDir + "/metasploit_modules.json"
)

func parseMetasploit(app *App) (func(*Enrichment), error) {
	var modules map[string]struct {
		Name           string   `json:"name"`
		Fullname       string   `json:"fullname"`
		Type           string   `json:"type"`
		DisclosureDate string   `json:"disclosure_date"`
		References     []string `json:"references"`
	}
	if err := readJSONFile(metasploitPath, &modules); err != nil {
		return nil, err
	}
	out := map[string][]ExploitRef{}
	for _, m := range modules {
		if m.Type != "exploit" && m.Type != "auxiliary" {
			continue
		}
		ref := ExploitRef{
			Source: "metasploit",
			Title:  m.Name,
			URL:    "https://www.rapid7.com/db/modules/" + m.Fullname + "/",
			Date:   m.DisclosureDate,
			Note:   m.Type + " module",
		}
		for _, r := range m.References {
			if strings.HasPrefix(r, "CVE-") {
				out[r] = append(out[r], ref)
			}
		}
	}
	logf("metasploit: %d CVEs with modules", len(out))
	app.board.records("metasploit", len(out), "CVEs with modules")
	return func(e *Enrichment) { e.Metasploit = out }, nil
}

// ---- Nuclei templates ----

const (
	nucleiURL  = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
	nucleiPath = DataDir + "/nuclei_cves.json"
)

func parseNuclei(app *App) (func(*Enrichment), error) {
	f, err := os.Open(nucleiPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string][]ExploitRef{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var t struct {
			ID   string `json:"ID"`
			Info struct {
				Name     string `json:"Name"`
				Severity string `json:"Severity"`
			} `json:"Info"`
			FilePath string `json:"file_path"`
		}
		if json.Unmarshal(sc.Bytes(), &t) != nil || !strings.HasPrefix(t.ID, "CVE-") {
			continue
		}
		out[t.ID] = append(out[t.ID], ExploitRef{
			Source: "nuclei",
			Title:  t.Info.Name,
			URL:    "https://github.com/projectdiscovery/nuclei-templates/blob/main/" + t.FilePath,
			Note:   "scanner template · " + t.Info.Severity,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	logf("nuclei: %d CVEs with templates", len(out))
	app.board.records("nuclei", len(out), "CVEs with templates")
	return func(e *Enrichment) { e.Nuclei = out }, nil
}

// ---- PoC-in-GitHub ----

const (
	pocGitHubURL  = "https://codeload.github.com/nomi-sec/PoC-in-GitHub/zip/refs/heads/master"
	pocGitHubPath = DataDir + "/poc-in-github.zip"
	maxGitHubPoCs = 8
)

func parsePoCGitHub(app *App) (func(*Enrichment), error) {
	zr, err := zip.OpenReader(pocGitHubPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	refs := map[string][]ExploitRef{}
	totals := map[string]int{}
	for _, f := range zr.File {
		id := strings.TrimSuffix(filepath.Base(f.Name), ".json")
		if !cveIDRe.MatchString(id) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var repos []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Stars       int    `json:"stargazers_count"`
			CreatedAt   string `json:"created_at"`
		}
		err = json.NewDecoder(rc).Decode(&repos)
		rc.Close()
		if err != nil || len(repos) == 0 {
			continue
		}
		sort.SliceStable(repos, func(i, j int) bool { return repos[i].Stars > repos[j].Stars })
		totals[id] = len(repos)
		for _, r := range repos[:min(maxGitHubPoCs, len(repos))] {
			title := r.FullName
			if d := strings.TrimSpace(r.Description); d != "" {
				title += " — " + d
			}
			refs[id] = append(refs[id], ExploitRef{
				Source: "github",
				Title:  truncate(title, 200),
				URL:    r.HTMLURL,
				Date:   r.CreatedAt[:min(10, len(r.CreatedAt))],
				Stars:  r.Stars,
			})
		}
	}
	logf("github-poc: %d CVEs with PoC repositories", len(refs))
	app.board.records("github-poc", len(refs), "CVEs with PoC repos")
	return func(e *Enrichment) { e.GitHubPoCs, e.GitHubPoCTotals = refs, totals }, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// ---- MITRE CWE catalog ----

const (
	cweURL  = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
	cwePath = DataDir + "/cwec_latest.xml.zip"
)

func parseCWE(app *App) (func(*Enrichment), error) {
	zr, err := zip.OpenReader(cwePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	names := map[string]string{}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		dec := xml.NewDecoder(bufio.NewReader(rc))
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			se, ok := tok.(xml.StartElement)
			if !ok || (se.Name.Local != "Weakness" && se.Name.Local != "Category") {
				continue
			}
			var id, name string
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "ID":
					id = a.Value
				case "Name":
					name = a.Value
				}
			}
			if id != "" && name != "" {
				names["CWE-"+id] = name
			}
		}
		rc.Close()
	}
	logf("cwe: %d weakness names", len(names))
	app.board.records("cwe", len(names), "weaknesses")
	return func(e *Enrichment) { e.CWENames = names }, nil
}

// ---- ENISA EU Vulnerability Database ----

const euvdPath = DataDir + "/euvd_exploited.json"

type euvdEntry struct {
	CVE   string `json:"cve"`
	EUVD  string `json:"euvd"`
	Since string `json:"since"`
}

func fetchEUVD(app *App) (bool, error) {
	var all []euvdEntry
	for page := 0; page < 100; page++ {
		var resp struct {
			Items []struct {
				ID             string `json:"id"`
				Aliases        string `json:"aliases"`
				ExploitedSince string `json:"exploitedSince"`
			} `json:"items"`
			Total int `json:"total"`
		}
		url := fmt.Sprintf("https://euvdservices.enisa.europa.eu/api/search?exploited=true&size=100&page=%d", page)
		if err := app.getJSON(url, &resp, nil); err != nil {
			return false, err
		}
		for _, it := range resp.Items {
			since := it.ExploitedSince
			if t, err := time.Parse("Jan 2, 2006, 3:04:05 PM", since); err == nil {
				since = t.Format("2006-01-02")
			}
			for _, id := range cveRefRe.FindAllString(it.Aliases, -1) {
				all = append(all, euvdEntry{CVE: id, EUVD: it.ID, Since: since})
			}
		}
		if len(resp.Items) < 100 || (page+1)*100 >= resp.Total {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(all) == 0 {
		return false, fmt.Errorf("euvd: no exploited entries returned")
	}
	return true, writeJSONAtomic(euvdPath, all)
}

func parseEUVD(app *App) (func(*Enrichment), error) {
	var entries []euvdEntry
	if err := readJSONFile(euvdPath, &entries); err != nil {
		return nil, err
	}
	out := make(map[string]euvdEntry, len(entries))
	for _, e := range entries {
		out[e.CVE] = e
	}
	logf("euvd: %d exploited CVEs", len(out))
	app.board.records("euvd", len(out), "exploited CVEs")
	return func(e *Enrichment) { e.EUVD = out }, nil
}

// ---- Microsoft Security Response Center ----

const (
	msrcPath    = DataDir + "/msrc.json"
	msrcUpdates = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
)

var msrcDocRe = regexp.MustCompile(`^(\d{4})-[A-Z][a-z]{2}$`)

type msrcStore struct {
	Docs map[string]string    `json:"docs"` // document ID -> CurrentReleaseDate seen
	CVEs map[string]*MSRCInfo `json:"cves"`
}

func fetchMSRC(app *App) (bool, error) {
	store := msrcStore{Docs: map[string]string{}, CVEs: map[string]*MSRCInfo{}}
	readJSONFile(msrcPath, &store) // missing on first run
	if store.Docs == nil {
		store.Docs, store.CVEs = map[string]string{}, map[string]*MSRCInfo{}
	}

	var updates struct {
		Value []struct {
			ID                 string `json:"ID"`
			CurrentReleaseDate string `json:"CurrentReleaseDate"`
			CvrfURL            string `json:"CvrfUrl"`
		} `json:"value"`
	}
	if err := app.getJSON(msrcUpdates, &updates, nil); err != nil {
		return false, err
	}
	// Oldest first, so a later document's assessment wins
	sort.Slice(updates.Value, func(i, j int) bool { return updates.Value[i].CurrentReleaseDate < updates.Value[j].CurrentReleaseDate })
	changed := 0
	for _, u := range updates.Value {
		m := msrcDocRe.FindStringSubmatch(u.ID)
		if m == nil || m[1] < "2016" || store.Docs[u.ID] == u.CurrentReleaseDate {
			continue
		}
		app.board.progress("msrc", "fetching "+u.ID)
		if err := app.fetchMSRCDoc(u.CvrfURL, u.ID, store.CVEs); err != nil {
			logf("msrc: %s: %v", u.ID, err)
			continue
		}
		store.Docs[u.ID] = u.CurrentReleaseDate
		changed++
		time.Sleep(time.Second)
	}
	if changed == 0 {
		return false, nil
	}
	logf("msrc: refreshed %d monthly documents", changed)
	return true, writeJSONAtomic(msrcPath, store)
}

func (app *App) fetchMSRCDoc(url, release string, into map[string]*MSRCInfo) error {
	var doc struct {
		Vulnerability []struct {
			CVE   string `json:"CVE"`
			Title struct {
				Value string `json:"Value"`
			} `json:"Title"`
			Threats []struct {
				Type        int `json:"Type"`
				Description struct {
					Value string `json:"Value"`
				} `json:"Description"`
			} `json:"Threats"`
		} `json:"Vulnerability"`
	}
	if err := app.getJSON(url, &doc, nil); err != nil {
		return err
	}
	for _, v := range doc.Vulnerability {
		if !strings.HasPrefix(v.CVE, "CVE-") {
			continue
		}
		info := &MSRCInfo{Title: v.Title.Value, Release: release}
		found := false
		for _, t := range v.Threats {
			if t.Type != 1 { // 1 = exploitability
				continue
			}
			// "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;DOS:N/A"
			for _, kv := range strings.Split(t.Description.Value, ";") {
				k, val, ok := strings.Cut(kv, ":")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "Publicly Disclosed":
					info.PubliclyDisclosed = strings.EqualFold(strings.TrimSpace(val), "yes")
				case "Exploited":
					info.Exploited = strings.EqualFold(strings.TrimSpace(val), "yes")
				case "Latest Software Release":
					info.Assessment = strings.TrimSpace(val)
				}
				found = true
			}
			break
		}
		if found {
			into[v.CVE] = info
		}
	}
	return nil
}

func parseMSRC(app *App) (func(*Enrichment), error) {
	var store msrcStore
	if err := readJSONFile(msrcPath, &store); err != nil {
		return nil, err
	}
	logf("msrc: %d CVEs with exploitability assessments", len(store.CVEs))
	app.board.records("msrc", len(store.CVEs), "assessed CVEs")
	return func(e *Enrichment) { e.MSRC = store.CVEs }, nil
}

// ---- OSV (GitHub advisories, language ecosystems, Linux distros) ----

// Ubuntu (750 MB) is left out; Debian, Red Hat and Alpine cover distro fixes
var osvEcosystems = []string{"npm", "PyPI", "Maven", "Go", "NuGet", "RubyGems", "crates.io", "Packagist", "Debian", "Alpine", "Red Hat"}

const (
	osvDir        = DataDir + "/osv"
	maxPkgPerCVE  = 40
	maxFixedPerPk = 6
)

func osvPath(eco string) string {
	return filepath.Join(osvDir, strings.ReplaceAll(eco, " ", "_")+".zip")
}

func fetchOSV(app *App) (bool, error) {
	changed := false
	var firstErr error
	for _, eco := range osvEcosystems {
		app.board.progress("osv", "downloading "+eco)
		url := "https://osv-vulnerabilities.storage.googleapis.com/" + strings.ReplaceAll(eco, " ", "%20") + "/all.zip"
		c, err := app.downloadIfChanged(url, osvPath(eco))
		if err != nil {
			logf("osv: %s: %v", eco, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		changed = changed || c
	}
	if !changed && firstErr != nil {
		return false, firstErr
	}
	return changed, nil
}

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Upstream  []string `json:"upstream"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func parseOSV(app *App) (func(*Enrichment), error) {
	out := map[string][]PackageFix{}
	files := 0
	for _, eco := range osvEcosystems {
		zr, err := zip.OpenReader(osvPath(eco))
		if err != nil {
			continue
		}
		files++
		for _, f := range zr.File {
			// MAL- entries are malicious-package reports, never CVEs
			if strings.HasPrefix(filepath.Base(f.Name), "MAL-") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			var rec osvRecord
			err = json.NewDecoder(rc).Decode(&rec)
			rc.Close()
			if err != nil || rec.Withdrawn != "" {
				continue
			}
			cves := osvCVEs(&rec)
			if len(cves) == 0 {
				continue
			}
			for _, a := range rec.Affected {
				fix := PackageFix{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, Advisory: rec.ID}
				for _, r := range a.Ranges {
					for _, ev := range r.Events {
						if v := ev["fixed"]; v != "" && !slices.Contains(fix.Fixed, v) && len(fix.Fixed) < maxFixedPerPk {
							fix.Fixed = append(fix.Fixed, v)
						}
					}
				}
				if fix.Name == "" {
					continue
				}
				for _, id := range cves {
					out[id] = mergeFix(out[id], fix)
				}
			}
		}
		zr.Close()
	}
	if files == 0 {
		return nil, os.ErrNotExist
	}
	logf("osv: %d CVEs with package fix data", len(out))
	app.board.records("osv", len(out), "CVEs with package fixes")
	return func(e *Enrichment) { e.OSV = out }, nil
}

func osvCVEs(rec *osvRecord) []string {
	var ids []string
	add := func(s string) {
		if cveIDRe.MatchString(s) && !slices.Contains(ids, s) {
			ids = append(ids, s)
		}
	}
	add(rec.ID)
	for _, a := range rec.Aliases {
		add(a)
	}
	for _, u := range rec.Upstream {
		add(u)
	}
	return ids
}

func mergeFix(list []PackageFix, fix PackageFix) []PackageFix {
	for i := range list {
		if list[i].Ecosystem == fix.Ecosystem && list[i].Name == fix.Name {
			for _, v := range fix.Fixed {
				if !slices.Contains(list[i].Fixed, v) && len(list[i].Fixed) < maxFixedPerPk {
					list[i].Fixed = append(list[i].Fixed, v)
				}
			}
			return list
		}
	}
	if len(list) >= maxPkgPerCVE {
		return list
	}
	return append(list, fix)
}

// ---- NVD ----

const (
	nvdAPI     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPath    = DataDir + "/nvd.gob"
	nvdPage    = 2000
	nvdMaxSpan = 119 * 24 * time.Hour // the API caps lastMod ranges at 120 days
)

// nvdStore is owned by the NVD fetch loop; installs hand the dataset a copy
var nvdStore map[string]*NVDInfo

func nvdDelay() time.Duration {
	if os.Getenv("NVD_API_KEY") != "" {
		return 700 * time.Millisecond // 50 requests / 30s
	}
	return 6500 * time.Millisecond // 5 requests / 30s without a key
}

func fetchNVD(app *App) (bool, error) {
	if nvdStore == nil {
		nvdStore = map[string]*NVDInfo{}
		if f, err := os.Open(nvdPath); err == nil {
			gob.NewDecoder(bufio.NewReader(f)).Decode(&nvdStore)
			f.Close()
		}
	}
	app.updateMu.Lock()
	watermark, resume := app.state.NVDWatermark, app.state.NVDResume
	app.updateMu.Unlock()

	start := time.Now().UTC()
	full := watermark.IsZero() || time.Since(watermark) > nvdMaxSpan || len(nvdStore) == 0
	query := ""
	if full {
		if resume == 0 {
			logf("nvd: starting full sync (about %d pages)", 170)
		} else {
			logf("nvd: resuming full sync at record %d", resume)
		}
	} else {
		from := watermark.Add(-time.Hour)
		query = "&lastModStartDate=" + from.Format("2006-01-02T15:04:05.000Z") + "&lastModEndDate=" + start.Format("2006-01-02T15:04:05.000Z")
		resume = 0
	}

	header := map[string]string{}
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		header["apiKey"] = key
	}
	updated := 0
	pageSize, streak := nvdPage, 0
	lastSaved := resume
	saveProgress := func(index int) {
		app.updateMu.Lock()
		app.state.NVDResume = index
		app.saveState()
		app.updateMu.Unlock()
		saveNVDStore()
		lastSaved = index
	}
	for index := resume; ; {
		var page nvdResponse
		var err error
		// NVD can take minutes to build a large page and sometimes stalls; on
		// failure, wait and retry with a smaller page, growing back after successes
		for attempt := 1; attempt <= 6; attempt++ {
			url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d%s", nvdAPI, pageSize, index, query)
			app.board.progress("nvd", fmt.Sprintf("requesting records %d–%d%s", index, index+pageSize, nvdProgressSuffix(full, page.TotalResults, attempt)))
			if err = app.getNVD(url, &page, header); err == nil {
				break
			}
			logf("nvd: request for %d records at %d failed (attempt %d): %v", pageSize, index, attempt, err)
			app.board.progress("nvd", fmt.Sprintf("NVD is slow or throttling; retrying in %ds with smaller pages (%v)", 20*attempt, shortErr(err)))
			pageSize = max(250, pageSize/2)
			streak = 0
			time.Sleep(time.Duration(20*attempt) * time.Second)
		}
		if err != nil {
			if full {
				saveProgress(index)
			}
			return updated > 0, err
		}
		for _, v := range page.Vulnerabilities {
			if info := v.CVE.info(); info != nil {
				nvdStore[v.CVE.ID] = info
			} else {
				delete(nvdStore, v.CVE.ID)
			}
			updated++
		}
		index += len(page.Vulnerabilities)
		if streak++; streak >= 3 && pageSize < nvdPage {
			pageSize, streak = min(nvdPage, pageSize*2), 0
		}
		if full {
			app.board.progress("nvd", fmt.Sprintf("full sync: %d of %d records", index, page.TotalResults))
			if index-lastSaved >= 20000 {
				saveProgress(index)
				logf("nvd: %d / %d records", index, page.TotalResults)
			}
		} else {
			app.board.progress("nvd", fmt.Sprintf("%d of %d changed records", index, page.TotalResults))
		}
		if len(page.Vulnerabilities) == 0 || index >= page.TotalResults {
			break
		}
		time.Sleep(nvdDelay())
	}

	if err := saveNVDStore(); err != nil {
		return false, err
	}
	app.updateMu.Lock()
	app.state.NVDWatermark = start
	app.state.NVDResume = 0
	app.saveState()
	app.updateMu.Unlock()
	if updated > 0 {
		logf("nvd: %d records updated (%d total)", updated, len(nvdStore))
	}
	return updated > 0, nil
}

// nvdClient bounds each NVD request; NVD sometimes stalls mid-response
var nvdClient = &http.Client{Timeout: 3 * time.Minute}

func (app *App) getNVD(url string, v any, header map[string]string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "webcve")
	for k, val := range header {
		req.Header.Set(k, val)
	}
	resp, err := nvdClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func nvdProgressSuffix(full bool, total, attempt int) string {
	s := ""
	if full && total > 0 {
		s = fmt.Sprintf(" of %d", total)
	}
	if attempt > 1 {
		s += fmt.Sprintf(" (attempt %d)", attempt)
	}
	return s
}

// shortErr trims long transport errors for the status page
func shortErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "deadline exceeded") {
		return "timed out"
	}
	return truncate(msg, 80)
}

func saveNVDStore() error {
	tmp := nvdPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	err = gob.NewEncoder(w).Encode(nvdStore)
	if ferr := w.Flush(); err == nil {
		err = ferr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, nvdPath)
}

func parseNVD(app *App) (func(*Enrichment), error) {
	if nvdStore == nil {
		// First load at startup, before the fetch loop has read the file
		store := map[string]*NVDInfo{}
		f, err := os.Open(nvdPath)
		if err != nil {
			return nil, err
		}
		err = gob.NewDecoder(bufio.NewReader(f)).Decode(&store)
		f.Close()
		if err != nil {
			return nil, err
		}
		nvdStore = store
	}
	snapshot := make(map[string]*NVDInfo, len(nvdStore))
	for k, v := range nvdStore {
		snapshot[k] = v
	}
	logf("nvd: %d records", len(snapshot))
	app.board.records("nvd", len(snapshot), "CVE records")
	return func(e *Enrichment) { e.NVD = snapshot }, nil
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CvssData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 keeps it beside cvssData
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	LastModified string `json:"lastModified"`
	Metrics      struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Type        string `json:"type"`
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Criteria   string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// info condenses an NVD record; nil for rejected records
func (c *nvdCVE) info() *NVDInfo {
	if c.VulnStatus == "Rejected" {
		return nil
	}
	info := &NVDInfo{Status: c.VulnStatus}
	if t, err := time.Parse("2006-01-02T15:04:05.000", c.LastModified); err == nil {
		info.Modified = t
	}
	// NVD's own (Primary) score first; 3.1 > 3.0 > 4.0 > 2.0 to match the CVE record's priority
	pick := func(primaryOnly bool) bool {
		for _, list := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2} {
			for _, m := range list {
				if (primaryOnly && m.Type != "Primary") || m.CvssData.BaseScore == 0 {
					continue
				}
				info.Version = m.CvssData.Version
				info.Score = m.CvssData.BaseScore
				info.Vector = m.CvssData.VectorString
				info.Severity = strings.ToUpper(m.CvssData.BaseSeverity)
				if info.Severity == "" {
					info.Severity = strings.ToUpper(m.BaseSeverity)
				}
				if info.Severity == "" {
					info.Severity = deriveSeverityFromScore(info.Score)
				}
				return true
			}
		}
		return false
	}
	if !pick(true) {
		pick(false)
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && info.CWE == "" {
				info.CWE = d.Value
			}
		}
	}
	seen := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable || len(info.Products) >= 25 {
					continue
				}
				vendor, product, ok := parseCPE(m.Criteria)
				if ok && !seen[vendor+"\x00"+product] {
					seen[vendor+"\x00"+product] = true
					info.Products = append(info.Products, AffectedProduct{Vendor: vendor, Product: product})
				}
			}
		}
	}
	return info
}

// parseCPE extracts a readable vendor and product from a CPE 2.3 string
func parseCPE(cpe string) (vendor, product string, ok bool) {
	// cpe:2.3:a:palo_alto_networks:pan-os:10.2.0:*:*:*:*:*:*:*
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 || parts[3] == "*" || parts[4] == "*" {
		return "", "", false
	}
	clean := func(s string) string {
		s = strings.ReplaceAll(s, `\`, "")
		return strings.ReplaceAll(s, "_", " ")
	}
	return clean(parts[3]), clean(parts[4]), true
}

// ---- EPSS history (on demand) ----

type epssPoint struct {
	Date       string  `json:"date"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// epssHistory returns ~30 days of EPSS scores from FIRST's API, cached for 6h
func (app *App) epssHistory(id string) ([]epssPoint, error) {
	app.epssMu.Lock()
	if c, ok := app.epssCache[id]; ok && time.Since(c.at) < 6*time.Hour {
		app.epssMu.Unlock()
		return c.points, nil
	}
	app.epssMu.Unlock()

	var resp struct {
		Data []struct {
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
			TimeSeries []struct {
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"time-series"`
		} `json:"data"`
	}
	if err := app.getJSON("https://api.first.org/data/v1/epss?scope=time-series&cve="+id, &resp, nil); err != nil {
		return nil, err
	}
	var points []epssPoint
	add := func(e, p, d string) {
		ev, err1 := strconv.ParseFloat(e, 64)
		pv, err2 := strconv.ParseFloat(p, 64)
		if err1 == nil && err2 == nil {
			points = append(points, epssPoint{Date: d, EPSS: ev, Percentile: pv})
		}
	}
	if len(resp.Data) > 0 {
		d := resp.Data[0]
		add(d.EPSS, d.Percentile, d.Date)
		for _, t := range d.TimeSeries {
			add(t.EPSS, t.Percentile, t.Date)
		}
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Date < points[j].Date })

	app.epssMu.Lock()
	if len(app.epssCache) > 5000 {
		app.epssCache = map[string]epssCacheEntry{}
	}
	app.epssCache[id] = epssCacheEntry{at: time.Now(), points: points}
	app.epssMu.Unlock()
	return points, nil
}

type epssCacheEntry struct {
	at     time.Time
	points []epssPoint
}
