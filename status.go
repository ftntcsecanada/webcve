package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// SourceInfo describes a data source for the status page
type SourceInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Interval    string `json:"interval"`
	every       time.Duration
	paths       []string // files whose size is reported (globs allowed)
}

// SourceStatus is the live state of one source
type SourceStatus struct {
	SourceInfo
	State       string    `json:"state"` // pending, syncing, ok, error
	Detail      string    `json:"detail,omitempty"`
	LastAttempt time.Time `json:"lastAttempt"`
	LastSuccess time.Time `json:"lastSuccess"`
	LastChange  time.Time `json:"lastChange"`
	NextCheck   time.Time `json:"nextCheck"`
	Error       string    `json:"error,omitempty"`
	ErrorAt     time.Time `json:"errorAt"`
	Records     int       `json:"records"`
	RecordUnit  string    `json:"recordUnit"`
	Bytes       int64     `json:"bytes"`
}

var sourceCatalog = []SourceInfo{
	{Name: "cve", Label: "CVE records", Description: "CVE Program records (cvelistV5): hourly deltas plus a weekly full snapshot.",
		URL: "https://github.com/CVEProject/cvelistV5", every: DeltaInterval, paths: []string{CachePath}},
	{Name: "kev", Label: "CISA KEV catalog", Description: "Known Exploited Vulnerabilities: CVEs CISA has evidence are exploited in the wild, with remediation due dates.",
		URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", every: KEVInterval, paths: []string{KEVPath}},
	{Name: "epss", Label: "FIRST EPSS", Description: "Exploit Prediction Scoring System: daily probability that a CVE is exploited in the next 30 days.",
		URL: "https://www.first.org/epss/", every: EPSSInterval, paths: []string{EPSSPath}},
	{Name: "nvd", Label: "NIST NVD", Description: "National Vulnerability Database: NVD's own CVSS scores (used when the CVE record has none), CWE and CPE product names.",
		URL: "https://nvd.nist.gov/developers/vulnerabilities", every: 2 * time.Hour, paths: []string{nvdPath}},
	{Name: "exploitdb", Label: "Exploit-DB", Description: "Offensive Security's archive of public exploits, mapped to CVEs.",
		URL: "https://www.exploit-db.com/", every: 24 * time.Hour, paths: []string{exploitDBPath}},
	{Name: "metasploit", Label: "Metasploit modules", Description: "Rapid7 Metasploit Framework exploit and auxiliary modules that reference CVEs.",
		URL: "https://github.com/rapid7/metasploit-framework", every: 24 * time.Hour, paths: []string{metasploitPath}},
	{Name: "nuclei", Label: "Nuclei templates", Description: "ProjectDiscovery scanner templates that detect specific CVEs.",
		URL: "https://github.com/projectdiscovery/nuclei-templates", every: 24 * time.Hour, paths: []string{nucleiPath}},
	{Name: "github-poc", Label: "PoC-in-GitHub", Description: "Community index of GitHub repositories with proof-of-concept code, by CVE. Unvetted.",
		URL: "https://github.com/nomi-sec/PoC-in-GitHub", every: 24 * time.Hour, paths: []string{pocGitHubPath}},
	{Name: "euvd", Label: "ENISA EUVD", Description: "EU Vulnerability Database: CVEs ENISA lists as exploited.",
		URL: "https://euvd.enisa.europa.eu/", every: 6 * time.Hour, paths: []string{euvdPath}},
	{Name: "msrc", Label: "Microsoft MSRC", Description: "Microsoft Security Response Center exploitability assessments from monthly security updates (2016 onward).",
		URL: "https://msrc.microsoft.com/update-guide", every: 12 * time.Hour, paths: []string{msrcPath}},
	{Name: "osv", Label: "OSV package fixes", Description: "Open Source Vulnerabilities: fixed versions from GitHub advisories, language ecosystems and Debian, Red Hat and Alpine.",
		URL: "https://osv.dev/", every: 24 * time.Hour, paths: []string{osvDir + "/*.zip"}},
	{Name: "cwe", Label: "MITRE CWE", Description: "Common Weakness Enumeration catalog, for weakness names.",
		URL: "https://cwe.mitre.org/", every: 7 * 24 * time.Hour, paths: []string{cwePath}},
}

type statusBoard struct {
	mu      sync.Mutex
	sources map[string]*SourceStatus
}

func newStatusBoard() *statusBoard {
	b := &statusBoard{sources: map[string]*SourceStatus{}}
	for _, info := range sourceCatalog {
		info.Interval = humanDuration(info.every)
		b.sources[info.Name] = &SourceStatus{SourceInfo: info, State: "pending"}
	}
	return b
}

func (b *statusBoard) update(name string, fn func(s *SourceStatus)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.sources[name]; s != nil {
		fn(s)
	}
}

// attempt marks a fetch as started
func (b *statusBoard) attempt(name, detail string) {
	b.update(name, func(s *SourceStatus) {
		s.LastAttempt, s.State, s.Detail = time.Now(), "syncing", detail
	})
}

// success records a completed fetch
func (b *statusBoard) success(name string, changed bool) {
	b.update(name, func(s *SourceStatus) {
		now := time.Now()
		s.LastSuccess, s.State, s.Detail, s.Error = now, "ok", "", ""
		s.NextCheck = now.Add(s.every)
		if changed || s.LastChange.IsZero() {
			s.LastChange = now
		}
	})
}

// fail records a failed fetch; earlier data stays in use
func (b *statusBoard) fail(name string, err error, retry time.Duration) {
	b.update(name, func(s *SourceStatus) {
		now := time.Now()
		s.State, s.Detail, s.Error, s.ErrorAt = "error", "", err.Error(), now
		s.NextCheck = now.Add(retry)
	})
}

func (b *statusBoard) progress(name, detail string) {
	b.update(name, func(s *SourceStatus) { s.Detail = detail })
}

func (b *statusBoard) records(name string, n int, unit string) {
	b.update(name, func(s *SourceStatus) { s.Records, s.RecordUnit = n, unit })
}

// seed fills times from persisted state so a restart doesn't show everything as never updated
func (b *statusBoard) seed(name string, last time.Time) {
	if last.IsZero() {
		return
	}
	b.update(name, func(s *SourceStatus) {
		if s.LastSuccess.IsZero() {
			s.LastSuccess, s.LastChange = last, last
			s.NextCheck = last.Add(s.every)
			if s.State == "pending" {
				s.State = "ok"
			}
		}
	})
}

func (b *statusBoard) snapshot() []SourceStatus {
	b.mu.Lock()
	out := make([]SourceStatus, 0, len(b.sources))
	for _, s := range b.sources {
		out = append(out, *s)
	}
	b.mu.Unlock()
	order := map[string]int{}
	for i, info := range sourceCatalog {
		order[info.Name] = i
	}
	sort.Slice(out, func(i, j int) bool { return order[out[i].Name] < order[out[j].Name] })
	for i := range out {
		out[i].Bytes = pathsSize(out[i].paths)
	}
	return out
}

func pathsSize(patterns []string) int64 {
	var total int64
	for _, p := range patterns {
		matches, _ := filepath.Glob(p)
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil {
				total += info.Size()
			}
		}
	}
	return total
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		if d == 24*time.Hour {
			return "daily"
		}
		if d == 7*24*time.Hour {
			return "weekly"
		}
		return d.String()
	case d == time.Hour:
		return "hourly"
	case d%time.Hour == 0:
		return fmt.Sprintf("every %d hours", int(d.Hours()))
	default:
		return "every " + d.String()
	}
}

func (app *App) handleSources(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"status":  app.statusString(),
		"sources": app.board.snapshot(),
		"now":     time.Now(),
	})
}
