package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// PoC repo inspection. PoC-in-GitHub indexes any repository named after a
// CVE, so "PoC repos" include advisory rewrites, link lists and version
// checkers alongside real exploits. Names and descriptions can't tell them
// apart, so each repo linked to an elevated CVE is downloaded (one codeload zip,
// no API quota) and classified by what it contains:
//
//	exploit   code that isn't just a detector
//	detector  code or docs that only check whether a target is vulnerable
//	no_code   documentation, web pages or images only
//
// Verdicts are cached in RepoChecksPath. Signature readiness counts only repos
// verified as exploits, and the research step reads the main exploit file.

const (
	RepoChecksPath = DataDir + "/github-repos.json"
	repoZipLimit   = 8 << 20
	repoRecheck    = 14 * 24 * time.Hour
)

type repoInfo struct {
	Kind     string    `json:"kind"` // exploit, detector, no_code, unknown
	Files    []string  `json:"files,omitempty"`
	Main     string    `json:"main,omitempty"`     // the file most likely to hold the exploit
	MainText string    `json:"mainText,omitempty"` // its first researchDocChars characters
	Readme   string    `json:"readme,omitempty"`
	Checked  time.Time `json:"checked"`
	Error    string    `json:"error,omitempty"`
}

var (
	repoMu     sync.RWMutex
	repoChecks = map[string]*repoInfo{}
	repoLoaded bool

	codeExt = map[string]bool{
		".py": true, ".go": true, ".rb": true, ".js": true, ".mjs": true, ".ts": true, ".c": true, ".cc": true, ".cpp": true,
		".h": true, ".java": true, ".kt": true, ".sh": true, ".bash": true, ".ps1": true, ".pl": true, ".php": true, ".rs": true,
		".cs": true, ".lua": true, ".nse": true, ".yaml": true, ".yml": true, ".http": true, ".swift": true, ".vbs": true,
	}
	mainFileHint = regexp.MustCompile(`(?i)(exploit|poc|cve|rce|payload|attack|pwn)`)
	repoURL      = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/#?]+)/?$`)
)

func loadRepoChecks() {
	repoMu.Lock()
	defer repoMu.Unlock()
	if repoLoaded {
		return
	}
	repoLoaded = true
	readJSONFile(RepoChecksPath, &repoChecks)
	if repoChecks == nil {
		repoChecks = map[string]*repoInfo{}
	}
}

func saveRepoChecksLocked() {
	if err := writeJSONAtomic(RepoChecksPath, repoChecks); err != nil {
		logf("Repo checks: could not save: %v", err)
	}
}

// repoVerdict returns the cached verdict for a repo URL, if it's been checked
func repoVerdict(url string) (string, bool) {
	repoMu.RLock()
	defer repoMu.RUnlock()
	if r := repoChecks[strings.TrimSuffix(url, "/")]; r != nil && r.Kind != "unknown" {
		return r.Kind, true
	}
	return "", false
}

// repoDetails returns the cached inspection of a repo
func repoDetails(url string) *repoInfo {
	repoMu.RLock()
	defer repoMu.RUnlock()
	return repoChecks[strings.TrimSuffix(url, "/")]
}

// checkRepo inspects a repo unless a fresh verdict is cached
func checkRepo(url string) *repoInfo {
	loadRepoChecks()
	url = strings.TrimSuffix(url, "/")
	if r := repoDetails(url); r != nil && time.Since(r.Checked) < repoRecheck && r.Kind != "unknown" {
		return r
	}
	info := inspectRepo(url)
	repoMu.Lock()
	repoChecks[url] = info
	saveRepoChecksLocked()
	repoMu.Unlock()
	return info
}

func inspectRepo(url string) *repoInfo {
	info := &repoInfo{Kind: "unknown", Checked: time.Now()}
	m := repoURL.FindStringSubmatch(url)
	if m == nil {
		info.Error = "not a repository URL"
		return info
	}
	req, _ := http.NewRequest("GET", "https://codeload.github.com/"+m[1]+"/"+m[2]+"/zip/HEAD", nil)
	req.Header.Set("User-Agent", "webcve")
	resp, err := researchClient.Do(req)
	if err != nil {
		info.Error = shortErr(err)
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		info.Kind, info.Error = "no_code", "repository gone or empty"
		return info
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return info
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, repoZipLimit+1))
	if err != nil {
		info.Error = shortErr(err)
		return info
	}
	if len(data) > repoZipLimit {
		// A large project is a real tool or framework, not an advisory copy
		info.Kind, info.Error = "exploit", "large repository, not inspected"
		return info
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		info.Error = "unreadable archive"
		return info
	}
	classifyRepo(info, zr)
	return info
}

// classifyRepo sets Kind, Files, Main and the text the research step reads
func classifyRepo(info *repoInfo, zr *zip.Reader) {
	type codeFile struct {
		name string
		f    *zip.File
	}
	var code []codeFile
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// Archive paths start with "<repo>-<ref>/"
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "/.") {
			continue
		}
		info.Files = append(info.Files, name)
		lower := strings.ToLower(name)
		if strings.HasPrefix(path.Base(lower), "readme") && info.Readme == "" {
			info.Readme = truncate(readZipText(f), 3000)
		}
		if codeExt[path.Ext(lower)] && f.UncompressedSize64 < 512<<10 && !strings.Contains(lower, "test") {
			code = append(code, codeFile{name, f})
		}
	}
	sort.Strings(info.Files)
	if len(info.Files) > 40 {
		info.Files = info.Files[:40]
	}
	if len(code) == 0 {
		info.Kind = "no_code"
		return
	}
	// Main file: named like an exploit, else the largest code file
	sort.Slice(code, func(i, j int) bool {
		hi, hj := mainFileHint.MatchString(path.Base(code[i].name)), mainFileHint.MatchString(path.Base(code[j].name))
		if hi != hj {
			return hi
		}
		return code[i].f.UncompressedSize64 > code[j].f.UncompressedSize64
	})
	info.Main = code[0].name
	info.MainText = truncate(readZipText(code[0].f), researchDocChars)

	var names []string
	for _, c := range code {
		names = append(names, c.name)
	}
	desc := info.Readme + " " + strings.Join(names, " ") + " " + truncate(info.MainText, 1500)
	if isDetectorRepo(desc) {
		info.Kind = "detector"
		return
	}
	info.Kind = "exploit"
}

func readZipText(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
	return string(b)
}

// sweepRepos inspects the PoC repos of high and severe CVEs that haven't been
// checked, so readiness is right before (and between) deep analyses
func (app *App) sweepRepos() error {
	loadRepoChecks()
	ds := app.dataset()
	if ds == nil {
		return nil
	}
	var todo []string
	for i := range ds.CVEs {
		c := &ds.CVEs[i]
		if c.AIImpact == nil || impactRank(c.AIImpact.Rating) < impactRank("high") {
			continue
		}
		for _, x := range c.Exploits {
			if x.Source != "github" {
				continue
			}
			if r := repoDetails(x.URL); r == nil || (r.Kind == "unknown" && time.Since(r.Checked) > time.Hour) {
				todo = append(todo, x.URL)
			}
		}
	}
	if len(todo) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, u := range todo {
		counts[checkRepo(u).Kind]++
		time.Sleep(time.Second) // polite to codeload
	}
	logf("Repo checks: inspected %d PoC repos %v", len(todo), counts)
	app.dirty.Store(true)
	return nil
}
