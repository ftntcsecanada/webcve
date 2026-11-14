package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Research context for deep analyses: the technical material a signature
// engineer would read before deciding whether network protections can catch a
// flaw. Scanner templates hold the exact exploit request, exploit code and PoC
// READMEs show the trigger, fix diffs show the vulnerable field, and
// advisories and write-ups describe the protocol path. The model judges
// detectability from this evidence instead of from memory.

const (
	researchDir      = DataDir + "/research"
	researchMaxDocs  = 6
	researchMaxChars = 16000
	researchDocChars = 5000
	researchTTL      = 7 * 24 * time.Hour
)

type researchDoc struct {
	Kind string `json:"kind"` // scanner-template, exploit, poc, fix-diff, advisory, write-up
	URL  string `json:"url"`
	Text string `json:"text"`
}

type researchCache struct {
	Fetched time.Time     `json:"fetched"`
	Key     string        `json:"key"` // what the context was built from; a change refetches
	Docs    []researchDoc `json:"docs"`
}

var (
	researchMu     sync.Mutex
	researchClient = &http.Client{Timeout: 20 * time.Second}
	// Hosts whose pages carry no technical detail (records about the record) or need a browser
	researchSkip  = regexp.MustCompile(`(?i)^https?://(?:[^/]*\.)?(?:nvd\.nist\.gov|cve\.org|cve\.mitre\.org|twitter\.com|x\.com|linkedin\.com|facebook\.com|youtube\.com|msrc\.microsoft\.com|cwe\.mitre\.org|first\.org|cisa\.gov/known-exploited)`)
	githubRepo    = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/#?]+)/?$`)
	githubBlob    = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$`)
	githubCommit  = regexp.MustCompile(`^https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}`)
	exploitDBPage = regexp.MustCompile(`^https://www\.exploit-db\.com/exploits/(\d+)`)
	rapid7Module  = regexp.MustCompile(`^https://www\.rapid7\.com/db/modules/(.+?)/?$`)
	scriptStyle   = regexp.MustCompile(`(?is)<(script|style|noscript|svg|nav|footer|header)[^>]*>.*?</(script|style|noscript|svg|nav|footer|header)>`)
)

// researchSources picks what to read for a CVE, most useful first
func researchSources(cve *CVE) []researchDoc {
	var out []researchDoc
	seen := map[string]bool{}
	add := func(kind, url string) {
		if url != "" && !seen[url] && !researchSkip.MatchString(url) {
			seen[url] = true
			out = append(out, researchDoc{Kind: kind, URL: url})
		}
	}
	for _, x := range cve.Exploits {
		switch x.Source {
		case "nuclei":
			add("scanner-template", x.URL)
		case "metasploit", "exploitdb":
			add("exploit", x.URL)
		}
	}
	for _, r := range cve.References {
		if githubCommit.MatchString(r.URL) || fixCommitRef.MatchString(r.URL) {
			add("fix-diff", r.URL)
		}
	}
	for _, x := range cve.Exploits {
		if x.Source == "github" {
			add("poc", x.URL)
		}
	}
	for _, r := range cve.References {
		add("advisory", r.URL)
	}
	return out
}

// rawURL maps a page to the form with the most text and least markup
func rawURL(kind, url string) string {
	switch {
	case githubCommit.MatchString(url):
		return strings.SplitN(url, "#", 2)[0] + ".patch"
	case githubBlob.MatchString(url):
		m := githubBlob.FindStringSubmatch(url)
		return "https://raw.githubusercontent.com/" + m[1] + "/" + m[2] + "/" + m[3]
	case githubRepo.MatchString(url) && kind == "poc":
		m := githubRepo.FindStringSubmatch(url)
		return "https://raw.githubusercontent.com/" + m[1] + "/" + m[2] + "/HEAD/README.md"
	case exploitDBPage.MatchString(url):
		return "https://www.exploit-db.com/raw/" + exploitDBPage.FindStringSubmatch(url)[1]
	case rapid7Module.MatchString(url):
		// exploit/linux/http/foo -> modules/exploits/linux/http/foo.rb
		name := rapid7Module.FindStringSubmatch(url)[1]
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			if parts[0] == "exploit" {
				parts[0] = "exploits"
			}
			return "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/" + parts[0] + "/" + parts[1] + ".rb"
		}
	}
	return url
}

// fetchResearchDoc downloads one document as plain text
func fetchResearchDoc(d researchDoc) (string, error) {
	req, err := http.NewRequest("GET", rawURL(d.Kind, d.URL), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "webcve")
	resp, err := researchClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text") && !strings.Contains(ct, "json") && !strings.Contains(ct, "xml") && !strings.Contains(ct, "yaml") && ct != "" {
		return "", fmt.Errorf("not text (%s)", ct)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	text := string(raw)
	if strings.Contains(ct, "html") {
		text = cleanText(scriptStyle.ReplaceAllString(text, " "))
	}
	return truncate(strings.TrimSpace(text), researchDocChars), nil
}

// researchKey summarises what the context is built from, so it's refetched
// when exploit material or references change
func researchKey(sources []researchDoc) string {
	var b strings.Builder
	for _, s := range sources {
		b.WriteString(s.URL)
		b.WriteByte('\n')
	}
	return fmt.Sprintf("%d:%x", len(sources), hashString(b.String()))
}

func hashString(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// gatherResearch returns the research context for a set of candidate
// sources, from the disk cache when it's fresh
func gatherResearch(cacheID string, sources []researchDoc) []researchDoc {
	key := researchKey(sources)
	path := researchDir + "/" + strings.NewReplacer("/", "_", "..", "_").Replace(cacheID) + ".json"
	var cache researchCache
	if readJSONFile(path, &cache) == nil && cache.Key == key && time.Since(cache.Fetched) < researchTTL {
		return cache.Docs
	}
	var docs []researchDoc
	total := 0
	for _, s := range sources {
		if len(docs) >= researchMaxDocs || total >= researchMaxChars {
			break
		}
		text, err := fetchResearchDoc(s)
		if err != nil || len(text) < 200 { // nothing useful: a script-rendered page or an error stub
			continue
		}
		text = truncate(text, researchMaxChars-total)
		total += len(text)
		docs = append(docs, researchDoc{Kind: s.Kind, URL: s.URL, Text: text})
	}
	researchMu.Lock()
	defer researchMu.Unlock()
	os.MkdirAll(researchDir, 0o755)
	if err := writeJSONAtomic(path, researchCache{Fetched: time.Now(), Key: key, Docs: docs}); err != nil {
		logf("Research: could not cache %s: %v", cacheID, err)
	}
	return docs
}
