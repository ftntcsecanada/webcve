package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseFeedFormats(t *testing.T) {
	now := time.Now().UTC()
	rss := `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Critical flaw in Foo &amp; Bar (CVE-2026-1234)</title><link>https://a/1</link><guid>g1</guid>
<description>&lt;p&gt;Exploited &lt;b&gt;now&lt;/b&gt;, see cve-2026-1234 and CVE-2026-5678&lt;/p&gt;</description>
<pubDate>` + now.Format(time.RFC1123Z) + `</pubDate></item>
<item><title>No date</title><link>https://a/2</link></item></channel></rss>`
	items, err := parseFeed("t", strings.NewReader(rss))
	if err != nil || len(items) != 1 {
		t.Fatalf("rss: %v %+v", err, items)
	}
	s := items[0]
	if s.Title != "Critical flaw in Foo & Bar (CVE-2026-1234)" || s.Summary != "Exploited now , see cve-2026-1234 and CVE-2026-5678" ||
		!slices.Equal(s.CVEs, []string{"CVE-2026-1234", "CVE-2026-5678"}) || s.URL != "https://a/1" {
		t.Errorf("rss item: %+v", s)
	}

	rdf := `<?xml version="1.0"?><rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>j</title></channel><item><title>JPCERT alert</title><link>https://j/1</link><description>d</description><dc:date>` + now.Format(time.RFC3339) + `</dc:date></item></rdf:RDF>`
	items, err = parseFeed("j", strings.NewReader(rdf))
	if err != nil || len(items) != 1 || items[0].Title != "JPCERT alert" {
		t.Fatalf("rdf: %v %+v", err, items)
	}

	atom := `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>c</title>
<entry><title type="html">VU#123 Foo</title><link rel="alternate" href="https://c/1"/><id>tag:c,1</id><summary>s</summary><updated>` + now.Format(time.RFC3339) + `</updated></entry></feed>`
	items, err = parseFeed("c", strings.NewReader(atom))
	if err != nil || len(items) != 1 || items[0].URL != "https://c/1" {
		t.Fatalf("atom: %v %+v", err, items)
	}
}

func TestParseFeedTime(t *testing.T) {
	for _, s := range []string{"Fri, 13 Nov 26 12:00:00 +0000", "2026-11-11T11:21+09:00", "Tue, 10 Nov 2026 15:33:07 Z",
		"Tue, 10 Nov 2026 15:33:07 +0000", "2026-11-11T11:21:00Z", "2026-11-11"} {
		if ts, ok := parseFeedTime(s); !ok || ts.Year() != 2026 {
			t.Errorf("%q: %v %v", s, ts, ok)
		}
	}
	if _, err := parseFeed("x", strings.NewReader("<rss><channel><item><title>a\x0bb</title><link>l</link><pubDate>2026-11-11</pubDate></item></channel></rss>")); err != nil {
		t.Errorf("control character: %v", err)
	}
}

func TestSignalStoreKeepsWindowAndAI(t *testing.T) {
	h := &SignalHub{store: signalStore{Items: map[string]*Signal{}, Feeds: map[string]*feedState{}}}
	fresh := &Signal{ID: "a", Title: "t", Summary: "s", Published: time.Now()}
	old := &Signal{ID: "b", Title: "t", Published: time.Now().Add(-signalWindow - time.Hour)}
	if n := h.addLocked([]*Signal{fresh, old}); n != 1 {
		t.Fatalf("added %d", n)
	}
	h.store.Items["a"].AI = &ImpactAssessment{Rating: "low"}
	// Re-fetching the same item keeps its AI result
	if n := h.addLocked([]*Signal{{ID: "a", Title: "t", Summary: "s", Published: fresh.Published}}); n != 0 || h.store.Items["a"].AI == nil {
		t.Error("unchanged item should keep its assessment")
	}
	// A revised item is assessed again
	if n := h.addLocked([]*Signal{{ID: "a", Title: "t2", Summary: "s", Published: fresh.Published}}); n != 1 || h.store.Items["a"].AI != nil {
		t.Error("revised item should be reassessed")
	}
}

func TestSignatureReadiness(t *testing.T) {
	cases := []struct {
		name string
		cve  CVE
		want string
	}{
		{"closed source", CVE{}, "needs_research"},
		{"public PoC", CVE{GitHubPoCs: 3}, "ready"},
		{"detector only", CVE{GitHubPoCs: 1, Exploits: []ExploitRef{{Source: "github", Title: "foxcornlab/sap-patchday-scanner — Detection-only triage for the SAP November patch day"}}}, "needs_research"},
		{"detector plus unlisted repos", CVE{GitHubPoCs: 3, Exploits: []ExploitRef{{Source: "github", Title: "x/version-checker"}}}, "ready"},
		{"real PoC repo", CVE{GitHubPoCs: 1, Exploits: []ExploitRef{{Source: "github", Title: "x/CVE-2026-1 — Unauthenticated RCE exploit"}}}, "ready"},
		{"exploit and scanner", CVE{GitHubPoCs: 1, Exploits: []ExploitRef{{Source: "github", Title: "x/y — PoC exploit and mass scanner"}}}, "ready"},
		{"SSVC poc", CVE{SSVCExploitation: "poc"}, "ready"},
		{"exploit module", CVE{Exploits: []ExploitRef{{Source: "metasploit"}}}, "ready"},
		{"fix commit", CVE{References: []Reference{{URL: "https://github.com/php/php-src/commit/abc"}}}, "ready"},
		{"package", CVE{Packages: []PackageFix{{Ecosystem: "npm", Name: "x"}}}, "ready"},
		{"cloud", CVE{AIImpact: &ImpactAssessment{Tier: "triage", VendorCloud: 0.95}}, "not_feasible"},
		{"radio", CVE{AIImpact: &ImpactAssessment{Tier: "triage", CoverageClass: "none"}}, "not_feasible"},
	}
	for _, c := range cases {
		if got, _ := signatureReadiness(&c.cve); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestNowActionableAlert(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		posts = append(posts, body["text"])
		mu.Unlock()
	}))
	defer srv.Close()
	al := &Alerter{webhook: srv.URL, client: srv.Client()}
	analysis := func(rating, network string) *ImpactAssessment {
		return &ImpactAssessment{Rating: rating, Tier: "analysis", AnalysisVersion: impactAnalysisVersion, Network: network, DetectionAnchor: "POST /api/x with ../"}
	}
	fresh, old := time.Now().Add(-time.Hour), time.Now().AddDate(0, 0, -20)
	ids := []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5"}
	mk := func() *Dataset {
		var cves []CVE
		for i, id := range ids {
			d := old
			if i == 0 || i == 4 {
				d = fresh
			}
			cves = append(cves, CVE{ID: id, State: "PUBLISHED", DatePublished: d})
		}
		return buildDataset(cves, &Enrichment{})
	}
	prev, next := mk(), mk()
	set := func(ds *Dataset, id string, a *ImpactAssessment) { ds.CVEs[ds.byID[id]].AIImpact = a }
	set(next, "CVE-2026-1", analysis("severe", "new_signature")) // fresh analysis, actionable: alert
	set(next, "CVE-2026-2", analysis("high", "needs_details"))   // not actionable: quiet
	set(prev, "CVE-2026-3", analysis("high", "needs_details"))   // a PoC appeared and the verdict flipped: alert
	set(next, "CVE-2026-3", analysis("high", "new_signature"))
	next.CVEs[next.byID["CVE-2026-3"]].GitHubPoCs = 1
	set(next, "CVE-2026-4", analysis("high", "new_signature")) // old CVE, re-analysis backfill, no new evidence: quiet
	set(prev, "CVE-2026-5", analysis("high", "new_signature")) // already notable: quiet
	set(next, "CVE-2026-5", analysis("severe", "new_signature"))
	al.nowActionable(prev, next)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(posts)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 {
		t.Fatalf("posts: %q", posts)
	}
	for _, id := range []string{"CVE-2026-1", "CVE-2026-3"} {
		if !strings.Contains(posts[0], id) {
			t.Errorf("missing %s: %s", id, posts[0])
		}
	}
	for _, id := range []string{"CVE-2026-2", "CVE-2026-4", "CVE-2026-5"} {
		if strings.Contains(posts[0], id+" ") {
			t.Errorf("unexpected %s: %s", id, posts[0])
		}
	}
	if !strings.Contains(posts[0], "Anchor: POST /api/x") {
		t.Errorf("anchor missing: %s", posts[0])
	}
}

func TestResearchRawURLs(t *testing.T) {
	cases := map[string]string{
		"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1.yaml": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2026/CVE-2026-1.yaml",
		"https://github.com/php/php-src/commit/abc1234":                                                 "https://github.com/php/php-src/commit/abc1234.patch",
		"https://www.exploit-db.com/exploits/51234":                                                     "https://www.exploit-db.com/raw/51234",
		"https://www.rapid7.com/db/modules/exploit/linux/http/foo_rce/":                                 "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/linux/http/foo_rce.rb",
	}
	for in, want := range cases {
		if got := rawURL("exploit", in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
	if got := rawURL("poc", "https://github.com/someone/CVE-2026-1-poc"); got != "https://raw.githubusercontent.com/someone/CVE-2026-1-poc/HEAD/README.md" {
		t.Errorf("poc readme: %s", got)
	}
	srcs := researchSources(&CVE{
		Exploits:   []ExploitRef{{Source: "github", URL: "https://github.com/a/b"}, {Source: "nuclei", URL: "https://github.com/projectdiscovery/nuclei-templates/blob/main/x.yaml"}},
		References: []Reference{{URL: "https://nvd.nist.gov/vuln/detail/CVE-1"}, {URL: "https://github.com/o/r/commit/abcdef1"}, {URL: "https://vendor.example/advisory"}},
	})
	var kinds []string
	for _, s := range srcs {
		kinds = append(kinds, s.Kind)
	}
	if strings.Join(kinds, ",") != "scanner-template,fix-diff,poc,advisory" {
		t.Errorf("source order: %v", kinds)
	}
}

func TestSignalReadiness(t *testing.T) {
	ghsa := &Signal{Feed: "ghsa"}
	vendor := &Signal{Feed: "cisco"}
	blogNews := &Signal{Feed: "rapid7", Report: "other"}
	if st, _ := signalReadiness(ghsa, nil); st != "ready" {
		t.Error("GHSA should be ready")
	}
	if st, _ := signalReadiness(vendor, nil); st != "needs_research" {
		t.Error("closed vendor notice should need research")
	}
	if st, _ := signalReadiness(blogNews, nil); st == "ready" {
		t.Error("a news post isn't a write-up")
	}
	ds := buildDataset([]CVE{{ID: "CVE-2026-9", State: "PUBLISHED"}}, &Enrichment{})
	ds.CVEs[0].GitHubPoCs = 1
	vendor.CVEs = []string{"CVE-2026-9"}
	if st, _ := signalReadiness(vendor, ds); st != "ready" {
		t.Error("a vendor notice naming a ready CVE should be ready")
	}
}

// zipOf builds an in-memory codeload-style archive from placeholder files
func zipOf(t *testing.T, files map[string]string) *zip.Reader {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, _ := w.Create("repo-main/" + name)
		f.Write([]byte(body))
	}
	w.Close()
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestClassifyRepo(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"advisory rewrite", map[string]string{"README.md": "Verification guide for the vendor advisory", "index.html": "<html>advisory table</html>"}, "no_code"},
		{"version checker", map[string]string{"README.md": "Checks whether a host runs a vulnerable version", "check_version.py": "print('compare banner to fixed version')"}, "detector"},
		{"exploit", map[string]string{"README.md": "PoC for the flaw", "exploit.py": "# placeholder"}, "exploit"},
	}
	for _, c := range cases {
		info := &repoInfo{}
		classifyRepo(info, zipOf(t, c.files))
		if info.Kind != c.want {
			t.Errorf("%s: got %s, want %s", c.name, info.Kind, c.want)
		}
	}
	info := &repoInfo{}
	classifyRepo(info, zipOf(t, map[string]string{"util.py": "# helper", "exploit.py": "# main", "README.md": "PoC"}))
	if info.Main != "exploit.py" {
		t.Errorf("main file: %s", info.Main)
	}
}

func TestInspectedRepoDecidesReadiness(t *testing.T) {
	loadRepoChecks()
	url := "https://github.com/someone/cve-2026-76954-guide"
	repoMu.Lock()
	repoChecks[url] = &repoInfo{Kind: "no_code", Checked: time.Now()}
	repoMu.Unlock()
	t.Cleanup(func() { repoMu.Lock(); delete(repoChecks, url); repoMu.Unlock() })
	cve := &CVE{GitHubPoCs: 1, Exploits: []ExploitRef{{Source: "github", URL: url, Title: "someone/cve-2026-76954-guide"}}}
	if st, _ := signatureReadiness(cve); st != "needs_research" {
		t.Errorf("a repo with no code should not make a CVE ready: %s", st)
	}
	if !strings.Contains(pocRepoText(repoChecks[url]), "no exploit code") {
		t.Error("research text should say the repo holds no exploit code")
	}
}
