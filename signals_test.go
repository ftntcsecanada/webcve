package main

import (
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
	severe := &ImpactAssessment{Rating: "severe", Tier: "analysis"}
	prev := buildDataset([]CVE{{ID: "CVE-2026-1", State: "PUBLISHED"}, {ID: "CVE-2026-2", State: "PUBLISHED"}}, &Enrichment{})
	next := buildDataset([]CVE{{ID: "CVE-2026-1", State: "PUBLISHED"}, {ID: "CVE-2026-2", State: "PUBLISHED"}}, &Enrichment{})
	next.CVEs[next.byID["CVE-2026-1"]].AIImpact = severe
	next.CVEs[next.byID["CVE-2026-1"]].GitHubPoCs = 1    // a PoC appeared
	next.CVEs[next.byID["CVE-2026-2"]].AIImpact = severe // still closed
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
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 || !strings.Contains(posts[0], "CVE-2026-1") || strings.Contains(posts[0], "CVE-2026-2") {
		t.Errorf("posts: %q", posts)
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
