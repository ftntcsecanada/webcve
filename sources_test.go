package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseCPE(t *testing.T) {
	v, p, ok := parseCPE(`cpe:2.3:a:palo_alto_networks:pan-os:10.2.0:*:*:*:*:*:*:*`)
	if !ok || v != "palo alto networks" || p != "pan-os" {
		t.Fatalf("got %q %q %v", v, p, ok)
	}
	if _, _, ok := parseCPE("cpe:2.3:a:*:*:*"); ok {
		t.Error("wildcard vendor accepted")
	}
	if normalizeVendor(v) != normalizeVendor("Palo Alto Networks") {
		t.Error("CPE vendor doesn't normalize like the CNA spelling")
	}
}

func TestNVDInfoPrefersPrimary(t *testing.T) {
	var c nvdCVE
	json.Unmarshal([]byte(`{"id":"CVE-2017-0144","vulnStatus":"Analyzed","lastModified":"2025-01-01T00:00:00.000",
	 "metrics":{"cvssMetricV31":[
	   {"source":"cna@example","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L","baseScore":5.3,"baseSeverity":"MEDIUM"}},
	   {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","baseScore":8.8,"baseSeverity":"HIGH"}}]},
	 "weaknesses":[{"type":"Primary","description":[{"value":"NVD-CWE-noinfo"}]},{"type":"Secondary","description":[{"value":"CWE-20"}]}],
	 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"},{"vulnerable":false,"criteria":"cpe:2.3:h:intel:x86:-:*:*:*:*:*:*:*"}]}]}]}`), &c)
	info := c.info()
	if info.Score != 8.8 || info.CWE != "CWE-20" || len(info.Products) != 1 || info.Products[0].Product != "windows 10" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if (&nvdCVE{VulnStatus: "Rejected"}).info() != nil {
		t.Error("rejected record kept")
	}
}

func TestNVDScoreFallback(t *testing.T) {
	enr := &Enrichment{NVD: map[string]*NVDInfo{
		"CVE-2020-1": {Status: "Analyzed", Version: "3.1", Score: 9.8, Severity: "CRITICAL", Vector: "CVSS:3.1/AV:N/AC:L", CWE: "CWE-79",
			Products: []AffectedProduct{{Vendor: "acme", Product: "widget"}}},
		"CVE-2020-2": {Score: 5.0, Severity: "MEDIUM"},
	}}
	ds := buildDataset([]CVE{
		{ID: "CVE-2020-1", AffectedProducts: []AffectedProduct{{Vendor: "n/a", Product: "n/a"}}},
		{ID: "CVE-2020-2", BaseScore: 7.5, BaseSeverity: "HIGH", CvssVersion: "3.1"},
	}, enr)
	a := ds.CVEs[ds.byID["CVE-2020-1"]]
	if a.BaseScore != 9.8 || a.ScoreSource != "nvd" || a.AttackVector != "NETWORK" || a.CWE != "CWE-79" {
		t.Fatalf("NVD fallback not applied: %+v", a)
	}
	if b := ds.CVEs[ds.byID["CVE-2020-2"]]; b.BaseScore != 7.5 || b.ScoreSource != "" {
		t.Errorf("CNA score overwritten: %+v", b)
	}
	if got := ids(ds, FilterRequest{Vendors: []string{"Acme"}}); !slices.Equal(got, []string{"CVE-2020-1"}) {
		t.Errorf("NVD vendor not filterable: %v", got)
	}
	// Once NVD drops the score, a rebuild clears what it had filled in
	enr.NVD = map[string]*NVDInfo{}
	ds2 := buildDataset(slices.Clone(ds.CVEs), enr)
	if a := ds2.CVEs[ds2.byID["CVE-2020-1"]]; a.BaseScore != 0 || a.CWE != "" || a.ScoreSource != "" {
		t.Errorf("stale NVD data survived a rebuild: %+v", a)
	}
}

func TestOSVHelpers(t *testing.T) {
	rec := &osvRecord{ID: "DEBIAN-CVE-2021-44228", Upstream: []string{"CVE-2021-44228"}, Aliases: []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}}
	if got := osvCVEs(rec); !slices.Equal(got, []string{"CVE-2021-44228"}) {
		t.Fatalf("osvCVEs = %v", got)
	}
	list := mergeFix(nil, PackageFix{Ecosystem: "Maven", Name: "log4j-core", Fixed: []string{"2.15.0"}})
	list = mergeFix(list, PackageFix{Ecosystem: "Maven", Name: "log4j-core", Fixed: []string{"2.12.2", "2.15.0"}})
	if len(list) != 1 || !slices.Equal(list[0].Fixed, []string{"2.15.0", "2.12.2"}) {
		t.Fatalf("mergeFix = %+v", list)
	}
}

func TestExploitSourcesAndDedup(t *testing.T) {
	enr := &Enrichment{
		Metasploit: map[string][]ExploitRef{"CVE-2024-1": {{Source: "metasploit", Title: "m", URL: "https://www.rapid7.com/db/modules/x/"}}},
		ExploitDB:  map[string][]ExploitRef{"CVE-2024-1": {{Source: "exploitdb", Title: "e", URL: "https://www.exploit-db.com/exploits/1"}}},
		EUVD:       map[string]euvdEntry{"CVE-2024-2": {CVE: "CVE-2024-2", EUVD: "EUVD-1", Since: "2024-05-01"}},
	}
	ds := buildDataset([]CVE{
		{ID: "CVE-2024-1", References: []Reference{{URL: "http://exploit-db.com/exploits/1/"}}},
		{ID: "CVE-2024-2"},
		{ID: "CVE-2024-3"},
	}, enr)
	ev := exploitEvidence(&ds.CVEs[ds.byID["CVE-2024-1"]])
	if len(ev) != 2 {
		t.Fatalf("reference duplicating an Exploit-DB entry not deduplicated: %+v", ev)
	}
	if got := ids(ds, FilterRequest{ExploitSources: []string{"metasploit", "euvd"}}); !slices.Equal(got, []string{"CVE-2024-1", "CVE-2024-2"}) {
		t.Errorf("exploit source filter = %v", got)
	}
	_, resp := ds.filterCVEs(compileFilter(ds, FilterRequest{ExploitSources: []string{"metasploit"}}), true)
	if resp.Facets.ExploitSources["euvd"] != 1 || resp.Facets.ExploitSources["metasploit"] != 1 {
		t.Errorf("exploit source facets = %v", resp.Facets.ExploitSources)
	}
}

func TestVendorRows(t *testing.T) {
	ds := testDataset()
	f := compileFilter(ds, FilterRequest{})
	rows := map[string]*VendorRow{}
	now := time.Now()
	for i := range ds.CVEs {
		if ds.failedGroups(i, f) != 0 {
			continue
		}
		for _, k := range ds.vendorKeys[i] {
			if rows[k] == nil {
				rows[k] = &VendorRow{Key: k, Years: make([]int, vendorYears), weakCount: map[string]int{}}
			}
			rows[k].add(&ds.CVEs[i], now.Year()-vendorYears+1, now.AddDate(-1, 0, 0), now.AddDate(-2, 0, 0), now.Format("2006-01-02"))
		}
	}
	ms := rows["microsoft"]
	ms.finish()
	if ms.CVEs != 2 || ms.Exploit != 1 || ms.Critical != 0 || ms.High != 1 || ms.CritHighPct != 0.5 {
		t.Fatalf("microsoft row = %+v", ms)
	}
	ft := rows["fortinet"]
	ft.finish()
	if ft.KEV != 1 || ft.Ransomware != 1 || ft.DaysToKEV != 2 || ft.KEVPct != 1 {
		t.Fatalf("fortinet row = %+v", ft)
	}
	list := []*VendorRow{ms, ft}
	sortVendorRows(list, "kevPct", true)
	if list[0].Key != "fortinet" {
		t.Error("sort by KEV rate failed")
	}
}

func TestStreamNVDFeed(t *testing.T) {
	feed := `{"resultsPerPage":2,"format":"NVD_CVE","timestamp":"2026-10-16T03:04:33",
	  "vulnerabilities":[
	    {"cve":{"id":"CVE-2002-0001","vulnStatus":"Analyzed","metrics":{"cvssMetricV2":[{"type":"Primary","cvssData":{"version":"2.0","baseScore":7.5},"baseSeverity":"HIGH"}]}}},
	    {"cve":{"id":"CVE-2002-0002","vulnStatus":"Rejected"}}
	  ]}`
	var got []string
	err := streamNVDFeed(strings.NewReader(feed), func(c *nvdCVE) {
		got = append(got, c.ID)
		if c.ID == "CVE-2002-0001" {
			if info := c.info(); info == nil || info.Score != 7.5 || info.Severity != "HIGH" {
				t.Errorf("v2 metric not parsed: %+v", info)
			}
		}
	})
	if err != nil || !slices.Equal(got, []string{"CVE-2002-0001", "CVE-2002-0002"}) {
		t.Fatalf("got %v, err %v", got, err)
	}
	if err := streamNVDFeed(strings.NewReader(`{"format":"NVD_CVE"}`), func(*nvdCVE) {}); err == nil {
		t.Error("feed without vulnerabilities accepted")
	}
}

func TestDownloadResumes(t *testing.T) {
	body := strings.Repeat("0123456789", 1000)
	failFirst := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if rng := r.Header.Get("Range"); rng != "" && r.Header.Get("If-Range") == `"v1"` {
			var from int
			fmt.Sscanf(rng, "bytes=%d-", &from)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(body)-1, len(body)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(body[from:]))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		if failFirst {
			// Send half, then drop the connection
			failFirst = false
			w.Write([]byte(body[:len(body)/2]))
			w.(http.Flusher).Flush()
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	app := newApp()
	app.loadState()
	path := filepath.Join(t.TempDir(), "feed.bin")
	if _, err := app.downloadIfChanged(srv.URL, path); err == nil {
		t.Fatal("expected the first, interrupted download to fail")
	}
	changed, err := app.downloadIfChanged(srv.URL, path)
	if err != nil || !changed {
		t.Fatalf("resume failed: changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Fatalf("resumed file is %d bytes, want %d", len(got), len(body))
	}
	if changed, err := app.downloadIfChanged(srv.URL, path); err != nil || changed {
		t.Fatalf("unchanged file re-downloaded: changed=%v err=%v", changed, err)
	}
}
