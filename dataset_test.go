package main

import (
	"slices"
	"testing"
	"time"
)

func testDataset() *Dataset {
	day := func(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }
	cves := []CVE{
		{ID: "CVE-2024-0001", Year: 2024, DatePublished: day("2024-01-10"), Title: "FortiOS SSL-VPN heap overflow",
			Description:      "A heap-based buffer overflow in FortiOS SSL-VPN allows remote code execution.",
			AffectedProducts: []AffectedProduct{{Vendor: "Fortinet, Inc.", Product: "FortiOS"}},
			BaseScore:        9.8, BaseSeverity: "CRITICAL", AttackVector: "NETWORK", CWE: "CWE-122", State: "PUBLISHED"},
		{ID: "CVE-2024-0002", Year: 2024, DatePublished: day("2024-02-01"), Title: "Windows SMB elevation of privilege",
			Description:      "Elevation of privilege in the SMB client.",
			AffectedProducts: []AffectedProduct{{Vendor: "Microsoft Corporation", Product: "Windows 11"}},
			BaseScore:        7.8, BaseSeverity: "HIGH", AttackVector: "LOCAL", CWE: "CWE-269", State: "PUBLISHED",
			References: []Reference{{URL: "https://www.exploit-db.com/exploits/1"}}},
		{ID: "CVE-2023-0003", Year: 2023, DatePublished: day("2023-06-01"), Title: "Edge spoofing",
			Description:      "Spoofing in Microsoft Edge via crafted page.",
			AffectedProducts: []AffectedProduct{{Vendor: "microsoft", Product: "Edge"}},
			BaseScore:        4.3, BaseSeverity: "MEDIUM", AttackVector: "NETWORK", CWE: "CWE-451", State: "PUBLISHED"},
		{ID: "CVE-2022-0004", Year: 2022, DatePublished: day("2022-03-01"), Title: "Unscored widget bug",
			Description:      "SQL injection in widget admin panel.",
			AffectedProducts: []AffectedProduct{{Vendor: "n/a", Product: "n/a"}}, State: "PUBLISHED",
			SSVCExploitation: "poc"},
	}
	enr := &Enrichment{
		KEV: map[string]*KEVEntry{
			"CVE-2024-0001": {CveID: "CVE-2024-0001", DateAdded: "2024-01-12", DueDate: "2024-01-19",
				KnownRansomwareCampaignUse: "Known", VulnerabilityName: "Fortinet FortiOS Out-of-Bounds Write"},
		},
		KEVCatalogDate: "2024-02-02T00:00:00Z",
		EPSS:           map[string]EPSSScore{"CVE-2024-0001": {Score: 0.94, Percentile: 0.99}, "CVE-2024-0002": {Score: 0.02, Percentile: 0.6}},
	}
	return buildDataset(cves, enr)
}

func ids(ds *Dataset, req FilterRequest) []string {
	matches, _ := ds.filterCVEs(compileFilter(ds, req), false)
	out := []string{}
	for _, i := range matches {
		out = append(out, ds.CVEs[i].ID)
	}
	slices.Sort(out)
	return out
}

func TestNormalizeVendor(t *testing.T) {
	cases := map[string]string{
		"Microsoft Corporation": "microsoft",
		"microsoft":             "microsoft",
		"Fortinet, Inc.":        "fortinet",
		"Hikvision Co., Ltd.":   "hikvision",
		"AT&T":                  "at&t",
		"Co":                    "co", // never strip down to nothing
	}
	for in, want := range cases {
		if got := normalizeVendor(in); got != want {
			t.Errorf("normalizeVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVendorFilterMergesSpellings(t *testing.T) {
	ds := testDataset()
	got := ids(ds, FilterRequest{Vendors: []string{"Microsoft"}})
	want := []string{"CVE-2023-0003", "CVE-2024-0002"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if ds.vendors[0].Key != "microsoft" || ds.vendors[0].Count != 2 {
		t.Errorf("top vendor option = %+v, want microsoft x2", ds.vendors[0])
	}
}

func TestSearch(t *testing.T) {
	ds := testDataset()
	cases := []struct {
		q    string
		want []string
	}{
		{"fortios", []string{"CVE-2024-0001"}},
		{"forti", []string{"CVE-2024-0001"}},            // prefix
		{"remote code", []string{"CVE-2024-0001"}},      // AND of terms
		{`"code execution"`, []string{"CVE-2024-0001"}}, // phrase
		{`"execution code"`, []string{}},                // phrase order matters
		{"CVE-2024-0002", []string{"CVE-2024-0002"}},
		{"cve-2024", []string{"CVE-2024-0001", "CVE-2024-0002"}},
		{"vendor:microsoft", []string{"CVE-2023-0003", "CVE-2024-0002"}},
		{"vendor:microsoft spoofing", []string{"CVE-2023-0003"}},
		{"cwe:122", []string{"CVE-2024-0001"}},
		{"sev:critical", []string{"CVE-2024-0001"}},
		{"kev:yes", []string{"CVE-2024-0001"}},
		{"epss:>50%", []string{"CVE-2024-0001"}},
		{"exploit:yes", []string{"CVE-2022-0004", "CVE-2024-0002"}},
		{"the", []string{"CVE-2022-0004", "CVE-2023-0003", "CVE-2024-0001", "CVE-2024-0002"}}, // stopword only
		{"nonexistentword", []string{}},
	}
	for _, c := range cases {
		if got := ids(ds, FilterRequest{Search: c.q}); !slices.Equal(got, c.want) {
			t.Errorf("search %q = %v, want %v", c.q, got, c.want)
		}
	}
}

func TestFacetsAreDisjunctive(t *testing.T) {
	ds := testDataset()
	_, resp := ds.filterCVEs(compileFilter(ds, FilterRequest{Severities: []string{"CRITICAL"}}), true)
	// Severity counts ignore the severity filter itself
	if resp.Facets.Severity["HIGH"] != 1 || resp.Facets.Severity["NONE"] != 1 {
		t.Errorf("severity facets = %v", resp.Facets.Severity)
	}
	// Other facets respect it
	if resp.Facets.AttackVector["LOCAL"] != 0 || resp.Facets.AttackVector["NETWORK"] != 1 {
		t.Errorf("attack vector facets = %v", resp.Facets.AttackVector)
	}
	if resp.Facets.KEV != 1 || resp.Facets.Ransomware != 1 {
		t.Errorf("kev facets = %+v", resp.Facets)
	}
}

func TestEnrichment(t *testing.T) {
	ds := testDataset()
	c := ds.CVEs[ds.byID["CVE-2024-0001"]]
	if !c.InKEV || c.EPSS < 0.9 || c.KEVVulnerabilityName == "" {
		t.Errorf("enrichment not applied: %+v", c)
	}
	if !ds.CVEs[ds.byID["CVE-2024-0002"]].PublicExploit || !ds.CVEs[ds.byID["CVE-2022-0004"]].PublicExploit {
		t.Error("exploit evidence from references/SSVC not detected")
	}
	if ds.stats.TotalKEV != 1 || ds.stats.WithEPSS != 2 || ds.stats.PublicExploits != 2 {
		t.Errorf("stats = %+v", ds.stats)
	}
}

func TestKEVPlaceholders(t *testing.T) {
	enr := &Enrichment{KEV: map[string]*KEVEntry{
		"CVE-2026-9999": {CveID: "CVE-2026-9999", VendorProject: "Acme", Product: "Widget", VulnerabilityName: "Acme Widget RCE", DateAdded: "2026-10-01"},
	}}
	ds := buildDataset([]CVE{{ID: "CVE-2026-0001"}}, enr)
	i, ok := ds.byID["CVE-2026-9999"]
	if !ok || !ds.CVEs[i].KEVOnly || !ds.CVEs[i].InKEV || ds.CVEs[i].Year != 2026 {
		t.Fatalf("placeholder missing or wrong: %+v", ds.CVEs)
	}
	// A rebuild once the real record has arrived drops the placeholder
	cves := append(slices.Clone(ds.CVEs), CVE{ID: "CVE-2026-9999", Title: "real"})
	ds2 := buildDataset(cves, enr)
	if len(ds2.CVEs) != 2 || ds2.CVEs[ds2.byID["CVE-2026-9999"]].Title != "real" {
		t.Fatalf("placeholder not replaced: %+v", ds2.CVEs)
	}
}

func TestSortByEPSS(t *testing.T) {
	ds := testDataset()
	matches, _ := ds.filterCVEs(compileFilter(ds, FilterRequest{SortBy: "epss", SortDesc: true}), false)
	if ds.CVEs[matches[0]].ID != "CVE-2024-0001" || ds.CVEs[matches[1]].ID != "CVE-2024-0002" {
		t.Errorf("unexpected order: %v", matches)
	}
}

func TestChangedSince(t *testing.T) {
	ds := testDataset()
	got := ids(ds, FilterRequest{ChangedSince: "2024-01-11"})
	// 0002 was published after; 0001 was published before but added to KEV after
	want := []string{"CVE-2024-0001", "CVE-2024-0002"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCVEPath(t *testing.T) {
	cases := map[string]string{
		"CVE-2024-12345":  "cves/2024/12xxx/CVE-2024-12345.json",
		"CVE-2024-0042":   "cves/2024/0xxx/CVE-2024-0042.json",
		"CVE-2026-105134": "cves/2026/105xxx/CVE-2026-105134.json",
		"not-a-cve":       "",
	}
	for id, want := range cases {
		if got := cvePath(id); got != want {
			t.Errorf("cvePath(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestPlanDeltas(t *testing.T) {
	rel := func(tag string) GitHubRelease {
		r := GitHubRelease{TagName: tag}
		r.Assets = append(r.Assets, struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
		}{Name: tag[4:14] + "_delta_CVEs_at_x.zip", BrowserDownloadURL: "u"})
		return r
	}
	releases := []GitHubRelease{
		rel("cve_2026-10-20_1900Z"), rel("cve_2026-10-20_1800Z"),
		rel("cve_2026-10-19_at_end_of_day"), rel("cve_2026-10-19_2300Z"),
		rel("cve_2026-10-18_at_end_of_day"), rel("cve_2026-10-17_at_end_of_day"),
	}
	asOf := time.Date(2026, 10, 18, 6, 0, 0, 0, time.UTC)
	var tags []string
	for _, r := range planDeltas(releases, asOf, "") {
		tags = append(tags, r.TagName)
	}
	want := []string{"cve_2026-10-18_at_end_of_day", "cve_2026-10-19_at_end_of_day", "cve_2026-10-20_1900Z"}
	if !slices.Equal(tags, want) {
		t.Fatalf("plan = %v, want %v", tags, want)
	}
	if got := planDeltas(releases, asOf, "cve_2026-10-20_1900Z"); len(got) != 0 {
		t.Errorf("already-applied deltas replanned: %v", got)
	}
}

func TestCSVCellNeutralizesFormulas(t *testing.T) {
	if got := csvCell("=HYPERLINK(1)"); got != "'=HYPERLINK(1)" {
		t.Errorf("got %q", got)
	}
	if got := csvCell(-1.5); got != "-1.5" {
		t.Errorf("got %q", got)
	}
}
