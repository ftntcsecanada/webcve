package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// VendorRow aggregates one vendor's CVEs (within the current filters)
type VendorRow struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Vendor  string `json:"vendor"` // display vendor name (for product rows, the product's vendor)
	Product string `json:"product,omitempty"`

	CVEs       int `json:"cves"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Scored     int `json:"scored"`
	KEV        int `json:"kev"`
	Ransomware int `json:"ransomware"`
	Exploit    int `json:"exploit"`
	Metasploit int `json:"metasploit"`
	EPSSHigh   int `json:"epssHigh"` // EPSS >= 10%
	Last12     int `json:"last12"`   // published in the last 12 months
	Prev12     int `json:"prev12"`   // the 12 months before that
	// Disclosure context
	SelfPublished int     `json:"selfPublished"` // CVEs the vendor published as its own CNA
	ZeroDay       int     `json:"zeroDay"`       // KEV entries exploited at or before disclosure
	NVDCompared   int     `json:"nvdCompared"`   // CVEs scored by both the CNA and NVD
	SelfPubPct    float64 `json:"selfPubPct"`
	ZeroDayPct    float64 `json:"zeroDayPct"` // of KEV entries
	NVDDelta      float64 `json:"nvdDelta"`   // mean (record score - NVD score); negative = scores itself lower

	AvgScore      float64  `json:"avgScore"`
	CritHighPct   float64  `json:"critHighPct"` // of scored CVEs
	KEVPct        float64  `json:"kevPct"`
	ExploitPct    float64  `json:"exploitPct"`
	Trend         float64  `json:"trend"`         // last 12 vs previous 12 months, as a fraction; NaN-free
	DaysToKEV     int      `json:"daysToKev"`     // median days from publication to KEV listing; -1 if none
	KEVOverdue    int      `json:"kevOverdue"`    // KEV entries past their due date
	Years         []int    `json:"years"`         // CVEs per year, oldest first
	TopWeaknesses []string `json:"topWeaknesses"` // most common CWEs

	scoreSum  float64
	nvdDelta  float64
	kevDays   []int
	weakCount map[string]int
	vendorKey string
}

type vendorsRequest struct {
	FilterRequest
	GroupBy string `json:"groupBy"` // vendor (default) or product
	MinCVEs int    `json:"minCves"`
	Sort    string `json:"sort"`
	Desc    bool   `json:"desc"`
	Query   string `json:"query"`
	Limit   int    `json:"limit"`
}

const vendorYears = 10

// cweNumRe skips placeholders like "CWE-noinfo" in the weakness ranking
var cweNumRe = regexp.MustCompile(`^CWE-\d+$`)

func (app *App) handleVendors(c echo.Context) error {
	start := time.Now()
	var req vendorsRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if req.MinCVEs <= 0 {
		req.MinCVEs = 1
	}
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	ds := app.dataset()
	f := compileFilter(ds, req.FilterRequest)
	// The vendor filter selects which vendors to compare, not which CVEs count
	f.vendors = nil

	now := time.Now()
	yearTo := now.Year()
	yearFrom := yearTo - vendorYears + 1
	cut12, cut24 := now.AddDate(-1, 0, 0), now.AddDate(-2, 0, 0)
	today := now.Format("2006-01-02")

	names := map[string]string{}
	for _, o := range ds.vendors {
		names[o.Key] = o.Name
	}
	var wantKeys map[string]bool
	if len(req.Vendors) > 0 {
		wantKeys = map[string]bool{}
		for _, v := range req.Vendors {
			wantKeys[normalizeVendor(v)] = true
		}
	}
	q := normalizeVendor(req.Query)

	byProduct := req.GroupBy == "product"
	rows := map[string]*VendorRow{}
	matched := 0
	for i := range ds.CVEs {
		if ds.failedGroups(i, f) != 0 {
			continue
		}
		cve := &ds.CVEs[i]
		counted := false
		keys := ds.vendorKeys[i]
		if byProduct {
			keys = ds.pairKeys[i]
		}
		for _, k := range keys {
			vk, pk, _ := strings.Cut(k, "\x00")
			if (wantKeys != nil && !wantKeys[vk]) || (q != "" && !strings.Contains(vk, q) && !strings.Contains(pk, q)) {
				continue
			}
			r := rows[k]
			if r == nil {
				r = &VendorRow{Key: k, vendorKey: vk, Years: make([]int, vendorYears), weakCount: map[string]int{}}
				r.Vendor = names[vk]
				if r.Vendor == "" {
					r.Vendor = vk
				}
				r.Name = r.Vendor
				if byProduct {
					r.Name = ds.pairs[k]
					if _, p, ok := strings.Cut(r.Name, " · "); ok {
						r.Product = p
					}
				}
				rows[k] = r
			}
			r.add(cve, yearFrom, cut12, cut24, today)
			counted = true
		}
		if counted {
			matched++
		}
	}

	out := make([]*VendorRow, 0, len(rows))
	for _, r := range rows {
		if r.CVEs >= req.MinCVEs {
			r.finish()
			out = append(out, r)
		}
	}
	sortVendorRows(out, req.Sort, req.Desc)
	total := len(out)
	out = out[:min(len(out), req.Limit)]

	return c.JSON(http.StatusOK, map[string]any{
		"vendors":  out,
		"total":    total,
		"matched":  matched,
		"yearFrom": yearFrom,
		"yearTo":   yearTo,
		"tookMs":   float64(time.Since(start).Microseconds()) / 1000,
	})
}

func (r *VendorRow) add(cve *CVE, yearFrom int, cut12, cut24 time.Time, today string) {
	r.CVEs++
	switch severityKey(cve.BaseSeverity) {
	case "CRITICAL":
		r.Critical++
	case "HIGH":
		r.High++
	}
	if cve.BaseScore > 0 {
		r.Scored++
		r.scoreSum += cve.BaseScore
	}
	if cve.InKEV {
		r.KEV++
		if cve.KEVKnownRansomwareCampaign == "Known" {
			r.Ransomware++
		}
		if cve.KEVDueDate != "" && cve.KEVDueDate < today {
			r.KEVOverdue++
		}
		if added, err := time.Parse("2006-01-02", cve.KEVDateAdded); err == nil && !cve.DatePublished.IsZero() {
			// Older CVEs can be listed years later; negative means listed before the record was published
			r.kevDays = append(r.kevDays, max(0, int(added.Sub(cve.DatePublished).Hours()/24)))
		}
	}
	if cve.PublicExploit {
		r.Exploit++
	}
	if cve.EvidenceBits&evMetasploit != 0 {
		r.Metasploit++
	}
	if cve.EPSS >= 0.1 {
		r.EPSSHigh++
	}
	if !cve.DatePublished.IsZero() {
		if cve.DatePublished.After(cut12) {
			r.Last12++
		} else if cve.DatePublished.After(cut24) {
			r.Prev12++
		}
	}
	if y := cve.Year - yearFrom; y >= 0 && y < len(r.Years) {
		r.Years[y]++
	}
	if cweNumRe.MatchString(cve.CWE) {
		r.weakCount[cve.CWE]++
	}
	if assignerMatchesVendor(cve.AssignerOrg, r.vendorKey) {
		r.SelfPublished++
	}
	if cve.InKEV && !cve.DatePublished.IsZero() {
		// Listed in KEV within a day of publication (or before): exploited at disclosure
		if added, err := time.Parse("2006-01-02", cve.KEVDateAdded); err == nil && added.Sub(cve.DatePublished) <= 24*time.Hour {
			r.ZeroDay++
		}
	}
	if cve.ScoreSource == "" && cve.BaseScore > 0 && cve.NVDScore > 0 {
		r.NVDCompared++
		r.nvdDelta += cve.BaseScore - cve.NVDScore
	}
}

// assignerMatchesVendor reports whether the CNA that published a CVE is the
// vendor itself ("palo_alto" publishing for Palo Alto Networks)
func assignerMatchesVendor(assigner, vendorKey string) bool {
	if assigner == "" || vendorKey == "" {
		return false
	}
	a := normalizeVendor(strings.ReplaceAll(assigner, "_", " "))
	if a == vendorKey || strings.HasPrefix(vendorKey, a+" ") || strings.HasPrefix(a, vendorKey+" ") {
		return true
	}
	// "checkpoint" publishes for "Check Point"
	return strings.ReplaceAll(a, " ", "") == strings.ReplaceAll(vendorKey, " ", "")
}

func (r *VendorRow) finish() {
	pct := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return float64(n) / float64(d)
	}
	if r.Scored > 0 {
		r.AvgScore = r.scoreSum / float64(r.Scored)
	}
	r.CritHighPct = pct(r.Critical+r.High, r.Scored)
	r.SelfPubPct = pct(r.SelfPublished, r.CVEs)
	r.ZeroDayPct = pct(r.ZeroDay, r.KEV)
	if r.NVDCompared > 0 {
		r.NVDDelta = r.nvdDelta / float64(r.NVDCompared)
	}
	r.KEVPct = pct(r.KEV, r.CVEs)
	r.ExploitPct = pct(r.Exploit, r.CVEs)
	switch {
	case r.Prev12 > 0:
		r.Trend = float64(r.Last12-r.Prev12) / float64(r.Prev12)
	case r.Last12 > 0:
		r.Trend = 1
	}
	r.DaysToKEV = -1
	if len(r.kevDays) > 0 {
		sort.Ints(r.kevDays)
		r.DaysToKEV = r.kevDays[len(r.kevDays)/2]
	}
	type wc struct {
		cwe string
		n   int
	}
	var ws []wc
	for k, n := range r.weakCount {
		ws = append(ws, wc{k, n})
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].n > ws[j].n || (ws[i].n == ws[j].n && ws[i].cwe < ws[j].cwe) })
	for _, w := range ws[:min(3, len(ws))] {
		r.TopWeaknesses = append(r.TopWeaknesses, w.cwe)
	}
}

func sortVendorRows(rows []*VendorRow, by string, desc bool) {
	val := func(r *VendorRow) float64 {
		switch by {
		case "name":
			return 0
		case "critical":
			return float64(r.Critical)
		case "critHighPct":
			return r.CritHighPct
		case "avgScore":
			return r.AvgScore
		case "kev":
			return float64(r.KEV)
		case "kevPct":
			return r.KEVPct
		case "ransomware":
			return float64(r.Ransomware)
		case "exploit":
			return float64(r.Exploit)
		case "exploitPct":
			return r.ExploitPct
		case "metasploit":
			return float64(r.Metasploit)
		case "epssHigh":
			return float64(r.EPSSHigh)
		case "last12":
			return float64(r.Last12)
		case "trend":
			return r.Trend
		case "daysToKev":
			if r.DaysToKEV < 0 {
				// Vendors without KEV entries sort last either way
				if desc {
					return -1
				}
				return 1e9
			}
			return float64(r.DaysToKEV)
		case "kevOverdue":
			return float64(r.KEVOverdue)
		case "selfPubPct":
			return r.SelfPubPct
		case "zeroDay":
			return float64(r.ZeroDay)
		case "zeroDayPct":
			return r.ZeroDayPct
		case "nvdDelta":
			return r.NVDDelta
		default:
			return float64(r.CVEs)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if by == "name" {
			if desc {
				return rows[i].Name > rows[j].Name
			}
			return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
		}
		a, b := val(rows[i]), val(rows[j])
		if a == b {
			return rows[i].CVEs > rows[j].CVEs
		}
		if desc {
			return a > b
		}
		return a < b
	})
}
