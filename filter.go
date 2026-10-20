package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// FilterRequest represents incoming filter parameters
type FilterRequest struct {
	YearFrom      *int     `json:"yearFrom"`
	YearTo        *int     `json:"yearTo"`
	Vendors       []string `json:"vendors"`
	Products      []string `json:"products"`
	Severities    []string `json:"severities"` // CRITICAL, HIGH, MEDIUM, LOW, NONE
	AttackVectors []string `json:"attackVectors"`
	Search        string   `json:"search"`
	CWE           string   `json:"cwe"`
	ScoreMin      *float64 `json:"scoreMin"`
	ScoreMax      *float64 `json:"scoreMax"`
	InKEV         *bool    `json:"inKEV"`
	Ransomware    bool     `json:"ransomware"`   // Only KEV entries with known ransomware use
	KEVAddedDays  int      `json:"kevAddedDays"` // Only KEV entries added within the last N days
	SortBy        string   `json:"sortBy"`
	SortDesc      bool     `json:"sortDesc"`
	Page          int      `json:"page"`
	PageSize      int      `json:"pageSize"`
}

// CVESummary is the slim row representation returned by list queries
type CVESummary struct {
	ID            string    `json:"id"`
	Year          int       `json:"year"`
	Vendor        string    `json:"vendor"`
	Product       string    `json:"product"`
	AffectedCount int       `json:"affectedCount"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	BaseScore     float64   `json:"baseScore"`
	BaseSeverity  string    `json:"baseSeverity"`
	CvssVersion   string    `json:"cvssVersion"`
	AttackVector  string    `json:"attackVector"`
	CWE           string    `json:"cwe"`
	DatePublished time.Time `json:"datePublished"`
	DateUpdated   time.Time `json:"dateUpdated"`
	InKEV         bool      `json:"inKEV"`
	KEVName       string    `json:"kevName,omitempty"`
	KEVDateAdded  string    `json:"kevDateAdded,omitempty"`
	KEVDueDate    string    `json:"kevDueDate,omitempty"`
	KEVRansomware string    `json:"kevKnownRansomwareCampaign,omitempty"`
}

// FilterResponse contains filtered results and metadata
type FilterResponse struct {
	CVEs       []CVESummary `json:"cves"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"pageSize"`
	TotalPages int          `json:"totalPages"`
	Facets     Facets       `json:"facets"`
	YearCounts []YearCount  `json:"yearCounts"`
	KEVMonths  []MonthCount `json:"kevMonths"`
	TookMs     float64      `json:"tookMs"`
}

// Facets are counts computed disjunctively: each facet's counts ignore that
// facet's own filter, so the UI can show what selecting another value would yield.
type Facets struct {
	Severity     map[string]int `json:"severity"`
	AttackVector map[string]int `json:"attackVector"`
	KEV          int            `json:"kev"`
	Ransomware   int            `json:"ransomware"`
}

// YearCount represents CVE count for a specific year with severity breakdown
type YearCount struct {
	Year     int            `json:"year"`
	Count    int            `json:"count"`
	Severity map[string]int `json:"severity"`
}

// MonthCount represents KEV additions for a month (YYYY-MM)
type MonthCount struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

// FilterOptions provides available filter values
type FilterOptions struct {
	Vendors       []string `json:"vendors"`
	Products      []string `json:"products"`
	Severities    []string `json:"severities"`
	Years         []int    `json:"years"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attackVectors"`
}

// Filter groups, used as bits so a single pass can compute disjunctive facets
const (
	gYear = 1 << iota
	gVendor
	gProduct
	gSeverity
	gAttackVector
	gCWE
	gScore
	gKEV
	gSearch
)

// compiledFilter holds a FilterRequest normalized for fast matching
type compiledFilter struct {
	req           *FilterRequest
	vendors       []string
	products      []string
	severities    map[string]bool
	attackVectors map[string]bool
	cwe           string
	terms         []string
	kevSince      string
}

func compileFilter(req *FilterRequest) *compiledFilter {
	f := &compiledFilter{req: req, cwe: strings.ToLower(strings.TrimSpace(req.CWE))}
	f.vendors = req.Vendors
	f.products = req.Products
	if len(req.Severities) > 0 {
		f.severities = make(map[string]bool)
		for _, s := range req.Severities {
			f.severities[strings.ToUpper(s)] = true
		}
	}
	if len(req.AttackVectors) > 0 {
		f.attackVectors = make(map[string]bool)
		for _, a := range req.AttackVectors {
			f.attackVectors[strings.ToUpper(a)] = true
		}
	}
	f.terms = strings.Fields(strings.ToLower(req.Search))
	if req.KEVAddedDays > 0 {
		f.kevSince = time.Now().AddDate(0, 0, -req.KEVAddedDays).Format("2006-01-02")
	}
	return f
}

func severityKey(s string) string {
	if s == "" {
		return "NONE"
	}
	return s
}

// normalizeAttackVector maps CVSS 2/3/4 spellings to a single set of values
func normalizeAttackVector(av string) string {
	switch strings.ToUpper(av) {
	case "NETWORK", "N":
		return "NETWORK"
	case "ADJACENT_NETWORK", "ADJACENT", "A":
		return "ADJACENT"
	case "LOCAL", "L":
		return "LOCAL"
	case "PHYSICAL", "P":
		return "PHYSICAL"
	}
	return ""
}

// failedGroups returns a bitmask of the filter groups that this CVE fails
func (app *App) failedGroups(i int, f *compiledFilter) int {
	cve := &app.cves[i]
	req := f.req
	failed := 0

	if (req.YearFrom != nil && cve.Year < *req.YearFrom) || (req.YearTo != nil && cve.Year > *req.YearTo) {
		failed |= gYear
	}
	if len(f.vendors) > 0 && !matchesAffected(cve, f.vendors, func(ap AffectedProduct) string { return ap.Vendor }, cve.Vendor) {
		failed |= gVendor
	}
	if len(f.products) > 0 && !matchesAffected(cve, f.products, func(ap AffectedProduct) string { return ap.Product }, cve.Product) {
		failed |= gProduct
	}
	if f.severities != nil && !f.severities[severityKey(cve.BaseSeverity)] {
		failed |= gSeverity
	}
	if f.attackVectors != nil && !f.attackVectors[normalizeAttackVector(cve.AttackVector)] {
		failed |= gAttackVector
	}
	if f.cwe != "" && !strings.Contains(strings.ToLower(cve.CWE), f.cwe) {
		failed |= gCWE
	}
	if (req.ScoreMin != nil && cve.BaseScore < *req.ScoreMin) || (req.ScoreMax != nil && cve.BaseScore > *req.ScoreMax) {
		failed |= gScore
	}
	if (req.InKEV != nil && *req.InKEV != cve.InKEV) ||
		(req.Ransomware && cve.KEVKnownRansomwareCampaign != "Known") ||
		(f.kevSince != "" && (!cve.InKEV || cve.KEVDateAdded < f.kevSince)) {
		failed |= gKEV
	}
	if len(f.terms) > 0 {
		text := app.searchText[i]
		for _, t := range f.terms {
			if !strings.Contains(text, t) {
				failed |= gSearch
				break
			}
		}
	}
	return failed
}

func matchesAffected(cve *CVE, wanted []string, field func(AffectedProduct) string, primary string) bool {
	if len(cve.AffectedProducts) == 0 {
		for _, w := range wanted {
			if strings.EqualFold(primary, w) {
				return true
			}
		}
		return false
	}
	for _, ap := range cve.AffectedProducts {
		v := field(ap)
		for _, w := range wanted {
			if strings.EqualFold(v, w) {
				return true
			}
		}
	}
	return false
}

// buildSearchIndex precomputes a lowercase haystack per CVE so text search
// doesn't have to lowercase every description on every request.
func (app *App) buildSearchIndex() {
	app.searchText = make([]string, len(app.cves))
	var b strings.Builder
	for i := range app.cves {
		cve := &app.cves[i]
		b.Reset()
		b.WriteString(cve.ID)
		b.WriteByte('\n')
		b.WriteString(cve.Title)
		b.WriteByte('\n')
		b.WriteString(cve.Description)
		b.WriteByte('\n')
		b.WriteString(cve.CWE)
		b.WriteByte('\n')
		b.WriteString(cve.KEVVulnerabilityName)
		if len(cve.AffectedProducts) == 0 {
			b.WriteByte('\n')
			b.WriteString(cve.Vendor)
			b.WriteByte(' ')
			b.WriteString(cve.Product)
		}
		for _, ap := range cve.AffectedProducts {
			b.WriteByte('\n')
			b.WriteString(ap.Vendor)
			b.WriteByte(' ')
			b.WriteString(ap.Product)
		}
		app.searchText[i] = strings.ToLower(b.String())
	}
}

// filterCVEs returns the indexes of matching CVEs and, optionally, disjunctive facets
func (app *App) filterCVEs(req *FilterRequest, withFacets bool) ([]int, *FilterResponse) {
	f := compileFilter(req)
	matches := make([]int, 0, 1024)

	resp := &FilterResponse{
		Facets: Facets{Severity: map[string]int{}, AttackVector: map[string]int{}},
	}
	years := map[int]*YearCount{}
	kevMonths := map[string]int{}

	// Walk CVEs in pre-sorted order so matches come out already sorted
	order := app.sortedOrder(req.SortBy)
	for n := range order {
		i := order[n]
		if req.SortDesc || req.SortBy == "" {
			i = order[len(order)-1-n]
		}
		failed := app.failedGroups(i, f)
		if failed == 0 {
			matches = append(matches, i)
		}
		if !withFacets {
			continue
		}
		cve := &app.cves[i]
		if failed&^gSeverity == 0 {
			resp.Facets.Severity[severityKey(cve.BaseSeverity)]++
		}
		if failed&^gAttackVector == 0 {
			if av := normalizeAttackVector(cve.AttackVector); av != "" {
				resp.Facets.AttackVector[av]++
			}
		}
		if failed&^gKEV == 0 && cve.InKEV {
			resp.Facets.KEV++
			if cve.KEVKnownRansomwareCampaign == "Known" {
				resp.Facets.Ransomware++
			}
		}
		if failed&^gYear == 0 && cve.Year > 0 {
			yc := years[cve.Year]
			if yc == nil {
				yc = &YearCount{Year: cve.Year, Severity: map[string]int{}}
				years[cve.Year] = yc
			}
			yc.Count++
			yc.Severity[severityKey(cve.BaseSeverity)]++
		}
		if failed == 0 && cve.InKEV && len(cve.KEVDateAdded) >= 7 {
			kevMonths[cve.KEVDateAdded[:7]]++
		}
	}

	if withFacets {
		// Contiguous year range so the chart has no gaps
		minYear, maxYear := 0, 0
		for y := range years {
			if minYear == 0 || y < minYear {
				minYear = y
			}
			if y > maxYear {
				maxYear = y
			}
		}
		for y := minYear; y <= maxYear && minYear > 0; y++ {
			if yc := years[y]; yc != nil {
				resp.YearCounts = append(resp.YearCounts, *yc)
			} else {
				resp.YearCounts = append(resp.YearCounts, YearCount{Year: y, Severity: map[string]int{}})
			}
		}
		// 24 months of KEV additions, ending at the catalog release month
		now, err := time.Parse("2006-01-02", app.kevCatalogDate[:min(10, len(app.kevCatalogDate))])
		if err != nil {
			now = time.Now()
		}
		for m := 23; m >= 0; m-- {
			key := now.AddDate(0, -m, 0).Format("2006-01")
			resp.KEVMonths = append(resp.KEVMonths, MonthCount{Month: key, Count: kevMonths[key]})
		}
	}

	return matches, resp
}

func (app *App) handleFilterCVEs(c echo.Context) error {
	start := time.Now()
	var req FilterRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.PageSize <= 0 {
		req.PageSize = 50
	}
	if req.PageSize > 500 {
		req.PageSize = 500
	}
	if req.Page < 1 {
		req.Page = 1
	}

	app.mu.RLock()
	defer app.mu.RUnlock()

	matches, resp := app.filterCVEs(&req, true)

	total := len(matches)
	from := min((req.Page-1)*req.PageSize, total)
	to := min(from+req.PageSize, total)

	resp.CVEs = make([]CVESummary, 0, to-from)
	for _, i := range matches[from:to] {
		resp.CVEs = append(resp.CVEs, summarize(&app.cves[i], &req))
	}
	resp.Total = total
	resp.Page = req.Page
	resp.PageSize = req.PageSize
	resp.TotalPages = (total + req.PageSize - 1) / req.PageSize
	resp.TookMs = float64(time.Since(start).Microseconds()) / 1000

	return c.JSON(http.StatusOK, resp)
}

// summarize builds a list row, showing the affected product that matched the
// vendor/product filter rather than always the first one
func summarize(cve *CVE, req *FilterRequest) CVESummary {
	vendor, product := cve.Vendor, cve.Product
	if len(req.Vendors) > 0 || len(req.Products) > 0 {
		for _, ap := range cve.AffectedProducts {
			if (len(req.Vendors) == 0 || containsFold(req.Vendors, ap.Vendor)) &&
				(len(req.Products) == 0 || containsFold(req.Products, ap.Product)) {
				vendor, product = ap.Vendor, ap.Product
				break
			}
		}
	}

	desc := cve.Description
	if len(desc) > 320 {
		desc = strings.ToValidUTF8(desc[:320], "") + "…"
	}

	return CVESummary{
		ID:            cve.ID,
		Year:          cve.Year,
		Vendor:        vendor,
		Product:       product,
		AffectedCount: len(cve.AffectedProducts),
		Title:         cve.Title,
		Description:   desc,
		BaseScore:     cve.BaseScore,
		BaseSeverity:  cve.BaseSeverity,
		CvssVersion:   cve.CvssVersion,
		AttackVector:  normalizeAttackVector(cve.AttackVector),
		CWE:           cve.CWE,
		DatePublished: cve.DatePublished,
		DateUpdated:   cve.DateUpdated,
		InKEV:         cve.InKEV,
		KEVName:       cve.KEVVulnerabilityName,
		KEVDateAdded:  cve.KEVDateAdded,
		KEVDueDate:    cve.KEVDueDate,
		KEVRansomware: cve.KEVKnownRansomwareCampaign,
	}
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// sortedOrder returns CVE indexes in ascending order for sortBy, built lazily
// and cached until the next buildIndexes
func (app *App) sortedOrder(sortBy string) []int {
	if sortBy == "" {
		sortBy = "datePublished"
	}
	app.orderMu.Lock()
	defer app.orderMu.Unlock()
	if order, ok := app.orders[sortBy]; ok {
		return order
	}
	order := make([]int, len(app.cves))
	for i := range order {
		order[i] = i
	}
	app.sortIndexes(order, sortBy)
	if app.orders == nil {
		app.orders = map[string][]int{}
	}
	app.orders[sortBy] = order
	return order
}

// sortIndexes sorts CVE indexes ascending by the given field, with CVE ID as tiebreaker
func (app *App) sortIndexes(idx []int, sortBy string) {
	cves := app.cves
	cmp := func(a, b *CVE) int {
		switch sortBy {
		case "id":
			return compareCVEIDs(a.ID, b.ID)
		case "year":
			return a.Year - b.Year
		case "dateUpdated":
			return a.DateUpdated.Compare(b.DateUpdated)
		case "vendor":
			return strings.Compare(strings.ToLower(a.Vendor), strings.ToLower(b.Vendor))
		case "product":
			return strings.Compare(strings.ToLower(a.Product), strings.ToLower(b.Product))
		case "severity", "baseSeverity":
			if d := severityOrder(a.BaseSeverity) - severityOrder(b.BaseSeverity); d != 0 {
				return d
			}
			return compareFloat(a.BaseScore, b.BaseScore)
		case "score", "baseScore":
			return compareFloat(a.BaseScore, b.BaseScore)
		case "kevDateAdded":
			return strings.Compare(a.KEVDateAdded, b.KEVDateAdded)
		case "kevDueDate":
			return strings.Compare(a.KEVDueDate, b.KEVDueDate)
		default:
			return a.DatePublished.Compare(b.DatePublished)
		}
	}
	slices.SortFunc(idx, func(i, j int) int {
		a, b := &cves[i], &cves[j]
		if c := cmp(a, b); c != 0 {
			return c
		}
		return compareCVEIDs(a.ID, b.ID)
	})
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareCVEIDs orders CVE-YYYY-NNNN numerically rather than lexically
func compareCVEIDs(a, b string) int {
	if len(a) != len(b) && strings.HasPrefix(a, "CVE-") && strings.HasPrefix(b, "CVE-") && len(a) > 9 && len(b) > 9 && a[:9] == b[:9] {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

func severityOrder(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
