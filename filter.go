package main

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// FilterRequest represents incoming filter parameters
type FilterRequest struct {
	YearFrom       *int     `json:"yearFrom"`
	YearTo         *int     `json:"yearTo"`
	Vendors        []string `json:"vendors"`
	Products       []string `json:"products"`
	Severities     []string `json:"severities"` // CRITICAL, HIGH, MEDIUM, LOW, NONE
	AttackVectors  []string `json:"attackVectors"`
	Search         string   `json:"search"`
	CWE            string   `json:"cwe"`
	ScoreMin       *float64 `json:"scoreMin"`
	ScoreMax       *float64 `json:"scoreMax"`
	EPSSMin        *float64 `json:"epssMin"` // 0..1
	PublicExploit  bool     `json:"publicExploit"`
	ExploitSources []string `json:"exploitSources"` // any of: metasploit, exploitdb, nuclei, github, cisa, euvd, msrc, other
	InKEV          *bool    `json:"inKEV"`
	Ransomware     bool     `json:"ransomware"`   // Only KEV entries with known ransomware use
	KEVAddedDays   int      `json:"kevAddedDays"` // Only KEV entries added within the last N days
	KEVDue         string   `json:"kevDue"`       // "overdue", or N = due within the next N days
	ChangedSince   string   `json:"changedSince"` // Published or added to KEV at/after this time (RFC 3339 or date)
	SortBy         string   `json:"sortBy"`
	SortDesc       bool     `json:"sortDesc"`
	Page           int      `json:"page"`
	PageSize       int      `json:"pageSize"`
	CountOnly      bool     `json:"countOnly"`
}

// CVESummary is the slim row representation returned by list queries
type CVESummary struct {
	ID             string    `json:"id"`
	Year           int       `json:"year"`
	Vendor         string    `json:"vendor"`
	Product        string    `json:"product"`
	AffectedCount  int       `json:"affectedCount"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	BaseScore      float64   `json:"baseScore"`
	BaseSeverity   string    `json:"baseSeverity"`
	CvssVersion    string    `json:"cvssVersion"`
	AttackVector   string    `json:"attackVector"`
	CWE            string    `json:"cwe"`
	DatePublished  time.Time `json:"datePublished"`
	DateUpdated    time.Time `json:"dateUpdated"`
	EPSS           float64   `json:"epss"`
	EPSSPercentile float64   `json:"epssPercentile"`
	PublicExploit  bool      `json:"publicExploit"`
	ExploitSources []string  `json:"exploitSources,omitempty"`
	ScoreSource    string    `json:"scoreSource,omitempty"`
	InKEV          bool      `json:"inKEV"`
	KEVName        string    `json:"kevName,omitempty"`
	KEVDateAdded   string    `json:"kevDateAdded,omitempty"`
	KEVDueDate     string    `json:"kevDueDate,omitempty"`
	KEVRansomware  string    `json:"kevKnownRansomwareCampaign,omitempty"`
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
	Terms      []string     `json:"terms,omitempty"` // Search terms that were ignored (stopwords)
	TookMs     float64      `json:"tookMs"`
}

// Facets are counts computed disjunctively: each facet's counts ignore that
// facet's own filter, so the UI can show what selecting another value would yield.
type Facets struct {
	Severity     map[string]int `json:"severity"`
	AttackVector map[string]int `json:"attackVector"`
	KEV          int            `json:"kev"`
	Ransomware   int            `json:"ransomware"`
	Exploit      int            `json:"exploit"`
	// Per exploit-evidence source, disjunctive with the exploit filters
	ExploitSources map[string]int `json:"exploitSources"`
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

// Filter groups, used as bits so a single pass can compute disjunctive facets
const (
	gYear = 1 << iota
	gVendor
	gProduct
	gSeverity
	gAttackVector
	gCWE
	gScore
	gEPSS
	gExploit
	gKEV
	gSearch
	gChanged
)

// compiledFilter holds a FilterRequest normalized for fast matching
type compiledFilter struct {
	req           FilterRequest
	vendors       []string // normalized keys, exact
	products      []string
	severities    map[string]bool
	attackVectors map[string]bool
	cwe           string
	evidenceMask  uint8
	kevSince      string
	dueFrom       string
	dueTo         string
	changedTime   time.Time
	changedDate   string

	// Free-text search: nil means no text filter; otherwise a membership bitset
	searchSet []uint64
	// From "vendor:" / "product:" search syntax: substring match on keys
	textVendors  []string
	textProducts []string
}

var fieldTermRe = regexp.MustCompile(`(?i)\b(vendor|product|cwe|sev|severity|kev|exploit|year|epss|av):("([^"]*)"|(\S+))`)

// compileFilter normalizes req against ds, resolving search text to candidate docs
func compileFilter(ds *Dataset, req FilterRequest) *compiledFilter {
	f := &compiledFilter{}

	// Pull field:value terms out of the search box into structured filters
	search := fieldTermRe.ReplaceAllStringFunc(req.Search, func(m string) string {
		sub := fieldTermRe.FindStringSubmatch(m)
		field, val := strings.ToLower(sub[1]), sub[3]
		if val == "" {
			val = sub[4]
		}
		lv := strings.ToLower(val)
		switch field {
		case "vendor":
			f.textVendors = append(f.textVendors, normalizeVendor(val))
		case "product":
			f.textProducts = append(f.textProducts, normalizeProduct(val))
		case "cwe":
			if _, err := strconv.Atoi(val); err == nil {
				val = "CWE-" + val
			}
			req.CWE = val
		case "sev", "severity":
			req.Severities = append(req.Severities, strings.ToUpper(val))
		case "av":
			req.AttackVectors = append(req.AttackVectors, normalizeAttackVector(val))
		case "kev":
			b := lv == "yes" || lv == "true" || lv == "1"
			req.InKEV = &b
		case "exploit":
			req.PublicExploit = lv == "yes" || lv == "true" || lv == "1"
		case "year":
			if y, err := strconv.Atoi(val); err == nil {
				req.YearFrom, req.YearTo = &y, &y
			}
		case "epss":
			if v, ok := parseEPSS(val); ok {
				req.EPSSMin = &v
			}
		}
		return " "
	})

	f.req = req
	f.cwe = strings.ToLower(strings.TrimSpace(req.CWE))
	for _, v := range req.Vendors {
		if k := normalizeVendor(v); k != "" {
			f.vendors = append(f.vendors, k)
		}
	}
	for _, p := range req.Products {
		if k := normalizeProduct(p); k != "" {
			f.products = append(f.products, k)
		}
	}
	if len(req.Severities) > 0 {
		f.severities = make(map[string]bool)
		for _, s := range req.Severities {
			f.severities[strings.ToUpper(s)] = true
		}
	}
	for _, name := range req.ExploitSources {
		for _, s := range evidenceSourceNames {
			if s.Name == name {
				f.evidenceMask |= s.Bit
			}
		}
	}
	if len(req.AttackVectors) > 0 {
		f.attackVectors = make(map[string]bool)
		for _, a := range req.AttackVectors {
			f.attackVectors[normalizeAttackVector(a)] = true
		}
	}
	if req.KEVAddedDays > 0 {
		f.kevSince = time.Now().AddDate(0, 0, -req.KEVAddedDays).Format("2006-01-02")
	}
	today := time.Now().Format("2006-01-02")
	switch req.KEVDue {
	case "":
	case "overdue":
		f.dueTo = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	default:
		if n, err := strconv.Atoi(req.KEVDue); err == nil && n > 0 {
			f.dueFrom = today
			f.dueTo = time.Now().AddDate(0, 0, n).Format("2006-01-02")
		}
	}
	if req.ChangedSince != "" {
		if t, err := time.Parse(time.RFC3339, req.ChangedSince); err == nil {
			f.changedTime = t
		} else if t, err := time.Parse("2006-01-02", req.ChangedSince); err == nil {
			f.changedTime = t
		}
		if !f.changedTime.IsZero() {
			f.changedDate = f.changedTime.UTC().Format("2006-01-02")
		}
	}

	f.compileSearch(ds, search)
	return f
}

func parseEPSS(s string) (float64, bool) {
	s = strings.TrimLeft(s, ">=")
	pct := strings.HasSuffix(s, "%")
	v, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil {
		return 0, false
	}
	if pct || v > 1 {
		v /= 100
	}
	return v, true
}

// splitSearchTerms splits on whitespace, keeping "quoted phrases" together
func splitSearchTerms(s string) (terms []string, phrases []bool) {
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if s[0] == '"' {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				end = len(s) - 1
			}
			if p := strings.TrimSpace(s[1 : end+1]); p != "" {
				terms = append(terms, p)
				phrases = append(phrases, true)
			}
			s = s[min(end+2, len(s)):]
			continue
		}
		end := strings.IndexAny(s, " \t\n")
		if end < 0 {
			end = len(s)
		}
		terms = append(terms, s[:end])
		phrases = append(phrases, false)
		s = s[end:]
	}
}

func (f *compiledFilter) compileSearch(ds *Dataset, search string) {
	terms, phrases := splitSearchTerms(search)
	var docs []uint32
	have := false
	for n, term := range terms {
		d, ok := ds.search.queryTerm(term)
		if !ok {
			continue // only stopwords/punctuation
		}
		// Multi-token terms and phrases are verified against the text, since
		// the index only knows that the tokens occur somewhere in the record
		var multi int
		tokenize(term, func(string) { multi++ })
		if phrases[n] || multi > 1 {
			phrase := strings.ToLower(term)
			kept := d[:0:0]
			for _, doc := range d {
				if containsFoldText(&ds.CVEs[doc], phrase) {
					kept = append(kept, doc)
				}
			}
			d = kept
		}
		if !have {
			docs, have = d, true
		} else {
			docs = intersectPostings(docs, d)
		}
	}
	if !have {
		return
	}
	f.searchSet = make([]uint64, (len(ds.CVEs)+63)/64)
	for _, d := range docs {
		f.searchSet[d>>6] |= 1 << (d & 63)
	}
}

func severityKey(s string) string {
	if s == "" {
		return "NONE"
	}
	return strings.ToUpper(s)
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

func anyKeyIn(keys, wanted []string) bool {
	for _, k := range keys {
		if slices.Contains(wanted, k) {
			return true
		}
	}
	return false
}

func anyKeyContains(keys, wanted []string) bool {
	for _, w := range wanted {
		found := false
		for _, k := range keys {
			if strings.Contains(k, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// failedGroups returns a bitmask of the filter groups that CVE i fails
func (ds *Dataset) failedGroups(i int, f *compiledFilter) int {
	cve := &ds.CVEs[i]
	req := &f.req
	failed := 0

	if (req.YearFrom != nil && cve.Year < *req.YearFrom) || (req.YearTo != nil && cve.Year > *req.YearTo) {
		failed |= gYear
	}
	if len(f.vendors) > 0 && !anyKeyIn(ds.vendorKeys[i], f.vendors) {
		failed |= gVendor
	}
	if len(f.products) > 0 && !anyKeyIn(ds.productKeys[i], f.products) {
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
	if req.EPSSMin != nil && cve.EPSS < *req.EPSSMin {
		failed |= gEPSS
	}
	if (req.PublicExploit && !cve.PublicExploit) || (f.evidenceMask != 0 && cve.EvidenceBits&f.evidenceMask == 0) {
		failed |= gExploit
	}
	if (req.InKEV != nil && *req.InKEV != cve.InKEV) ||
		(req.Ransomware && cve.KEVKnownRansomwareCampaign != "Known") ||
		(f.kevSince != "" && (!cve.InKEV || cve.KEVDateAdded < f.kevSince)) ||
		(f.dueTo != "" && (!cve.InKEV || cve.KEVDueDate == "" || cve.KEVDueDate > f.dueTo || cve.KEVDueDate < f.dueFrom)) {
		failed |= gKEV
	}
	if (f.searchSet != nil && f.searchSet[i>>6]&(1<<(uint(i)&63)) == 0) ||
		(len(f.textVendors) > 0 && !anyKeyContains(ds.vendorKeys[i], f.textVendors)) ||
		(len(f.textProducts) > 0 && !anyKeyContains(ds.productKeys[i], f.textProducts)) {
		failed |= gSearch
	}
	if !f.changedTime.IsZero() && cve.DatePublished.Before(f.changedTime) && (!cve.InKEV || cve.KEVDateAdded < f.changedDate) {
		failed |= gChanged
	}
	return failed
}

// filterCVEs returns the sorted indexes of matching CVEs and, optionally, facets
func (ds *Dataset) filterCVEs(f *compiledFilter, withFacets bool) ([]int, *FilterResponse) {
	req := &f.req
	matches := make([]int, 0, 1024)

	resp := &FilterResponse{
		Facets: Facets{Severity: map[string]int{}, AttackVector: map[string]int{}, ExploitSources: map[string]int{}},
	}
	years := map[int]*YearCount{}
	kevMonths := map[string]int{}

	// Walk CVEs in pre-sorted order so matches come out already sorted
	order := ds.sortedOrder(req.SortBy)
	desc := req.SortDesc || req.SortBy == ""
	for n := range order {
		i := order[n]
		if desc {
			i = order[len(order)-1-n]
		}
		failed := ds.failedGroups(i, f)
		if failed == 0 {
			matches = append(matches, i)
		}
		if !withFacets {
			continue
		}
		cve := &ds.CVEs[i]
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
		if failed&^gExploit == 0 && cve.EvidenceBits != 0 {
			resp.Facets.Exploit++
			for _, s := range evidenceSourceNames {
				if cve.EvidenceBits&s.Bit != 0 {
					resp.Facets.ExploitSources[s.Name]++
				}
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
			maxYear = max(maxYear, y)
		}
		for y := minYear; y <= maxYear && minYear > 0; y++ {
			if yc := years[y]; yc != nil {
				resp.YearCounts = append(resp.YearCounts, *yc)
			} else {
				resp.YearCounts = append(resp.YearCounts, YearCount{Year: y, Severity: map[string]int{}})
			}
		}
		// 24 months of KEV additions, ending at the catalog release month
		end, err := time.Parse("2006-01-02", ds.kevCatalogDate[:min(10, len(ds.kevCatalogDate))])
		if err != nil {
			end = time.Now()
		}
		end = time.Date(end.Year(), end.Month(), 1, 0, 0, 0, 0, time.UTC)
		for m := 23; m >= 0; m-- {
			key := end.AddDate(0, -m, 0).Format("2006-01")
			resp.KEVMonths = append(resp.KEVMonths, MonthCount{Month: key, Count: kevMonths[key]})
		}
	}

	return matches, resp
}

// summarize builds a list row, showing the affected product that matched the
// vendor/product filter rather than always the first one
func (ds *Dataset) summarize(i int, f *compiledFilter) CVESummary {
	cve := &ds.CVEs[i]
	vendor, product := cve.Vendor, cve.Product
	// Records that only say "n/a" borrow NVD's CPE vendor/product
	if isPlaceholderName(vendor) && len(cve.NVDProducts) > 0 {
		vendor, product = cve.NVDProducts[0].Vendor, cve.NVDProducts[0].Product
	}
	if f != nil && (len(f.vendors) > 0 || len(f.products) > 0 || len(f.textVendors) > 0) {
		for _, ap := range cve.AffectedProducts {
			vk, pk := normalizeVendor(ap.Vendor), normalizeProduct(ap.Product)
			if (len(f.vendors) == 0 || slices.Contains(f.vendors, vk)) &&
				(len(f.products) == 0 || slices.Contains(f.products, pk)) &&
				anyKeyContains([]string{vk}, f.textVendors) {
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
		ID:             cve.ID,
		Year:           cve.Year,
		Vendor:         vendor,
		Product:        product,
		AffectedCount:  len(cve.AffectedProducts),
		Title:          cve.Title,
		Description:    desc,
		BaseScore:      cve.BaseScore,
		BaseSeverity:   cve.BaseSeverity,
		CvssVersion:    cve.CvssVersion,
		AttackVector:   normalizeAttackVector(cve.AttackVector),
		CWE:            cve.CWE,
		DatePublished:  cve.DatePublished,
		DateUpdated:    cve.DateUpdated,
		EPSS:           cve.EPSS,
		EPSSPercentile: cve.EPSSPercentile,
		PublicExploit:  cve.PublicExploit,
		ExploitSources: evidenceNames(cve.EvidenceBits),
		ScoreSource:    cve.ScoreSource,
		InKEV:          cve.InKEV,
		KEVName:        cve.KEVVulnerabilityName,
		KEVDateAdded:   cve.KEVDateAdded,
		KEVDueDate:     cve.KEVDueDate,
		KEVRansomware:  cve.KEVKnownRansomwareCampaign,
	}
}

// sortIndexes sorts CVE indexes ascending by the given field, with CVE ID as tiebreaker
func sortIndexes(cves []CVE, idx []int, sortBy string) {
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
		case "epss":
			return compareFloat(a.EPSS, b.EPSS)
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
