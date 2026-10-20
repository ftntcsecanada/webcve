package main

import (
	"math/bits"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Dataset is an immutable snapshot of everything the API serves. Updates build
// a new Dataset off to the side and swap it in atomically, so queries never
// wait on a refresh.
type Dataset struct {
	CVEs []CVE
	byID map[string]int

	// Normalized vendor/product keys per CVE (aligned with CVEs), for filtering
	vendorKeys  [][]string
	productKeys [][]string

	// Option lists for autocomplete, most common first
	vendors  []Option
	products []Option
	cwes     []Option

	search *SearchIndex
	stats  StatsResponse

	kevCatalogDate string

	orderMu sync.Mutex
	orders  map[string][]int
}

// Option is an autocomplete entry: a display name for a normalized key
type Option struct {
	Key   string
	Name  string
	Count int
}

// Enrichment is the non-CVE data a dataset is built with
type Enrichment struct {
	KEV            map[string]*KEVEntry
	KEVCatalogDate string
	EPSS           map[string]EPSSScore
	EPSSDate       string
}

// buildDataset enriches cves (which it takes ownership of) and builds all indexes
func buildDataset(cves []CVE, enr *Enrichment) *Dataset {
	start := time.Now()
	cves = withKEVPlaceholders(cves, enr.KEV)
	ds := &Dataset{CVEs: cves, byID: make(map[string]int, len(cves)), kevCatalogDate: enr.KEVCatalogDate}

	for i := range ds.CVEs {
		cve := &ds.CVEs[i]
		ds.byID[cve.ID] = i
		applyEnrichment(cve, enr)
	}

	ds.buildKeys()
	ds.buildOptions()
	ds.search = buildSearchIndex(ds.CVEs)
	ds.buildStats(enr)
	logf("Built dataset: %d CVEs, %d search terms in %s", len(ds.CVEs), len(ds.search.terms), time.Since(start).Round(time.Millisecond))
	return ds
}

// withKEVPlaceholders drops placeholders from a previous build and adds one for
// every KEV entry whose CVE record isn't loaded, so the KEV view is never missing
// entries while a new record waits for the next delta
func withKEVPlaceholders(cves []CVE, kev map[string]*KEVEntry) []CVE {
	present := make(map[string]bool, len(cves))
	kept := cves[:0]
	for _, c := range cves {
		if !c.KEVOnly {
			kept = append(kept, c)
			present[c.ID] = true
		}
	}
	added := 0
	for id, k := range kev {
		if present[id] {
			continue
		}
		c := CVE{
			ID:               id,
			State:            "PUBLISHED",
			Vendor:           k.VendorProject,
			Product:          k.Product,
			AffectedProducts: []AffectedProduct{{Vendor: k.VendorProject, Product: k.Product}},
			Title:            k.VulnerabilityName,
			Description:      k.ShortDescription,
			KEVOnly:          true,
		}
		if t, err := time.Parse("2006-01-02", k.DateAdded); err == nil {
			c.DatePublished, c.Year = t, t.Year()
		}
		if len(k.CWEs) > 0 {
			c.CWE = k.CWEs[0]
		}
		kept = append(kept, c)
		added++
	}
	if added > 0 {
		logf("Added %d KEV entries not yet in the CVE list as placeholders", added)
	}
	return kept
}

func applyEnrichment(cve *CVE, enr *Enrichment) {
	cve.InKEV = false
	cve.KEVDateAdded, cve.KEVDueDate, cve.KEVRequiredAction = "", "", ""
	cve.KEVKnownRansomwareCampaign, cve.KEVNotes, cve.KEVVulnerabilityName = "", "", ""
	if k := enr.KEV[cve.ID]; k != nil {
		cve.InKEV = true
		cve.KEVVulnerabilityName = k.VulnerabilityName
		cve.KEVDateAdded = k.DateAdded
		cve.KEVDueDate = k.DueDate
		cve.KEVRequiredAction = k.RequiredAction
		cve.KEVKnownRansomwareCampaign = k.KnownRansomwareCampaignUse
		cve.KEVNotes = k.Notes
	}
	cve.EPSS, cve.EPSSPercentile = 0, 0
	if e, ok := enr.EPSS[cve.ID]; ok {
		cve.EPSS = float64(e.Score)
		cve.EPSSPercentile = float64(e.Percentile)
	}
	cve.PublicExploit = hasPublicExploit(cve)
}

// ---- Vendor / product normalization ----

var corpSuffixes = []string{
	"corporation", "corp", "incorporated", "inc", "limited", "ltd", "llc", "gmbh",
	"co", "company", "plc", "ag", "sa", "srl", "bv", "oy", "ab", "pty", "kk",
}

// normalizeVendor folds case, punctuation and corporate suffixes so that
// "Microsoft Corporation", "microsoft" and "Microsoft" share one key
func normalizeVendor(s string) string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '&' && r != '+'
	})
	for len(words) > 1 {
		last := words[len(words)-1]
		trimmed := false
		for _, suf := range corpSuffixes {
			if last == suf {
				words = words[:len(words)-1]
				trimmed = true
				break
			}
		}
		if !trimmed {
			break
		}
	}
	return strings.Join(words, " ")
}

// normalizeProduct folds case, punctuation and whitespace
func normalizeProduct(s string) string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '&' && r != '+' && r != '.'
	})
	return strings.Join(words, " ")
}

// isPlaceholderName reports vendor/product values that carry no information
func isPlaceholderName(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "unknown", "unspecified", "-", "*", "none":
		return true
	}
	return false
}

func (ds *Dataset) buildKeys() {
	intern := map[string]string{}
	in := func(s string) string {
		if v, ok := intern[s]; ok {
			return v
		}
		intern[s] = s
		return s
	}
	ds.vendorKeys = make([][]string, len(ds.CVEs))
	ds.productKeys = make([][]string, len(ds.CVEs))
	for i := range ds.CVEs {
		cve := &ds.CVEs[i]
		aps := cve.AffectedProducts
		if len(aps) == 0 && (cve.Vendor != "" || cve.Product != "") {
			aps = []AffectedProduct{{Vendor: cve.Vendor, Product: cve.Product}}
		}
		var vk, pk []string
		for _, ap := range aps {
			if !isPlaceholderName(ap.Vendor) {
				if k := normalizeVendor(ap.Vendor); k != "" && !contains(vk, k) {
					vk = append(vk, in(k))
				}
			}
			if !isPlaceholderName(ap.Product) {
				if k := normalizeProduct(ap.Product); k != "" && !contains(pk, k) {
					pk = append(pk, in(k))
				}
			}
		}
		ds.vendorKeys[i] = vk
		ds.productKeys[i] = pk
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// buildOptions groups spelling variants by key, naming each group after its most common spelling
func (ds *Dataset) buildOptions() {
	type agg struct {
		count    int
		spelling map[string]int
	}
	collect := func(get func(AffectedProduct) string, norm func(string) string) []Option {
		groups := map[string]*agg{}
		for i := range ds.CVEs {
			cve := &ds.CVEs[i]
			seen := map[string]bool{}
			for _, ap := range cve.AffectedProducts {
				name := strings.TrimSpace(get(ap))
				if isPlaceholderName(name) {
					continue
				}
				k := norm(name)
				if k == "" {
					continue
				}
				g := groups[k]
				if g == nil {
					g = &agg{spelling: map[string]int{}}
					groups[k] = g
				}
				g.spelling[name]++
				if !seen[k] {
					seen[k] = true
					g.count++
				}
			}
		}
		out := make([]Option, 0, len(groups))
		for k, g := range groups {
			best, bestN := "", -1
			for name, n := range g.spelling {
				if n > bestN || (n == bestN && name < best) {
					best, bestN = name, n
				}
			}
			out = append(out, Option{Key: k, Name: best, Count: g.count})
		}
		sortOptions(out)
		return out
	}
	ds.vendors = collect(func(ap AffectedProduct) string { return ap.Vendor }, normalizeVendor)
	ds.products = collect(func(ap AffectedProduct) string { return ap.Product }, normalizeProduct)

	cweCounts := map[string]int{}
	for i := range ds.CVEs {
		if c := ds.CVEs[i].CWE; c != "" {
			cweCounts[c]++
		}
	}
	ds.cwes = make([]Option, 0, len(cweCounts))
	for c, n := range cweCounts {
		ds.cwes = append(ds.cwes, Option{Key: strings.ToLower(c), Name: c, Count: n})
	}
	sortOptions(ds.cwes)
}

func sortOptions(opts []Option) {
	sort.Slice(opts, func(i, j int) bool {
		if opts[i].Count != opts[j].Count {
			return opts[i].Count > opts[j].Count
		}
		return opts[i].Name < opts[j].Name
	})
}

// rankOptions returns up to limit options matching search, prefix matches
// first, preserving the source order (most common first) within each group
func rankOptions(source []Option, search string, limit int) []Option {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return source[:min(limit, len(source))]
	}
	var prefix, rest []Option
	for _, o := range source {
		name := strings.ToLower(o.Name)
		switch {
		case strings.HasPrefix(name, search) || strings.HasPrefix(o.Key, search):
			prefix = append(prefix, o)
		case len(rest) < limit && (strings.Contains(name, search) || strings.Contains(o.Key, search)):
			rest = append(rest, o)
		}
		if len(prefix) >= limit {
			break
		}
	}
	out := append(prefix, rest...)
	return out[:min(limit, len(out))]
}

// ---- Stats ----

func (ds *Dataset) buildStats(enr *Enrichment) {
	s := StatsResponse{
		Status:         "ready",
		TotalCVEs:      len(ds.CVEs),
		SeverityCounts: map[string]int{},
		KEVCatalogDate: enr.KEVCatalogDate,
		EPSSDate:       enr.EPSSDate,
	}
	minYear, maxYear := 9999, 0
	today := time.Now().Format("2006-01-02")
	since30 := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	due30 := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	for i := range ds.CVEs {
		cve := &ds.CVEs[i]
		s.SeverityCounts[severityKey(cve.BaseSeverity)]++
		if cve.Year > 0 {
			minYear = min(minYear, cve.Year)
			maxYear = max(maxYear, cve.Year)
		}
		if cve.DateUpdated.After(s.LastUpdated) {
			s.LastUpdated = cve.DateUpdated
		}
		if cve.EPSS > 0 {
			s.WithEPSS++
		}
		if cve.PublicExploit {
			s.PublicExploits++
		}
		if cve.InKEV {
			s.TotalKEV++
			if cve.KEVKnownRansomwareCampaign == "Known" {
				s.KEVRansomware++
			}
			if cve.KEVDateAdded >= since30 {
				s.KEVLast30Days++
			}
			if cve.KEVDueDate >= today && cve.KEVDueDate <= due30 {
				s.KEVDueNext30++
			}
		}
	}
	s.YearRange = [2]int{minYear, maxYear}
	ds.stats = s
}

// ---- Search index ----

// SearchIndex is an inverted index of lowercase alphanumeric tokens to sorted
// CVE indexes. Terms are sorted so prefix queries are a binary-search range.
type SearchIndex struct {
	terms    []string
	postings [][]uint32
	numDocs  int
}

var stopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true, "be": true, "by": true,
	"for": true, "from": true, "in": true, "is": true, "it": true, "of": true, "on": true, "or": true,
	"that": true, "the": true, "this": true, "to": true, "was": true, "which": true, "with": true,
}

// tokenize splits text into lowercase alphanumeric tokens
func tokenize(s string, emit func(string)) {
	start := -1
	lower := strings.ToLower(s)
	for i, r := range lower {
		alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
		if alnum && start < 0 {
			start = i
		} else if !alnum && start >= 0 {
			emit(lower[start:i])
			start = -1
		}
	}
	if start >= 0 {
		emit(lower[start:])
	}
}

// searchFields returns the text a CVE is searchable by
func searchFields(cve *CVE, emit func(string)) {
	emit(cve.ID)
	emit(cve.Title)
	emit(cve.Description)
	emit(cve.CWE)
	emit(cve.KEVVulnerabilityName)
	emit(cve.Vendor)
	emit(cve.Product)
	for _, ap := range cve.AffectedProducts {
		emit(ap.Vendor)
		emit(ap.Product)
	}
}

func buildSearchIndex(cves []CVE) *SearchIndex {
	ids := map[string]uint32{}
	var terms []string
	var postings [][]uint32
	for i := range cves {
		doc := uint32(i)
		searchFields(&cves[i], func(field string) {
			tokenize(field, func(tok string) {
				if stopwords[tok] || len(tok) > 48 {
					return
				}
				id, ok := ids[tok]
				if !ok {
					id = uint32(len(terms))
					ids[tok] = id
					terms = append(terms, strings.Clone(tok))
					postings = append(postings, nil)
				}
				p := postings[id]
				// Docs are visited in order, so a duplicate can only be the last entry
				if n := len(p); n == 0 || p[n-1] != doc {
					postings[id] = append(p, doc)
				}
			})
		})
	}
	// Sort terms, carrying postings along
	order := make([]int, len(terms))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return terms[order[a]] < terms[order[b]] })
	idx := &SearchIndex{terms: make([]string, len(terms)), postings: make([][]uint32, len(terms)), numDocs: len(cves)}
	for n, o := range order {
		idx.terms[n] = terms[o]
		p := postings[o]
		idx.postings[n] = p[:len(p):len(p)]
	}
	return idx
}

// lookup returns the sorted docs containing tok exactly, or (if prefix) any token starting with tok
func (idx *SearchIndex) lookup(tok string, prefix bool) []uint32 {
	lo := sort.SearchStrings(idx.terms, tok)
	if !prefix {
		if lo < len(idx.terms) && idx.terms[lo] == tok {
			return idx.postings[lo]
		}
		return nil
	}
	hi := lo
	for hi < len(idx.terms) && strings.HasPrefix(idx.terms[hi], tok) {
		hi++
	}
	switch hi - lo {
	case 0:
		return nil
	case 1:
		return idx.postings[lo]
	}
	return unionPostings(idx.postings[lo:hi], idx.numDocs)
}

// unionPostings merges sorted lists via a bitset, which yields sorted output for free
func unionPostings(lists [][]uint32, numDocs int) []uint32 {
	set := make([]uint64, (numDocs+63)/64)
	total := 0
	for _, l := range lists {
		for _, d := range l {
			if set[d>>6]&(1<<(d&63)) == 0 {
				set[d>>6] |= 1 << (d & 63)
				total++
			}
		}
	}
	out := make([]uint32, 0, total)
	for w, word := range set {
		for word != 0 {
			b := uint32(bits.TrailingZeros64(word))
			out = append(out, uint32(w)<<6|b)
			word &= word - 1
		}
	}
	return out
}

func intersectPostings(a, b []uint32) []uint32 {
	out := make([]uint32, 0, min(len(a), len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// queryTerm returns docs matching one user term. A term's tokens must all be
// present; the last one matches as a prefix (so "fortig" finds "fortigate").
func (idx *SearchIndex) queryTerm(term string) (docs []uint32, ok bool) {
	var toks []string
	tokenize(term, func(t string) {
		if !stopwords[t] {
			toks = append(toks, t)
		}
	})
	if len(toks) == 0 {
		return nil, false
	}
	for n, t := range toks {
		// Very short prefixes expand to thousands of terms; match them exactly
		prefix := n == len(toks)-1 && len(t) >= 3
		p := idx.lookup(t, prefix)
		if n == 0 {
			docs = p
		} else {
			docs = intersectPostings(docs, p)
		}
		if len(docs) == 0 {
			break
		}
	}
	return docs, true
}

// containsFoldText reports whether any searchable field of cve contains phrase (lowercase)
func containsFoldText(cve *CVE, phrase string) bool {
	found := false
	searchFields(cve, func(f string) {
		if !found && f != "" && strings.Contains(strings.ToLower(f), phrase) {
			found = true
		}
	})
	return found
}

// ---- Sort orders ----

// sortedOrder returns CVE indexes in ascending order for sortBy, built lazily and cached
func (ds *Dataset) sortedOrder(sortBy string) []int {
	if sortBy == "" {
		sortBy = "datePublished"
	}
	ds.orderMu.Lock()
	defer ds.orderMu.Unlock()
	if order, ok := ds.orders[sortBy]; ok {
		return order
	}
	order := make([]int, len(ds.CVEs))
	for i := range order {
		order[i] = i
	}
	sortIndexes(ds.CVEs, order, sortBy)
	if ds.orders == nil {
		ds.orders = map[string][]int{}
	}
	ds.orders[sortBy] = order
	return order
}
