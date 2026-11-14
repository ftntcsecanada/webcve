package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// Signals: early-warning items from sources that aren't tied to a CVE record
// (yet): government CERT alerts, vendor PSIRT advisories, the oss-security
// list, GitHub security advisories and exploitation research. Many describe a
// flaw before its CVE is published or enriched, or report exploitation before
// CISA KEV lists it. Items are kept for signalWindow, linked to the CVEs they
// mention, and rated by the same two-tier AI as CVEs (signals_ai.go).

const (
	SignalsPath     = DataDir + "/signals.json"
	signalWindow    = 30 * 24 * time.Hour
	signalsInterval = 30 * time.Minute
)

// signalFeed is one source of signals
type signalFeed struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // cert, vendor, research, community, advisory
	URL   string `json:"url"`
	Site  string `json:"site"`
	ghsa  bool
}

var signalFeeds = []signalFeed{
	{Name: "cisa", Label: "CISA advisories", Kind: "cert", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Site: "https://www.cisa.gov/news-events/cybersecurity-advisories"},
	{Name: "cccs", Label: "Canadian Centre for Cyber Security", Kind: "cert", URL: "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en", Site: "https://www.cyber.gc.ca/en/alerts-advisories"},
	{Name: "ncsc-uk", Label: "NCSC UK", Kind: "cert", URL: "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml", Site: "https://www.ncsc.gov.uk/section/keep-up-to-date/ncsc-news"},
	{Name: "cert-eu", Label: "CERT-EU", Kind: "cert", URL: "https://cert.europa.eu/publications/security-advisories-rss", Site: "https://cert.europa.eu/publications/security-advisories"},
	{Name: "jpcert", Label: "JPCERT/CC", Kind: "cert", URL: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", Site: "https://www.jpcert.or.jp/english/"},
	{Name: "certcc", Label: "CERT/CC vulnerability notes", Kind: "cert", URL: "https://kb.cert.org/vuls/atomfeed/", Site: "https://kb.cert.org/vuls/"},
	{Name: "cisco", Label: "Cisco PSIRT", Kind: "vendor", URL: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", Site: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
	{Name: "paloalto", Label: "Palo Alto Networks", Kind: "vendor", URL: "https://security.paloaltonetworks.com/rss.xml", Site: "https://security.paloaltonetworks.com/"},
	{Name: "ivanti", Label: "Ivanti security advisories", Kind: "vendor", URL: "https://www.ivanti.com/blog/topics/security-advisory/rss", Site: "https://www.ivanti.com/blog/topics/security-advisory"},
	{Name: "oss-security", Label: "oss-security list", Kind: "community", URL: "https://seclists.org/rss/oss-sec.rss", Site: "https://www.openwall.com/lists/oss-security/"},
	{Name: "ghsa", Label: "GitHub security advisories", Kind: "advisory", URL: "https://api.github.com/advisories", Site: "https://github.com/advisories", ghsa: true},
	{Name: "watchtowr", Label: "watchTowr Labs", Kind: "research", URL: "https://labs.watchtowr.com/rss/", Site: "https://labs.watchtowr.com/"},
	{Name: "horizon3", Label: "Horizon3.ai", Kind: "research", URL: "https://horizon3.ai/feed/", Site: "https://horizon3.ai/attack-research/"},
	{Name: "rapid7", Label: "Rapid7", Kind: "research", URL: "https://www.rapid7.com/rss.xml", Site: "https://www.rapid7.com/blog/"},
}

func feedByName(name string) *signalFeed {
	for i := range signalFeeds {
		if signalFeeds[i].Name == name {
			return &signalFeeds[i]
		}
	}
	return nil
}

// Signal is one item from a feed
type Signal struct {
	ID        string    `json:"id"`
	Feed      string    `json:"feed"`
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	Summary   string    `json:"summary"`
	Published time.Time `json:"published"`
	FirstSeen time.Time `json:"firstSeen"`
	CVEs      []string  `json:"cves,omitempty"`

	// AI: Report is the triage verdict on what the item is (vulnerability,
	// exploitation or other); AI holds the triage or deep-analysis rating
	Report      string             `json:"report,omitempty"`
	ReportProbs map[string]float64 `json:"reportProbs,omitempty"`
	AI          *ImpactAssessment  `json:"ai,omitempty"`
	FailAt      time.Time          `json:"failAt,omitzero"`
	FailErr     string             `json:"failErr,omitempty"`
}

// feedState is the last fetch outcome for one feed
type feedState struct {
	LastOK    time.Time `json:"lastOK,omitzero"`
	LastError string    `json:"lastError,omitempty"`
	ErrorAt   time.Time `json:"errorAt,omitzero"`
	Items     int       `json:"items"`
}

type signalStore struct {
	Items map[string]*Signal    `json:"items"`
	Feeds map[string]*feedState `json:"feeds"`
}

// SignalHub fetches feeds, keeps the store and runs the AI on new items
type SignalHub struct {
	app *App

	mu       sync.Mutex
	store    signalStore
	inFlight string // item the AI is working on

	triageWake, analysisWake chan struct{} // set by start when the AI is on
}

var signalStorePath = SignalsPath

func newSignalHub(app *App) *SignalHub {
	h := &SignalHub{app: app,
		store: signalStore{Items: map[string]*Signal{}, Feeds: map[string]*feedState{}}}
	if err := readJSONFile(signalStorePath, &h.store); err != nil && !os.IsNotExist(err) {
		logf("Signals: ignoring unreadable %s: %v", signalStorePath, err)
	}
	if h.store.Items == nil {
		h.store.Items = map[string]*Signal{}
	}
	if h.store.Feeds == nil {
		h.store.Feeds = map[string]*feedState{}
	}
	// Triage results from older rules are cheap to redo
	for _, s := range h.store.Items {
		if s.AI != nil && s.AI.Tier == "triage" && s.AI.RulesVersion != signalRulesVersion {
			s.AI, s.Report, s.ReportProbs = nil, "", nil
		}
	}
	return h
}

func (h *SignalHub) saveLocked() {
	if err := writeJSONAtomic(signalStorePath, h.store); err != nil {
		logf("Signals: could not save %s: %v", signalStorePath, err)
	}
}

// signalWork tells the AI workers new items may need them
func (h *SignalHub) signalWork() {
	if h.triageWake != nil {
		select {
		case h.triageWake <- struct{}{}:
		default:
		}
	}
	h.wakeAnalysis()
}

// ---- Fetching ----

// poll fetches every feed once and stores new items
func (h *SignalHub) poll() error {
	h.app.board.attempt("signals", "fetching feeds")
	var failed []string
	added := 0
	for _, f := range signalFeeds {
		items, err := h.fetchFeed(f)
		h.mu.Lock()
		st := h.store.Feeds[f.Name]
		if st == nil {
			st = &feedState{}
			h.store.Feeds[f.Name] = st
		}
		if err != nil {
			st.LastError, st.ErrorAt = shortErr(err), time.Now()
			failed = append(failed, f.Label)
			h.mu.Unlock()
			logf("Signals: %s: %v", f.Name, err)
			continue
		}
		st.LastOK, st.LastError = time.Now(), ""
		added += h.addLocked(items)
		h.mu.Unlock()
	}
	h.mu.Lock()
	h.pruneLocked()
	for name, st := range h.store.Feeds {
		st.Items = 0
		for _, s := range h.store.Items {
			if s.Feed == name {
				st.Items++
			}
		}
	}
	total := len(h.store.Items)
	h.saveLocked()
	h.mu.Unlock()

	if added > 0 {
		logf("Signals: %d new items (%d kept)", added, total)
		h.signalWork()
	}
	h.app.board.records("signals", total, "items")
	if len(failed) == len(signalFeeds) {
		err := fmt.Errorf("all feeds failed")
		h.app.board.fail("signals", err, 10*time.Minute)
		return err
	}
	h.app.board.success("signals", added > 0)
	if len(failed) > 0 {
		h.app.board.progress("signals", "Failed: "+strings.Join(failed, ", "))
	}
	return nil
}

// addLocked stores items not seen before, within the window. Caller holds mu.
func (h *SignalHub) addLocked(items []*Signal) int {
	cutoff := time.Now().Add(-signalWindow)
	added := 0
	for _, s := range items {
		if s.Published.Before(cutoff) {
			continue
		}
		if old := h.store.Items[s.ID]; old != nil {
			// Feeds revise items; keep the AI result unless the text changed
			if old.Title != s.Title || old.Summary != s.Summary {
				old.Title, old.Summary, old.CVEs, old.URL = s.Title, s.Summary, s.CVEs, s.URL
				old.AI, old.Report, old.ReportProbs = nil, "", nil
				added++
			}
			continue
		}
		s.FirstSeen = time.Now()
		h.store.Items[s.ID] = s
		added++
	}
	return added
}

func (h *SignalHub) pruneLocked() {
	cutoff := time.Now().Add(-signalWindow)
	for id, s := range h.store.Items {
		if s.Published.Before(cutoff) {
			delete(h.store.Items, id)
		}
	}
}

func (h *SignalHub) fetchFeed(f signalFeed) ([]*Signal, error) {
	if f.ghsa {
		return h.fetchGHSA(f)
	}
	resp, err := h.app.get(f.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseFeed(f.Name, io.LimitReader(resp.Body, 32<<20))
}

// ---- RSS 2.0, RSS 1.0 (RDF) and Atom ----

type feedDoc struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	Items   []rssItem   `xml:"item"` // RSS 1.0 puts items beside the channel
	Entries []atomEntry `xml:"entry"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	Description string `xml:"description"`
	Encoded     string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
	PubDate     string `xml:"pubDate"`
	DCDate      string `xml:"http://purl.org/dc/elements/1.1/ date"`
}

type atomEntry struct {
	Title string `xml:"title"`
	Links []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
	ID        string `xml:"id"`
	Summary   string `xml:"summary"`
	Content   string `xml:"content"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
}

func parseFeed(feed string, r io.Reader) ([]*Signal, error) {
	dec := xml.NewDecoder(xmlCleanReader{r})
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	// Feeds are UTF-8 in practice; accept a declared charset rather than fail
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var doc feedDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("unreadable feed: %w", err)
	}
	var out []*Signal
	for _, it := range append(doc.Channel.Items, doc.Items...) {
		body := it.Description
		if len(it.Encoded) > len(body) {
			body = it.Encoded
		}
		date := it.PubDate
		if date == "" {
			date = it.DCDate
		}
		key := strings.TrimSpace(it.GUID)
		if key == "" {
			key = strings.TrimSpace(it.Link)
		}
		if s := newSignal(feed, key, it.Title, strings.TrimSpace(it.Link), body, date); s != nil {
			out = append(out, s)
		}
	}
	for _, e := range doc.Entries {
		link := ""
		for _, l := range e.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				link = strings.TrimSpace(l.Href)
				break
			}
		}
		if link == "" && len(e.Links) > 0 {
			link = strings.TrimSpace(e.Links[0].Href)
		}
		body := e.Summary
		if len(e.Content) > len(body) {
			body = e.Content
		}
		date := e.Published
		if date == "" {
			date = e.Updated
		}
		key := strings.TrimSpace(e.ID)
		if key == "" {
			key = link
		}
		if s := newSignal(feed, key, e.Title, link, body, date); s != nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// xmlCleanReader drops control characters XML forbids, which some feeds carry
type xmlCleanReader struct{ r io.Reader }

func (c xmlCleanReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	out := p[:0]
	for _, b := range p[:n] {
		if b >= 0x20 || b == '\t' || b == '\n' || b == '\r' {
			out = append(out, b)
		}
	}
	if len(out) == 0 && n > 0 && err == nil {
		return c.Read(p)
	}
	return len(out), err
}

func newSignal(feed, key, title, link, body, date string) *Signal {
	title = cleanText(title)
	if title == "" || key == "" {
		return nil
	}
	published, ok := parseFeedTime(date)
	if !ok {
		return nil
	}
	summary := cleanText(body)
	return &Signal{
		ID: signalID(feed, key), Feed: feed, Title: truncate(title, 300), URL: link,
		Summary: truncate(summary, 3000), Published: published.UTC(), CVEs: mentionedCVEs(title + " " + summary),
	}
}

func signalID(feed, key string) string {
	sum := sha1.Sum([]byte(feed + "\x00" + key))
	return feed + "-" + hex.EncodeToString(sum[:8])
}

var (
	htmlTag    = regexp.MustCompile(`(?s)<[^>]*>`)
	whitespace = regexp.MustCompile(`\s+`)
)

// cleanText turns feed HTML into plain text
func cleanText(s string) string {
	s = htmlTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.TrimSpace(whitespace.ReplaceAllString(s, " "))
}

func mentionedCVEs(text string) []string {
	var out []string
	for _, id := range cveRefRe.FindAllString(strings.ToUpper(text), -1) {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) > 25 {
		out = out[:25] // a roundup of many CVEs; the rest add nothing
	}
	return out
}

var feedTimeLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 02 Jan 2006 15:04 -0700",
	"2 Jan 2006 15:04:05 -0700", "Mon, 02 Jan 06 15:04:05 -0700", "Mon, 2 Jan 06 15:04:05 -0700",
	"2006-01-02T15:04Z07:00", "2006-01-02T15:04:05", "2006-01-02T15:04:05-07:00", "2006-01-02 15:04:05", "2006-01-02",
}

func parseFeedTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, " Z") { // "Tue, 10 Nov 2026 15:33:07 Z"
		s = strings.TrimSuffix(s, " Z") + " +0000"
	}
	for _, layout := range feedTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ---- GitHub security advisories ----

type ghsaAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

// fetchGHSA reads recent critical advisories, reviewed and unreviewed. Many
// appear before the CVE record is published or enriched.
func (h *SignalHub) fetchGHSA(f signalFeed) ([]*Signal, error) {
	var out []*Signal
	for _, typ := range []string{"reviewed", "unreviewed"} {
		var advs []ghsaAdvisory
		url := f.URL + "?severity=critical&sort=published&direction=desc&per_page=100&type=" + typ
		resp, err := h.app.get(url)
		if err != nil {
			return nil, err
		}
		err = json.NewDecoder(resp.Body).Decode(&advs)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, a := range advs {
			var pkgs []string
			for _, v := range a.Vulnerabilities {
				if p := strings.TrimSpace(v.Package.Ecosystem + " " + v.Package.Name); p != "" && !slices.Contains(pkgs, p) {
					pkgs = append(pkgs, p)
				}
			}
			body := a.Description
			if len(pkgs) > 0 {
				body = "Packages: " + strings.Join(pkgs[:min(len(pkgs), 10)], ", ") + ". " + body
			}
			if a.CVSS.Score > 0 {
				body = fmt.Sprintf("CVSS %.1f. ", a.CVSS.Score) + body
			}
			s := newSignal(f.Name, a.GHSAID, a.GHSAID+": "+a.Summary, a.HTMLURL, body, a.PublishedAt)
			if s == nil {
				continue
			}
			if a.CVEID != "" && !slices.Contains(s.CVEs, a.CVEID) {
				s.CVEs = append([]string{a.CVEID}, s.CVEs...)
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// ---- API ----

// SignalView is a signal as the UI sees it
type SignalView struct {
	*Signal
	FeedLabel  string      `json:"feedLabel"`
	FeedKind   string      `json:"feedKind"`
	Linked     []linkedCVE `json:"linked,omitempty"`
	Readiness  string      `json:"readiness"`
	ReadyWhy   string      `json:"readyWhy"`
	Actionable bool        `json:"actionable"`
	AlsoIn     []string    `json:"alsoIn,omitempty"` // other feeds reporting the same CVEs
}

type linkedCVE struct {
	ID       string       `json:"id"`
	Score    float64      `json:"score"`
	InKEV    bool         `json:"inKEV"`
	AIImpact string       `json:"aiImpact,omitempty"`
	Covered  bool         `json:"covered,omitempty"` // a FortiGuard IPS signature exists
	IPSRules []IPSRuleRef `json:"ipsRules,omitempty"`
}

func (h *SignalHub) views() []SignalView {
	ds := h.app.dataset()
	h.mu.Lock()
	defer h.mu.Unlock()
	byCVE := map[string]map[string]bool{}
	for _, s := range h.store.Items {
		for _, id := range s.CVEs {
			if byCVE[id] == nil {
				byCVE[id] = map[string]bool{}
			}
			byCVE[id][s.Feed] = true
		}
	}
	out := make([]SignalView, 0, len(h.store.Items))
	for _, s := range h.store.Items {
		cp := *s
		v := SignalView{Signal: &cp}
		if f := feedByName(s.Feed); f != nil {
			v.FeedLabel, v.FeedKind = f.Label, f.Kind
		}
		also := map[string]bool{}
		for _, id := range s.CVEs {
			for feed := range byCVE[id] {
				if feed != s.Feed {
					also[feed] = true
				}
			}
			if ds != nil {
				if i, ok := ds.byID[id]; ok {
					c := &ds.CVEs[i]
					l := linkedCVE{ID: id, Score: c.BaseScore, InKEV: c.InKEV, Covered: len(c.FortiGuardIPS) > 0, IPSRules: c.FortiGuardIPS}
					if c.AIImpact != nil {
						l.AIImpact = c.AIImpact.Rating
					}
					v.Linked = append(v.Linked, l)
				}
			}
		}
		for feed := range also {
			if f := feedByName(feed); f != nil {
				v.AlsoIn = append(v.AlsoIn, f.Label)
			}
		}
		slices.Sort(v.AlsoIn)
		v.Readiness, v.ReadyWhy = signalReadiness(s, ds)
		v.Actionable = signalActionable(s, ds)
		// Pending standouts show without a rating until their analysis lands
		if v.AI != nil && v.AI.Pending {
			v.AI = nil
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b SignalView) int { return b.Published.Compare(a.Published) })
	return out
}

type feedStatusView struct {
	signalFeed
	feedState
}

func (app *App) handleSignals(c echo.Context) error {
	h := app.signals
	items := h.views()
	h.mu.Lock()
	feeds := make([]feedStatusView, 0, len(signalFeeds))
	for _, f := range signalFeeds {
		v := feedStatusView{signalFeed: f}
		if st := h.store.Feeds[f.Name]; st != nil {
			v.feedState = *st
		}
		feeds = append(feeds, v)
	}
	h.mu.Unlock()
	return c.JSON(http.StatusOK, map[string]any{
		"items": items, "feeds": feeds, "windowDays": int(signalWindow.Hours() / 24), "queue": h.queueStatus(),
	})
}
