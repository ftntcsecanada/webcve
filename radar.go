package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// RadarEvent is one dated development for a CVE: listed in KEV, a public
// exploit appeared, a GitHub PoC appeared, or a critical CVE was published
type RadarEvent struct {
	Date     string  `json:"date"`
	Type     string  `json:"type"` // kev, exploit, poc, critical
	CVE      string  `json:"cve"`
	Vendor   string  `json:"vendor"`
	Title    string  `json:"title"`
	Detail   string  `json:"detail,omitempty"`
	URL      string  `json:"url,omitempty"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	EPSS     float64 `json:"epss"`
	Ransom   bool    `json:"ransomware,omitempty"`
}

type radarRequest struct {
	Vendors []string `json:"vendors"`
	Days    int      `json:"days"`
	Types   []string `json:"types"`
}

// RadarCounts summarizes one vendor's events in the window
type RadarCounts struct {
	Vendor   string `json:"vendor"`
	KEV      int    `json:"kev"`
	Exploit  int    `json:"exploit"`
	PoC      int    `json:"poc"`
	Critical int    `json:"critical"`
}

const radarMaxEvents = 400

func (app *App) handleRadar(c echo.Context) error {
	var req radarRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if req.Days <= 0 || req.Days > 365 {
		req.Days = 30
	}
	want := map[string]bool{}
	for _, t := range req.Types {
		want[t] = true
	}
	if len(want) == 0 {
		want = map[string]bool{"kev": true, "exploit": true, "poc": true, "critical": true}
	}
	vendorKeys := map[string]bool{}
	for _, v := range req.Vendors {
		vendorKeys[normalizeVendor(v)] = true
	}
	ds := app.dataset()
	names := map[string]string{}
	for _, o := range ds.vendors {
		names[o.Key] = o.Name
	}
	since := time.Now().AddDate(0, 0, -req.Days).Format("2006-01-02")

	var events []RadarEvent
	counts := map[string]*RadarCounts{}
	for i := range ds.CVEs {
		cve := &ds.CVEs[i]
		vendor := ""
		for _, k := range ds.vendorKeys[i] {
			if len(vendorKeys) == 0 || vendorKeys[k] {
				vendor = names[k]
				if vendor == "" {
					vendor = k
				}
				break
			}
		}
		if vendor == "" {
			continue
		}
		base := RadarEvent{
			CVE: cve.ID, Vendor: vendor, Title: summaryTitle(cve),
			Score: cve.BaseScore, Severity: cve.BaseSeverity, EPSS: cve.EPSS,
			Ransom: cve.KEVKnownRansomwareCampaign == "Known",
		}
		cnt := counts[vendor]
		if cnt == nil {
			cnt = &RadarCounts{Vendor: vendor}
			counts[vendor] = cnt
		}
		add := func(e RadarEvent) {
			switch e.Type {
			case "kev":
				cnt.KEV++
			case "exploit":
				cnt.Exploit++
			case "poc":
				cnt.PoC++
			case "critical":
				cnt.Critical++
			}
			if want[e.Type] {
				events = append(events, e)
			}
		}

		if cve.InKEV && cve.KEVDateAdded >= since {
			e := base
			e.Type, e.Date = "kev", cve.KEVDateAdded
			if cve.KEVVulnerabilityName != "" {
				e.Title = cve.KEVVulnerabilityName
			}
			e.Detail = "Added to CISA KEV"
			if cve.KEVDueDate != "" {
				e.Detail += " · due " + cve.KEVDueDate
			}
			add(e)
		}
		// Exploit-DB entries carry a publication date; Metasploit dates are the
		// vulnerability's disclosure, so they can't say when a module appeared
		firstPoC := ""
		var pocRef ExploitRef
		for _, x := range cve.Exploits {
			switch x.Source {
			case "exploitdb":
				if x.Date >= since {
					e := base
					e.Type, e.Date, e.URL = "exploit", x.Date, x.URL
					e.Detail = "Exploit-DB: " + x.Title
					add(e)
				}
			case "github":
				if x.Date != "" && (firstPoC == "" || x.Date < firstPoC) {
					firstPoC, pocRef = x.Date, x
				}
			}
		}
		// Only report a PoC when the earliest known one falls in the window
		if firstPoC >= since {
			e := base
			e.Type, e.Date, e.URL = "poc", firstPoC, pocRef.URL
			e.Detail = "First GitHub PoC: " + strings.SplitN(pocRef.Title, " — ", 2)[0]
			add(e)
		}
		if cve.BaseScore >= 9 && !cve.DatePublished.IsZero() {
			if d := cve.DatePublished.Format("2006-01-02"); d >= since {
				e := base
				e.Type, e.Date = "critical", d
				e.Detail = "Critical CVE published"
				add(e)
			}
		}
	}

	sort.Slice(events, func(a, b int) bool {
		if events[a].Date != events[b].Date {
			return events[a].Date > events[b].Date
		}
		return events[a].CVE > events[b].CVE
	})
	total := len(events)
	events = events[:min(total, radarMaxEvents)]

	summary := make([]*RadarCounts, 0, len(counts))
	for _, cnt := range counts {
		if cnt.KEV+cnt.Exploit+cnt.PoC+cnt.Critical > 0 {
			summary = append(summary, cnt)
		}
	}
	sort.Slice(summary, func(a, b int) bool {
		x, y := summary[a], summary[b]
		if x.KEV != y.KEV {
			return x.KEV > y.KEV
		}
		return x.Exploit+x.PoC+x.Critical > y.Exploit+y.PoC+y.Critical
	})
	if len(vendorKeys) == 0 {
		summary = summary[:min(len(summary), 25)]
	}

	return c.JSON(http.StatusOK, map[string]any{
		"events":  events,
		"total":   total,
		"summary": summary,
		"since":   since,
	})
}

func summaryTitle(cve *CVE) string {
	switch {
	case cve.Title != "":
		return cve.Title
	case cve.KEVVulnerabilityName != "":
		return cve.KEVVulnerabilityName
	default:
		return truncate(cve.Description, 160)
	}
}
