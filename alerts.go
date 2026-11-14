package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Alerter posts new KEV entries and new high-severity CVEs for watched vendors
// to a Slack-compatible webhook ({"text": ...}). Configured by environment:
//
//	WEBCVE_ALERT_WEBHOOK    webhook URL (alerts are off when unset)
//	WEBCVE_ALERT_VENDORS    comma-separated vendors to watch (default: all)
//	WEBCVE_ALERT_MIN_SCORE  minimum CVSS for new non-KEV CVEs (default 9.0; 0 disables)
//	WEBCVE_PUBLIC_URL       base URL for links back to the browser
type Alerter struct {
	webhook  string
	vendors  []string
	minScore float64
	baseURL  string
	client   *http.Client
}

func newAlerterFromEnv() *Alerter {
	a := &Alerter{
		webhook:  strings.TrimSpace(os.Getenv("WEBCVE_ALERT_WEBHOOK")),
		minScore: 9.0,
		baseURL:  strings.TrimRight(os.Getenv("WEBCVE_PUBLIC_URL"), "/"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
	for _, v := range strings.Split(os.Getenv("WEBCVE_ALERT_VENDORS"), ",") {
		if k := normalizeVendor(v); k != "" {
			a.vendors = append(a.vendors, k)
		}
	}
	if s := os.Getenv("WEBCVE_ALERT_MIN_SCORE"); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			a.minScore = v
		}
	}
	if a.webhook != "" {
		logf("Alerts enabled (vendors: %v, min CVSS for new CVEs: %.1f)", a.vendors, a.minScore)
	}
	return a
}

// changes lists what's newsworthy in next compared to prev
func (a *Alerter) changes(prev, next *Dataset) (newKEV, newCritical []int) {
	for i := range next.CVEs {
		cve := &next.CVEs[i]
		if a.vendors != nil && !anyKeyIn(next.vendorKeys[i], a.vendors) {
			continue
		}
		j, existed := prev.byID[cve.ID]
		switch {
		case cve.InKEV && (!existed || !prev.CVEs[j].InKEV):
			newKEV = append(newKEV, i)
		case !existed && a.minScore > 0 && cve.BaseScore >= a.minScore && cve.State == "PUBLISHED":
			newCritical = append(newCritical, i)
		}
	}
	return
}

func (a *Alerter) notify(prev, next *Dataset) {
	if a == nil || a.webhook == "" {
		return
	}
	a.nowActionable(prev, next)
	newKEV, newCritical := a.changes(prev, next)
	if len(newKEV) == 0 && len(newCritical) == 0 {
		return
	}
	var b strings.Builder
	line := func(i int, prefix string) {
		cve := &next.CVEs[i]
		name := cve.KEVVulnerabilityName
		if name == "" {
			name = cve.Title
		}
		if name == "" {
			name = strings.TrimSpace(cve.Vendor + " " + cve.Product)
		}
		id := cve.ID
		if a.baseURL != "" {
			id = fmt.Sprintf("<%s/?cve=%s|%s>", a.baseURL, cve.ID, cve.ID)
		}
		fmt.Fprintf(&b, "%s %s (CVSS %.1f) %s", prefix, id, cve.BaseScore, name)
		if cve.InKEV && cve.KEVDueDate != "" {
			fmt.Fprintf(&b, " · due %s", cve.KEVDueDate)
		}
		b.WriteByte('\n')
	}
	const maxLines = 20
	if len(newKEV) > 0 {
		fmt.Fprintf(&b, "*%d new Known Exploited Vulnerabilit%s*\n", len(newKEV), plural(len(newKEV), "y", "ies"))
		for n, i := range newKEV {
			if n == maxLines {
				fmt.Fprintf(&b, "…and %d more\n", len(newKEV)-maxLines)
				break
			}
			line(i, "🔥")
		}
	}
	if len(newCritical) > 0 {
		fmt.Fprintf(&b, "*%d new CVE%s scored %.1f+*\n", len(newCritical), plural(len(newCritical), "", "s"), a.minScore)
		for n, i := range newCritical {
			if n == maxLines {
				fmt.Fprintf(&b, "…and %d more\n", len(newCritical)-maxLines)
				break
			}
			line(i, "•")
		}
	}
	a.post(b.String())
}

// post sends text to the webhook in the background
func (a *Alerter) post(text string) {
	body, _ := json.Marshal(map[string]string{"text": text})
	go func() {
		resp, err := a.client.Post(a.webhook, "application/json", bytes.NewReader(body))
		if err != nil {
			logf("Alert webhook failed: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			logf("Alert webhook returned HTTP %d", resp.StatusCode)
		}
	}()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// nowActionable posts when a CVE becomes notable for the signature team: rated
// high or severe by its deep analysis, and actionable by Fortinet network
// protections. That happens when an analysis lands, a rating escalates, or new
// exploit material turns "needs details" into "new signature". Only fresh CVEs
// or new evidence alert, so a backfill or re-analysis doesn't flood the webhook.
func (a *Alerter) nowActionable(prev, next *Dataset) {
	notable := func(c *CVE) bool {
		return c.AIImpact != nil && c.AIImpact.Tier != "triage" && impactRank(c.AIImpact.Rating) >= impactRank("high") && networkActionable(c)
	}
	var lines []string
	for i := range next.CVEs {
		cve := &next.CVEs[i]
		if !notable(cve) {
			continue
		}
		if a.vendors != nil && !anyKeyIn(next.vendorKeys[i], a.vendors) {
			continue
		}
		var before *CVE
		if j, ok := prev.byID[cve.ID]; ok {
			before = &prev.CVEs[j]
		}
		if before != nil && notable(before) {
			continue
		}
		fresh := time.Since(cve.DatePublished) <= impactAlertMaxAge ||
			(cve.InKEV && cve.KEVDateAdded >= time.Now().Add(-impactAlertMaxAge).Format("2006-01-02"))
		newEvidence := before != nil && (len(cve.Exploits) != len(before.Exploits) || cve.GitHubPoCs != before.GitHubPoCs ||
			cve.PublicExploit != before.PublicExploit)
		if !fresh && !newEvidence {
			continue
		}
		id := cve.ID
		if a.baseURL != "" {
			id = fmt.Sprintf("<%s/?cve=%s|%s>", a.baseURL, cve.ID, cve.ID)
		}
		line := fmt.Sprintf("🛡️ %s (CVSS %.1f, %s global risk) %s", id, cve.BaseScore, cve.AIImpact.Rating, summaryTitle(cve))
		if anchor := cve.AIImpact.DetectionAnchor; anchor != "" {
			line += "\n    Anchor: " + truncate(anchor, 240)
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return
	}
	if len(lines) > 20 {
		lines = append(lines[:20], fmt.Sprintf("…and %d more", len(lines)-20))
	}
	a.post("*AI early warning: actionable by Fortinet network protections*\n" + strings.Join(lines, "\n"))
}
