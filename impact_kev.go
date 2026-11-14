package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fast triage for AI impact assessments: the kev-8b decision model on the
// Bifrost gateway (POST /v1/decisions). It answers typed choice questions with
// a probability distribution in about 150 ms, so every candidate gets one.
//
// A small model is only as good as what it's given, so the triage input is
// concise prose built from facts rather than the raw record: CVSS components,
// the weakness, affected products, package ecosystems, exploitation evidence,
// and how prominent the vendor and product are in our own CVE corpus (CVE and
// KEV counts), which is the best reach signal we have.
//
// Triage asks two factual questions:
//   - deployment: how widely the affected product is deployed. Asked instead
//     about global impact, kev-8b put P(high)+P(severe) above 0.7 for 90% of two
//     weeks of real critical CVEs, so that question filtered nothing.
//   - coverage: which kind of Fortinet control could see exploitation (network
//     IPS, web application firewall, file scanning, endpoint), or none. We
//     write signatures; a CVE nothing in the portfolio can see matters less.
//
// Standouts (enough reach and coverable, or Fortinet's own products, or KEV or
// actively exploited) go on to the reasoning model in impact_llm.go.

const impactDefaultTriageModel = "kev-8b"

// Coverage classes, and the Fortinet controls behind each
var coverageProducts = map[string]string{
	"network":  "FortiGate IPS",
	"web":      "FortiWeb / FortiGate IPS",
	"file":     "FortiGate AV / FortiMail / FortiSandbox",
	"endpoint": "FortiEDR",
	"none":     "",
}

var triageQuestions = map[string]any{
	"deployment": map[string]any{
		"type":         "choice",
		"instructions": "How widely is the affected product deployed worldwide? Use the product, the vendor and the CVE history given.",
		"criteria": map[string]any{
			"ubiquitous": "runs at a large share of all organizations: major operating systems, browsers, core open source libraries, dominant enterprise platforms and edge devices",
			"widespread": "used by many thousands of organizations",
			"niche":      "a specific sector, a small vendor or a modest user base",
			"obscure":    "a small open source project, a plugin, or a single consumer device model",
		},
	},
	"coverage": map[string]any{
		"type": "choice",
		"instructions": "How would exploitation of this vulnerability reach the target, and so which kind of security control " +
			"could detect or block it? Use the attack vector, the weakness and the description.",
		"criteria": map[string]any{
			"network":  "exploit traffic crosses the network in a protocol an intrusion prevention system can inspect: crafted requests to a device, server or service (HTTP to an appliance, SMB, RDP, SSH, DNS, VPN, industrial or other service protocols)",
			"web":      "an attack on a web application or API through HTTP requests: injection, authentication bypass, file upload, SSRF, path traversal, deserialization",
			"file":     "the victim opens a malicious file, document, image, media file, archive or email attachment",
			"endpoint": "local exploitation on a host the attacker already has access to: privilege escalation, drivers, kernel, local services or binaries",
			"none":     "nothing a network or endpoint security product can see: physical, Bluetooth, Wi-Fi or cellular radio access, hardware or side-channel flaws, fixes made only on a cloud provider's backend, supply-chain compromise of a package",
		},
	},
}

type decisionAnswer struct {
	Value         string             `json:"value"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type decisionResponse struct {
	Answers map[string]decisionAnswer `json:"answers"`
}

// triageReach is the probability that the product is widespread or ubiquitous
func triageReach(p map[string]float64) float64 { return p["ubiquitous"] + p["widespread"] }

// ---- Reach index: how prominent each vendor and product is in the corpus ----

type reachCount struct{ cves, kev int }

type reachIndex struct {
	vendors map[string]*reachCount
	pairs   map[string]*reachCount
}

var (
	reachMu    sync.Mutex
	reachFor   *Dataset
	reachCache *reachIndex
)

// reachOf returns the reach index for ds, building it on first use
func reachOf(ds *Dataset) *reachIndex {
	reachMu.Lock()
	defer reachMu.Unlock()
	if reachFor == ds && reachCache != nil {
		return reachCache
	}
	idx := &reachIndex{vendors: map[string]*reachCount{}, pairs: map[string]*reachCount{}}
	add := func(m map[string]*reachCount, k string, kev bool) {
		c := m[k]
		if c == nil {
			c = &reachCount{}
			m[k] = c
		}
		c.cves++
		if kev {
			c.kev++
		}
	}
	for i := range ds.CVEs {
		kev := ds.CVEs[i].InKEV
		if i < len(ds.vendorKeys) {
			for _, k := range ds.vendorKeys[i] {
				add(idx.vendors, k, kev)
			}
		}
		if i < len(ds.pairKeys) {
			for _, k := range ds.pairKeys[i] {
				add(idx.pairs, k, kev)
			}
		}
	}
	reachFor, reachCache = ds, idx
	return idx
}

// ---- Triage input ----

// triageState describes cve for the decision model in short factual prose
func triageState(cve *CVE, ds *Dataset) string {
	var b strings.Builder
	b.WriteString(cve.ID)
	if !cve.DatePublished.IsZero() {
		b.WriteString(", published " + cve.DatePublished.UTC().Format("2006-01-02"))
	}
	b.WriteString(".")
	if cve.BaseScore > 0 {
		fmt.Fprintf(&b, " CVSS %.1f", cve.BaseScore)
		var parts []string
		for _, p := range [][2]string{{"attack vector", cve.AttackVector}, {"complexity", cve.AttackComplexity},
			{"privileges required", cve.PrivilegesRequired}, {"user interaction", cve.UserInteraction}} {
			if p[1] != "" {
				parts = append(parts, p[0]+" "+strings.ToLower(p[1]))
			}
		}
		if len(parts) > 0 {
			b.WriteString(": " + strings.Join(parts, ", "))
		}
		b.WriteString(".")
	}
	if cwe := strings.TrimSpace(cve.CWE + " " + cve.CWEName); cwe != "" {
		b.WriteString(" Weakness: " + cwe + ".")
	}

	products := cve.AffectedProducts
	if !hasRealVendor(products) && len(cve.NVDProducts) > 0 {
		products = cve.NVDProducts
	}
	if len(products) > 0 {
		seen := map[string]bool{}
		var names []string
		for _, p := range products {
			n := strings.TrimSpace(p.Vendor + " " + p.Product)
			if n != "" && !seen[strings.ToLower(n)] && len(names) < 8 {
				seen[strings.ToLower(n)] = true
				names = append(names, n)
			}
		}
		fmt.Fprintf(&b, "\nAffected: %s", strings.Join(names, "; "))
		if len(products) > len(names) {
			fmt.Fprintf(&b, " (%d product entries in all)", len(products))
		}
		b.WriteString(".")
	}
	if len(cve.Packages) > 0 {
		eco := map[string]bool{}
		var ecos []string
		for _, p := range cve.Packages {
			if !eco[p.Ecosystem] {
				eco[p.Ecosystem] = true
				ecos = append(ecos, p.Ecosystem)
			}
		}
		fmt.Fprintf(&b, " Open source package listings: %d, across %s.", len(cve.Packages), strings.Join(ecos[:min(len(ecos), 10)], ", "))
	}

	// Corpus prominence of the vendor and product
	if ds != nil {
		if i, ok := ds.byID[cve.ID]; ok {
			idx := reachOf(ds)
			if i < len(ds.pairKeys) && len(ds.pairKeys[i]) > 0 {
				k := ds.pairKeys[i][0]
				if c := idx.pairs[k]; c != nil {
					name := ds.pairs[k]
					if name == "" {
						name = "this product"
					}
					fmt.Fprintf(&b, "\nHistory: %s has %d CVEs on record, %d of them in CISA KEV.", name, c.cves, c.kev)
				}
			}
			if i < len(ds.vendorKeys) && len(ds.vendorKeys[i]) > 0 {
				if c := idx.vendors[ds.vendorKeys[i][0]]; c != nil {
					fmt.Fprintf(&b, " The vendor has %d CVEs on record, %d in CISA KEV.", c.cves, c.kev)
				}
			}
		}
	}

	if hints := deliveryHints(cve); len(hints) > 0 {
		b.WriteString("\nDelivery: " + strings.Join(hints, " "))
	}

	var ev []string
	if cve.InKEV {
		s := "in CISA KEV since " + cve.KEVDateAdded
		if strings.EqualFold(cve.KEVKnownRansomwareCampaign, "known") {
			s += ", used by ransomware"
		}
		ev = append(ev, s)
	}
	if cve.SSVCExploitation != "" && cve.SSVCExploitation != "none" {
		ev = append(ev, "CISA SSVC exploitation "+cve.SSVCExploitation)
	}
	if cve.EUVDExploitedSince != "" {
		ev = append(ev, "ENISA reports exploitation since "+cve.EUVDExploitedSince)
	}
	if len(cve.Exploits) > 0 {
		src := map[string]bool{}
		var srcs []string
		for _, x := range cve.Exploits {
			if !src[x.Source] {
				src[x.Source] = true
				srcs = append(srcs, x.Source)
			}
		}
		ev = append(ev, "public exploit code ("+strings.Join(srcs, ", ")+")")
	}
	if cve.EPSS > 0 {
		ev = append(ev, fmt.Sprintf("EPSS %.3f", cve.EPSS))
	}
	if len(ev) == 0 {
		ev = append(ev, "no exploitation evidence yet")
	}
	b.WriteString("\nExploitation: " + strings.Join(ev, "; ") + ".")

	if t := summaryTitle(cve); t != "" {
		b.WriteString("\nTitle: " + t)
	}
	b.WriteString("\nDescription: " + truncate(strings.TrimSpace(cve.Description), 1200))
	return b.String()
}

// Weaknesses that almost always mean an attack on a web application or API
var webCWEs = map[string]bool{
	"CWE-22": true, "CWE-23": true, "CWE-79": true, "CWE-89": true, "CWE-98": true, "CWE-352": true, "CWE-434": true,
	"CWE-601": true, "CWE-611": true, "CWE-639": true, "CWE-917": true, "CWE-918": true, "CWE-943": true, "CWE-1321": true, "CWE-1336": true,
}

// Memory-safety weaknesses: with user interaction these usually mean a malicious file or page
var memoryCWEs = map[string]bool{
	"CWE-119": true, "CWE-120": true, "CWE-121": true, "CWE-122": true, "CWE-125": true, "CWE-190": true,
	"CWE-416": true, "CWE-476": true, "CWE-787": true, "CWE-843": true,
}

// deliveryHints spells out, from CVSS and the CWE, how exploitation reaches the
// target, so the decision model doesn't have to infer it
func deliveryHints(cve *CVE) []string {
	var h []string
	ui := strings.EqualFold(cve.UserInteraction, "required") || strings.EqualFold(cve.UserInteraction, "active") ||
		strings.EqualFold(cve.UserInteraction, "passive")
	switch normalizeAttackVector(cve.AttackVector) {
	case "NETWORK":
		if ui {
			h = append(h, "Reachable over the network, but a user must open a link, page or file.")
		} else {
			h = append(h, "Reachable remotely over the network without user action.")
		}
	case "ADJACENT":
		h = append(h, "Needs the same network segment or radio range (Wi-Fi, Bluetooth, cellular).")
	case "LOCAL":
		if ui {
			h = append(h, "Local: a user on the target host must open a file or run something.")
		} else {
			h = append(h, "Local: needs code already running on the target host.")
		}
	case "PHYSICAL":
		h = append(h, "Needs physical access to the device.")
	}
	cwe := strings.ToUpper(strings.TrimSpace(cve.CWE))
	switch {
	case webCWEs[cwe]:
		h = append(h, "The weakness is typical of web applications and APIs.")
	case memoryCWEs[cwe] && ui:
		h = append(h, "A memory-safety flaw triggered by content the victim opens or processes.")
	}
	return h
}

// ---- Triage call ----

// triage asks the decision model for reach and coverage
func (a *Assessor) triage(cve *CVE, ds *Dataset) (*ImpactAssessment, error) {
	body, _ := json.Marshal(map[string]any{
		"model": a.cfg.triageModel, "state": triageState(cve, ds), "questions": triageQuestions,
	})
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(impactRetryDelay(attempt))
		}
		raw, err := a.post("/v1/decisions", body, 60*time.Second)
		if retry := (errRetryable{}); errors.As(err, &retry) {
			lastErr = err
			continue
		}
		if err != nil {
			return nil, err
		}
		var res decisionResponse
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("unreadable decision response: %w", err)
		}
		dep, cov := res.Answers["deployment"], res.Answers["coverage"]
		if len(dep.Probabilities) == 0 || len(cov.Probabilities) == 0 {
			return nil, fmt.Errorf("decision model gave no usable answer: %s", truncate(string(raw), 200))
		}
		// Only CVEs below the escalation bar keep a triage rating, and limited
		// reach caps those at moderate
		rating := "moderate"
		if triageReach(dep.Probabilities) < 0.3 {
			rating = "low"
		}
		return &ImpactAssessment{
			Rating: rating, Confidence: triageConfidence(dep.Confidence),
			Probabilities: dep.Probabilities, CoverageProbabilities: cov.Probabilities,
			CoverageClass: cov.Value, Coverage: triageCoverageText(cov),
			Model: a.cfg.triageModel, Tier: "triage", AssessedAt: time.Now().UTC(), Signals: impactSignals(cve),
		}, nil
	}
	return nil, lastErr
}

func triageConfidence(c float64) string {
	switch {
	case c >= 0.7:
		return "high"
	case c >= 0.4:
		return "medium"
	}
	return "low"
}

func triageCoverageText(cov decisionAnswer) string {
	if cov.Value == "none" {
		return fmt.Sprintf("Probably nothing in the portfolio can see exploitation (%.0f%%).", cov.Probabilities["none"]*100)
	}
	return fmt.Sprintf("Likely %s exploitation (%.0f%%): %s.", cov.Value, cov.Probabilities[cov.Value]*100, coverageProducts[cov.Value])
}

// triageSummary explains a triage result that wasn't escalated
func triageSummary(t *ImpactAssessment, coverable bool) string {
	if !coverable {
		return "Fast triage found no Fortinet control likely to see exploitation, so it didn't get a deep analysis. " +
			"Deployment estimate: " + probList(t.Probabilities) + "."
	}
	return "Fast triage judged the affected product's deployment too limited for heavy global impact, so it didn't get a deep analysis. " +
		"Deployment estimate: " + probList(t.Probabilities) + "."
}

func probList(p map[string]float64) string {
	labels := make([]string, 0, len(p))
	for k := range p {
		labels = append(labels, k)
	}
	sort.Slice(labels, func(i, j int) bool { return p[labels[i]] > p[labels[j]] })
	parts := make([]string, 0, len(labels))
	for _, k := range labels {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", k, p[k]*100))
	}
	return strings.Join(parts, ", ")
}

// coverable reports whether some Fortinet control could plausibly see exploitation
func (c impactConfig) coverable(t *ImpactAssessment) bool {
	return t.CoverageProbabilities["none"] < 0.5
}

// standout reports whether a triaged CVE should get the deep analysis
func (c impactConfig) standout(cve *CVE, t *ImpactAssessment) bool {
	if cve.InKEV || strings.EqualFold(cve.SSVCExploitation, "active") || cve.EUVDExploitedSince != "" {
		return true
	}
	if isFortinet(cve) {
		return true
	}
	return c.coverable(t) && triageReach(t.Probabilities) >= c.escalateAt
}

func isFortinet(cve *CVE) bool {
	for _, k := range cveVendorKeys(cve) {
		if k == "fortinet" {
			return true
		}
	}
	return false
}

// post sends a JSON request to the gateway and returns the body of a 200 reply.
// Network errors, 429 and 5xx come back as errRetryable.
func (a *Assessor) post(path string, body []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, errRetryable{err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, errRetryable{err}
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(truncate(string(raw), 300))
		var e struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != nil && e.Error.Message != "" {
			msg = e.Error.Message
		}
		err := fmt.Errorf("gateway HTTP %d: %s", resp.StatusCode, msg)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, errRetryable{err}
		}
		return nil, err
	}
	return raw, nil
}
