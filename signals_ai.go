package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"
)

// AI for signals, the same two tiers as CVEs (impact_kev.go, impact_llm.go):
// kev-8b triages every item, with one extra question since feeds also carry
// news, guidance and roundups; standouts get the reasoning model's deep
// analysis. When an item names a CVE that already has a deep analysis, that
// analysis is reused instead of running a new one.

// signalRulesVersion stamps signal triage results; bump it when the signal
// triage questions, input or escalation rules change
const signalRulesVersion = 2

var signalReportQuestion = map[string]any{
	"type":         "choice",
	"instructions": "What is this item about?",
	"criteria": map[string]any{
		"vulnerability": "discloses, warns about or analyses a specific security vulnerability in a named product",
		"exploitation":  "reports active exploitation, attacks or a campaign abusing a specific vulnerability or product",
		"other":         "news, opinion, a product or company announcement, an event, policy, general guidance, or a roundup of many unrelated issues",
	},
}

func signalQuestions() map[string]any {
	q := maps.Clone(triageQuestions)
	q["report"] = signalReportQuestion
	return q
}

// start launches the AI workers when assessments are configured
func (h *SignalHub) start() {
	cfg := h.app.impact.cfg
	if !cfg.enabled || cfg.triageModel == "" {
		return
	}
	h.triageWake, h.analysisWake = make(chan struct{}, 1), make(chan struct{}, 1)
	go h.triageLoop()
	go h.analysisLoop()
	h.signalWork()
}

// ---- Triage ----

func (h *SignalHub) needsTriage(s *Signal, now time.Time) bool {
	return s.AI == nil && now.Sub(s.Published) < signalWindow && (s.FailAt.IsZero() || now.Sub(s.FailAt) > impactRetryAfter)
}

func (h *SignalHub) triageLoop() {
	for {
		id := h.next(func(s *Signal, now time.Time) bool { return h.needsTriage(s, now) }, func(s *Signal) float64 {
			return float64(s.Published.Unix()) // newest first
		})
		if id == "" {
			waitOrTimeout(h.triageWake, 5*time.Minute)
			continue
		}
		h.triageOne(id)
	}
}

func (h *SignalHub) triageOne(id string) {
	h.mu.Lock()
	s := h.store.Items[id]
	if s == nil {
		h.mu.Unlock()
		return
	}
	cp := *s
	h.inFlight = id
	h.mu.Unlock()

	result, report, err := h.triage(&cp)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight = ""
	s = h.store.Items[id]
	if s == nil {
		return
	}
	if err != nil {
		s.FailAt, s.FailErr = time.Now(), "triage: "+err.Error()
		h.saveLocked()
		logf("Signals: triage of %s failed: %v", id, err)
		return
	}
	s.FailAt, s.FailErr = time.Time{}, ""
	s.Report, s.ReportProbs = report.Value, report.Probabilities
	escalate := h.standout(s, result)
	result.Pending = escalate
	if !escalate {
		result.Summary = signalTriageSummary(s, result, h.app.impact.cfg.coverable(result))
	}
	s.AI = result
	h.saveLocked()
	if escalate {
		h.wakeAnalysis()
	}
}

// triage asks the decision model the CVE questions plus what the item is
func (h *SignalHub) triage(s *Signal) (*ImpactAssessment, decisionAnswer, error) {
	a := h.app.impact
	body, _ := json.Marshal(map[string]any{
		"model": a.cfg.triageModel, "state": h.signalState(s), "questions": signalQuestions(),
	})
	raw, err := a.post("/v1/decisions", body, 60*time.Second)
	if err != nil {
		return nil, decisionAnswer{}, err
	}
	var res decisionResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, decisionAnswer{}, fmt.Errorf("unreadable decision response: %w", err)
	}
	dep, cov, host, rep := res.Answers["deployment"], res.Answers["coverage"], res.Answers["hosting"], res.Answers["report"]
	if len(dep.Probabilities) == 0 || len(cov.Probabilities) == 0 || len(rep.Probabilities) == 0 {
		return nil, decisionAnswer{}, fmt.Errorf("decision model gave no usable answer: %s", truncate(string(raw), 200))
	}
	rating := "moderate"
	// News and general material isn't a vulnerability report, whatever it mentions
	if triageReach(dep.Probabilities) < 0.3 || rep.Probabilities["other"] >= 0.5 {
		rating = "low"
	}
	return &ImpactAssessment{
		Rating: rating, Confidence: triageConfidence(dep.Confidence),
		Probabilities: dep.Probabilities, CoverageProbabilities: cov.Probabilities,
		CoverageClass: cov.Value, Coverage: triageCoverageText(cov), VendorCloud: host.Probabilities["vendor_cloud"],
		Model: a.cfg.triageModel, Tier: "triage", RulesVersion: signalRulesVersion, AssessedAt: time.Now().UTC(),
	}, rep, nil
}

// signalState describes a signal for the decision model in short prose
func (h *SignalHub) signalState(s *Signal) string {
	var b strings.Builder
	label, kind := s.Feed, ""
	if f := feedByName(s.Feed); f != nil {
		label, kind = f.Label, f.Kind
	}
	fmt.Fprintf(&b, "Source: %s (%s), published %s.\nTitle: %s", label, signalKindText(kind), s.Published.Format("2006-01-02"), s.Title)
	if len(s.CVEs) > 0 {
		fmt.Fprintf(&b, "\nCVEs mentioned: %s.", strings.Join(s.CVEs[:min(len(s.CVEs), 8)], ", "))
	}
	// What we know about a named CVE grounds the item in facts
	if ds := h.app.dataset(); ds != nil {
		for _, id := range s.CVEs {
			if i, ok := ds.byID[id]; ok {
				b.WriteString("\nOur record of " + id + ":\n" + truncate(triageState(&ds.CVEs[i], ds), 1500))
				break
			}
		}
	}
	b.WriteString("\nText: " + truncate(s.Summary, 1500))
	return b.String()
}

func signalKindText(kind string) string {
	return map[string]string{
		"cert": "government CERT", "vendor": "vendor security advisory", "research": "security research blog",
		"community": "open source security mailing list", "advisory": "package security advisory",
	}[kind]
}

// standout decides whether a triaged signal gets the deep analysis. The item
// must be about a vulnerability or exploitation, coverable, and either on a
// near-ubiquitous product or about exploitation of a widely deployed one.
// When it names CVEs we hold, the CVE rules apply: critical, or exploited.
func (h *SignalHub) standout(s *Signal, t *ImpactAssessment) bool {
	cfg := h.app.impact.cfg
	if s.ReportProbs["other"] >= 0.5 || !cfg.coverable(t) {
		return false
	}
	exploited := s.ReportProbs["exploitation"] >= 0.5
	if ds := h.app.dataset(); ds != nil && len(s.CVEs) > 0 && !exploited {
		known, critical := 0, false
		for _, id := range s.CVEs {
			if i, ok := ds.byID[id]; ok {
				c := &ds.CVEs[i]
				if c.BaseScore > 0 {
					known++
				}
				if c.BaseScore >= cfg.minScore || c.InKEV {
					critical = true
				}
			}
		}
		if known > 0 && !critical {
			return false
		}
	}
	reach := triageReach(t.Probabilities)
	return reach >= 0.85 || (exploited && reach >= 0.6)
}

func signalTriageSummary(s *Signal, t *ImpactAssessment, coverable bool) string {
	switch {
	case s.ReportProbs["other"] >= 0.5:
		return "Fast triage judged this news or general material rather than a report of a specific vulnerability."
	case t.VendorCloud >= 0.85:
		return "Fast triage judged this about a cloud service the vendor fixes on its own backend, which no Fortinet control can cover."
	case !coverable:
		return "Fast triage found no Fortinet control likely to see exploitation."
	}
	return "Fast triage judged the affected product's deployment too limited, or its CVEs below critical, for a deep analysis. " +
		"Deployment estimate: " + probList(t.Probabilities) + "."
}

// ---- Deep analysis ----

func (h *SignalHub) analysisLoop() {
	for {
		id := h.next(func(s *Signal, now time.Time) bool {
			return s.AI != nil && s.AI.Pending && (s.FailAt.IsZero() || now.Sub(s.FailAt) > impactRetryAfter)
		}, func(s *Signal) float64 {
			p := 100 * triageReach(s.AI.Probabilities)
			if s.ReportProbs["exploitation"] >= 0.5 {
				p += 1000
			}
			return p
		})
		if id == "" {
			waitOrTimeout(h.analysisWake, 5*time.Minute)
			continue
		}
		h.analyseOne(id)
	}
}

func (h *SignalHub) analyseOne(id string) {
	h.mu.Lock()
	s := h.store.Items[id]
	if s == nil {
		h.mu.Unlock()
		return
	}
	cp := *s
	h.inFlight = id
	h.mu.Unlock()

	result, err := h.reuseCVEAnalysis(&cp)
	if result == nil && err == nil {
		result, err = h.analyse(&cp)
	}
	h.mu.Lock()
	h.inFlight = ""
	s = h.store.Items[id]
	if s == nil {
		h.mu.Unlock()
		return
	}
	if err != nil {
		s.FailAt, s.FailErr = time.Now(), err.Error()
		h.saveLocked()
		h.mu.Unlock()
		logf("Signals: analysis of %s failed: %v", id, err)
		return
	}
	s.FailAt, s.FailErr = time.Time{}, ""
	s.AI = result
	h.saveLocked()
	h.mu.Unlock()
	logf("Signals: %s rated %s (%s)", id, result.Rating, result.Tier)
	h.app.alerts.signalWarning(&cp, result)
}

// reuseCVEAnalysis returns a copy of a deep analysis already made for a CVE the item names
func (h *SignalHub) reuseCVEAnalysis(s *Signal) (*ImpactAssessment, error) {
	a := h.app.impact
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range s.CVEs {
		if prev := a.store.Assessments[id]; prev != nil && prev.Tier != "triage" {
			cp := *prev
			cp.Tier = "linked"
			cp.Summary = "From the analysis of " + id + ": " + prev.Summary
			return &cp, nil
		}
	}
	return nil, nil
}

// analyse asks the reasoning model about the item itself
func (h *SignalHub) analyse(s *Signal) (*ImpactAssessment, error) {
	a := h.app.impact
	label := s.Feed
	if f := feedByName(s.Feed); f != nil {
		label = f.Label + " (" + signalKindText(f.Kind) + ")"
	}
	in := map[string]any{
		"today": time.Now().UTC().Format("2006-01-02"), "source": label, "published": s.Published.Format("2006-01-02"),
		"title": s.Title, "url": s.URL, "text": truncate(s.Summary, 4000), "cvesMentioned": s.CVEs,
	}
	if ds := h.app.dataset(); ds != nil {
		for _, id := range s.CVEs {
			if i, ok := ds.byID[id]; ok {
				var rec any
				json.Unmarshal([]byte(impactInput(&ds.CVEs[i], time.Now())), &rec)
				in["cveRecord"] = rec
				break
			}
		}
	}
	data, _ := json.MarshalIndent(in, "", "  ")
	body, _ := json.Marshal(chatRequest{
		Model: a.cfg.model, Temperature: 0.2, MaxTokens: 16000,
		Messages: []chatMessage{
			{Role: "system", Content: impactSystemPrompt},
			{Role: "user", Content: "Assess this security report for its likelihood of heavy global impact. It may describe a vulnerability " +
				"before a CVE is published, so judge from what it says. If it isn't about a specific vulnerability or its exploitation, rate it low and say so.\n\n<report>\n" +
				string(data) + "\n</report>"},
		},
		ResponseFormat: map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": "impact_assessment", "strict": true, "schema": impactSchema},
		},
	})
	res, err := a.chat(body)
	if err != nil {
		return nil, err
	}
	out, err := decodeImpactOutput(res.content)
	if err != nil {
		return nil, err
	}
	model := res.model
	if model == "" {
		model = a.cfg.model
	}
	return &ImpactAssessment{
		Rating: out.Rating, Confidence: out.Confidence, Summary: out.Summary, Drivers: out.Drivers,
		Exposure: out.Exposure, WatchFor: out.WatchFor, Coverage: out.Coverage,
		Model: model, Tier: "analysis", AssessedAt: time.Now().UTC(),
	}, nil
}

// ---- Queue helpers ----

// next returns the best item matching want, or "" when there's none
func (h *SignalHub) next(want func(*Signal, time.Time) bool, prio func(*Signal) float64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	now, best, bestP := time.Now(), "", 0.0
	for id, s := range h.store.Items {
		if !want(s, now) {
			continue
		}
		if p := prio(s); best == "" || p > bestP {
			best, bestP = id, p
		}
	}
	return best
}

func (h *SignalHub) wakeAnalysis() {
	if h.analysisWake == nil {
		return
	}
	select {
	case h.analysisWake <- struct{}{}:
	default:
	}
}

func waitOrTimeout(ch chan struct{}, d time.Duration) {
	select {
	case <-ch:
	case <-time.After(d):
	}
}

// SignalQueueStatus is the signal AI's queue depth
type SignalQueueStatus struct {
	AwaitingTriage   int    `json:"awaitingTriage"`
	AwaitingAnalysis int    `json:"awaitingAnalysis"`
	InFlight         string `json:"inFlight,omitempty"`
}

func (h *SignalHub) queueStatus() SignalQueueStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := SignalQueueStatus{InFlight: h.inFlight}
	if h.triageWake == nil {
		return st
	}
	now := time.Now()
	for _, s := range h.store.Items {
		switch {
		case h.needsTriage(s, now):
			st.AwaitingTriage++
		case s.AI != nil && s.AI.Pending:
			st.AwaitingAnalysis++
		}
	}
	return st
}

// ---- Alerts ----

// signalWarning posts to the alert webhook when a fresh signal's deep analysis
// rates it high or severe
func (al *Alerter) signalWarning(s *Signal, cur *ImpactAssessment) {
	if al == nil || al.webhook == "" || cur.Tier != "analysis" || impactRank(cur.Rating) < impactRank("high") ||
		time.Since(s.Published) > impactAlertMaxAge {
		return
	}
	if st, _ := signalReadiness(s, nil); st != "ready" {
		return
	}
	label := s.Feed
	if f := feedByName(s.Feed); f != nil {
		label = f.Label
	}
	title := s.Title
	if s.URL != "" {
		title = fmt.Sprintf("<%s|%s>", s.URL, s.Title)
	}
	al.post(fmt.Sprintf("*AI early warning (signal): %s global-impact risk*\n⚠️ %s (%s)\n%s", strings.ToUpper(cur.Rating), title, label, cur.Summary))
}
