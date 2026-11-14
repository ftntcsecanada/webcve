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
	"time"
)

// Fast triage for AI impact assessments: the kev-8b decision model on the
// Bifrost gateway (POST /v1/decisions). It answers a typed choice question with
// a probability distribution in about 150 ms, so every candidate gets one.
// Only standouts go on to the slower reasoning model in impact_llm.go.

const impactDefaultTriageModel = "kev-8b"

var triageQuestions = map[string]any{
	"global_impact": map[string]any{
		"type": "choice",
		"instructions": "Judge how likely this critical CVE is to cause heavy global impact (mass exploitation or emergency " +
			"remediation across many organizations and countries) within about 90 days. Weigh how widely the affected code " +
			"is deployed above all; missing exploitation evidence on a new CVE is normal.",
		"criteria": map[string]any{
			"severe":   "ubiquitous open source component or dominant platform, remotely exploitable in default deployments; likely global incident",
			"high":     "widely deployed package or platform; a precondition or narrower exposure keeps it below severe",
			"moderate": "niche or sector-specific product, non-default configuration, authentication required or mostly internal",
			"low":      "obscure product, plugin or small project, hard preconditions or local only",
		},
	},
}

type decisionResponse struct {
	Answers map[string]struct {
		Value         string             `json:"value"`
		Confidence    float64            `json:"confidence"`
		Probabilities map[string]float64 `json:"probabilities"`
	} `json:"answers"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// triageState is the CVE data given to the decision model: the deep-analysis
// input without references and with a shorter description
func triageState(cve *CVE, now time.Time) string {
	var in map[string]any
	if err := json.Unmarshal([]byte(impactInput(cve, now)), &in); err != nil {
		return cve.ID + ": " + truncate(cve.Description, 1500)
	}
	delete(in, "references")
	delete(in, "today")
	in["description"] = truncate(cve.Description, 1500)
	b, _ := json.Marshal(in)
	return string(b)
}

// triage asks the decision model for a one-shot rating
func (a *Assessor) triage(cve *CVE) (*ImpactAssessment, error) {
	body, _ := json.Marshal(map[string]any{
		"model": a.cfg.triageModel, "state": triageState(cve, time.Now()), "questions": triageQuestions,
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
		ans, ok := res.Answers["global_impact"]
		if !ok || impactRank(ans.Value) == 0 {
			return nil, fmt.Errorf("decision model gave no usable rating: %s", truncate(string(raw), 200))
		}
		return &ImpactAssessment{
			Rating: ans.Value, Confidence: triageConfidence(ans.Confidence), Probabilities: ans.Probabilities,
			Summary:  triageSummary(ans.Value, ans.Probabilities),
			WatchFor: "A KEV listing, active exploitation or a jump in EPSS sends it for deep analysis.",
			Model:    a.cfg.triageModel, Tier: "triage", AssessedAt: time.Now().UTC(), Signals: impactSignals(cve),
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

func triageSummary(rating string, p map[string]float64) string {
	labels := make([]string, 0, len(p))
	for k := range p {
		labels = append(labels, k)
	}
	sort.Slice(labels, func(i, j int) bool { return p[labels[i]] > p[labels[j]] })
	parts := make([]string, 0, len(labels))
	for _, k := range labels {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", k, p[k]*100))
	}
	return fmt.Sprintf("Fast triage rated this %s (%s). It did not stand out enough for deep analysis.", rating, strings.Join(parts, ", "))
}

// standout reports whether a triaged CVE should get the deep analysis
func (c impactConfig) standout(cve *CVE, t *ImpactAssessment) bool {
	if cve.InKEV || strings.EqualFold(cve.SSVCExploitation, "active") || cve.EUVDExploitedSince != "" {
		return true
	}
	if impactRank(t.Rating) >= impactRank("high") {
		return true
	}
	return t.Probabilities["severe"]+t.Probabilities["high"] >= c.escalateAt
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
