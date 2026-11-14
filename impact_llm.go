package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Inference client for AI impact assessments: the private Bifrost gateway's
// OpenAI-compatible chat completions API.

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	MaxTokens      int           `json:"max_tokens"`
	ResponseFormat any           `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type chatResult struct{ content, model string }

// errRetryable marks gateway failures worth retrying right away (network, 429, 5xx)
type errRetryable struct{ error }

// impactRetryDelay is the pause before retry n (1, 2, …); a variable so tests can shorten it
var impactRetryDelay = func(n int) time.Duration { return time.Duration(n*n) * 20 * time.Second }

// assess asks the model for one assessment, retrying transient gateway errors
func (a *Assessor) assess(cve *CVE) (*ImpactAssessment, error) {
	body, _ := json.Marshal(chatRequest{
		Model:       a.cfg.model,
		Temperature: 0.2,
		MaxTokens:   16000, // reasoning models spend most of this thinking before answering
		Messages: []chatMessage{
			{Role: "system", Content: impactSystemPrompt},
			{Role: "user", Content: "Assess this CVE for its likelihood of heavy global impact.\n\n<cve_data>\n" +
				impactInput(cve, time.Now()) + "\n</cve_data>"},
		},
		ResponseFormat: map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": "impact_assessment", "strict": true, "schema": impactSchema},
		},
	})
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(impactRetryDelay(attempt))
		}
		res, err := a.chat(body)
		if retry := (errRetryable{}); errors.As(err, &retry) {
			lastErr = err
			continue
		}
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
			Rating: out.Rating, Confidence: out.Confidence, Summary: out.Summary,
			Drivers: out.Drivers, Exposure: out.Exposure, WatchFor: out.WatchFor, Coverage: out.Coverage,
			Model: model, Tier: "analysis", AssessedAt: time.Now().UTC(), Signals: impactSignals(cve),
		}, nil
	}
	return nil, lastErr
}

func (a *Assessor) chat(body []byte) (*chatResult, error) {
	raw, err := a.post("/v1/chat/completions", body, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	var res chatResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("unreadable gateway response: %w", err)
	}
	if len(res.Choices) == 0 {
		return nil, errors.New("gateway returned no choices")
	}
	choice := res.Choices[0]
	switch {
	case choice.Message.Refusal != "":
		return nil, fmt.Errorf("model declined: %s", truncate(choice.Message.Refusal, 200))
	case choice.FinishReason == "length":
		return nil, errors.New("response hit max_tokens")
	}
	return &chatResult{content: choice.Message.Content, model: res.Model}, nil
}

var (
	thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>`)
	codeFence  = regexp.MustCompile("(?s)^```(?:json)?\\s*(.*?)\\s*```$")
)

// cleanModelJSON strips reasoning tags, code fences and stray prose around the
// JSON object, for backends that don't enforce the response schema
func cleanModelJSON(text string) string {
	text = strings.TrimSpace(thinkBlock.ReplaceAllString(text, ""))
	if m := codeFence.FindStringSubmatch(text); m != nil {
		text = m[1]
	}
	if i, j := strings.Index(text, "{"), strings.LastIndex(text, "}"); i >= 0 && j > i {
		text = text[i : j+1]
	}
	return text
}
