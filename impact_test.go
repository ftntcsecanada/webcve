package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestImpactCandidate(t *testing.T) {
	cfg := impactConfig{minScore: 9.0, triageMin: 7.0, window: 30 * 24 * time.Hour}
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	recent, old := now.AddDate(0, 0, -3), now.AddDate(-2, 0, 0)
	cases := []struct {
		name string
		cve  CVE
		want bool
	}{
		{"new critical", CVE{State: "PUBLISHED", BaseScore: 9.8, DatePublished: recent}, true},
		{"new high, no triage", CVE{State: "PUBLISHED", BaseScore: 8.8, DatePublished: recent}, false},
		{"new unscored, no triage", CVE{State: "PUBLISHED", DatePublished: recent}, false},
		{"old critical", CVE{State: "PUBLISHED", BaseScore: 9.8, DatePublished: old}, false},
		{"old critical newly in KEV", CVE{State: "PUBLISHED", BaseScore: 9.8, DatePublished: old, InKEV: true, KEVDateAdded: "2026-11-10"}, true},
		{"old critical, old KEV", CVE{State: "PUBLISHED", BaseScore: 9.8, DatePublished: old, InKEV: true, KEVDateAdded: "2024-01-01"}, false},
		{"rejected", CVE{State: "REJECTED", BaseScore: 9.8, DatePublished: recent}, false},
		{"KEV placeholder", CVE{State: "PUBLISHED", BaseScore: 9.8, DatePublished: recent, KEVOnly: true}, false},
	}
	for _, c := range cases {
		if got := cfg.impactCandidate(&c.cve, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	cfg.triageModel = "kev-8b"
	for _, c := range []struct {
		name string
		cve  CVE
		want bool
	}{
		{"high goes to triage", CVE{State: "PUBLISHED", BaseScore: 8.1, DatePublished: recent}, true},
		{"unscored goes to triage", CVE{State: "PUBLISHED", DatePublished: recent}, true},
		{"medium stays out", CVE{State: "PUBLISHED", BaseScore: 6.5, DatePublished: recent}, false},
	} {
		if got := cfg.impactCandidate(&c.cve, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNeedsAssessment(t *testing.T) {
	now := time.Now()
	cve := &CVE{BaseScore: 9.8, EPSS: 0.02}
	sig := impactSignals(cve)
	if !needsAssessment(cve, nil, nil, now) {
		t.Error("unassessed CVE should need assessment")
	}
	fresh := &ImpactAssessment{Signals: sig, AssessedAt: now.Add(-48 * time.Hour)}
	if needsAssessment(cve, fresh, nil, now) {
		t.Error("unchanged signals should not trigger reassessment")
	}
	// Daily EPSS drift within a bucket is not a signal change
	cve.EPSS = 0.05
	if needsAssessment(cve, fresh, nil, now) {
		t.Error("EPSS drift within a bucket should not trigger reassessment")
	}
	cve.InKEV = true
	if !needsAssessment(cve, fresh, nil, now) {
		t.Error("KEV listing should trigger reassessment")
	}
	recent := &ImpactAssessment{Signals: sig, AssessedAt: now.Add(-time.Hour)}
	if needsAssessment(cve, recent, nil, now) {
		t.Error("an assessment under a day old should not be redone")
	}
	failed := &impactFailure{At: now.Add(-time.Hour), Signals: impactSignals(cve)}
	if needsAssessment(cve, nil, failed, now) {
		t.Error("a recent failure with the same signals should back off")
	}
	failed.At = now.Add(-impactRetryAfter - time.Minute)
	if !needsAssessment(cve, nil, failed, now) {
		t.Error("a failure should be retried after the backoff")
	}
}

func TestDecodeImpactOutput(t *testing.T) {
	out, err := decodeImpactOutput(`{"rating":"high","confidence":"medium","summary":"Pre-auth RCE in a common VPN.","drivers":["internet-facing"],"exposure":"Tens of thousands exposed.","watch_for":"Public PoC."}`)
	if err != nil || out.Rating != "high" || out.WatchFor != "Public PoC." {
		t.Fatalf("got %+v, %v", out, err)
	}
	if _, err := decodeImpactOutput(`{"rating":"catastrophic","confidence":"high","summary":"x"}`); err == nil {
		t.Error("unknown rating should be rejected")
	}
	if _, err := decodeImpactOutput(`not json`); err == nil {
		t.Error("malformed output should be rejected")
	}
	out, _ = decodeImpactOutput(`{"rating":"low","confidence":"certain","summary":"x"}`)
	if out.Confidence != "low" {
		t.Errorf("unknown confidence should fall back to low, got %q", out.Confidence)
	}
}

func TestImpactInputIsBoundedJSON(t *testing.T) {
	cve := &CVE{ID: "CVE-2026-0001", Description: strings.Repeat("x", 10000), InKEV: true, KEVDateAdded: "2026-11-01"}
	for range 200 {
		cve.References = append(cve.References, Reference{URL: "https://example.com"})
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(impactInput(cve, time.Now())), &in); err != nil {
		t.Fatal(err)
	}
	if n := len(in["references"].([]any)); n != 25 {
		t.Errorf("references not capped: %d", n)
	}
	if len(in["description"].(string)) > 4010 {
		t.Error("description not truncated")
	}
	if in["cisaKEV"] == nil {
		t.Error("KEV context missing")
	}
}

func TestFilterAndSortByAIImpact(t *testing.T) {
	ds := testDataset()
	ds.CVEs[ds.byID["CVE-2024-0001"]].AIImpact = &ImpactAssessment{Rating: "severe", Confidence: "high"}
	ds.CVEs[ds.byID["CVE-2024-0002"]].AIImpact = &ImpactAssessment{Rating: "moderate", Confidence: "medium"}

	if got := ids(ds, FilterRequest{AIImpact: []string{"severe", "high"}}); !slices.Equal(got, []string{"CVE-2024-0001"}) {
		t.Errorf("rating filter: %v", got)
	}
	if got := ids(ds, FilterRequest{Search: "impact:moderate"}); !slices.Equal(got, []string{"CVE-2024-0002"}) {
		t.Errorf("impact: syntax: %v", got)
	}
	// Facets ignore the rating filter itself so other ratings stay selectable
	_, resp := ds.filterCVEs(compileFilter(ds, FilterRequest{AIImpact: []string{"severe"}}), true)
	if resp.Facets.AIImpact["severe"] != 1 || resp.Facets.AIImpact["moderate"] != 1 {
		t.Errorf("facets: %v", resp.Facets.AIImpact)
	}
	matches, _ := ds.filterCVEs(compileFilter(ds, FilterRequest{SortBy: "aiImpact", SortDesc: true}), false)
	if ds.CVEs[matches[0]].ID != "CVE-2024-0001" || ds.CVEs[matches[1]].ID != "CVE-2024-0002" {
		t.Errorf("sort order starts %s, %s", ds.CVEs[matches[0]].ID, ds.CVEs[matches[1]].ID)
	}
	if s := ds.summarize(matches[0], compileFilter(ds, FilterRequest{})); s.AIImpact != "severe" || s.AIConfidence != "high" {
		t.Errorf("summary: %+v", s)
	}
}

func TestEnrichmentAppliesAIImpact(t *testing.T) {
	a := &ImpactAssessment{Rating: "high"}
	cve := CVE{ID: "CVE-2024-0001"}
	applyEnrichment(&cve, &Enrichment{AIImpact: map[string]*ImpactAssessment{"CVE-2024-0001": a}})
	if cve.AIImpact != a {
		t.Fatal("assessment not applied")
	}
	applyEnrichment(&cve, &Enrichment{})
	if cve.AIImpact != nil {
		t.Fatal("stale assessment kept after rebuild")
	}
}

func TestEarlyWarningAlerts(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		posts = append(posts, body["text"])
		mu.Unlock()
	}))
	defer srv.Close()
	al := &Alerter{webhook: srv.URL, client: srv.Client()}
	fresh := &CVE{ID: "CVE-2026-1", DatePublished: time.Now().Add(-time.Hour), BaseScore: 9.8}
	old := &CVE{ID: "CVE-2026-2", DatePublished: time.Now().AddDate(0, 0, -20), BaseScore: 9.8}

	al.earlyWarning(fresh, nil, &ImpactAssessment{Rating: "severe", Summary: "s"})                               // alert
	al.earlyWarning(fresh, nil, &ImpactAssessment{Rating: "moderate", Summary: "s"})                             // below threshold
	al.earlyWarning(old, nil, &ImpactAssessment{Rating: "high", Summary: "s"})                                   // backfill: no alert
	al.earlyWarning(old, &ImpactAssessment{Rating: "moderate"}, &ImpactAssessment{Rating: "high", Summary: "s"}) // escalation
	al.earlyWarning(old, &ImpactAssessment{Rating: "severe"}, &ImpactAssessment{Rating: "severe", Summary: "s"}) // no change

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(posts)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 2 {
		t.Fatalf("want 2 alerts, got %d: %q", len(posts), posts)
	}
	joined := strings.Join(posts, "\n")
	if !strings.Contains(joined, "CVE-2026-1") || !strings.Contains(joined, "raised to HIGH (was moderate)") {
		t.Errorf("unexpected alerts: %q", posts)
	}
}

// TestLiveCalibration calls the real API on day-zero scenarios: fictional CVE
// IDs published today, with no KEV, EPSS or exploit signals, so the model can't
// lean on memory or exploitation evidence. Run with WEBCVE_LIVE_TEST=1 and BIFROST_URL/BIFROST_API_KEY set.
func TestLiveCalibration(t *testing.T) {
	if os.Getenv("WEBCVE_LIVE_TEST") == "" {
		t.Skip("set WEBCVE_LIVE_TEST=1 to call the Bifrost gateway")
	}
	t.Setenv("WEBCVE_AI_ASSESSMENTS", "1")
	a := newAssessor(&App{board: newStatusBoard()})
	if !a.cfg.enabled {
		t.Fatal("set BIFROST_URL and BIFROST_API_KEY")
	}
	now := time.Now()
	network := func(c CVE) CVE {
		c.State, c.DatePublished, c.CvssVersion, c.BaseScore, c.BaseSeverity = "PUBLISHED", now, "3.1", 9.8, "CRITICAL"
		c.AttackVector, c.AttackComplexity, c.PrivilegesRequired, c.UserInteraction = "NETWORK", "LOW", "NONE", "NONE"
		c.VectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		return c
	}
	cases := []struct {
		cve     CVE
		atLeast string // minimum acceptable rating
		atMost  string // maximum acceptable rating
	}{
		{network(CVE{ID: "CVE-2026-90001", Title: "OpenSSL: heap overflow in TLS 1.3 server handshake allows remote code execution",
			Description:      "A heap buffer overflow in the TLS 1.3 key share processing of OpenSSL 3.0 through 3.5 allows an unauthenticated remote attacker to execute arbitrary code on any server that accepts TLS 1.3 connections, in the default configuration.",
			AffectedProducts: []AffectedProduct{{Vendor: "OpenSSL", Product: "OpenSSL", Versions: "3.0.0 - 3.5.4"}}, CWE: "CWE-122",
			Packages: []PackageFix{{Ecosystem: "Debian", Name: "openssl"}, {Ecosystem: "Alpine", Name: "openssl"}, {Ecosystem: "Red Hat", Name: "openssl"}, {Ecosystem: "crates.io", Name: "openssl-src"}, {Ecosystem: "PyPI", Name: "cryptography"}}}),
			"high", "severe"},
		{network(CVE{ID: "CVE-2026-90002", Title: "Microsoft Exchange Server remote code execution vulnerability",
			Description:      "Deserialization of untrusted data in Microsoft Exchange Server 2019 and Exchange Server Subscription Edition allows an unauthenticated attacker to execute code as SYSTEM over the network via a crafted request to the Outlook Web Access endpoint.",
			AffectedProducts: []AffectedProduct{{Vendor: "Microsoft", Product: "Exchange Server 2019"}, {Vendor: "Microsoft", Product: "Exchange Server Subscription Edition"}}, CWE: "CWE-502"}),
			"high", "severe"},
		{network(CVE{ID: "CVE-2026-90003", Title: "jackson-databind: remote code execution through default polymorphic typing",
			Description:      "FasterXML jackson-databind 2.x before 2.21.1 deserializes attacker-chosen classes when reading JSON with the default ObjectMapper configuration, allowing remote code execution in any application that parses untrusted JSON.",
			AffectedProducts: []AffectedProduct{{Vendor: "FasterXML", Product: "jackson-databind"}}, CWE: "CWE-502",
			Packages: []PackageFix{{Ecosystem: "Maven", Name: "com.fasterxml.jackson.core:jackson-databind"}, {Ecosystem: "Debian", Name: "jackson-databind"}, {Ecosystem: "Red Hat", Name: "jackson-databind"}}}),
			"high", "severe"},
		{network(CVE{ID: "CVE-2026-90004", Title: "Simple Event Booking Lite plugin for WordPress: unauthenticated SQL injection",
			Description:      "The Simple Event Booking Lite plugin for WordPress (about 2,000 active installations) is vulnerable to SQL injection via the 'event_id' parameter in versions up to 1.4.2, allowing unauthenticated attackers to extract database contents.",
			AffectedProducts: []AffectedProduct{{Vendor: "seblite", Product: "Simple Event Booking Lite"}}, CWE: "CWE-89"}),
			"low", "moderate"},
		{network(CVE{ID: "CVE-2026-90005", Title: "Tenda AC9 V15.03.05.19 stack overflow in /goform/SetSysTimeCfg",
			Description:      "Tenda AC9 firmware V15.03.05.19 contains a stack-based buffer overflow in the time parameter of /goform/SetSysTimeCfg, reachable from the web management interface, leading to remote code execution.",
			AffectedProducts: []AffectedProduct{{Vendor: "Tenda", Product: "AC9"}}, CWE: "CWE-121"}),
			"low", "moderate"},
	}
	for _, c := range cases {
		t.Run(c.cve.ID, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			res, err := a.assess(&c.cve)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s -> %s (%s confidence, %s) in %s\n%s\nDrivers: %s",
				c.cve.Title, strings.ToUpper(res.Rating), res.Confidence, res.Model, time.Since(start).Round(time.Second),
				res.Summary, strings.Join(res.Drivers, " | "))
			if r := impactRank(res.Rating); r < impactRank(c.atLeast) || r > impactRank(c.atMost) {
				t.Errorf("rated %s, want %s..%s", res.Rating, c.atLeast, c.atMost)
			}
		})
	}
}

// fakeGateway serves OpenAI-compatible chat responses from a script of handlers
func fakeGateway(t *testing.T, steps ...func(w http.ResponseWriter, body map[string]any)) (*Assessor, *int) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/decisions") || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		step := steps[min(calls, len(steps)-1)]
		calls++
		step(w, body)
	}))
	t.Cleanup(srv.Close)
	old := impactRetryDelay
	impactRetryDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { impactRetryDelay = old })
	a := &Assessor{cfg: impactConfig{baseURL: srv.URL, apiKey: "test-key", model: impactDefaultModel,
		triageModel: impactDefaultTriageModel, escalateAt: 0.5}, http: srv.Client()}
	return a, &calls
}

func chatReply(content, finish string) func(http.ResponseWriter, map[string]any) {
	return func(w http.ResponseWriter, _ map[string]any) {
		json.NewEncoder(w).Encode(map[string]any{
			"model":   "flgpu-openai/qwen3.8-27b-openai",
			"choices": []any{map[string]any{"finish_reason": finish, "message": map[string]any{"role": "assistant", "content": content}}},
		})
	}
}

const goodAnswer = `{"rating":"severe","confidence":"high","summary":"Ubiquitous library.","drivers":["everywhere"],"exposure":"Most servers.","watch_for":"PoC."}`

func TestBifrostAssess(t *testing.T) {
	var sent map[string]any
	a, calls := fakeGateway(t, func(w http.ResponseWriter, body map[string]any) {
		sent = body
		chatReply(goodAnswer, "stop")(w, body)
	})
	res, err := a.assess(&CVE{ID: "CVE-2026-1", BaseScore: 9.8})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rating != "severe" || res.Model != "flgpu-openai/qwen3.8-27b-openai" || res.Signals == "" || *calls != 1 {
		t.Errorf("got %+v after %d calls", res, *calls)
	}
	if sent["model"] != impactDefaultModel {
		t.Errorf("model sent: %v", sent["model"])
	}
	rf, _ := sent["response_format"].(map[string]any)
	if rf["type"] != "json_schema" {
		t.Errorf("response_format not sent: %v", sent["response_format"])
	}
	msgs, _ := sent["messages"].([]any)
	if len(msgs) != 2 || !strings.Contains(msgs[1].(map[string]any)["content"].(string), "CVE-2026-1") {
		t.Errorf("messages: %v", msgs)
	}
}

func TestBifrostRetriesTransientErrors(t *testing.T) {
	a, calls := fakeGateway(t,
		func(w http.ResponseWriter, _ map[string]any) {
			http.Error(w, `{"error":{"message":"overloaded"}}`, 503)
		},
		chatReply(goodAnswer, "stop"))
	if _, err := a.assess(&CVE{ID: "CVE-2026-1"}); err != nil || *calls != 2 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
}

func TestBifrostDoesNotRetryClientErrors(t *testing.T) {
	a, calls := fakeGateway(t, func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":{"message":"unknown model"}}`))
	})
	_, err := a.assess(&CVE{ID: "CVE-2026-1"})
	if err == nil || !strings.Contains(err.Error(), "unknown model") || *calls != 1 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
}

func TestBifrostGivesUpAfterRetries(t *testing.T) {
	a, calls := fakeGateway(t, func(w http.ResponseWriter, _ map[string]any) { w.WriteHeader(502) })
	if _, err := a.assess(&CVE{ID: "CVE-2026-1"}); err == nil || *calls != 3 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
}

func TestBifrostTruncatedResponse(t *testing.T) {
	a, _ := fakeGateway(t, chatReply(`{"rating":"sev`, "length"))
	if _, err := a.assess(&CVE{ID: "CVE-2026-1"}); err == nil || !strings.Contains(err.Error(), "max_tokens") {
		t.Fatalf("err=%v", err)
	}
}

func TestCleanModelJSON(t *testing.T) {
	for _, in := range []string{
		goodAnswer,
		"<think>reasoning about {braces}</think>\n" + goodAnswer,
		"```json\n" + goodAnswer + "\n```",
		"Here is the assessment:\n" + goodAnswer + "\nHope this helps.",
	} {
		if out, err := decodeImpactOutput(in); err != nil || out.Rating != "severe" {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestImpactConfigFromEnv(t *testing.T) {
	t.Setenv("WEBCVE_NO_UPDATES", "")
	t.Setenv("WEBCVE_AI_ASSESSMENTS", "")
	t.Setenv("BIFROST_API_KEY", "k")
	t.Setenv("BIFROST_URL", "bifrost.example.internal/")
	c := impactConfigFromEnv()
	if !c.enabled || c.baseURL != "https://bifrost.example.internal" || c.model != impactDefaultModel {
		t.Errorf("got %+v", c)
	}
	t.Setenv("WEBCVE_AI_ASSESSMENTS", "0")
	if impactConfigFromEnv().enabled {
		t.Error("WEBCVE_AI_ASSESSMENTS=0 should disable")
	}
	t.Setenv("WEBCVE_AI_ASSESSMENTS", "")
	t.Setenv("BIFROST_API_KEY", "")
	if impactConfigFromEnv().enabled {
		t.Error("missing key should disable")
	}
	t.Setenv("BIFROST_API_KEY", "k")
	t.Setenv("WEBCVE_NO_UPDATES", "1")
	if impactConfigFromEnv().enabled {
		t.Error("local-data mode should not call out unless asked")
	}
}

func decisionReply(deploy, coverage map[string]float64) func(http.ResponseWriter, map[string]any) {
	top := func(p map[string]float64) string {
		best := ""
		for k, v := range p {
			if best == "" || v > p[best] {
				best = k
			}
		}
		return best
	}
	return func(w http.ResponseWriter, _ map[string]any) {
		json.NewEncoder(w).Encode(map[string]any{"model": "kev-8b", "answers": map[string]any{
			"deployment": map[string]any{"kind": "choice", "value": top(deploy), "confidence": 0.8, "probabilities": deploy},
			"coverage":   map[string]any{"kind": "choice", "value": top(coverage), "confidence": 0.8, "probabilities": coverage},
			"hosting":    map[string]any{"kind": "choice", "value": "customer_installed", "confidence": 0.9, "probabilities": map[string]float64{"customer_installed": 0.9, "vendor_cloud": 0.1}},
		}})
	}
}

func TestTriage(t *testing.T) {
	var sent map[string]any
	a, _ := fakeGateway(t, func(w http.ResponseWriter, body map[string]any) {
		sent = body
		decisionReply(map[string]float64{"obscure": 0.6, "niche": 0.3, "widespread": 0.08, "ubiquitous": 0.02},
			map[string]float64{"web": 0.9, "network": 0.05, "none": 0.05})(w, body)
	})
	cve := &CVE{ID: "CVE-2026-1", BaseScore: 9.8, AttackVector: "NETWORK", CWE: "CWE-89", Description: "plugin sqli",
		References: []Reference{{URL: "https://x"}}}
	res, err := a.triage(cve, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rating != "low" || res.Tier != "triage" || res.Model != "kev-8b" || res.Confidence != "high" || res.Signals == "" ||
		res.CoverageClass != "web" || !strings.Contains(res.Coverage, "FortiWeb") {
		t.Errorf("got %+v", res)
	}
	state := sent["state"].(string)
	if sent["model"] != "kev-8b" || strings.Contains(state, "https://x") ||
		!strings.Contains(state, "typical of web applications") || !strings.Contains(state, "without user action") {
		t.Errorf("request: %v", sent)
	}
	if a.cfg.standout(cve, res) {
		t.Error("an obscure product should not escalate")
	}
}

func TestTriageStateHistory(t *testing.T) {
	ds := buildDataset([]CVE{
		{ID: "CVE-2026-1", State: "PUBLISHED", AffectedProducts: []AffectedProduct{{Vendor: "Acme", Product: "Gateway"}}},
		{ID: "CVE-2026-2", State: "PUBLISHED", AffectedProducts: []AffectedProduct{{Vendor: "Acme", Product: "Gateway"}}},
		{ID: "CVE-2026-3", State: "PUBLISHED", AffectedProducts: []AffectedProduct{{Vendor: "Acme", Product: "Other"}}},
	}, &Enrichment{})
	ds.CVEs[ds.byID["CVE-2026-1"]].InKEV = true
	state := triageState(&ds.CVEs[ds.byID["CVE-2026-2"]], ds)
	if !strings.Contains(state, "has 2 CVEs on record, 1 of them in CISA KEV") || !strings.Contains(state, "vendor has 3 CVEs on record, 1 in CISA KEV") {
		t.Errorf("state:\n%s", state)
	}
}

func TestStandout(t *testing.T) {
	cfg := impactConfig{escalateAt: 0.7, minScore: 9, escalateLow: 0.9}
	niche := map[string]float64{"obscure": 0.2, "niche": 0.5, "widespread": 0.28, "ubiquitous": 0.02}
	broad := map[string]float64{"niche": 0.25, "widespread": 0.6, "ubiquitous": 0.15}
	seen := map[string]float64{"network": 0.8, "none": 0.2}
	unseen := map[string]float64{"network": 0.2, "none": 0.8}
	cases := []struct {
		name   string
		cve    CVE
		deploy map[string]float64
		cov    map[string]float64
		want   bool
	}{
		{"niche", CVE{BaseScore: 9.8}, niche, seen, false},
		{"widely deployed and coverable", CVE{BaseScore: 9.8}, broad, seen, true},
		{"widely deployed but only CVSS 8", CVE{BaseScore: 8.1}, broad, seen, false},
		{"ubiquitous and unscored", CVE{}, map[string]float64{"ubiquitous": 0.7, "widespread": 0.25}, seen, true},
		{"widely deployed, nothing can see it", CVE{BaseScore: 9.8}, broad, unseen, false},
		{"niche but in KEV", CVE{InKEV: true}, niche, unseen, true},
		{"niche but actively exploited", CVE{SSVCExploitation: "active"}, niche, seen, true},
		{"Fortinet product", CVE{AffectedProducts: []AffectedProduct{{Vendor: "Fortinet", Product: "FortiOS"}}}, niche, unseen, true},
	}
	for _, c := range cases {
		res := &ImpactAssessment{Probabilities: c.deploy, CoverageProbabilities: c.cov}
		if got := cfg.standout(&c.cve, res); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	cloud := &ImpactAssessment{Probabilities: broad, CoverageProbabilities: seen, VendorCloud: 0.95}
	if cfg.standout(&CVE{BaseScore: 9.8}, cloud) {
		t.Error("a vendor-operated cloud service should not escalate")
	}
}

func TestDeliveryHints(t *testing.T) {
	has := func(c CVE, want string) bool { return strings.Contains(strings.Join(deliveryHints(&c), " "), want) }
	if !has(CVE{AttackVector: "NETWORK", Description: "In the NAS message handler, improper validation causes memory corruption"}, "radio interface") {
		t.Error("cellular NAS bug should be flagged as radio")
	}
	if has(CVE{AttackVector: "NETWORK", Description: "Stack overflow in the Wi-Fi settings page of the router web interface"}, "radio interface") {
		t.Error("a router's Wi-Fi settings page is not radio delivery")
	}
	if !has(CVE{AttackVector: "ADJACENT", Description: "Crafted 802.11 frames cause a heap overflow"}, "radio interface") {
		t.Error("adjacent Wi-Fi frames should be flagged as radio")
	}
	if !has(CVE{AttackVector: "LOCAL", UserInteraction: "REQUIRED", CWE: "CWE-787"}, "content the victim opens") {
		t.Error("local memory corruption with user interaction should be file delivery")
	}
}

func TestTriageRouting(t *testing.T) {
	now := time.Now()
	cve := &CVE{BaseScore: 9.8}
	sig := impactSignals(cve)
	cfg := impactConfig{triageModel: "kev-8b"}
	if cfg.needsAnalysis(nil) {
		t.Error("a new CVE should be triaged first")
	}
	pending := &ImpactAssessment{Tier: "triage", Pending: true, Signals: sig, AssessedAt: now}
	if !needsAssessment(cve, pending, nil, now) || !cfg.needsAnalysis(pending) {
		t.Error("a pending standout should go straight to deep analysis")
	}
	triaged := &ImpactAssessment{Tier: "triage", Signals: sig, AssessedAt: now.Add(-time.Minute)}
	if needsAssessment(cve, triaged, nil, now) {
		t.Error("unchanged triage should not be redone")
	}
	cve.InKEV = true
	if !needsAssessment(cve, triaged, nil, now) || cfg.needsAnalysis(triaged) {
		t.Error("a signal change should re-triage right away")
	}
	analysed := &ImpactAssessment{Tier: "analysis", Signals: sig, AssessedAt: now.Add(-48 * time.Hour)}
	if !cfg.needsAnalysis(analysed) {
		t.Error("a CVE with a deep analysis should be reanalysed, not re-triaged")
	}
	if !(impactConfig{}).needsAnalysis(nil) {
		t.Error("with triage off everything goes to deep analysis")
	}
}

func TestSnapshotHidesPendingTriage(t *testing.T) {
	a := &Assessor{store: impactStore{Assessments: map[string]*ImpactAssessment{
		"CVE-1": {Rating: "high", Tier: "triage", Pending: true},
		"CVE-2": {Rating: "low", Tier: "triage"},
	}}}
	snap := a.snapshot()
	if _, ok := snap["CVE-1"]; ok || snap["CVE-2"] == nil {
		t.Errorf("snapshot: %v", snap)
	}
}
