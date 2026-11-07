package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSigLabProxyLifecycle(t *testing.T) {
	const token = "test-siglab-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities":
			io.WriteString(w, `{"fortios_versions":["8.0.2"],"running_jobs":1}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/jobs":
			if r.URL.Query().Get("cve_id") != "CVE-2025-32432" {
				t.Errorf("unexpected CVE filter: %q", r.URL.Query().Get("cve_id"))
			}
			io.WriteString(w, `{"jobs":[{"id":"job_abc123","status":"running","stage":"validation","progress":0.68}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/jobs/job_abc123":
			io.WriteString(w, `{"id":"job_abc123","status":"running","stage":"validation","progress":0.68}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/jobs/job_abc123/events":
			io.WriteString(w, `{"events":[{"seq":1,"message":"Validation running"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/jobs/job_abc123/cancel":
			io.WriteString(w, `{"id":"job_abc123","status":"cancelling"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/jobs":
			if r.Header.Get("Idempotency-Key") != "browser-request-1" {
				t.Errorf("idempotency key was not forwarded")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			cve := body["cve"].(map[string]any)
			if cve["id"] != "CVE-2025-32432" {
				t.Errorf("unexpected submitted CVE: %v", cve["id"])
			}
			refs, ok := cve["references"].([]any)
			if !ok || len(refs) != 1 || refs[0].(map[string]any)["url"] != "https://vendor.example/advisory" {
				t.Errorf("CVE references were not forwarded: %#v", cve["references"])
			}
			exploits, ok := cve["exploit_refs"].([]any)
			if !ok || len(exploits) != 1 || exploits[0].(map[string]any)["url"] != "https://github.com/example/poc" {
				t.Errorf("exploit references were not forwarded: %#v", cve["exploit_refs"])
			}
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"id":"job_def456","status":"queued","stage":"intake","progress":0}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	t.Setenv("WEBCVE_SIGLAB_URL", upstream.URL)
	t.Setenv("WEBCVE_SIGLAB_TOKEN", token)
	app := newApp()
	app.ds.Store(&Dataset{
		CVEs: []CVE{{
			ID: "CVE-2025-32432", Title: "Craft CMS RCE", Description: "Fixture description",
			References: []Reference{{URL: "https://vendor.example/advisory", Tags: []string{"vendor-advisory"}}},
			Exploits:   []ExploitRef{{Source: "github", Title: "PoC", URL: "https://github.com/example/poc"}},
		}},
		byID: map[string]int{"CVE-2025-32432": 0},
	})
	e := echo.New()
	api := e.Group("/api")
	registerSigLabRoutes(api, api.Group(""), app)

	assertStatus := func(method, path, body string, headers map[string]string, want int) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		recorder := httptest.NewRecorder()
		e.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("%s %s: got %d body %s, want %d", method, path, recorder.Code, recorder.Body.String(), want)
		}
		var decoded map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}

	status := assertStatus(http.MethodGet, "/api/siglab/status", "", nil, http.StatusOK)
	if status["status"] != "ready" || status["reachable"] != true {
		t.Fatalf("unexpected lab status: %#v", status)
	}
	listing := assertStatus(http.MethodGet, "/api/siglab/jobs?cve_id=CVE-2025-32432", "", nil, http.StatusOK)
	if len(listing["jobs"].([]any)) != 1 {
		t.Fatalf("unexpected job listing: %#v", listing)
	}
	created := assertStatus(http.MethodPost, "/api/cves/CVE-2025-32432/siglab/jobs", `{}`,
		map[string]string{"Content-Type": "application/json", "Idempotency-Key": "browser-request-1"}, http.StatusAccepted)
	if created["status"] != "queued" {
		t.Fatalf("unexpected created job: %#v", created)
	}
	cancelled := assertStatus(http.MethodPost, "/api/siglab/jobs/job_abc123/cancel", `{}`,
		map[string]string{"Content-Type": "application/json"}, http.StatusOK)
	if cancelled["status"] != "cancelling" {
		t.Fatalf("unexpected cancellation: %#v", cancelled)
	}
}

func TestSigLabStatusIsExplicitWhenUnconfigured(t *testing.T) {
	t.Setenv("WEBCVE_SIGLAB_URL", "")
	t.Setenv("WEBCVE_SIGLAB_TOKEN", "")
	app := newApp()
	e := echo.New()
	api := e.Group("/api")
	registerSigLabRoutes(api, api.Group(""), app)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/siglab/status", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"unconfigured"`) {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
	}
}
