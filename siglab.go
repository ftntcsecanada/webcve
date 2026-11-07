package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

var sigLabJobID = regexp.MustCompile(`^job_[a-f0-9]+$`)
var sigLabArtifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type sigLabClient struct {
	base  string
	token string
	http  *http.Client
}

func newSigLabClient() *sigLabClient {
	return &sigLabClient{
		base:  strings.TrimRight(strings.TrimSpace(os.Getenv("WEBCVE_SIGLAB_URL")), "/"),
		token: strings.TrimSpace(os.Getenv("WEBCVE_SIGLAB_TOKEN")),
		http:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (s *sigLabClient) configured() bool {
	if s.base == "" || s.token == "" {
		return false
	}
	u, err := url.Parse(s.base)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (s *sigLabClient) request(method, path string, body []byte, idem string) (*http.Response, error) {
	if !s.configured() {
		return nil, fmt.Errorf("Signature Lab is not configured")
	}
	req, err := http.NewRequest(method, s.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	return s.http.Do(req)
}

func relaySigLab(c echo.Context, response *http.Response, err error) error {
	if err != nil {
		return c.JSON(http.StatusBadGateway, map[string]any{
			"error": "signature_lab_unreachable", "detail": err.Error(),
		})
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if readErr != nil {
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "invalid_signature_lab_response"})
	}
	contentType := response.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	if disposition := response.Header.Get("Content-Disposition"); disposition != "" {
		c.Response().Header().Set("Content-Disposition", disposition)
	}
	return c.Blob(response.StatusCode, contentType, body)
}

func (app *App) handleSigLabStatus(c echo.Context) error {
	siglab := newSigLabClient()
	if !siglab.configured() {
		return c.JSON(http.StatusOK, map[string]any{
			"configured": false, "reachable": false,
			"status": "unconfigured",
		})
	}
	response, err := siglab.request(http.MethodGet, "/v1/capabilities", nil, "")
	if err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"configured": true, "reachable": false,
			"status": "unreachable", "detail": err.Error(),
		})
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil || response.StatusCode/100 != 2 {
		return c.JSON(http.StatusOK, map[string]any{
			"configured": true, "reachable": false,
			"status": "error", "upstreamStatus": response.StatusCode,
		})
	}
	var capabilities map[string]any
	if json.Unmarshal(body, &capabilities) != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"configured": true, "reachable": false, "status": "error",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"configured": true, "reachable": true, "status": "ready",
		"capabilities": capabilities,
	})
}

func (app *App) handleSigLabJobs(c echo.Context) error {
	values := url.Values{}
	if cve := strings.ToUpper(strings.TrimSpace(c.QueryParam("cve_id"))); cve != "" {
		if !cveIDRe.MatchString(cve) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid CVE ID"})
		}
		values.Set("cve_id", cve)
	}
	limit := 20
	if parsed, err := strconv.Atoi(c.QueryParam("limit")); err == nil && parsed > 0 {
		limit = min(parsed, 100)
	}
	values.Set("limit", strconv.Itoa(limit))
	response, err := newSigLabClient().request(http.MethodGet, "/v1/jobs?"+values.Encode(), nil, "")
	return relaySigLab(c, response, err)
}

func checkedJobID(c echo.Context) (string, error) {
	id := c.Param("jobID")
	if !sigLabJobID.MatchString(id) {
		return "", echo.NewHTTPError(http.StatusBadRequest, "invalid Signature Lab job ID")
	}
	return id, nil
}

func (app *App) handleSigLabJob(c echo.Context) error {
	id, err := checkedJobID(c)
	if err != nil {
		return err
	}
	response, requestErr := newSigLabClient().request(http.MethodGet, "/v1/jobs/"+id, nil, "")
	return relaySigLab(c, response, requestErr)
}

func (app *App) handleSigLabEvents(c echo.Context) error {
	id, err := checkedJobID(c)
	if err != nil {
		return err
	}
	after := 0
	if parsed, parseErr := strconv.Atoi(c.QueryParam("after")); parseErr == nil && parsed >= 0 {
		after = parsed
	}
	path := fmt.Sprintf("/v1/jobs/%s/events?after=%d", id, after)
	response, requestErr := newSigLabClient().request(http.MethodGet, path, nil, "")
	return relaySigLab(c, response, requestErr)
}

func (app *App) handleSigLabArtifacts(c echo.Context) error {
	id, err := checkedJobID(c)
	if err != nil {
		return err
	}
	response, requestErr := newSigLabClient().request(
		http.MethodGet, "/v1/jobs/"+id+"/artifacts", nil, "")
	return relaySigLab(c, response, requestErr)
}

func (app *App) handleSigLabArtifact(c echo.Context) error {
	id, err := checkedJobID(c)
	if err != nil {
		return err
	}
	name := c.Param("artifact")
	if !sigLabArtifactName.MatchString(name) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid Signature Lab artifact name")
	}
	path := "/v1/jobs/" + id + "/artifacts/" + url.PathEscape(name)
	response, requestErr := newSigLabClient().request(http.MethodGet, path, nil, "")
	return relaySigLab(c, response, requestErr)
}

func (app *App) handleSigLabCancel(c echo.Context) error {
	id, err := checkedJobID(c)
	if err != nil {
		return err
	}
	var request struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(c.Request().Body, 16<<10)).Decode(&request)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" {
		request.Reason = "Cancelled from WebCVE"
	}
	body, _ := json.Marshal(request)
	response, requestErr := newSigLabClient().request(
		http.MethodPost, "/v1/jobs/"+id+"/cancel", body, "")
	return relaySigLab(c, response, requestErr)
}

func (app *App) handleSigLabSubmit(c echo.Context) error {
	id := strings.ToUpper(c.Param("id"))
	ds := app.dataset()
	index, ok := ds.byID[id]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
	}
	cve := &ds.CVEs[index]
	var options struct {
		ActionPreference string `json:"actionPreference"`
		AnalystNotes     string `json:"analystNotes"`
		MaxIterations    int    `json:"maxIterations"`
	}
	_ = json.NewDecoder(io.LimitReader(c.Request().Body, 32<<10)).Decode(&options)
	if options.ActionPreference != "monitor" {
		options.ActionPreference = "block"
	}
	if options.MaxIterations < 1 || options.MaxIterations > 10 {
		options.MaxIterations = 3
	}
	if len(options.AnalystNotes) > 4000 {
		options.AnalystNotes = options.AnalystNotes[:4000]
	}
	title := cve.Title
	if title == "" {
		title = cve.KEVVulnerabilityName
	}
	description := strings.TrimSpace(cve.Description)
	if description == "" {
		description = strings.TrimSpace(title)
	}
	if description == "" {
		description = "WebCVE Signature Lab request for " + id
	}
	references := cve.References
	if len(references) > 100 {
		references = references[:100]
	}
	exploits := cve.Exploits
	if len(exploits) > 25 {
		exploits = exploits[:25]
	}
	payload := map[string]any{
		"client_ref": fmt.Sprintf("webcve:%s:%d", id, time.Now().UnixMilli()),
		"cve": map[string]any{
			"id":           id,
			"title":        title,
			"description":  description,
			"references":   references,
			"exploit_refs": exploits,
			"affected":     cve.AffectedProducts,
			"cwe":          map[string]string{"id": cve.CWE, "description": cve.CWEDescription},
			"cvss": map[string]any{
				"version":  cve.CvssVersion,
				"score":    cve.BaseScore,
				"severity": cve.BaseSeverity,
				"vector":   cve.VectorString,
			},
		},
		"options": map[string]any{
			"action_preference": options.ActionPreference,
			"analyst_notes":     options.AnalystNotes,
			"max_iterations":    options.MaxIterations,
			"allow_human_input": false,
		},
	}
	body, _ := json.Marshal(payload)
	idempotency := strings.TrimSpace(c.Request().Header.Get("Idempotency-Key"))
	if idempotency == "" {
		idempotency = fmt.Sprintf("webcve-%s-%d", strings.ToLower(id), time.Now().UnixNano())
	}
	response, requestErr := newSigLabClient().request(http.MethodPost, "/v1/jobs", body, idempotency)
	return relaySigLab(c, response, requestErr)
}

func registerSigLabRoutes(api, data *echo.Group, app *App) {
	api.GET("/siglab/status", app.handleSigLabStatus)
	api.GET("/siglab/jobs", app.handleSigLabJobs)
	api.GET("/siglab/jobs/:jobID", app.handleSigLabJob)
	api.GET("/siglab/jobs/:jobID/events", app.handleSigLabEvents)
	api.GET("/siglab/jobs/:jobID/artifacts", app.handleSigLabArtifacts)
	api.GET("/siglab/jobs/:jobID/artifacts/:artifact", app.handleSigLabArtifact)
	api.POST("/siglab/jobs/:jobID/cancel", app.handleSigLabCancel)
	data.POST("/cves/:id/siglab/jobs", app.handleSigLabSubmit)
}
