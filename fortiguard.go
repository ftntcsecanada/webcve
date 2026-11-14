package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// FortiGuard IPS coverage: which CVEs a FortiGuard IPS signature already
// covers, read from a FortiGate's built-in rule table. GET
// /api/v2/cmdb/ips/rule returns every signature (about 22,000, 9 MB); rule
// metadata 13 carries the CVE as a number, year then sequence ("20074387" is
// CVE-2007-4387). A CVE with a rule isn't a signature job: it shows as covered
// and drops out of the actionable lists.
//
//	FGT_URL       FortiGate base URL, e.g. https://10.162.7.100
//	FGT_API_KEY   REST API token (read access to IPS is enough)
//	FGT_VERIFY_TLS=1  verify the certificate (off by default: FortiGates usually self-sign)

const (
	fortiguardPath = DataDir + "/fortiguard_ips.json"
	ipsMetaCVE     = 13
)

// IPSRuleRef is one FortiGuard IPS signature that references a CVE
type IPSRuleRef struct {
	Name     string `json:"name"`
	RuleID   int    `json:"ruleId"`
	Action   string `json:"action,omitempty"`
	Severity string `json:"severity,omitempty"`
	Date     string `json:"date,omitempty"` // signature release date
}

type fortiguardFile struct {
	DBVersion string                  `json:"dbVersion"`
	Fetched   time.Time               `json:"fetched"`
	Rules     int                     `json:"rules"`
	ByCVE     map[string][]IPSRuleRef `json:"byCVE"`
}

func fortiguardConfig() (base, key string) {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("FGT_URL")), "/"), strings.TrimSpace(os.Getenv("FGT_API_KEY"))
}

func fortiguardClient() *http.Client {
	insecure := os.Getenv("FGT_VERIFY_TLS") != "1"
	return &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // FortiGates self-sign; opt in to verification
	}}
}

func fgtGet(client *http.Client, base, key, path string, v any) error {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FortiGate %s: HTTP %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// fetchFortiGuard checks the IPS database version (hourly, one small call) and
// downloads the rule table only when it has changed
func fetchFortiGuard(app *App) (bool, error) {
	base, key := fortiguardConfig()
	if base == "" || key == "" {
		app.board.update("fortiguard", func(s *SourceStatus) { s.State, s.Detail = "pending", "Off: set FGT_URL and FGT_API_KEY" })
		return false, nil
	}
	client := fortiguardClient()
	var lic struct {
		Results map[string]struct {
			Version string `json:"version"`
		} `json:"results"`
	}
	if err := fgtGet(client, base, key, "/api/v2/monitor/license/status", &lic); err != nil {
		return false, err
	}
	version := lic.Results["ips"].Version
	var prev fortiguardFile
	if readJSONFile(fortiguardPath, &prev) == nil && version != "" && prev.DBVersion == version {
		return false, nil
	}

	var table struct {
		Results []struct {
			Name     string `json:"name"`
			RuleID   int    `json:"rule-id"`
			Action   string `json:"action"`
			Severity string `json:"severity"`
			Date     int64  `json:"date"`
			Metadata []struct {
				MetaID  int   `json:"metaid"`
				ValueID int64 `json:"valueid"`
			} `json:"metadata"`
		} `json:"results"`
	}
	if err := fgtGet(client, base, key, "/api/v2/cmdb/ips/rule?format=name|rule-id|action|severity|date|metadata", &table); err != nil {
		return false, err
	}
	out := fortiguardFile{DBVersion: version, Fetched: time.Now().UTC(), Rules: len(table.Results), ByCVE: map[string][]IPSRuleRef{}}
	for _, r := range table.Results {
		ref := IPSRuleRef{Name: r.Name, RuleID: r.RuleID, Action: r.Action, Severity: r.Severity}
		if r.Date > 0 {
			ref.Date = time.Unix(r.Date, 0).UTC().Format("2006-01-02")
		}
		for _, m := range r.Metadata {
			if m.MetaID != ipsMetaCVE {
				continue
			}
			if id := ipsCVEID(m.ValueID); id != "" {
				out.ByCVE[id] = append(out.ByCVE[id], ref)
			}
		}
	}
	if len(table.Results) == 0 {
		return false, fmt.Errorf("FortiGate returned no IPS rules")
	}
	logf("FortiGuard IPS %s: %d rules covering %d CVEs", version, out.Rules, len(out.ByCVE))
	return true, writeJSONAtomic(fortiguardPath, out)
}

// ipsCVEID decodes rule metadata: the year's four digits, then the sequence
func ipsCVEID(v int64) string {
	s := strconv.FormatInt(v, 10)
	if len(s) < 8 || s[:2] != "19" && s[:2] != "20" {
		return ""
	}
	return "CVE-" + s[:4] + "-" + s[4:]
}

func parseFortiGuard(app *App) (func(*Enrichment), error) {
	var f fortiguardFile
	if err := readJSONFile(fortiguardPath, &f); err != nil {
		return nil, err
	}
	app.board.records("fortiguard", len(f.ByCVE), "CVEs covered")
	if f.DBVersion != "" {
		app.board.progress("fortiguard", "IPS database "+f.DBVersion+", "+strconv.Itoa(f.Rules)+" signatures")
	}
	return func(e *Enrichment) { e.FortiGuardIPS = f.ByCVE }, nil
}
