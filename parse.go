package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

var dateFormats = []string{
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
}

func parseCVEFile(path string) (CVE, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CVE{}, err
	}
	return parseCVEJSON(data, path)
}

// parseCVEJSON flattens a CVE JSON 5.x record. path is recorded for cache validation.
func parseCVEJSON(data []byte, path string) (CVE, error) {
	var raw RawCVE
	if err := json.Unmarshal(data, &raw); err != nil {
		return CVE{}, err
	}

	cve := CVE{
		ID:          raw.CveMetadata.CveID,
		State:       raw.CveMetadata.State,
		AssignerOrg: raw.CveMetadata.AssignerShortName,
		FilePath:    path,
	}

	cve.DatePublished = parseDate(raw.CveMetadata.DatePublished)
	cve.DateUpdated = parseDate(raw.CveMetadata.DateUpdated)
	cve.DateReserved = parseDate(raw.CveMetadata.DateReserved)

	if !cve.DatePublished.IsZero() {
		cve.Year = cve.DatePublished.Year()
	} else if !cve.DateReserved.IsZero() {
		cve.Year = cve.DateReserved.Year()
	}

	cna := &raw.Containers.Cna

	for _, affected := range cna.Affected {
		var versions []string
		for _, v := range affected.Versions {
			if v.Version != "" {
				versions = append(versions, v.Version)
			}
		}
		cve.AffectedProducts = append(cve.AffectedProducts, AffectedProduct{
			Vendor:   affected.Vendor,
			Product:  affected.Product,
			Versions: strings.Join(versions, ", "),
		})
	}
	if len(cve.AffectedProducts) > 0 {
		cve.Vendor = cve.AffectedProducts[0].Vendor
		cve.Product = cve.AffectedProducts[0].Product
		cve.Versions = cve.AffectedProducts[0].Versions
	}

	cve.Title = cna.Title
	for _, desc := range cna.Descriptions {
		if desc.Lang == "en" || strings.HasPrefix(desc.Lang, "en-") {
			cve.Description = desc.Value
			break
		}
	}
	if cve.Description == "" && len(cna.Descriptions) > 0 {
		cve.Description = cna.Descriptions[0].Value
	}

	// CVSS from the CNA first, then ADP containers (CISA vulnrichment)
	extractCvssFromMetrics(cna.Metrics, &cve)
	for _, adp := range raw.Containers.Adp {
		if cve.BaseScore > 0 {
			break
		}
		extractCvssFromMetrics(adp.Metrics, &cve)
	}

	// CVSS 4.0 alongside an older primary score, plus SSVC decision points
	containers := append([]ContainerData{*cna}, raw.Containers.Adp...)
	for _, c := range containers {
		for _, m := range c.Metrics {
			if m.CvssV40 != nil && cve.CvssV4Score == 0 && m.CvssV40.BaseScore > 0 {
				cve.CvssV4Score = m.CvssV40.BaseScore
				cve.CvssV4Severity = strings.ToUpper(m.CvssV40.BaseSeverity)
				cve.CvssV4Vector = m.CvssV40.VectorString
			}
			if m.Other != nil && m.Other.Type == "ssvc" {
				for _, opt := range m.Other.Content.Options {
					for k, v := range opt {
						switch strings.ToLower(k) {
						case "exploitation":
							cve.SSVCExploitation = strings.ToLower(v)
						case "automatable":
							cve.SSVCAutomatable = strings.ToLower(v)
						case "technical impact":
							cve.SSVCTechnicalImpact = strings.ToLower(v)
						}
					}
				}
			}
		}
	}
	if cve.CvssVersion == "4.0" {
		cve.CvssV4Score, cve.CvssV4Severity, cve.CvssV4Vector = 0, "", ""
	}

	// CWE from the CNA, falling back to ADP
	for _, c := range containers {
		extractCWE(&c, &cve)
		if cve.CWE != "" {
			break
		}
	}

	for _, ref := range cna.References {
		cve.References = append(cve.References, Reference{URL: ref.URL, Tags: ref.Tags})
	}

	return cve, nil
}

func extractCWE(c *ContainerData, cve *CVE) {
	for _, pt := range c.ProblemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CweId != "" {
				cve.CWE = desc.CweId
				cve.CWEDescription = desc.Description
				return
			}
			if strings.HasPrefix(desc.Description, "CWE-") {
				parts := strings.SplitN(desc.Description, " ", 2)
				cve.CWE = strings.TrimSuffix(parts[0], ":")
				if len(parts) > 1 {
					cve.CWEDescription = parts[1]
				}
				return
			}
		}
	}
}

func parseDate(s string) time.Time {
	for _, format := range dateFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// extractCvssFromMetrics extracts CVSS data from a metrics array.
// Priority: CVSS 3.1 > CVSS 3.0 > CVSS 4.0 > CVSS 2.0
func extractCvssFromMetrics(metrics []MetricEntry, cve *CVE) {
	for _, metric := range metrics {
		if metric.CvssV31 != nil {
			applyCvssMetrics(metric.CvssV31, cve)
			return
		}
	}
	for _, metric := range metrics {
		if metric.CvssV30 != nil {
			applyCvssMetrics(metric.CvssV30, cve)
			return
		}
	}
	for _, metric := range metrics {
		if metric.CvssV40 != nil {
			applyCvssMetrics(metric.CvssV40, cve)
			return
		}
	}
	for _, metric := range metrics {
		if metric.CvssV2 != nil {
			cve.CvssVersion = metric.CvssV2.Version
			cve.BaseScore = metric.CvssV2.BaseScore
			cve.VectorString = metric.CvssV2.VectorString
			// CVSS 2.0 doesn't have severity, derive from score
			cve.BaseSeverity = deriveSeverityFromScore(metric.CvssV2.BaseScore)
			return
		}
	}
}

func applyCvssMetrics(cvss *CvssMetrics, cve *CVE) {
	cve.CvssVersion = cvss.Version
	cve.BaseScore = cvss.BaseScore
	cve.BaseSeverity = strings.ToUpper(cvss.BaseSeverity)
	cve.AttackVector = cvss.AttackVector
	cve.AttackComplexity = cvss.AttackComplexity
	cve.PrivilegesRequired = cvss.PrivilegesRequired
	cve.UserInteraction = cvss.UserInteraction
	cve.Scope = cvss.Scope
	cve.ConfidentialityImpact = cvss.ConfidentialityImpact
	cve.IntegrityImpact = cvss.IntegrityImpact
	cve.AvailabilityImpact = cvss.AvailabilityImpact
	cve.VectorString = cvss.VectorString

	if cve.BaseSeverity == "" && cve.BaseScore > 0 {
		cve.BaseSeverity = deriveSeverityFromScore(cve.BaseScore)
	}
}

func deriveSeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}

// exploitHosts are reference hosts that indicate public exploit code
var exploitHosts = []string{
	"exploit-db.com/",
	"packetstormsecurity.com/",
	"packetstorm.news/",
	"github.com/rapid7/metasploit-framework",
	"metasploit.com/",
	"0day.today/",
}

// hasPublicExploit reports exploit evidence from SSVC or the references
func hasPublicExploit(cve *CVE) bool {
	if cve.SSVCExploitation == "poc" || cve.SSVCExploitation == "active" {
		return true
	}
	for _, r := range cve.References {
		for _, t := range r.Tags {
			if strings.EqualFold(t, "exploit") {
				return true
			}
		}
		u := strings.ToLower(r.URL)
		for _, h := range exploitHosts {
			if strings.Contains(u, h) {
				return true
			}
		}
	}
	return false
}
