package main

import "time"

// AffectedProduct represents a single affected vendor/product
type AffectedProduct struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Versions string `json:"versions"`
}

// CVE is a flattened CVE record optimized for filtering. Fields after the
// "enrichment" marker are derived from KEV/EPSS/references at dataset build
// time rather than parsed from the record.
type CVE struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	DatePublished time.Time `json:"datePublished"`
	DateUpdated   time.Time `json:"dateUpdated"`
	DateReserved  time.Time `json:"dateReserved"`
	Year          int       `json:"year"`

	// Primary (first) affected product
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Versions string `json:"versions"`

	AffectedProducts []AffectedProduct `json:"affectedProducts"`

	Title       string `json:"title"`
	Description string `json:"description"`

	// Primary CVSS metrics (3.1 > 3.0 > 4.0 > 2.0, CNA first then ADP)
	CvssVersion           string  `json:"cvssVersion"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	VectorString          string  `json:"vectorString"`

	// CVSS 4.0, kept alongside when the primary score is an older version
	CvssV4Score    float64 `json:"cvssV4Score,omitempty"`
	CvssV4Severity string  `json:"cvssV4Severity,omitempty"`
	CvssV4Vector   string  `json:"cvssV4Vector,omitempty"`

	// CISA SSVC decision points (from the CISA-ADP container)
	SSVCExploitation    string `json:"ssvcExploitation,omitempty"`
	SSVCAutomatable     string `json:"ssvcAutomatable,omitempty"`
	SSVCTechnicalImpact string `json:"ssvcTechnicalImpact,omitempty"`

	CWE            string `json:"cwe"`
	CWEDescription string `json:"cweDescription"`

	References []Reference `json:"references"`

	AssignerOrg string `json:"assignerOrg"`

	// ---- enrichment ----

	InKEV                      bool   `json:"inKEV"`
	KEVDateAdded               string `json:"kevDateAdded,omitempty"`
	KEVDueDate                 string `json:"kevDueDate,omitempty"`
	KEVRequiredAction          string `json:"kevRequiredAction,omitempty"`
	KEVKnownRansomwareCampaign string `json:"kevKnownRansomwareCampaign,omitempty"`
	KEVNotes                   string `json:"kevNotes,omitempty"`
	KEVVulnerabilityName       string `json:"kevName,omitempty"`

	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epssPercentile,omitempty"`

	// PublicExploit is set when SSVC says poc/active or a reference points at exploit code
	PublicExploit bool  `json:"publicExploit"`
	EvidenceBits  uint8 `json:"-"`

	// KEVOnly marks a placeholder built from the KEV catalog because the CVE
	// record isn't in the local corpus yet; a real record replaces it
	KEVOnly bool `json:"kevOnly,omitempty"`

	// Exploit code and scanner templates from Exploit-DB, Metasploit, Nuclei and PoC-in-GitHub
	Exploits    []ExploitRef `json:"exploits,omitempty"`
	GitHubPoCs  int          `json:"githubPocs,omitempty"`  // total repos; Exploits keeps the most starred
	ScoreSource string       `json:"scoreSource,omitempty"` // "nvd" when the CVSS fields came from NVD
	NVDStatus   string       `json:"nvdStatus,omitempty"`
	NVDScore    float64      `json:"nvdScore,omitempty"` // NVD's own score, kept even when the record has one
	// Vendor/product pairs from NVD's CPE configurations
	NVDProducts []AffectedProduct `json:"nvdProducts,omitempty"`
	// Fixed package versions from OSV (GitHub advisories, language ecosystems, Linux distros)
	Packages []PackageFix `json:"packages,omitempty"`
	// ENISA EU Vulnerability Database
	EUVDID             string `json:"euvdId,omitempty"`
	EUVDExploitedSince string `json:"euvdExploitedSince,omitempty"`
	// Microsoft Security Response Center exploitability assessment
	MSRC       *MSRCInfo `json:"msrc,omitempty"`
	CWEName    string    `json:"cweName,omitempty"`
	CWEFromNVD bool      `json:"cweFromNvd,omitempty"`

	// File path for cache validation
	FilePath string `json:"-"`
}

// ExploitRef is a link to exploit code or a scanner template
type ExploitRef struct {
	Source string `json:"source"` // exploitdb, metasploit, nuclei, github
	Title  string `json:"title"`
	URL    string `json:"url"`
	Date   string `json:"date,omitempty"`
	Stars  int    `json:"stars,omitempty"`
	Note   string `json:"note,omitempty"` // e.g. "verified", "exploit module", "auxiliary module"
}

// PackageFix lists the versions that fix a CVE in one package
type PackageFix struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Fixed     []string `json:"fixed,omitempty"`
	Advisory  string   `json:"advisory,omitempty"` // OSV/GHSA/distro advisory ID
}

// MSRCInfo is Microsoft's exploitability assessment for a CVE
type MSRCInfo struct {
	Title             string `json:"title"`
	Exploited         bool   `json:"exploited"`
	PubliclyDisclosed bool   `json:"publiclyDisclosed"`
	Assessment        string `json:"assessment,omitempty"` // e.g. "Exploitation More Likely"
	Release           string `json:"release,omitempty"`    // e.g. "2024-Apr"
}

// NVDInfo is what we keep from an NVD API record
type NVDInfo struct {
	Status   string
	Version  string
	Score    float64
	Severity string
	Vector   string
	CWE      string
	Products []AffectedProduct
	Modified time.Time
}

type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// CvssMetrics captures CVSS data from any version
type CvssMetrics struct {
	Version               string  `json:"version"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	VectorString          string  `json:"vectorString"`
}

// MetricEntry is a single metric entry, which can hold any CVSS version or an "other" block
type MetricEntry struct {
	CvssV40 *CvssMetrics `json:"cvssV4_0"`
	CvssV31 *CvssMetrics `json:"cvssV3_1"`
	CvssV30 *CvssMetrics `json:"cvssV3_0"`
	CvssV2  *struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssV2_0"`
	Other *struct {
		Type    string `json:"type"`
		Content struct {
			Options []map[string]string `json:"options"`
		} `json:"content"`
	} `json:"other"`
}

// ContainerData represents common fields in both CNA and ADP containers
type ContainerData struct {
	Title    string `json:"title"`
	Affected []struct {
		Vendor   string `json:"vendor"`
		Product  string `json:"product"`
		Versions []struct {
			Version string `json:"version"`
			Status  string `json:"status"`
		} `json:"versions"`
	} `json:"affected"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics      []MetricEntry `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CweId       string `json:"cweId"`
			Description string `json:"description"`
			Lang        string `json:"lang"`
			Type        string `json:"type"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

// RawCVE represents the original CVE JSON 5.x structure
type RawCVE struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		CveID             string `json:"cveId"`
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		State             string `json:"state"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna ContainerData   `json:"cna"`
		Adp []ContainerData `json:"adp"`
	} `json:"containers"`
}

// KEVCatalog represents the CISA Known Exploited Vulnerabilities catalog
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVEntry represents a single entry in the KEV catalog
type KEVEntry struct {
	CveID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// EPSSScore is one row of the FIRST EPSS feed
type EPSSScore struct {
	Score      float32
	Percentile float32
}

// StatsResponse provides database statistics
type StatsResponse struct {
	Status         string               `json:"status"`
	Sources        map[string]time.Time `json:"sources"`
	TotalCVEs      int                  `json:"totalCves"`
	LastUpdated    time.Time            `json:"lastUpdated"`
	LastDataUpdate time.Time            `json:"lastDataUpdate"`
	NextUpdateIn   string               `json:"nextUpdateIn"`
	CVEDelta       string               `json:"cveDelta,omitempty"`
	SourceErrors   []string             `json:"sourceErrors"`
	YearRange      [2]int               `json:"yearRange"`
	SeverityCounts map[string]int       `json:"severityCounts"`
	TotalKEV       int                  `json:"totalKev"`
	KEVRansomware  int                  `json:"kevRansomware"`
	KEVLast30Days  int                  `json:"kevLast30Days"`
	KEVDueNext30   int                  `json:"kevDueNext30"`
	KEVCatalogDate string               `json:"kevCatalogDate"`
	WithEPSS       int                  `json:"withEpss"`
	EPSSDate       string               `json:"epssDate"`
	PublicExploits int                  `json:"publicExploits"`
}
