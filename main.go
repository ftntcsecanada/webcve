package main

import (
	"archive/zip"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/xuri/excelize/v2"
)

// CVE represents a simplified, flattened CVE record optimized for filtering
// AffectedProduct represents a single affected vendor/product
type AffectedProduct struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Versions string `json:"versions"`
}

type CVE struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	DatePublished time.Time `json:"datePublished"`
	DateUpdated   time.Time `json:"dateUpdated"`
	DateReserved  time.Time `json:"dateReserved"`
	Year          int       `json:"year"`

	// Affected products - primary (first) for filtering
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Versions string `json:"versions"`

	// All affected products
	AffectedProducts []AffectedProduct `json:"affectedProducts"`

	// Description
	Title       string `json:"title"`
	Description string `json:"description"`

	// CVSS Metrics
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

	// Problem types (CWE)
	CWE            string `json:"cwe"`
	CWEDescription string `json:"cweDescription"`

	// References
	References []Reference `json:"references"`

	// Assigner
	AssignerOrg string `json:"assignerOrg"`

	// CISA KEV (Known Exploited Vulnerabilities)
	InKEV                      bool   `json:"inKEV"`
	KEVDateAdded               string `json:"kevDateAdded,omitempty"`
	KEVDueDate                 string `json:"kevDueDate,omitempty"`
	KEVRequiredAction          string `json:"kevRequiredAction,omitempty"`
	KEVKnownRansomwareCampaign string `json:"kevKnownRansomwareCampaign,omitempty"`
	KEVNotes                   string `json:"kevNotes,omitempty"`
	KEVVulnerabilityName       string `json:"kevName,omitempty"`

	// File path for cache validation
	FilePath string `json:"-"`
}

type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// CvssMetrics is a flexible structure to capture CVSS data from any version
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

// MetricEntry represents a single metric entry which can have various CVSS versions
type MetricEntry struct {
	CvssV40 *CvssMetrics `json:"cvssV4_0"`
	CvssV31 *CvssMetrics `json:"cvssV3_1"`
	CvssV30 *CvssMetrics `json:"cvssV3_0"`
	CvssV2  *struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssV2_0"`
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

// RawCVE represents the original CVE JSON structure
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

// Cache represents the GOB cache structure
type Cache struct {
	Version   int               `json:"version"`
	BuildTime time.Time         `json:"buildTime"`
	CVEs      []CVE             `json:"cves"`
	FileIndex map[string]string `json:"fileIndex"` // filepath -> CVE ID mapping
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

const (
	CacheVersion = 4 // Incremented to force cache rebuild with KEV details
	CachePath    = "cve_cache.gob"
	CVEDir       = "cves"
	KEVDir       = "kev"
	KEVPath      = "kev/known_exploited_vulnerabilities.json"

	// Download URLs
	KEVDownloadURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// CVE bulk download - using the GitHub releases zip
	CVEReleasesAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

	// Update interval
	UpdateInterval = 7 * 24 * time.Hour // Weekly updates
)

// App holds the application state
type App struct {
	cves     []CVE
	cveIndex map[string]*CVE      // Quick lookup by ID
	kevIndex map[string]*KEVEntry // CVE IDs in CISA KEV catalog with full entry data
	mu       sync.RWMutex

	// Filter option caches
	vendors    []string
	products   []string
	severities []string
	years      []int
	cwes       []string

	productCounts map[string]int

	// Update tracking
	lastDataUpdate time.Time

	// Lowercased search haystack per CVE, aligned with cves
	searchText []string

	// Cached ascending sort orders (CVE indexes) keyed by sort field
	orders  map[string][]int
	orderMu sync.Mutex

	// KEV catalog metadata
	kevCatalogDate string

	// Cached stats
	cachedStats *StatsResponse
}

// StatsResponse provides database statistics
type StatsResponse struct {
	TotalCVEs      int            `json:"totalCves"`
	LastUpdated    time.Time      `json:"lastUpdated"`
	LastDataUpdate time.Time      `json:"lastDataUpdate"`
	NextUpdateIn   string         `json:"nextUpdateIn"`
	YearRange      [2]int         `json:"yearRange"`
	TopVendors     []VendorCount  `json:"topVendors"`
	SeverityCounts map[string]int `json:"severityCounts"`
	TotalKEV       int            `json:"totalKev"`
	KEVRansomware  int            `json:"kevRansomware"`
	KEVLast30Days  int            `json:"kevLast30Days"`
	KEVCatalogDate string         `json:"kevCatalogDate"`
}

type VendorCount struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
}

func main() {
	app := &App{
		cveIndex: make(map[string]*CVE),
		kevIndex: make(map[string]*KEVEntry),
	}

	// Check and download data if missing
	if err := app.checkAndDownloadData(); err != nil {
		fmt.Printf("Error checking/downloading data: %v\n", err)
		// Continue anyway, may have partial data
	}

	// Load CISA KEV catalog first
	if err := app.loadKEV(); err != nil {
		fmt.Printf("Warning: Could not load KEV catalog: %v\n", err)
	} else {
		fmt.Printf("Loaded %d KEV entries\n", len(app.kevIndex))
	}

	// Load CVEs with caching
	if err := app.loadCVEs(); err != nil {
		fmt.Printf("Error loading CVEs: %v\n", err)
		return
	}

	// Build filter option caches, search index and stats
	app.buildIndexes()

	// Set initial last update time from cache file or current time
	if info, err := os.Stat(CachePath); err == nil {
		app.lastDataUpdate = info.ModTime()
	} else {
		app.lastDataUpdate = time.Now()
	}

	fmt.Printf("Loaded %d CVEs (%d in CISA KEV)\n", len(app.cves), app.cachedStats.TotalKEV)

	// Start the background update scheduler
	app.startUpdateScheduler()

	// Setup Echo router
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Serve static files
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		HTML5:  true,
		Index:  "index.html",
		Browse: false,
		Root:   "site",
	}))

	// API routes
	api := e.Group("/api")
	api.POST("/cves", app.handleFilterCVEs)
	api.GET("/cves/:id", app.handleGetCVE)
	api.GET("/stats", app.handleGetStats)
	api.GET("/options", app.handleGetOptions)
	api.POST("/options/search", app.handleSearchOptions)
	api.POST("/export", app.handleExportXLS)

	e.Logger.Fatal(e.Start(":3000"))
}

// loadKEV loads the CISA Known Exploited Vulnerabilities catalog
func (app *App) loadKEV() error {
	data, err := os.ReadFile(KEVPath)
	if err != nil {
		return err
	}

	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return err
	}

	app.kevCatalogDate = catalog.DateReleased
	for i := range catalog.Vulnerabilities {
		entry := &catalog.Vulnerabilities[i]
		app.kevIndex[entry.CveID] = entry
	}

	return nil
}

func (app *App) loadCVEs() error {
	// Try to load from cache first
	cache, err := app.loadCache()
	if err == nil && cache.Version == CacheVersion {
		fmt.Println("Loading CVEs from cache...")

		// Verify cache is up to date
		missingFiles, newFiles := app.verifyCacheIntegrity(cache)

		if len(missingFiles) == 0 && len(newFiles) == 0 {
			app.cves = cache.CVEs
			for i := range app.cves {
				app.cveIndex[app.cves[i].ID] = &app.cves[i]
			}
			// Apply KEV status (KEV catalog may have been updated)
			app.applyKEVStatus()
			fmt.Printf("Cache valid, loaded %d CVEs\n", len(app.cves))
			return nil
		}

		fmt.Printf("Cache outdated: %d missing, %d new files\n", len(missingFiles), len(newFiles))

		// Incremental update: keep valid entries, add new ones
		app.cves = cache.CVEs
		for i := range app.cves {
			app.cveIndex[app.cves[i].ID] = &app.cves[i]
		}

		// Remove entries for missing files
		if len(missingFiles) > 0 {
			validCVEs := make([]CVE, 0, len(app.cves))
			for _, cve := range app.cves {
				if _, missing := missingFiles[cve.FilePath]; !missing {
					validCVEs = append(validCVEs, cve)
				} else {
					delete(app.cveIndex, cve.ID)
				}
			}
			app.cves = validCVEs
		}

		// Add new files
		if len(newFiles) > 0 {
			fmt.Printf("Loading %d new CVE files...\n", len(newFiles))
			newCVEs := app.loadCVEFiles(newFiles)
			app.cves = append(app.cves, newCVEs...)
			for i := len(app.cves) - len(newCVEs); i < len(app.cves); i++ {
				app.cveIndex[app.cves[i].ID] = &app.cves[i]
			}
		}

		// Apply KEV status (KEV catalog may have been updated)
		app.applyKEVStatus()

		// Save updated cache
		app.saveCache()
		return nil
	}

	// No valid cache, load all CVEs from disk
	fmt.Println("No valid cache found, loading all CVEs from disk...")
	files := app.findAllCVEFiles()
	app.cves = app.loadCVEFiles(files)

	for i := range app.cves {
		app.cveIndex[app.cves[i].ID] = &app.cves[i]
	}

	// Apply KEV status to all CVEs
	app.applyKEVStatus()

	// Save cache for next time
	app.saveCache()

	return nil
}

// applyKEVStatus marks CVEs that are in the CISA KEV catalog and populates KEV details
func (app *App) applyKEVStatus() {
	for i := range app.cves {
		cve := &app.cves[i]
		cve.InKEV = false
		cve.KEVDateAdded, cve.KEVDueDate, cve.KEVRequiredAction = "", "", ""
		cve.KEVKnownRansomwareCampaign, cve.KEVNotes, cve.KEVVulnerabilityName = "", "", ""
		if kevEntry := app.kevIndex[app.cves[i].ID]; kevEntry != nil {
			app.cves[i].InKEV = true
			app.cves[i].KEVVulnerabilityName = kevEntry.VulnerabilityName
			app.cves[i].KEVDateAdded = kevEntry.DateAdded
			app.cves[i].KEVDueDate = kevEntry.DueDate
			app.cves[i].KEVRequiredAction = kevEntry.RequiredAction
			app.cves[i].KEVKnownRansomwareCampaign = kevEntry.KnownRansomwareCampaignUse
			app.cves[i].KEVNotes = kevEntry.Notes
		}
	}
}

// downloadKEV downloads the CISA KEV catalog
func (app *App) downloadKEV() error {
	fmt.Println("Downloading CISA KEV catalog...")

	// Create KEV directory if it doesn't exist
	if err := os.MkdirAll(KEVDir, 0755); err != nil {
		return fmt.Errorf("failed to create KEV directory: %w", err)
	}

	// Download the JSON file
	resp, err := http.Get(KEVDownloadURL)
	if err != nil {
		return fmt.Errorf("failed to download KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download KEV catalog: HTTP %d", resp.StatusCode)
	}

	// Create the output file
	outFile, err := os.Create(KEVPath)
	if err != nil {
		return fmt.Errorf("failed to create KEV file: %w", err)
	}
	defer outFile.Close()

	// Copy the response body to the file
	written, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write KEV file: %w", err)
	}

	fmt.Printf("Downloaded KEV catalog: %d bytes\n", written)
	return nil
}

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// downloadCVEs downloads the CVE database from GitHub releases
func (app *App) downloadCVEs() error {
	fmt.Println("Downloading CVE database from GitHub...")

	// Get the latest release info
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", CVEReleasesAPI, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "webcve-downloader")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get release info: HTTP %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release info: %w", err)
	}

	// Find the "all CVEs" zip file (the largest one, typically named with _all_CVEs)
	var downloadURL string
	var downloadSize int64
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, "all_CVEs") && strings.HasSuffix(asset.Name, ".zip") {
			downloadURL = asset.BrowserDownloadURL
			downloadSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		// Fallback: get the largest zip file
		for _, asset := range release.Assets {
			if strings.HasSuffix(asset.Name, ".zip") && asset.Size > downloadSize {
				downloadURL = asset.BrowserDownloadURL
				downloadSize = asset.Size
			}
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no suitable CVE zip file found in release %s", release.TagName)
	}

	fmt.Printf("Found release %s, downloading %.2f MB...\n", release.TagName, float64(downloadSize)/(1024*1024))

	// Download the zip file to a temp location
	tempZip := filepath.Join(os.TempDir(), "cve_download.zip")
	if err := downloadFile(downloadURL, tempZip); err != nil {
		return fmt.Errorf("failed to download CVE zip: %w", err)
	}
	defer os.Remove(tempZip)

	// Handle nested zip (e.g. all_CVEs.zip.zip contains cves.zip which has the actual data)
	actualZip := tempZip
	if strings.HasSuffix(downloadURL, ".zip.zip") {
		fmt.Println("Detected nested zip, extracting inner archive...")
		innerDir := filepath.Join(os.TempDir(), "cve_inner")
		os.MkdirAll(innerDir, 0755)
		defer os.RemoveAll(innerDir)
		// Extract outer zip without stripping path components
		outerReader, err := zip.OpenReader(tempZip)
		if err != nil {
			return fmt.Errorf("failed to open outer zip: %w", err)
		}
		for _, file := range outerReader.File {
			if file.FileInfo().IsDir() {
				continue
			}
			destPath := filepath.Join(innerDir, filepath.Base(file.Name))
			srcFile, err := file.Open()
			if err != nil {
				outerReader.Close()
				return fmt.Errorf("failed to open file in outer zip: %w", err)
			}
			destFile, err := os.Create(destPath)
			if err != nil {
				srcFile.Close()
				outerReader.Close()
				return fmt.Errorf("failed to create inner zip file: %w", err)
			}
			io.Copy(destFile, srcFile)
			srcFile.Close()
			destFile.Close()
		}
		outerReader.Close()
		// Find the inner zip file
		innerEntries, err := os.ReadDir(innerDir)
		if err != nil {
			return fmt.Errorf("failed to read inner zip dir: %w", err)
		}
		for _, e := range innerEntries {
			if strings.HasSuffix(e.Name(), ".zip") {
				actualZip = filepath.Join(innerDir, e.Name())
				break
			}
		}
		if actualZip == tempZip {
			return fmt.Errorf("no inner zip found in nested archive")
		}
	}

	// Clear existing CVE directory contents (don't remove the dir itself — it may be a mount point)
	entries, err := os.ReadDir(CVEDir)
	if err == nil {
		for _, entry := range entries {
			os.RemoveAll(filepath.Join(CVEDir, entry.Name()))
		}
	}
	if err := os.MkdirAll(CVEDir, 0755); err != nil {
		return fmt.Errorf("failed to create CVE directory: %w", err)
	}

	// Extract the zip file
	fmt.Println("Extracting CVE database...")
	if err := extractZip(actualZip, CVEDir); err != nil {
		return fmt.Errorf("failed to extract CVE zip: %w", err)
	}

	fmt.Println("CVE database download complete")
	return nil
}

// downloadFile downloads a file from URL to the specified path
func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// extractZip extracts a zip file to the specified directory
func extractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Count files for progress
	totalFiles := len(reader.File)
	extracted := 0

	for _, file := range reader.File {
		// Skip the root directory in the zip (usually cvelistV5-main or similar)
		parts := strings.SplitN(file.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		relativePath := parts[1]
		if relativePath == "" {
			continue
		}

		destPath := filepath.Join(destDir, relativePath)

		// Security check: ensure path is within destDir
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}

		// Extract file
		srcFile, err := file.Open()
		if err != nil {
			return err
		}

		destFile, err := os.Create(destPath)
		if err != nil {
			srcFile.Close()
			return err
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()

		if err != nil {
			return err
		}

		extracted++
		if extracted%50000 == 0 {
			fmt.Printf("Extracted %d/%d files...\n", extracted, totalFiles)
		}
	}

	fmt.Printf("Extracted %d files\n", extracted)
	return nil
}

// checkAndDownloadData checks if data exists and downloads if needed
func (app *App) checkAndDownloadData() error {
	kevExists := false
	cveExists := false

	// Check if KEV file exists
	if _, err := os.Stat(KEVPath); err == nil {
		kevExists = true
	}

	// Check if CVE directory exists and has files
	if info, err := os.Stat(CVEDir); err == nil && info.IsDir() {
		// Check if there are any JSON files
		files := app.findAllCVEFiles()
		cveExists = len(files) > 0
	}

	// Download missing data
	if !kevExists {
		fmt.Println("KEV catalog not found, downloading...")
		if err := app.downloadKEV(); err != nil {
			return fmt.Errorf("failed to download KEV: %w", err)
		}
	}

	if !cveExists {
		fmt.Println("CVE database not found, downloading...")
		if err := app.downloadCVEs(); err != nil {
			return fmt.Errorf("failed to download CVEs: %w", err)
		}
	}

	return nil
}

// startUpdateScheduler starts a background goroutine that updates data weekly
func (app *App) startUpdateScheduler() {
	go func() {
		ticker := time.NewTicker(UpdateInterval)
		defer ticker.Stop()

		for range ticker.C {
			fmt.Println("Starting scheduled data update...")
			app.performUpdate()
		}
	}()
	fmt.Printf("Update scheduler started (interval: %v)\n", UpdateInterval)
}

// performUpdate downloads new data and reloads the application state
func (app *App) performUpdate() {
	updateSuccess := false

	// Download KEV
	if err := app.downloadKEV(); err != nil {
		fmt.Printf("Error updating KEV catalog: %v\n", err)
	} else {
		// Reload KEV data
		app.mu.Lock()
		app.kevIndex = make(map[string]*KEVEntry)
		if err := app.loadKEV(); err != nil {
			fmt.Printf("Error reloading KEV catalog: %v\n", err)
		} else {
			fmt.Printf("Reloaded %d KEV entries\n", len(app.kevIndex))
			updateSuccess = true
		}
		// Reapply KEV status to existing CVEs
		app.applyKEVStatus()
		app.buildIndexes()
		app.mu.Unlock()
	}

	// Download CVEs
	if err := app.downloadCVEs(); err != nil {
		fmt.Printf("Error updating CVE database: %v\n", err)
	} else {
		// Remove old cache to force rebuild
		os.Remove(CachePath)

		// Reload CVEs
		app.mu.Lock()
		app.cves = nil
		app.cveIndex = make(map[string]*CVE)
		if err := app.loadCVEs(); err != nil {
			fmt.Printf("Error reloading CVE database: %v\n", err)
		} else {
			app.buildIndexes()
			fmt.Printf("Reloaded %d CVEs (%d in CISA KEV)\n", len(app.cves), app.cachedStats.TotalKEV)
			updateSuccess = true
		}
		app.mu.Unlock()
	}

	// Update the last update timestamp if successful
	if updateSuccess {
		app.mu.Lock()
		app.lastDataUpdate = time.Now()
		app.mu.Unlock()
	}

	fmt.Println("Scheduled update complete")
}

func (app *App) loadCache() (*Cache, error) {
	file, err := os.Open(CachePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cache Cache
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

func (app *App) saveCache() error {
	file, err := os.Create(CachePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileIndex := make(map[string]string)
	for _, cve := range app.cves {
		fileIndex[cve.FilePath] = cve.ID
	}

	cache := Cache{
		Version:   CacheVersion,
		BuildTime: time.Now(),
		CVEs:      app.cves,
		FileIndex: fileIndex,
	}

	encoder := gob.NewEncoder(file)
	return encoder.Encode(&cache)
}

func (app *App) verifyCacheIntegrity(cache *Cache) (missing map[string]bool, newFiles []string) {
	missing = make(map[string]bool)

	// Check all cached files still exist
	for filePath := range cache.FileIndex {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			missing[filePath] = true
		}
	}

	// Find new files not in cache
	currentFiles := app.findAllCVEFiles()
	for _, file := range currentFiles {
		if _, exists := cache.FileIndex[file]; !exists {
			newFiles = append(newFiles, file)
		}
	}

	return missing, newFiles
}

func (app *App) findAllCVEFiles() []string {
	var files []string

	filepath.Walk(CVEDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") && strings.Contains(path, "CVE-") {
			files = append(files, path)
		}
		return nil
	})

	return files
}

func (app *App) loadCVEFiles(files []string) []CVE {
	// Use worker pool for parallel loading
	numWorkers := 8
	fileChan := make(chan string, len(files))
	resultChan := make(chan CVE, len(files))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				if cve, err := app.parseCVEFile(file); err == nil {
					resultChan <- cve
				}
			}
		}()
	}

	// Send files to workers
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var cves []CVE
	for cve := range resultChan {
		cves = append(cves, cve)
	}

	return cves
}

func (app *App) parseCVEFile(path string) (CVE, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CVE{}, err
	}

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

	// Parse dates
	dateFormats := []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}

	cve.DatePublished = parseDate(raw.CveMetadata.DatePublished, dateFormats)
	cve.DateUpdated = parseDate(raw.CveMetadata.DateUpdated, dateFormats)
	cve.DateReserved = parseDate(raw.CveMetadata.DateReserved, dateFormats)

	if !cve.DatePublished.IsZero() {
		cve.Year = cve.DatePublished.Year()
	} else if !cve.DateReserved.IsZero() {
		cve.Year = cve.DateReserved.Year()
	}

	// Extract all affected products
	for _, affected := range raw.Containers.Cna.Affected {
		var versions []string
		for _, v := range affected.Versions {
			if v.Version != "" {
				versions = append(versions, v.Version)
			}
		}
		ap := AffectedProduct{
			Vendor:   affected.Vendor,
			Product:  affected.Product,
			Versions: strings.Join(versions, ", "),
		}
		cve.AffectedProducts = append(cve.AffectedProducts, ap)
	}

	// Set primary vendor/product from first entry (for filtering compatibility)
	if len(cve.AffectedProducts) > 0 {
		cve.Vendor = cve.AffectedProducts[0].Vendor
		cve.Product = cve.AffectedProducts[0].Product
		cve.Versions = cve.AffectedProducts[0].Versions
	}

	// Extract title and description
	cve.Title = raw.Containers.Cna.Title
	for _, desc := range raw.Containers.Cna.Descriptions {
		if desc.Lang == "en" {
			cve.Description = desc.Value
			break
		}
	}
	if cve.Description == "" && len(raw.Containers.Cna.Descriptions) > 0 {
		cve.Description = raw.Containers.Cna.Descriptions[0].Value
	}

	// Extract CVSS metrics from CNA first, then ADP if not found
	// Priority: CVSS 3.1 > CVSS 3.0 > CVSS 4.0 > CVSS 2.0
	extractCvssFromMetrics(raw.Containers.Cna.Metrics, &cve)

	// If no CVSS found in CNA, check ADP containers
	if cve.BaseScore == 0 && len(raw.Containers.Adp) > 0 {
		for _, adp := range raw.Containers.Adp {
			extractCvssFromMetrics(adp.Metrics, &cve)
			if cve.BaseScore > 0 {
				break
			}
		}
	}

	// Extract CWE
	for _, pt := range raw.Containers.Cna.ProblemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CweId != "" {
				cve.CWE = desc.CweId
				cve.CWEDescription = desc.Description
				break
			} else if strings.HasPrefix(desc.Description, "CWE-") {
				parts := strings.SplitN(desc.Description, " ", 2)
				cve.CWE = parts[0]
				if len(parts) > 1 {
					cve.CWEDescription = parts[1]
				}
				break
			}
		}
		if cve.CWE != "" {
			break
		}
	}

	// Extract references
	for _, ref := range raw.Containers.Cna.References {
		cve.References = append(cve.References, Reference{
			URL:  ref.URL,
			Tags: ref.Tags,
		})
	}

	return cve, nil
}

func parseDate(s string, formats []string) time.Time {
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// extractCvssFromMetrics extracts CVSS data from metrics array
// Priority: CVSS 3.1 > CVSS 3.0 > CVSS 4.0 > CVSS 2.0
func extractCvssFromMetrics(metrics []MetricEntry, cve *CVE) {
	for _, metric := range metrics {
		// Prefer CVSS 3.1
		if metric.CvssV31 != nil {
			applyCvssMetrics(metric.CvssV31, cve)
			return
		}
	}

	for _, metric := range metrics {
		// Then CVSS 3.0
		if metric.CvssV30 != nil {
			applyCvssMetrics(metric.CvssV30, cve)
			return
		}
	}

	for _, metric := range metrics {
		// Then CVSS 4.0 (newer but less common)
		if metric.CvssV40 != nil {
			applyCvssMetrics(metric.CvssV40, cve)
			return
		}
	}

	for _, metric := range metrics {
		// Finally CVSS 2.0
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

// applyCvssMetrics applies CVSS metrics to the CVE struct
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

	// If severity is empty but we have a score, derive it
	if cve.BaseSeverity == "" && cve.BaseScore > 0 {
		cve.BaseSeverity = deriveSeverityFromScore(cve.BaseScore)
	}
}

// deriveSeverityFromScore derives severity rating from CVSS score
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

// buildIndexes rebuilds everything derived from app.cves; callers hold the write lock
func (app *App) buildIndexes() {
	app.orderMu.Lock()
	app.orders = nil
	app.orderMu.Unlock()
	app.buildFilterCaches()
	app.buildSearchIndex()
	app.buildStatsCache()
}

func (app *App) buildFilterCaches() {
	app.years = nil
	vendorCounts := make(map[string]int)
	productCounts := make(map[string]int)
	cweCounts := make(map[string]int)
	severitySet := make(map[string]bool)
	yearSet := make(map[int]bool)

	for i := range app.cves {
		cve := &app.cves[i]
		// Count every affected vendor/product once per CVE, not just the primary one
		seen := make(map[string]bool, len(cve.AffectedProducts)*2)
		for _, ap := range cve.AffectedProducts {
			if !isPlaceholderName(ap.Vendor) && !seen["v"+ap.Vendor] {
				seen["v"+ap.Vendor] = true
				vendorCounts[ap.Vendor]++
			}
			if !isPlaceholderName(ap.Product) && !seen["p"+ap.Product] {
				seen["p"+ap.Product] = true
				productCounts[ap.Product]++
			}
		}
		if cve.BaseSeverity != "" {
			severitySet[cve.BaseSeverity] = true
		}
		if cve.Year > 0 {
			yearSet[cve.Year] = true
		}
		if cve.CWE != "" {
			cweCounts[cve.CWE]++
		}
	}

	app.vendors = keysByCount(vendorCounts)
	app.products = keysByCount(productCounts)
	app.cwes = keysByCount(cweCounts)
	app.productCounts = productCounts
	app.severities = mapKeysToSlice(severitySet)
	sort.Strings(app.severities)

	for year := range yearSet {
		app.years = append(app.years, year)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(app.years)))
}

// keysByCount returns map keys ordered by descending count, then name
func keysByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// isPlaceholderName reports vendor/product values that carry no information
func isPlaceholderName(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "unknown", "unspecified", "-", "*":
		return true
	}
	return false
}

// rankMatches returns up to limit items containing search, prefix matches first,
// preserving the source order (most common first) within each group
func rankMatches(source []string, search string, limit int) []string {
	if search == "" {
		return source[:min(limit, len(source))]
	}
	var prefix, contains []string
	for _, item := range source {
		lower := strings.ToLower(item)
		if strings.HasPrefix(lower, search) {
			prefix = append(prefix, item)
			if len(prefix) >= limit {
				break
			}
		} else if len(contains) < limit && strings.Contains(lower, search) {
			contains = append(contains, item)
		}
	}
	out := append(prefix, contains...)
	return out[:min(limit, len(out))]
}

func mapKeysToSlice(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (app *App) handleGetCVE(c echo.Context) error {
	id := c.Param("id")

	app.mu.RLock()
	cve, exists := app.cveIndex[id]
	app.mu.RUnlock()

	if !exists {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
	}

	return c.JSON(http.StatusOK, cve)
}

func (app *App) buildStatsCache() {
	vendorCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	var minYear, maxYear int = 9999, 0
	var lastUpdated time.Time
	kevCount, kevRansomware, kevRecent := 0, 0, 0
	kevSince := time.Now().AddDate(0, 0, -30).Format("2006-01-02")

	for _, cve := range app.cves {
		vendorCounts[cve.Vendor]++
		if cve.BaseSeverity != "" {
			severityCounts[cve.BaseSeverity]++
		}
		if cve.Year > 0 && cve.Year < minYear {
			minYear = cve.Year
		}
		if cve.Year > maxYear {
			maxYear = cve.Year
		}
		if cve.DateUpdated.After(lastUpdated) {
			lastUpdated = cve.DateUpdated
		}
		if cve.InKEV {
			kevCount++
			if cve.KEVKnownRansomwareCampaign == "Known" {
				kevRansomware++
			}
			if cve.KEVDateAdded >= kevSince {
				kevRecent++
			}
		}
	}

	type kv struct {
		Key   string
		Value int
	}
	var sortedVendors []kv
	for k, v := range vendorCounts {
		if k != "" {
			sortedVendors = append(sortedVendors, kv{k, v})
		}
	}
	sort.Slice(sortedVendors, func(i, j int) bool {
		return sortedVendors[i].Value > sortedVendors[j].Value
	})

	topVendors := make([]VendorCount, 0, 10)
	for i := 0; i < len(sortedVendors) && i < 10; i++ {
		topVendors = append(topVendors, VendorCount{
			Vendor: sortedVendors[i].Key,
			Count:  sortedVendors[i].Value,
		})
	}

	app.cachedStats = &StatsResponse{
		TotalCVEs:      len(app.cves),
		LastUpdated:    lastUpdated,
		LastDataUpdate: app.lastDataUpdate,
		YearRange:      [2]int{minYear, maxYear},
		TopVendors:     topVendors,
		SeverityCounts: severityCounts,
		TotalKEV:       kevCount,
		KEVRansomware:  kevRansomware,
		KEVLast30Days:  kevRecent,
		KEVCatalogDate: app.kevCatalogDate,
	}
}

func (app *App) handleGetStats(c echo.Context) error {
	app.mu.RLock()
	defer app.mu.RUnlock()

	if app.cachedStats == nil {
		return c.JSON(http.StatusOK, StatsResponse{})
	}

	// Copy cached stats and add dynamic fields
	stats := *app.cachedStats
	stats.LastDataUpdate = app.lastDataUpdate

	nextUpdate := app.lastDataUpdate.Add(UpdateInterval)
	timeUntilNext := time.Until(nextUpdate)
	if timeUntilNext > 0 {
		days := int(timeUntilNext.Hours() / 24)
		hours := int(timeUntilNext.Hours()) % 24
		if days > 0 {
			stats.NextUpdateIn = fmt.Sprintf("%dd %dh", days, hours)
		} else {
			stats.NextUpdateIn = fmt.Sprintf("%dh", hours)
		}
	} else {
		stats.NextUpdateIn = "soon"
	}

	return c.JSON(http.StatusOK, stats)
}

func (app *App) handleGetOptions(c echo.Context) error {
	app.mu.RLock()
	defer app.mu.RUnlock()

	options := FilterOptions{
		Vendors:       app.vendors,
		Products:      app.products,
		Severities:    app.severities,
		Years:         app.years,
		CWEs:          app.cwes,
		AttackVectors: []string{"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
	}

	return c.JSON(http.StatusOK, options)
}

// SearchOptionsRequest for searching vendors/products
type SearchOptionsRequest struct {
	Field   string   `json:"field"`
	Search  string   `json:"search"`
	Limit   int      `json:"limit"`
	Vendor  string   `json:"vendor"`  // Optional: filter products by single vendor (legacy)
	Vendors []string `json:"vendors"` // Optional: filter products by multiple vendors
}

func (app *App) handleSearchOptions(c echo.Context) error {
	var req SearchOptionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 200 {
		req.Limit = 200
	}

	app.mu.RLock()
	defer app.mu.RUnlock()

	search := strings.ToLower(strings.TrimSpace(req.Search))

	vendors := req.Vendors
	if req.Vendor != "" && len(vendors) == 0 {
		vendors = []string{req.Vendor}
	}

	// Products scoped to the selected vendors
	if req.Field == "product" && len(vendors) > 0 {
		productSet := make(map[string]bool)
		for _, cve := range app.cves {
			for _, ap := range cve.AffectedProducts {
				if !isPlaceholderName(ap.Product) && containsFold(vendors, ap.Vendor) {
					productSet[ap.Product] = true
				}
			}
		}
		scoped := make(map[string]int, len(productSet))
		for p := range productSet {
			scoped[p] = app.productCounts[p]
		}
		return c.JSON(http.StatusOK, rankMatches(keysByCount(scoped), search, req.Limit))
	}

	var source []string
	switch req.Field {
	case "vendor":
		source = app.vendors
	case "product":
		source = app.products
	case "cwe":
		source = app.cwes
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid field"})
	}

	return c.JSON(http.StatusOK, rankMatches(source, search, req.Limit))
}

func (app *App) handleExportXLS(c echo.Context) error {
	var req FilterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	app.mu.RLock()
	matches, _ := app.filterCVEs(&req, false)
	// Limit export to 10000 rows
	if len(matches) > 10000 {
		matches = matches[:10000]
	}
	filtered := make([]CVE, len(matches))
	for n, i := range matches {
		filtered[n] = app.cves[i]
	}
	app.mu.RUnlock()

	// Create Excel file
	f := excelize.NewFile()
	defer f.Close()

	sheetName := "CVEs"
	f.SetSheetName("Sheet1", sheetName)

	// Headers
	headers := []string{"CVE ID", "Year", "Vendor", "Product", "Title", "Severity", "Score", "Attack Vector", "CVSS Vector", "CWE", "Published", "In KEV", "KEV Date Added", "KEV Due Date", "KEV Required Action", "KEV Ransomware", "Description"}
	colWidths := []float64{16, 6, 18, 18, 30, 10, 7, 14, 40, 12, 12, 7, 14, 14, 40, 12, 60}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheetName, cell, h)
	}

	// Style for header
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
	})
	f.SetRowStyle(sheetName, 1, 1, headerStyle)

	// Data rows
	for i, cve := range filtered {
		row := i + 2
		f.SetCellValue(sheetName, cellName(1, row), cve.ID)
		f.SetCellValue(sheetName, cellName(2, row), cve.Year)
		f.SetCellValue(sheetName, cellName(3, row), cve.Vendor)
		f.SetCellValue(sheetName, cellName(4, row), cve.Product)
		title := cve.Title
		if title == "" {
			title = cve.KEVVulnerabilityName
		}
		f.SetCellValue(sheetName, cellName(5, row), title)
		f.SetCellValue(sheetName, cellName(6, row), cve.BaseSeverity)
		f.SetCellValue(sheetName, cellName(7, row), cve.BaseScore)
		f.SetCellValue(sheetName, cellName(8, row), cve.AttackVector)
		f.SetCellValue(sheetName, cellName(9, row), cve.VectorString)
		f.SetCellValue(sheetName, cellName(10, row), cve.CWE)
		f.SetCellValue(sheetName, cellName(11, row), cve.DatePublished.Format("2006-01-02"))
		kevStr := ""
		if cve.InKEV {
			kevStr = "Yes"
		}
		f.SetCellValue(sheetName, cellName(12, row), kevStr)
		f.SetCellValue(sheetName, cellName(13, row), cve.KEVDateAdded)
		f.SetCellValue(sheetName, cellName(14, row), cve.KEVDueDate)
		f.SetCellValue(sheetName, cellName(15, row), cve.KEVRequiredAction)
		f.SetCellValue(sheetName, cellName(16, row), cve.KEVKnownRansomwareCampaign)

		desc := cve.Description
		if len(desc) > 1000 {
			desc = desc[:1000] + "..."
		}
		f.SetCellValue(sheetName, cellName(17, row), desc)
	}

	// Set column widths
	for i, w := range colWidths {
		col, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(sheetName, col, col, w)
	}

	// Generate filename with timestamp
	filename := "cve_export_" + time.Now().Format("20060102_150405") + ".xlsx"

	c.Response().Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Response().Header().Set("Content-Disposition", "attachment; filename="+filename)

	return f.Write(c.Response().Writer)
}

func cellName(col, row int) string {
	name, _ := excelize.CoordinatesToCellName(col, row)
	return name
}
