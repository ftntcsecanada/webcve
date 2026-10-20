package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/xuri/excelize/v2"
)

// requireData answers 503 until the first dataset is published
func (app *App) requireData(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if app.dataset() == nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "loading", "status": app.statusString()})
		}
		return next(c)
	}
}

func (app *App) handleHealth(c echo.Context) error {
	resp := map[string]any{"status": app.statusString()}
	if ds := app.dataset(); ds != nil {
		resp["cves"] = len(ds.CVEs)
		if src := app.sourceTimes.Load(); src != nil {
			resp["sources"] = src.Times
			resp["cveDelta"] = src.CVEDelta
		}
	}
	return c.JSON(http.StatusOK, resp)
}

func (app *App) handleFilterCVEs(c echo.Context) error {
	start := time.Now()
	var req FilterRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if req.PageSize <= 0 {
		req.PageSize = 50
	}
	req.PageSize = min(req.PageSize, 500)
	req.Page = max(req.Page, 1)

	ds := app.dataset()
	f := compileFilter(ds, req)
	matches, resp := ds.filterCVEs(f, !req.CountOnly)
	// An exact CVE ID search shows that CVE first, ahead of records that mention it
	if id := strings.ToUpper(strings.TrimSpace(req.Search)); cveIDRe.MatchString(id) {
		if want, ok := ds.byID[id]; ok {
			if n := slices.Index(matches, want); n > 0 {
				copy(matches[1:n+1], matches[:n])
				matches[0] = want
			}
		}
	}
	resp.Total = len(matches)
	resp.TookMs = float64(time.Since(start).Microseconds()) / 1000
	if req.CountOnly {
		return c.JSON(http.StatusOK, map[string]any{"total": resp.Total, "tookMs": resp.TookMs})
	}

	from := min((req.Page-1)*req.PageSize, resp.Total)
	to := min(from+req.PageSize, resp.Total)
	resp.CVEs = make([]CVESummary, 0, to-from)
	for _, i := range matches[from:to] {
		resp.CVEs = append(resp.CVEs, ds.summarize(i, f))
	}
	resp.Page = req.Page
	resp.PageSize = req.PageSize
	resp.TotalPages = (resp.Total + req.PageSize - 1) / req.PageSize
	resp.TookMs = float64(time.Since(start).Microseconds()) / 1000
	return c.JSON(http.StatusOK, resp)
}

func (app *App) handleGetCVE(c echo.Context) error {
	ds := app.dataset()
	i, ok := ds.byID[strings.ToUpper(c.Param("id"))]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
	}
	cve := &ds.CVEs[i]
	return c.JSON(http.StatusOK, struct {
		*CVE
		ExploitEvidence []Evidence `json:"exploitEvidence"`
	}{cve, exploitEvidence(cve)})
}

// handleRelated returns other CVEs for the same products, and with the same
// weakness from the same vendor, newest first
func (app *App) handleRelated(c echo.Context) error {
	ds := app.dataset()
	i, ok := ds.byID[strings.ToUpper(c.Param("id"))]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
	}
	const limit = 8
	self := &ds.CVEs[i]
	vk, pk := ds.vendorKeys[i], ds.productKeys[i]

	var sameProduct, sameWeakness []int
	productTotal, weaknessTotal := 0, 0
	order := ds.sortedOrder("datePublished")
	for n := len(order) - 1; n >= 0; n-- {
		j := order[n]
		if j == i {
			continue
		}
		if len(pk) > 0 && anyKeyIn(ds.productKeys[j], pk) && (len(vk) == 0 || anyKeyIn(ds.vendorKeys[j], vk)) {
			productTotal++
			if len(sameProduct) < limit {
				sameProduct = append(sameProduct, j)
			}
		} else if self.CWE != "" && ds.CVEs[j].CWE == self.CWE && len(vk) > 0 && anyKeyIn(ds.vendorKeys[j], vk) {
			weaknessTotal++
			if len(sameWeakness) < limit {
				sameWeakness = append(sameWeakness, j)
			}
		}
	}
	rows := func(idx []int) []CVESummary {
		out := make([]CVESummary, 0, len(idx))
		for _, j := range idx {
			out = append(out, ds.summarize(j, nil))
		}
		return out
	}
	return c.JSON(http.StatusOK, map[string]any{
		"sameProduct":       rows(sameProduct),
		"sameProductTotal":  productTotal,
		"sameWeakness":      rows(sameWeakness),
		"sameWeaknessTotal": weaknessTotal,
	})
}

// handleEPSSHistory proxies FIRST's EPSS time series for one CVE
func (app *App) handleEPSSHistory(c echo.Context) error {
	id := strings.ToUpper(c.Param("id"))
	if !cveIDRe.MatchString(id) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid CVE ID"})
	}
	points, err := app.epssHistory(id)
	if err != nil {
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "EPSS history unavailable"})
	}
	return c.JSON(http.StatusOK, points)
}

func (app *App) handleGetStats(c echo.Context) error {
	ds := app.dataset()
	stats := ds.stats
	for _, s := range app.board.snapshot() {
		if s.State == "error" {
			stats.SourceErrors = append(stats.SourceErrors, s.Label)
		}
	}
	if src := app.sourceTimes.Load(); src != nil {
		stats.Sources = src.Times
		stats.CVEDelta = src.CVEDelta
		stats.LastDataUpdate = src.Times["cve"]
		next := time.Until(stats.LastDataUpdate.Add(DeltaInterval))
		if next > 0 {
			stats.NextUpdateIn = fmt.Sprintf("%dm", int(next.Minutes())+1)
		} else {
			stats.NextUpdateIn = "soon"
		}
	}
	return c.JSON(http.StatusOK, stats)
}

// SearchOptionsRequest for searching vendors/products/CWEs
type SearchOptionsRequest struct {
	Field   string   `json:"field"`
	Search  string   `json:"search"`
	Limit   int      `json:"limit"`
	Vendors []string `json:"vendors"` // Optional: scope products to these vendors
}

func (app *App) handleSearchOptions(c echo.Context) error {
	var req SearchOptionsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if req.Limit <= 0 {
		req.Limit = 50
	}
	req.Limit = min(req.Limit, 200)
	ds := app.dataset()

	var source []Option
	switch req.Field {
	case "vendor":
		source = ds.vendors
	case "cwe":
		source = ds.cwes
	case "product":
		source = ds.products
		if len(req.Vendors) > 0 {
			source = ds.productsForVendors(req.Vendors)
		}
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid field"})
	}

	ranked := rankOptions(source, req.Search, req.Limit)
	names := make([]string, len(ranked))
	for i, o := range ranked {
		names[i] = o.Name
	}
	return c.JSON(http.StatusOK, names)
}

// productsForVendors lists products of the given vendors, most common first
func (ds *Dataset) productsForVendors(vendors []string) []Option {
	var keys []string
	for _, v := range vendors {
		keys = append(keys, normalizeVendor(v))
	}
	counts := map[string]int{}
	for i := range ds.CVEs {
		if anyKeyIn(ds.vendorKeys[i], keys) {
			for _, p := range ds.productKeys[i] {
				counts[p]++
			}
		}
	}
	out := make([]Option, 0, len(counts))
	for _, o := range ds.products {
		if n, ok := counts[o.Key]; ok {
			out = append(out, Option{Key: o.Key, Name: o.Name, Count: n})
		}
	}
	sortOptions(out)
	return out
}

// ---- Export ----

const exportLimit = 10000

var exportHeaders = []string{
	"CVE ID", "Year", "Vendor", "Product", "Title", "Severity", "Score", "CVSS Version", "Attack Vector",
	"CVSS Vector", "EPSS", "EPSS Percentile", "Exploit Evidence", "CWE", "Published", "Updated",
	"In KEV", "KEV Date Added", "KEV Due Date", "KEV Required Action", "KEV Ransomware", "Description",
}

func exportRow(cve *CVE) []any {
	title := cve.Title
	if title == "" {
		title = cve.KEVVulnerabilityName
	}
	desc := cve.Description
	if len(desc) > 2000 {
		desc = strings.ToValidUTF8(desc[:2000], "") + "…"
	}
	yesNo := func(b bool) string {
		if b {
			return "Yes"
		}
		return ""
	}
	return []any{
		cve.ID, cve.Year, cve.Vendor, cve.Product, title, cve.BaseSeverity, cve.BaseScore, cve.CvssVersion,
		normalizeAttackVector(cve.AttackVector), cve.VectorString, cve.EPSS, cve.EPSSPercentile, yesNo(cve.PublicExploit),
		cve.CWE, cve.DatePublished.Format("2006-01-02"), cve.DateUpdated.Format("2006-01-02"),
		yesNo(cve.InKEV), cve.KEVDateAdded, cve.KEVDueDate, cve.KEVRequiredAction, cve.KEVKnownRansomwareCampaign, desc,
	}
}

func (app *App) handleExport(c echo.Context) error {
	var req FilterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	format := c.QueryParam("format")
	ds := app.dataset()
	matches, _ := ds.filterCVEs(compileFilter(ds, req), false)
	matches = matches[:min(len(matches), exportLimit)]

	stamp := time.Now().Format("20060102_150405")
	res := c.Response()
	switch format {
	case "csv":
		res.Header().Set("Content-Type", "text/csv; charset=utf-8")
		res.Header().Set("Content-Disposition", `attachment; filename="cve_export_`+stamp+`.csv"`)
		w := csv.NewWriter(res.Writer)
		w.Write(exportHeaders)
		for _, i := range matches {
			row := exportRow(&ds.CVEs[i])
			rec := make([]string, len(row))
			for n, v := range row {
				rec[n] = csvCell(v)
			}
			w.Write(rec)
		}
		w.Flush()
		return w.Error()
	case "json":
		res.Header().Set("Content-Type", "application/json")
		res.Header().Set("Content-Disposition", `attachment; filename="cve_export_`+stamp+`.json"`)
		out := make([]*CVE, len(matches))
		for n, i := range matches {
			out[n] = &ds.CVEs[i]
		}
		return json.NewEncoder(res.Writer).Encode(out)
	}

	f := excelize.NewFile()
	defer f.Close()
	sheet := "CVEs"
	f.SetSheetName("Sheet1", sheet)
	sw, err := f.NewStreamWriter(sheet)
	if err != nil {
		return err
	}
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#3355D6"}, Pattern: 1},
	})
	widths := []float64{16, 6, 18, 18, 40, 10, 7, 8, 12, 40, 8, 10, 9, 12, 12, 12, 7, 14, 14, 40, 12, 80}
	for n, w := range widths {
		sw.SetColWidth(n+1, n+1, w)
	}
	header := make([]any, len(exportHeaders))
	for n, h := range exportHeaders {
		header[n] = excelize.Cell{StyleID: headerStyle, Value: h}
	}
	sw.SetRow("A1", header)
	for n, i := range matches {
		cell, _ := excelize.CoordinatesToCellName(1, n+2)
		sw.SetRow(cell, exportRow(&ds.CVEs[i]))
	}
	if err := sw.Flush(); err != nil {
		return err
	}
	res.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	res.Header().Set("Content-Disposition", `attachment; filename="cve_export_`+stamp+`.xlsx"`)
	return f.Write(res.Writer)
}

// csvCell formats a value for CSV, neutralizing spreadsheet formula injection
func csvCell(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		s = fmt.Sprint(x)
	}
	if s != "" && slices.Contains([]byte("=+-@\t\r"), s[0]) {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			s = "'" + s
		}
	}
	return s
}
