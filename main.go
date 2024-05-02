package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

type filter struct {
	Field    string `json:"field"`
	Value    string `json:"value"`
	Operator string `json:"operator"`
}

type cve struct {
	Containers struct {
		Cna struct {
			Metrics []struct {
				CvssV31 struct {
					AttackComplexity      string  `json:"attackComplexity"`
					AttackVector          string  `json:"attackVector"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					ExploitCodeMaturity   string  `json:"exploitCodeMaturity"`
					IntegrityImpact       string  `json:"integrityImpact"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					RemediationLevel      string  `json:"remediationLevel"`
					ReportConfidence      string  `json:"reportConfidence"`
					Scope                 string  `json:"scope"`
					TemporalScore         float64 `json:"temporalScore"`
					TemporalSeverity      string  `json:"temporalSeverity"`
					UserInteraction       string  `json:"userInteraction"`
					VectorString          string  `json:"vectorString"`
					Version               string  `json:"version"`
				} `json:"cvssV3_1"`
			} `json:"metrics"`
			Affected []struct {
				Product  string `json:"product"`
				Vendor   string `json:"vendor"`
				Versions []struct {
					Status  string `json:"status"`
					Version string `json:"version"`
				} `json:"versions"`
			} `json:"affected"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			ProblemTypes []struct {
				Descriptions []struct {
					Description string `json:"description"`
					Lang        string `json:"lang"`
					Type        string `json:"type"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			ProviderMetadata struct {
				DateUpdated string `json:"dateUpdated"`
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
			} `json:"providerMetadata"`
			References []struct {
				Tags []string `json:"tags"`
				URL  string   `json:"url"`
			} `json:"references"`
			XLegacyV4Record struct {
				CVEDataMeta struct {
					Assigner string `json:"ASSIGNER"`
					ID       string `json:"ID"`
					State    string `json:"STATE"`
				} `json:"CVE_data_meta"`
				Affects struct {
					Vendor struct {
						VendorData []struct {
							Product struct {
								ProductData []struct {
									ProductName string `json:"product_name"`
									Version     struct {
										VersionData []struct {
											VersionValue string `json:"version_value"`
										} `json:"version_data"`
									} `json:"version"`
								} `json:"product_data"`
							} `json:"product"`
							VendorName string `json:"vendor_name"`
						} `json:"vendor_data"`
					} `json:"vendor"`
				} `json:"affects"`
				DataFormat  string `json:"data_format"`
				DataType    string `json:"data_type"`
				DataVersion string `json:"data_version"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
				Problemtype struct {
					ProblemtypeData []struct {
						Description []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"description"`
					} `json:"problemtype_data"`
				} `json:"problemtype"`
				References struct {
					ReferenceData []struct {
						Name      string `json:"name"`
						Refsource string `json:"refsource"`
						URL       string `json:"url"`
					} `json:"reference_data"`
				} `json:"references"`
			} `json:"x_legacyV4Record"`
		} `json:"cna"`
	} `json:"containers"`
	CveMetadata struct {
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		CveID             string `json:"cveId"`
		DatePublished     string `json:"datePublished"`
		DateReserved      string `json:"dateReserved"`
		DateUpdated       string `json:"dateUpdated"`
		State             string `json:"state"`
	} `json:"cveMetadata"`
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Description string `json:"description"`
	Vendor      string `json:"vendor"`
	Severity    string `json:"severity"`
}

type App struct {
	cves    []cve
	Filters []string
}

type CveResponse struct {
	Cves    []cve               `json:"cves"`
	Options map[string][]string `json:"options"`
}

func main() {
	cveFiles := "../cvelistV5/cves" // Directory containing CVE JSON files
	var a App

	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.AttackVector")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.AvailabilityImpact")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.BaseSeverity")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.ConfidentialityImpact")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.ExploitCodeMaturity")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.IntegrityImpact")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.PrivilegesRequired")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.RemediationLevel")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.ReportConfidence")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.UserInteraction")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.TemporalSeverity")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.VectorString")
	a.Filters = append(a.Filters, "Containers.Cna.Metrics.CvssV31.Version")
	a.Filters = append(a.Filters, "Containers.Cna.Descriptions.Value")
	a.Filters = append(a.Filters, "Containers.Cna.Affected.Product")
	a.Filters = append(a.Filters, "Containers.Cna.Affected.Vendor")
	a.Filters = append(a.Filters, "Containers.Cna.Affected.Versions")

	cvenum := 0
	err := filepath.Walk(cveFiles, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Printf("Failed to read %s: %s\n", path, err)
				return nil // returning nil to continue processing other files
			}
			var cveData cve
			if err := json.Unmarshal(data, &cveData); err != nil {
				fmt.Printf("Failed to parse JSON from %s: %s\n", path, err)
				return nil
			}

			a.cves = append(a.cves, cveData)
			cvenum++
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking the path %q: %v\n", cveFiles, err)
		return
	}

	// Print or process the parsed CVE data
	fmt.Println("Successfully parsed CVEs:", len(a.cves))

	mainrouter := echo.New()

	mainrouter.Use(middleware.Logger())
	mainrouter.Use(middleware.Recover())

	mainrouter.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		HTML5:  true,
		Index:  "index.html",
		Browse: false,
		Root:   "site", // because files are located in `web` directory in `webAssets` fs
	}))
	api := mainrouter.Group("/api")
	api.POST("/cves", a.GetCves)

	mainrouter.Logger.Fatal(mainrouter.Start(":3000"))

}

func (a *App) GetCves(c echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return err
	}
	params := []filter{}
	err = json.Unmarshal(body, &params)
	if err != nil {
		return err
	}

	var filteredCves []cve
	var fortinetCves []cve
	for _, cve := range a.cves {
		include := false
		for _, v := range cve.Containers.Cna.Affected {
			if v.Vendor == "Fortinet" {
				include = true
				break
			}
		}
		if include {
			fortinetCves = append(fortinetCves, cve)
		}
	}
	for _, cve := range fortinetCves {
		include := true

		for _, p := range params {
			dateformats := []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05Z"}
			field := reflect.ValueOf(cve)
			fieldexists := true
			for _, v := range strings.Split(p.Field, ".") {
				if field.IsValid() && field.Kind() == reflect.Slice {
					field = field.Index(0)
				}
				if field.IsValid() && field.Kind() == reflect.Struct {
					field = field.FieldByName(v)
					if !field.IsValid() {
						fieldexists = false

						fmt.Printf("Field %s not found in the structure\n", v)
					}
				} else {
					fieldexists = false
					fmt.Printf("Field navigation error before accessing %s\n", v)
				}
			}
			if !fieldexists {
				continue
			}
			switch p.Operator {
			case "eq":
				if field.String() != p.Value {
					include = false

				}
			case "ne":
				if field.String() == p.Value {

					include = false

				}
			case "inc":
				if !strings.Contains(strings.ToUpper(field.String()), strings.ToUpper(p.Value)) {
					include = false
					break
				}
			case "ninc":
				if strings.Contains(strings.ToUpper(field.String()), strings.ToUpper(p.Value)) {
					include = false
					break
				}
			case "gt":
				if p.Field == "CveMetadata.DateReserved" {
					filterRawDate, _ := strconv.Atoi(p.Value)
					filterdate := time.Unix(int64(filterRawDate)/1000, 0)
					cvedatestring := reflect.ValueOf(cve).FieldByName("CveMetadata").FieldByName("DateReserved").String()
					var cvedate time.Time
					for _, dateformat := range dateformats {
						cvedate, err = time.Parse(dateformat, cvedatestring)
						if err == nil {
							break
						}
					}
					if err != nil {
						fmt.Println(err)
						break
					}
					if !cvedate.After(filterdate) {
						include = false
					}
				}
			case "lt":
				if p.Field == "CveMetadata.DateReserved" {
					cvedatestring := reflect.ValueOf(cve).FieldByName("CveMetadata").FieldByName("DateReserved").String()
					var cvedate time.Time
					filterRawDate, _ := strconv.Atoi(p.Value)
					filterdate := time.Unix(int64(filterRawDate)/1000, 0)
					for _, dateformat := range dateformats {
						cvedate, err = time.Parse(dateformat, cvedatestring)
						if err == nil {
							break
						}
					}
					if err != nil {
						fmt.Println(err)
						break
					}
					if !cvedate.Before(filterdate) {
						include = false

					}
				}
			}
			if !include {
				break
			}

		}
		if include {
			filteredCves = append(filteredCves, cve)
		}
	}
	fmt.Println("Filtered CVEs: ", len(filteredCves))

	options := make(map[string][]string)

	for _, cve := range filteredCves {
		for _, f := range a.Filters {
			field := reflect.ValueOf(cve)
			fieldexists := true
			for _, v := range strings.Split(f, ".") {
				if field.IsValid() && field.Kind() == reflect.Slice {
					field = field.Index(0)
				}
				if field.IsValid() && field.Kind() == reflect.Struct {
					field = field.FieldByName(v)
					if !field.IsValid() {
						fieldexists = false

						fmt.Printf("Field %s not found in the structure\n", v)
					}
				} else {
					fieldexists = false
					fmt.Printf("Field navigation error before accessing %s\n", v)
				}
			}
			if !fieldexists {
				continue
			}

			if field.Kind() == reflect.Slice {
				for i := 0; i < field.Len(); i++ {
					if !StringInSlice(field.Index(i).String(), options[f]) {
						options[f] = append(options[f], field.Index(i).String())
					}
				}
			} else {
				if !StringInSlice(field.String(), options[f]) {
					options[f] = append(options[f], field.String())
				}
			}
		}
	}
	response := CveResponse{Cves: filteredCves, Options: options}
	return c.JSON(http.StatusOK, response)

}

func inspect(t reflect.Type, path string) []map[string]interface{} {
	var fields []map[string]interface{}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldType := field.Type
		fieldPath := path + field.Name

		// Check if the field is a struct and recurse
		if fieldType.Kind() == reflect.Struct {
			nestedFields := inspect(fieldType, fieldPath+".")
			fields = append(fields, map[string]interface{}{
				"name":   fieldPath,
				"type":   fieldType.String(),
				"nested": nestedFields,
			})
		} else {
			fields = append(fields, map[string]interface{}{
				"name": fieldPath,
				"type": fieldType.String(),
			})
		}
	}
	return fields
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
