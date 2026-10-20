package main

import (
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	app := newApp()

	// Serve immediately; data loads in the background and the UI shows progress
	go app.bootstrap()

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod: true, LogURI: true, LogStatus: true, LogLatency: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logf("%s %s %d %s", v.Method, v.URI, v.Status, v.Latency)
			return nil
		},
		Skipper: func(c echo.Context) bool { return c.Path() == "/api/health" },
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.Gzip())

	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		HTML5: true,
		Index: "index.html",
		Root:  "site",
	}))

	api := e.Group("/api")
	api.GET("/health", app.handleHealth)
	data := api.Group("", app.requireData)
	data.POST("/cves", app.handleFilterCVEs)
	data.GET("/cves/:id", app.handleGetCVE)
	data.GET("/cves/:id/related", app.handleRelated)
	data.GET("/stats", app.handleGetStats)
	data.POST("/options/search", app.handleSearchOptions)
	data.POST("/export", app.handleExport)

	addr := ":3000"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	logf("Listening on %s", addr)
	e.Logger.Fatal(e.Start(addr))
}
