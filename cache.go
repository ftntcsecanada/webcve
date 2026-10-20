package main

import (
	"encoding/gob"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Cache is the on-disk GOB snapshot of parsed CVEs
type Cache struct {
	Version   int
	BuildTime time.Time
	CVEs      []CVE
}

// loadCVEs returns parsed CVEs, reusing the cache for files that haven't
// changed since it was written and parsing the rest
func loadCVEs() ([]CVE, error) {
	start := time.Now()
	files := findCVEFiles()

	cache, err := loadCache()
	if err != nil || cache.Version != CacheVersion {
		logf("No usable cache, parsing %d CVE files...", len(files))
		cves := parseCVEFiles(pathsOf(files))
		if err := saveCache(cves); err != nil {
			logf("Warning: could not save cache: %v", err)
		}
		logf("Parsed %d CVEs in %s", len(cves), time.Since(start).Round(time.Second))
		return cves, nil
	}

	// Files modified after the cache was written (or unknown to it) need parsing
	cached := make(map[string]int, len(cache.CVEs))
	for i := range cache.CVEs {
		cached[cache.CVEs[i].FilePath] = i
	}
	var stale []string
	onDisk := make(map[string]bool, len(files))
	for _, f := range files {
		onDisk[f.path] = true
		if _, ok := cached[f.path]; !ok || f.mod.After(cache.BuildTime) {
			stale = append(stale, f.path)
		}
	}

	cves := make([]CVE, 0, len(files))
	staleSet := make(map[string]bool, len(stale))
	for _, p := range stale {
		staleSet[p] = true
	}
	removed := 0
	for i := range cache.CVEs {
		c := &cache.CVEs[i]
		switch {
		case !onDisk[c.FilePath]:
			removed++
		case !staleSet[c.FilePath]:
			cves = append(cves, *c)
		}
	}
	if len(stale) > 0 {
		logf("Cache: parsing %d new or changed files", len(stale))
		cves = append(cves, parseCVEFiles(stale)...)
	}
	if len(stale) > 0 || removed > 0 {
		if err := saveCache(cves); err != nil {
			logf("Warning: could not save cache: %v", err)
		}
	}
	logf("Loaded %d CVEs (%d reparsed, %d removed) in %s", len(cves), len(stale), removed, time.Since(start).Round(time.Second))
	return cves, nil
}

type cveFile struct {
	path string
	mod  time.Time
}

func pathsOf(files []cveFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

func findCVEFiles() []cveFile {
	var files []cveFile
	filepath.WalkDir(CVEDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "CVE-") && strings.HasSuffix(name, ".json") {
			if info, err := d.Info(); err == nil {
				files = append(files, cveFile{path, info.ModTime()})
			}
		}
		return nil
	})
	return files
}

func parseCVEFiles(paths []string) []CVE {
	results := make([]CVE, len(paths))
	ok := make([]bool, len(paths))
	var wg sync.WaitGroup
	next := make(chan int, 1024)
	for w := 0; w < max(4, runtime.NumCPU()); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if cve, err := parseCVEFile(paths[i]); err == nil && cve.ID != "" {
					results[i], ok[i] = cve, true
				}
			}
		}()
	}
	for i := range paths {
		next <- i
	}
	close(next)
	wg.Wait()

	out := results[:0]
	for i := range results {
		if ok[i] {
			out = append(out, results[i])
		}
	}
	return out
}

func loadCache() (*Cache, error) {
	f, err := os.Open(CachePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cache Cache
	if err := gob.NewDecoder(f).Decode(&cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

// saveCache writes the cache. It writes in place rather than via rename
// because the cache file is commonly bind-mounted as a single file.
func saveCache(cves []CVE) error {
	f, err := os.Create(CachePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(&Cache{Version: CacheVersion, BuildTime: time.Now(), CVEs: cves})
}
