package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Signature readiness: whether a signature team can work on a CVE today, from
// facts in the data rather than an AI judgment. A CVE can carry severe global
// risk and still offer nothing to build on (a closed-source Patch Tuesday fix
// with no public details), and it becomes workable the day a PoC appears.
//
//	ready          public exploit code, a scanner template or PoC repos, or open
//	               source whose fix commit shows the trigger
//	needs_research coverable, but closed source with no public technical detail
//	not_feasible   triage found no Fortinet control that could see exploitation

// Repos that only detect: version checks, patch-level scanners, triage tools
var detectionOnly = regexp.MustCompile(`(?i)\b(detect(ion|or|s)?|scanner|checker|check(s|ing)? (if|whether|for)|version[- ]check|patch[- ]?(level|day)|triage|fingerprint|vulnerab\w* scan)`)

var (
	exploitWords        = regexp.MustCompile(`(?i)\b(exploit|rce|poc|proof[- ]of[- ]concept|payload|reverse[- ]shell|webshell|weaponi[sz]ed)`)
	explicitlyNoExploit = regexp.MustCompile(`(?i)(detection[- ]only|non[- ]exploit|no exploit|does not exploit|without exploit|safe check|non[- ]intrusive)`)
)

// isDetectorRepo reports whether a repo describes itself as a detector rather
// than an exploit. "Exploit + scanner" repos count as exploits.
func isDetectorRepo(desc string) bool {
	if explicitlyNoExploit.MatchString(desc) {
		return true
	}
	return detectionOnly.MatchString(desc) && !exploitWords.MatchString(desc)
}

// Fix commits and merge requests in public source repositories
var fixCommitRef = regexp.MustCompile(`(?i)^https?://(?:(?:www\.)?github\.com|gitlab\.com|bitbucket\.org)/[^/]+/[^/]+/(?:-/)?(?:commit|commits|pull|merge_requests|compare)/|^https?://(?:git\.kernel\.org|sourceware\.org/git|git\.savannah\.gnu\.org|gitlab\.gnome\.org|android\.googlesource\.com)/`)

func signatureReadiness(cve *CVE) (state, reason string) {
	if a := cve.AIImpact; a != nil && a.Tier == "triage" {
		if a.VendorCloud >= 0.85 {
			return "not_feasible", "A cloud service the vendor fixes on its own backend."
		}
		if a.CoverageClass == "none" {
			return "not_feasible", "No Fortinet control is likely to see exploitation."
		}
	}
	// Exploit material, not detectors: a version checker or patch-level scanner
	// says nothing about the exploit traffic
	var srcs []string
	listedGitHub, detectors := 0, 0
	for _, x := range cve.Exploits {
		if x.Source == "github" {
			listedGitHub++
			// An inspected repo's contents decide; until then, its description
			if kind, ok := repoVerdict(x.URL); ok {
				if kind != "exploit" {
					detectors++
					continue
				}
			} else if isDetectorRepo(x.Title + " " + x.Note) {
				detectors++
				continue
			}
		}
		if !contains(srcs, x.Source) {
			srcs = append(srcs, x.Source)
		}
	}
	// Repos beyond the listed ones are unknown, so they may be real PoCs
	if unlisted := cve.GitHubPoCs - listedGitHub; unlisted > 0 && !contains(srcs, "github") {
		srcs = append(srcs, "github")
	}
	if len(srcs) > 0 {
		r := "Public exploit material: " + strings.Join(srcs, ", ")
		if n := cve.GitHubPoCs - detectors; n > 0 {
			r += fmt.Sprintf(" (%d PoC repos)", n)
		}
		return "ready", r + "."
	}
	if s := strings.ToLower(cve.SSVCExploitation); s == "poc" || s == "active" {
		return "ready", "CISA reports public proof-of-concept or active exploitation."
	}
	for _, r := range cve.References {
		if fixCommitRef.MatchString(r.URL) {
			return "ready", "Open source: the fix commit shows the trigger."
		}
	}
	if len(cve.Packages) > 0 {
		return "ready", "Open source package: the fixed release shows the change."
	}
	if detectors > 0 {
		return "needs_research", "The linked PoC repos hold no exploit code (advisory copies, detectors or version checks); a signature needs patch diffing or vendor detail."
	}
	return "needs_research", "Closed source with no public exploit or fix diff yet; a signature needs patch diffing or vendor detail."
}

func readinessRank(state string) int {
	switch state {
	case "ready":
		return 2
	case "needs_research":
		return 1
	}
	return 0
}

// signalReadiness applies the same idea to a signal: open source advisories
// and research write-ups carry the detail a signature needs; a CERT or vendor
// notice is as ready as the most ready CVE it names
func signalReadiness(s *Signal, ds *Dataset) (state, reason string) {
	if s.AI != nil && s.AI.Tier == "triage" {
		if s.AI.VendorCloud >= 0.85 {
			return "not_feasible", "A cloud service the vendor fixes on its own backend."
		}
		if s.AI.CoverageClass == "none" {
			return "not_feasible", "No Fortinet control is likely to see exploitation."
		}
	}
	best, bestReason := "", ""
	if ds != nil {
		for _, id := range s.CVEs {
			if i, ok := ds.byID[id]; ok {
				if st, r := signatureReadiness(&ds.CVEs[i]); best == "" || readinessRank(st) > readinessRank(best) {
					best, bestReason = st, id+": "+r
				}
			}
		}
	}
	if best == "ready" {
		return best, bestReason
	}
	if f := feedByName(s.Feed); f != nil {
		switch f.Kind {
		case "advisory", "community":
			return "ready", "Open source: the advisory and fix are public."
		case "research":
			if s.Report != "other" {
				return "ready", "A technical write-up from exploitation researchers."
			}
		}
	}
	if best != "" {
		return best, bestReason
	}
	return "needs_research", "Closed-source notice with no public technical detail yet."
}

// networkActionable reports whether the signature team can work on a CVE
// today: its deep analysis found a concrete detection anchor for a network
// protection. Analyses from before the network verdict existed fall back to
// public-detail readiness until they're redone.
func networkActionable(cve *CVE) bool {
	a := cve.AIImpact
	if a == nil || a.Tier == "triage" {
		return false
	}
	if a.AnalysisVersion >= 2 {
		return a.Network == "new_signature"
	}
	st, _ := signatureReadiness(cve)
	return st == "ready"
}

// signalActionable is the same test for a signal
func signalActionable(s *Signal, ds *Dataset) bool {
	a := s.AI
	if a == nil || a.Tier == "triage" || a.Pending {
		return false
	}
	if a.AnalysisVersion >= 2 {
		return a.Network == "new_signature"
	}
	st, _ := signalReadiness(s, ds)
	return st == "ready" && s.Report != "other"
}
