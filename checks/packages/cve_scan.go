package packages

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/t3rmit3/assessor/internal/cve"
	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type cveScanCheck struct{}

func (cveScanCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "packages.cve.scan",
		Title:       "Installed packages cross-referenced against CVE feed",
		Bucket:      "packages",
		Severity:    finding.SevHigh,
		Description: "Match installed package versions against locally-cached NVD/OSV data",
		Profiles:    []string{"server", "workstation"},
	}
}

// db is set by the CLI before Run; left nil disables the check gracefully.
var db *cve.DB

func SetDB(d *cve.DB) { db = d }

func (cveScanCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if db == nil {
		return finding.Finding{
			Status:  finding.StatusSkipped,
			Message: "CVE database not loaded (run with --cve-db <path> or `assessor cve sync`)",
		}
	}
	pkgs, err := listPackages(facts.PackageManager)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	matches := db.Match(pkgs)
	if len(matches) == 0 {
		return finding.Finding{
			Status:  finding.StatusPass,
			Message: fmt.Sprintf("no known CVEs across %d packages", len(pkgs)),
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return sevWeight(matches[i].Vuln.Severity) > sevWeight(matches[j].Vuln.Severity)
	})
	highest := finding.SevMedium
	var lines []string
	for _, m := range matches {
		lines = append(lines, fmt.Sprintf("%s  %s %s  (fixed in %s)",
			m.Vuln.ID, m.Package.Name, m.Package.Version, fixedVersion(m)))
		if mapped := mapSev(m.Vuln.Severity); sevRank(mapped) > sevRank(highest) {
			highest = mapped
		}
	}
	out := finding.Finding{
		Status:  finding.StatusFail,
		Message: fmt.Sprintf("%d CVE match(es) on %d packages", len(matches), countDistinctPkgs(matches)),
		Evidence: []finding.Evidence{
			evidence.TrackedNote("cve-match", strings.Join(lines, "\n")),
		},
		Remediation: finding.Remediation{
			Description: fmt.Sprintf("Update affected packages via %s.", facts.PackageManager),
		},
	}
	out.Meta.Severity = highest
	return out
}

func fixedVersion(m cve.Match) string {
	for _, a := range m.Vuln.Affected {
		if strings.EqualFold(a.Package, m.Package.Name) && a.Fixed != "" {
			return a.Fixed
		}
	}
	return "?"
}

func countDistinctPkgs(ms []cve.Match) int {
	seen := map[string]bool{}
	for _, m := range ms {
		seen[m.Package.Name] = true
	}
	return len(seen)
}

func mapSev(s cve.Severity) finding.Severity {
	switch s {
	case cve.SevCritical:
		return finding.SevCritical
	case cve.SevHigh:
		return finding.SevHigh
	case cve.SevMedium:
		return finding.SevMedium
	case cve.SevLow:
		return finding.SevLow
	}
	return finding.SevInfo
}

func sevRank(s finding.Severity) int {
	switch s {
	case finding.SevCritical:
		return 5
	case finding.SevHigh:
		return 4
	case finding.SevMedium:
		return 3
	case finding.SevLow:
		return 2
	case finding.SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s cve.Severity) int {
	switch s {
	case cve.SevCritical:
		return 5
	case cve.SevHigh:
		return 4
	case cve.SevMedium:
		return 3
	case cve.SevLow:
		return 2
	}
	return 1
}

func listPackages(mgr string) ([]cve.Package, error) {
	switch mgr {
	case "apt":
		return aptPackages()
	case "dnf", "yum":
		return rpmPackages()
	case "pacman":
		return pacmanPackages()
	case "apk":
		return apkPackages()
	}
	return nil, fmt.Errorf("unsupported package manager: %q", mgr)
}

func aptPackages() ([]cve.Package, error) {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\\t${Version}\\n").Output()
	if err != nil {
		return nil, err
	}
	return parseTabbed(string(out), "deb"), nil
}

func rpmPackages() ([]cve.Package, error) {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return nil, err
	}
	return parseTabbed(string(out), "rpm"), nil
}

func pacmanPackages() ([]cve.Package, error) {
	out, err := exec.Command("pacman", "-Q").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []cve.Package
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkgs = append(pkgs, cve.Package{Ecosystem: "Arch", Name: fields[0], Version: fields[1]})
		}
	}
	return pkgs, nil
}

func apkPackages() ([]cve.Package, error) {
	out, err := exec.Command("apk", "info", "-vv").Output()
	if err != nil {
		return nil, err
	}
	var pkgs []cve.Package
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, _, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		idx := strings.LastIndex(name, "-")
		if idx < 0 {
			continue
		}
		pkgs = append(pkgs, cve.Package{Ecosystem: "Alpine", Name: name[:idx], Version: name[idx+1:]})
	}
	return pkgs, nil
}

func parseTabbed(s, eco string) []cve.Package {
	var pkgs []cve.Package
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 && parts[0] != "" {
			pkgs = append(pkgs, cve.Package{Ecosystem: eco, Name: parts[0], Version: parts[1]})
		}
	}
	return pkgs
}

func init() { engine.Register(cveScanCheck{}) }
