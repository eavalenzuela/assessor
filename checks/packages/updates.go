package packages

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type updatesPendingCheck struct{}

func (updatesPendingCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "packages.updates.pending",
		Title:    "Pending package updates (security separated where possible)",
		Bucket:   "packages",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "workstation"},
	}
}

func (updatesPendingCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	switch facts.PackageManager {
	case "apt":
		return aptUpdates()
	case "dnf", "yum":
		return dnfUpdates(facts.PackageManager)
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no supported package manager"}
}

func aptUpdates() finding.Finding {
	out, err := exec.Command("apt-get", "-s", "-q", "upgrade").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	upgrades, security := countAptUpgrades(string(out))
	ev := evidence.Note("apt-get -s upgrade", fmt.Sprintf("upgrades=%d security=%d", upgrades, security))
	if upgrades == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no pending updates", Evidence: []finding.Evidence{ev}}
	}
	status := finding.StatusWarn
	if security > 0 {
		status = finding.StatusFail
	}
	return finding.Finding{
		Status:   status,
		Message:  fmt.Sprintf("%d update(s) pending (%d security)", upgrades, security),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Apply security updates promptly.",
			Commands:    []string{"apt-get update && apt-get upgrade"},
		},
	}
}

func dnfUpdates(mgr string) finding.Finding {
	out, err := exec.Command(mgr, "-q", "check-update", "--security").Output()
	// dnf returns exit 100 when updates exist — that's not a Go error from Output,
	// but if it is, we still want to count.
	count := countDnfUpdates(string(out))
	ev := evidence.Note(mgr+" check-update --security", string(out))
	if err != nil && count == 0 {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	if count == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no security updates pending", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:      finding.StatusFail,
		Message:     fmt.Sprintf("%d security update(s) pending", count),
		Evidence:    []finding.Evidence{ev},
		Remediation: finding.Remediation{Commands: []string{mgr + " upgrade --security"}},
	}
}

type eolDistroCheck struct{}

func (eolDistroCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "packages.distro.eol",
		Title:    "Distro release is within its support window",
		Bucket:   "packages",
		Severity: finding.SevHigh,
	}
}

// Conservative EOL dates for major distros — easy to extend, kept short
// because the goal is just to fail loudly when a host is years out of date.
var distroEOL = map[string]map[string]time.Time{
	"ubuntu": {
		"20.04": time.Date(2025, 5, 31, 0, 0, 0, 0, time.UTC),
		"22.04": time.Date(2027, 4, 30, 0, 0, 0, 0, time.UTC),
		"24.04": time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
		"24.10": time.Date(2025, 7, 10, 0, 0, 0, 0, time.UTC),
		"25.04": time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		"25.10": time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC),
	},
	"debian": {
		"11": time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC),
		"12": time.Date(2028, 6, 30, 0, 0, 0, 0, time.UTC),
	},
	"rhel": {
		"8": time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
		"9": time.Date(2032, 5, 31, 0, 0, 0, 0, time.UTC),
	},
}

func (eolDistroCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	status, msg := evaluateEOL(facts.OSReleaseID, facts.OSReleaseVer, time.Now())
	f := finding.Finding{Status: status, Message: msg}
	if status != finding.StatusUnverified {
		id := strings.ToLower(facts.OSReleaseID)
		eol := distroEOL[id][facts.OSReleaseVer]
		f.Evidence = []finding.Evidence{
			evidence.Note("os-release", fmt.Sprintf("%s %s, EOL %s", id, facts.OSReleaseVer, eol.Format("2006-01-02"))),
		}
	}
	if status == finding.StatusFail {
		f.Remediation = finding.Remediation{Description: "Upgrade to a supported release."}
	}
	return f
}

// evaluateEOL classifies a distro release against its known end-of-life date:
// Fail if past EOL, Warn if within 90 days, Pass otherwise. Returns Unverified
// when the distro/version isn't in distroEOL. `now` is injected for testability.
func evaluateEOL(osID, ver string, now time.Time) (finding.Status, string) {
	id := strings.ToLower(osID)
	if id == "" {
		return finding.StatusUnverified, "could not determine distro"
	}
	versions, ok := distroEOL[id]
	if !ok {
		return finding.StatusUnverified, "no EOL data for " + id
	}
	eol, ok := versions[ver]
	if !ok {
		return finding.StatusUnverified, "no EOL entry for " + id + " " + ver
	}
	d := eol.Format("2006-01-02")
	switch {
	case now.After(eol):
		return finding.StatusFail, fmt.Sprintf("%s %s is past EOL (%s)", id, ver, d)
	case eol.Sub(now) < 90*24*time.Hour:
		return finding.StatusWarn, fmt.Sprintf("%s %s EOL within 90 days (%s)", id, ver, d)
	default:
		return finding.StatusPass, fmt.Sprintf("%s %s supported until %s", id, ver, d)
	}
}

// countAptUpgrades counts pending upgrades (lines starting "Inst ") in
// `apt-get -s upgrade` output, and how many of those are security updates.
func countAptUpgrades(out string) (upgrades, security int) {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Inst ") {
			upgrades++
			if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
				security++
			}
		}
	}
	return upgrades, security
}

// countDnfUpdates counts the package lines in `dnf check-update --security`
// output, ignoring blanks and the "Last metadata" status line.
func countDnfUpdates(out string) int {
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if line != "" && !strings.HasPrefix(line, "Last metadata") {
			count++
		}
	}
	return count
}

func init() {
	engine.Register(updatesPendingCheck{})
	engine.Register(eolDistroCheck{})
}
