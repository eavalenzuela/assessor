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
	var upgrades, security int
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Inst ") {
			upgrades++
			if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
				security++
			}
		}
	}
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
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" && !strings.HasPrefix(line, "Last metadata") {
			count++
		}
	}
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
	id := strings.ToLower(facts.OSReleaseID)
	if id == "" {
		return finding.Finding{Status: finding.StatusUnverified, Message: "could not determine distro"}
	}
	versions, ok := distroEOL[id]
	if !ok {
		return finding.Finding{Status: finding.StatusUnverified, Message: "no EOL data for " + id}
	}
	eol, ok := versions[facts.OSReleaseVer]
	if !ok {
		return finding.Finding{Status: finding.StatusUnverified, Message: "no EOL entry for " + id + " " + facts.OSReleaseVer}
	}
	ev := evidence.Note("os-release", fmt.Sprintf("%s %s, EOL %s", id, facts.OSReleaseVer, eol.Format("2006-01-02")))
	now := time.Now()
	if now.After(eol) {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  fmt.Sprintf("%s %s is past EOL (%s)", id, facts.OSReleaseVer, eol.Format("2006-01-02")),
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Upgrade to a supported release.",
			},
		}
	}
	if eol.Sub(now) < 90*24*time.Hour {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  fmt.Sprintf("%s %s EOL within 90 days (%s)", id, facts.OSReleaseVer, eol.Format("2006-01-02")),
			Evidence: []finding.Evidence{ev},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: fmt.Sprintf("%s %s supported until %s", id, facts.OSReleaseVer, eol.Format("2006-01-02")), Evidence: []finding.Evidence{ev}}
}

func init() {
	engine.Register(updatesPendingCheck{})
	engine.Register(eolDistroCheck{})
}
