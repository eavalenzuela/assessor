package services

import (
	"context"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type failedUnitsCheck struct{}

func (failedUnitsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "services.systemd.failed_units",
		Title:    "No failed systemd units",
		Bucket:   "services",
		Severity: finding.SevLow,
		Profiles: []string{"server", "workstation"},
	}
}

func (failedUnitsCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "systemd not running"}
	}
	ev, err := evidence.Command("systemctl", "--failed", "--no-legend", "--plain")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	lines := nonEmptyLines(ev.Content)
	if len(lines) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no failed units"}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "failed systemd units present",
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Investigate with `systemctl status <unit>` and `journalctl -u <unit>`.",
		},
	}
}

// nonEmptyLines splits content on newlines and drops blank/whitespace-only
// lines. Shared by the systemctl-output parsers in this package.
func nonEmptyLines(content string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(content), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func init() { engine.Register(failedUnitsCheck{}) }
