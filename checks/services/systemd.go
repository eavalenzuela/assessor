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
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(ev.Content), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
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

func init() { engine.Register(failedUnitsCheck{}) }
