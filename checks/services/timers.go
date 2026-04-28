package services

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type timersInventoryCheck struct{}

func (timersInventoryCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "services.timers.inventory",
		Title:       "systemd timer inventory",
		Bucket:      "services",
		Severity:    finding.SevInfo,
		Description: "Catalog active timers — review for unsanctioned scheduled jobs",
	}
}

func (timersInventoryCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no systemd"}
	}
	out, err := exec.Command("systemctl", "list-timers", "--all", "--no-legend", "--no-pager").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	ev := evidence.TrackedNote("systemctl list-timers", strings.Join(lines, "\n"))
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "review timer list — snapshot with `assessor run --snapshot` to detect future additions",
		Evidence: []finding.Evidence{ev},
	}
}

func init() { engine.Register(timersInventoryCheck{}) }
