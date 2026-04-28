package logging

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type auditdCheck struct{}

func (auditdCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.auditd.running",
		Title:    "auditd installed and running",
		Bucket:   "logging",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (auditdCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no systemd"}
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		return finding.Finding{
			Status: finding.StatusFail, Message: "auditd not installed",
			Remediation: finding.Remediation{
				Description: "Install and enable the audit subsystem.",
				Commands:    []string{"apt install auditd || dnf install audit", "systemctl enable --now auditd"},
			},
		}
	}
	ev, _ := evidence.Command("systemctl", "is-active", "auditd")
	if strings.TrimSpace(ev.Content) == "active" {
		return finding.Finding{Status: finding.StatusPass, Message: "auditd active",
			Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  "auditd installed but not active",
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Enable the auditd unit.",
			Commands:    []string{"systemctl enable --now auditd"},
		},
	}
}

func init() { engine.Register(auditdCheck{}) }
