package kernel

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type lockdownCheck struct{}

func (lockdownCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "kernel.lockdown.mode",
		Title:       "Kernel lockdown is enabled (integrity or confidentiality)",
		Bucket:      "kernel",
		Severity:    finding.SevMedium,
		Description: "/sys/kernel/security/lockdown should not be 'none'",
	}
}

func (lockdownCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/sys/kernel/security/lockdown"
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "kernel does not expose lockdown state"}
	}
	val := strings.TrimSpace(string(b))
	ev := evidence.Note(path, val)
	// The active mode is wrapped in [brackets].
	if strings.Contains(val, "[none]") {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "lockdown=none",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Enable Secure Boot or boot with lockdown=integrity to restrict kernel modifications.",
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "lockdown active: " + val, Evidence: []finding.Evidence{ev}}
}

func init() { engine.Register(lockdownCheck{}) }
