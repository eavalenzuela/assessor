package mac

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type macModeCheck struct{}

func (macModeCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "mac.mode.enforcing",
		Title:    "SELinux or AppArmor is in enforcing mode",
		Bucket:   "mac",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (macModeCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if facts.HasSELinux {
		b, err := os.ReadFile("/sys/fs/selinux/enforce")
		if err == nil {
			val := strings.TrimSpace(string(b))
			ev := evidence.Note("/sys/fs/selinux/enforce", val)
			if val == "1" {
				return finding.Finding{Status: finding.StatusPass, Message: "SELinux enforcing", Evidence: []finding.Evidence{ev}}
			}
			return finding.Finding{
				Status:   finding.StatusFail,
				Message:  "SELinux is not enforcing",
				Evidence: []finding.Evidence{ev},
				Remediation: finding.Remediation{
					Description: "Set SELINUX=enforcing in /etc/selinux/config and reboot.",
				},
			}
		}
	}
	if facts.HasAppArmor {
		b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil && strings.TrimSpace(string(b)) == "Y" {
			ev := evidence.Note("/sys/module/apparmor/parameters/enabled", "Y")
			return finding.Finding{Status: finding.StatusPass, Message: "AppArmor enabled", Evidence: []finding.Evidence{ev}}
		}
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "AppArmor present but not enabled",
			Remediation: finding.Remediation{
				Description: "Enable AppArmor via the apparmor.service unit.",
				Commands:    []string{"systemctl enable --now apparmor"},
			},
		}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: "no MAC subsystem detected (neither SELinux nor AppArmor)",
		Remediation: finding.Remediation{
			Description: "Install and enable SELinux or AppArmor for your distro.",
		},
	}
}

func init() { engine.Register(macModeCheck{}) }
