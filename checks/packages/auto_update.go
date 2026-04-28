package packages

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type autoUpdateCheck struct{}

func (autoUpdateCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "packages.auto_update.configured",
		Title:    "Automatic security updates are configured",
		Bucket:   "packages",
		Severity: finding.SevMedium,
		Profiles: []string{"server"},
	}
}

func (autoUpdateCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	switch facts.PackageManager {
	case "apt":
		return aptAutoUpdate()
	case "dnf", "yum":
		return dnfAutoUpdate()
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no supported package manager"}
}

func aptAutoUpdate() finding.Finding {
	const periodic = "/etc/apt/apt.conf.d/20auto-upgrades"
	const unattended = "/etc/apt/apt.conf.d/50unattended-upgrades"
	if _, err := os.Stat(periodic); err != nil {
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "no /etc/apt/apt.conf.d/20auto-upgrades",
			Remediation: finding.Remediation{
				Commands: []string{"apt install unattended-upgrades", "dpkg-reconfigure -plow unattended-upgrades"},
			},
		}
	}
	b, err := os.ReadFile(periodic)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	c := string(b)
	if !strings.Contains(c, "Update-Package-Lists \"1\"") || !strings.Contains(c, "Unattended-Upgrade \"1\"") {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "auto-upgrades file present but disabled",
			Evidence: []finding.Evidence{evidence.Note(periodic, c)},
		}
	}
	if _, err := os.Stat(unattended); err != nil {
		return finding.Finding{Status: finding.StatusWarn, Message: "20auto-upgrades enabled but no 50unattended-upgrades"}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "unattended-upgrades enabled"}
}

func dnfAutoUpdate() finding.Finding {
	const path = "/etc/dnf/automatic.conf"
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "dnf-automatic not configured",
			Remediation: finding.Remediation{
				Commands: []string{"dnf install dnf-automatic", "systemctl enable --now dnf-automatic.timer"},
			},
		}
	}
	c := string(b)
	if !strings.Contains(c, "apply_updates = yes") {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "dnf-automatic present but apply_updates != yes",
			Evidence: []finding.Evidence{evidence.Note(path, c)},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "dnf-automatic applies updates"}
}

func init() { engine.Register(autoUpdateCheck{}) }
