package time

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type ntpSyncedCheck struct{}

func (ntpSyncedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "time.ntp.synced",
		Title:       "System clock is synchronized to a time source",
		Bucket:      "time",
		Severity:    finding.SevMedium,
		Description: "Drift breaks TLS validation, log correlation, Kerberos, and TOTP",
	}
}

func (ntpSyncedCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	// Try timedatectl first (covers chrony, systemd-timesyncd, ntpd via the bus).
	if out, err := exec.Command("timedatectl", "show").Output(); err == nil {
		ev := evidence.Note("timedatectl show", string(out))
		if strings.Contains(string(out), "NTPSynchronized=yes") {
			return finding.Finding{Status: finding.StatusPass, Message: "clock synchronized", Evidence: []finding.Evidence{ev}}
		}
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "NTPSynchronized != yes",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Enable a time daemon: chrony, systemd-timesyncd, or ntpd.",
				Commands:    []string{"systemctl enable --now chrony || systemctl enable --now systemd-timesyncd"},
			},
		}
	}
	if _, err := exec.LookPath("chronyc"); err == nil {
		ev, _ := evidence.Command("chronyc", "tracking")
		if strings.Contains(ev.Content, "Leap status") && !strings.Contains(ev.Content, "Not synchronised") {
			return finding.Finding{Status: finding.StatusPass, Message: "chrony synced", Evidence: []finding.Evidence{ev}}
		}
		return finding.Finding{Status: finding.StatusFail, Message: "chrony not synced", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusUnverified, Message: "no time client tooling available"}
}

type timezoneCheck struct{}

func (timezoneCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "time.timezone.set",
		Title:    "/etc/localtime points to a timezone (not factory default)",
		Bucket:   "time",
		Severity: finding.SevLow,
	}
}

func (timezoneCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	target, err := os.Readlink("/etc/localtime")
	if err != nil {
		return finding.Finding{Status: finding.StatusWarn, Message: "/etc/localtime is not a symlink"}
	}
	ev := evidence.Note("/etc/localtime -> ", target)
	if strings.Contains(target, "Factory") || target == "" {
		return finding.Finding{Status: finding.StatusFail, Message: "timezone not configured (factory default)", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "timezone: " + target, Evidence: []finding.Evidence{ev}}
}

func init() {
	engine.Register(ntpSyncedCheck{})
	engine.Register(timezoneCheck{})
}
