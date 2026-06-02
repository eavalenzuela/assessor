package services

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type unwantedServicesCheck struct{}

func (unwantedServicesCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "services.unwanted.enabled",
		Title:    "Legacy or risky services are not enabled",
		Bucket:   "services",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "cis-l1"},
	}
}

var unwanted = []string{
	"telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket",
	"tftp.socket", "talk.socket", "ntalk.socket", "chargen.socket",
	"discard.socket", "echo.socket", "time.socket",
	"ypserv.service", "rpcbind.service", "avahi-daemon.service",
	"cups.service", "isc-dhcp-server.service", "dovecot.service",
	"smb.service", "nfs-server.service", "vsftpd.service",
}

func (unwantedServicesCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no systemd"}
	}
	var enabled []string
	var evs []finding.Evidence
	for _, u := range unwanted {
		out, err := exec.Command("systemctl", "is-enabled", u).Output()
		if err != nil {
			continue
		}
		state := strings.TrimSpace(string(out))
		if isUnwantedEnabledState(state) {
			enabled = append(enabled, u)
			evs = append(evs, evidence.Note("systemctl is-enabled "+u, state))
		}
	}
	if len(enabled) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no legacy services enabled"}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("enabled legacy/risky services: %s", strings.Join(enabled, ", ")),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Disable services not required for this host's role.",
			Commands:    []string{"systemctl disable --now <unit>"},
		},
	}
}

type unitHardeningCheck struct{}

func (unitHardeningCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "services.unit_hardening.coverage",
		Title:    "Custom systemd services use sandboxing directives",
		Bucket:   "services",
		Severity: finding.SevLow,
	}
}

func (unitHardeningCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no systemd"}
	}
	out, err := exec.Command("systemd-analyze", "security", "--no-pager").CombinedOutput()
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "systemd-analyze unavailable", Err: err.Error()}
	}
	risky := riskyUnits(string(out))
	ev := evidence.Note("systemd-analyze security", string(out))
	if len(risky) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no exposed/unsafe units", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d unit(s) at EXPOSED/UNSAFE level — review hardening", len(risky)),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Add NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp, etc., to drop-in overrides.",
		},
	}
}

// isUnwantedEnabledState reports whether a `systemctl is-enabled` state means
// the unit is active in boot — "enabled" or "static" both pull the unit in.
func isUnwantedEnabledState(state string) bool {
	return state == "enabled" || state == "static"
}

// riskyUnits returns the `systemd-analyze security` lines rated EXPOSED or
// UNSAFE (the two worst exposure levels).
func riskyUnits(out string) []string {
	var risky []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "EXPOSED") || strings.Contains(line, "UNSAFE") {
			risky = append(risky, strings.TrimSpace(line))
		}
	}
	return risky
}

func init() {
	engine.Register(unwantedServicesCheck{})
	engine.Register(unitHardeningCheck{})
}
