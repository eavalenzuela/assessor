package network

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type ipv6PostureCheck struct{}

func (ipv6PostureCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "network.ipv6.posture",
		Title:       "IPv6 is consistently enabled-and-firewalled or disabled-everywhere",
		Bucket:      "network",
		Severity:    finding.SevMedium,
		Description: "Detects the half-disabled state where the kernel still has IPv6 but firewall rules don't cover it",
	}
}

func (ipv6PostureCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	disabled := readSysctl("net.ipv6.conf.all.disable_ipv6") == "1"
	hasIPv6Listeners := false
	if b, err := os.ReadFile("/proc/net/tcp6"); err == nil && strings.Count(string(b), "\n") > 1 {
		hasIPv6Listeners = true
	}
	ev := evidence.Note("ipv6 posture",
		"disable_ipv6="+readSysctl("net.ipv6.conf.all.disable_ipv6")+
			"  has_v6_listeners="+boolStr(hasIPv6Listeners))
	if disabled && hasIPv6Listeners {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "disable_ipv6=1 but processes are still bound to IPv6 sockets",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Either restart services after disabling IPv6, or re-enable it and add v6 firewall rules.",
			},
		}
	}
	if !disabled && hasIPv6Listeners {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "IPv6 is active — ensure firewall has matching v6 rules (ip6tables / nft inet)",
			Evidence: []finding.Evidence{ev},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "IPv6 posture consistent", Evidence: []finding.Evidence{ev}}
}

func readSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func init() { engine.Register(ipv6PostureCheck{}) }
