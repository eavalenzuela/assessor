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

type firewallCheck struct{}

func (firewallCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "network.firewall.active",
		Title:       "An active firewall is present",
		Bucket:      "network",
		Severity:    finding.SevHigh,
		Description: "Detect ufw / firewalld / nftables / iptables and report which is active",
		Profiles:    []string{"server", "workstation", "cis-l1"},
	}
}

func (firewallCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	var present []string
	var evs []finding.Evidence
	if facts.HasUFW {
		ev, _ := evidence.Command("ufw", "status")
		evs = append(evs, ev)
		if strings.Contains(strings.ToLower(ev.Content), "status: active") {
			present = append(present, "ufw")
		}
	}
	if facts.HasFirewalld {
		ev, _ := evidence.Command("firewall-cmd", "--state")
		evs = append(evs, ev)
		if strings.TrimSpace(ev.Content) == "running" {
			present = append(present, "firewalld")
		}
	}
	if facts.HasNftables {
		ev, _ := evidence.Command("nft", "list", "ruleset")
		evs = append(evs, ev)
		if strings.TrimSpace(ev.Content) != "" {
			present = append(present, "nftables")
		}
	}
	if facts.HasIptables {
		ev, _ := evidence.Command("iptables", "-S")
		evs = append(evs, ev)
		// Default with no rules is "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT".
		if strings.Count(ev.Content, "\n") > 3 {
			present = append(present, "iptables")
		}
	}
	if len(present) == 0 {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "no active firewall detected",
			Evidence: evs,
			Remediation: finding.Remediation{
				Description: "Enable ufw, firewalld, or load nftables rules.",
				Commands:    []string{"ufw enable", "systemctl enable --now firewalld"},
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "active firewall(s): " + strings.Join(present, ", "), Evidence: evs}
}

type tcpWrappersCheck struct{}

func (tcpWrappersCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "network.tcp_wrappers.review",
		Title:    "/etc/hosts.{allow,deny} are reviewed if present",
		Bucket:   "network",
		Severity: finding.SevLow,
	}
}

func (tcpWrappersCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var evs []finding.Evidence
	for _, p := range []string{"/etc/hosts.allow", "/etc/hosts.deny"} {
		if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			ev, _ := evidence.File(p)
			evs = append(evs, ev)
		}
	}
	if len(evs) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no TCP wrappers config in use"}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "TCP wrappers config present — review entries",
		Evidence: evs,
	}
}

func init() {
	engine.Register(firewallCheck{})
	engine.Register(tcpWrappersCheck{})
}
