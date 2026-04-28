package network

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type firewallDefaultPolicyCheck struct{}

func (firewallDefaultPolicyCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "network.firewall.default_policy",
		Title:       "INPUT/FORWARD chains default to DROP or REJECT",
		Bucket:      "network",
		Severity:    finding.SevHigh,
		Description: "Default ACCEPT on INPUT means anything not explicitly denied is allowed",
		Profiles:    []string{"server", "cis-l1"},
	}
}

func (firewallDefaultPolicyCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	// nftables hook policy
	if facts.HasNftables {
		out, err := exec.Command("nft", "-a", "list", "ruleset").Output()
		if err == nil && strings.Contains(string(out), "policy drop;") {
			return finding.Finding{Status: finding.StatusPass, Message: "nftables INPUT policy = drop"}
		}
	}
	// iptables -S returns "-P INPUT ACCEPT" by default
	if facts.HasIptables {
		ev, _ := evidence.Command("iptables", "-S")
		bad := []string{}
		for _, want := range []string{"-P INPUT", "-P FORWARD"} {
			line := findLine(ev.Content, want)
			if strings.HasSuffix(line, " ACCEPT") {
				bad = append(bad, line)
			}
		}
		if len(bad) > 0 {
			return finding.Finding{
				Status:   finding.StatusFail,
				Message:  "default policy ACCEPT on " + strings.Join(bad, ", "),
				Evidence: []finding.Evidence{ev},
				Remediation: finding.Remediation{
					Commands: []string{"iptables -P INPUT DROP", "iptables -P FORWARD DROP"},
				},
			}
		}
		return finding.Finding{Status: finding.StatusPass, Message: "iptables default policies are restrictive", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no firewall backend to evaluate"}
}

func findLine(haystack, prefix string) string {
	for _, l := range strings.Split(haystack, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

type dnsResolversCheck struct{}

func (dnsResolversCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "network.dns.resolvers",
		Title:    "/etc/resolv.conf has at least one nameserver",
		Bucket:   "network",
		Severity: finding.SevLow,
	}
}

func (dnsResolversCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	ev, err := evidence.File("/etc/resolv.conf")
	if err != nil {
		return finding.Finding{Status: finding.StatusFail, Message: "no /etc/resolv.conf"}
	}
	count := 0
	for _, l := range strings.Split(ev.Content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "nameserver") {
			count++
		}
	}
	if count == 0 {
		return finding.Finding{Status: finding.StatusFail, Message: "no nameservers configured", Evidence: []finding.Evidence{ev}}
	}
	if count == 1 {
		return finding.Finding{Status: finding.StatusWarn, Message: "only one nameserver — no fallback", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "resolvers configured", Evidence: []finding.Evidence{ev}}
}

func init() {
	engine.Register(firewallDefaultPolicyCheck{})
	engine.Register(dnsResolversCheck{})
}
