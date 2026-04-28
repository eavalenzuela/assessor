package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type directiveValue struct {
	val  string
	line int
}

func parseSshdConfig(r io.Reader) map[string]directiveValue {
	got := map[string]directiveValue{}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		got[strings.ToLower(fields[0])] = directiveValue{
			val:  strings.Join(fields[1:], " "),
			line: lineNo,
		}
	}
	return got
}

var sshdRules = []rule{
	{"permitrootlogin", "no", finding.SevHigh, "PermitRootLogin no"},
	{"passwordauthentication", "no", finding.SevHigh, "PasswordAuthentication no"},
	{"permitemptypasswords", "no", finding.SevCritical, "PermitEmptyPasswords no"},
	{"x11forwarding", "no", finding.SevLow, "X11Forwarding no"},
	{"maxauthtries", "4", finding.SevMedium, "MaxAuthTries 4"},
	{"clientaliveinterval", "300", finding.SevLow, "ClientAliveInterval 300"},
	{"clientalivecountmax", "0", finding.SevLow, "ClientAliveCountMax 0"},
	{"protocol", "2", finding.SevHigh, "Protocol 2"},
	{"logingracetime", "60", finding.SevLow, "LoginGraceTime 60"},
}

// evaluateSshd compares parsed config against sshdRules. Returns human-readable
// failures, the highest severity seen, and a list of rules that need fixing.
func evaluateSshd(got map[string]directiveValue) (bad []string, highest finding.Severity, broken []rule) {
	highest = finding.SevInfo
	for _, r := range sshdRules {
		v, ok := got[r.directive]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s not set (default may be insecure)", r.directive))
			broken = append(broken, r)
			if sevWeight(r.severity) > sevWeight(highest) {
				highest = r.severity
			}
			continue
		}
		if !strings.EqualFold(v.val, r.want) {
			bad = append(bad, fmt.Sprintf("%s = %q (want %q)", r.directive, v.val, r.want))
			broken = append(broken, r)
			if sevWeight(r.severity) > sevWeight(highest) {
				highest = r.severity
			}
		}
	}
	return
}

type sshdConfigCheck struct{}

func (sshdConfigCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "ssh.sshd.hardening",
		Title:       "sshd_config hardening directives",
		Bucket:      "ssh",
		Severity:    finding.SevHigh,
		Description: "PermitRootLogin, PasswordAuthentication, X11Forwarding, MaxAuthTries baseline",
		Refs: []finding.Reference{
			{Source: "CIS", ID: "5.2"},
		},
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

type rule struct {
	directive  string
	want       string
	severity   finding.Severity
	suggestion string
}

func (sshdConfigCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/ssh/sshd_config"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{
			Status:  finding.StatusSkipped,
			Message: fmt.Sprintf("could not open %s: %v", path, err),
		}
	}
	defer f.Close()

	got := parseSshdConfig(f)
	bad, highest, broken := evaluateSshd(got)

	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "sshd_config matches baseline"}
	}

	var evs []finding.Evidence
	for _, r := range broken {
		if v, ok := got[r.directive]; ok {
			evs = append(evs, evidence.FileLine(path, v.line, fmt.Sprintf("%s %s", r.directive, v.val)))
		}
	}

	fixCmds := []string{}
	for _, r := range broken {
		fixCmds = append(fixCmds, fmt.Sprintf("sed -i 's/^#\\?%s.*/%s/' %s", r.directive, r.suggestion, path))
	}
	fixCmds = append(fixCmds, "sshd -t && systemctl reload ssh")

	out := finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Set the directives above and reload sshd after validating with `sshd -t`.",
			Commands:    fixCmds,
		},
	}
	out.Meta.Severity = highest
	return out
}

func sevWeight(s finding.Severity) int {
	switch s {
	case finding.SevCritical:
		return 5
	case finding.SevHigh:
		return 4
	case finding.SevMedium:
		return 3
	case finding.SevLow:
		return 2
	case finding.SevInfo:
		return 1
	}
	return 0
}

func init() {
	engine.Register(sshdConfigCheck{})
}
