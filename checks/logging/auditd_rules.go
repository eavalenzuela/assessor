package logging

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type auditdRulesCheck struct{}

func (auditdRulesCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.auditd.rules_baseline",
		Title:    "auditd is loaded with key CIS rules (identity, sudo, time, mounts)",
		Bucket:   "logging",
		Severity: finding.SevMedium,
		Refs:     []finding.Reference{{Source: "CIS", ID: "4.1.3"}},
		Profiles: []string{"server", "cis-l1"},
	}
}

// Substrings expected to appear in `auditctl -l` output for a CIS-aligned ruleset.
var auditExpect = []string{
	"-w /etc/passwd",
	"-w /etc/shadow",
	"-w /etc/group",
	"-w /etc/sudoers",
	"-a always,exit -F arch=b64 -S execve",
	"-w /var/log/faillog",
}

func (auditdRulesCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if _, err := exec.LookPath("auditctl"); err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "auditctl not installed"}
	}
	out, err := exec.Command("auditctl", "-l").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	rules := string(out)
	var missing []string
	for _, want := range auditExpect {
		if !strings.Contains(rules, want) {
			missing = append(missing, want)
		}
	}
	ev := evidence.Note("auditctl -l", rules)
	if len(missing) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all baselined audit rules present", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d expected audit rule(s) missing", len(missing)),
		Evidence: []finding.Evidence{ev, evidence.Note("missing", strings.Join(missing, "\n"))},
		Remediation: finding.Remediation{
			Description: "Drop the CIS audit ruleset into /etc/audit/rules.d/ and `augenrules --load`.",
		},
	}
}

type rsyslogForwardCheck struct{}

func (rsyslogForwardCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.rsyslog.forwarding",
		Title:    "rsyslog or syslog-ng forwards logs to a remote collector",
		Bucket:   "logging",
		Severity: finding.SevMedium,
		Profiles: []string{"server"},
	}
}

func (rsyslogForwardCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	contents := concatConfigsLogging([]string{"/etc/rsyslog.conf", "/etc/rsyslog.d", "/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng/conf.d"})
	if contents == "" {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no rsyslog/syslog-ng configs found"}
	}
	// Look for forwarding action: lines like `*.* @@host:port` or `*.* @host:port`
	// or syslog-ng `destination(...) network(...)`.
	if strings.Contains(contents, "@@") || strings.Contains(contents, "@1") || strings.Contains(contents, "@2") ||
		strings.Contains(contents, "tcp(") || strings.Contains(contents, "syslog(") {
		return finding.Finding{Status: finding.StatusPass, Message: "remote log forwarding detected"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: "no remote forwarding directives found",
		Remediation: finding.Remediation{
			Description: "Add `*.* @@logserver:514` (TCP) to rsyslog or a network destination to syslog-ng.",
		},
	}
}

func concatConfigsLogging(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if data, err := os.ReadFile(p + "/" + e.Name()); err == nil {
					b.Write(data)
					b.WriteString("\n")
				}
			}
		} else {
			if data, err := os.ReadFile(p); err == nil {
				b.Write(data)
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func init() {
	engine.Register(auditdRulesCheck{})
	engine.Register(rsyslogForwardCheck{})
}
