package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type sysctlCheck struct{}

func (sysctlCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "kernel.sysctl.hardening",
		Title:       "Kernel sysctl hardening baseline",
		Bucket:      "kernel",
		Severity:    finding.SevMedium,
		Description: "Network and kernel sysctls aligned with hardened defaults",
		Profiles:    []string{"server", "workstation", "cis-l1"},
	}
}

var sysctlBaseline = map[string]string{
	"kernel.kptr_restrict":                       "2",
	"kernel.dmesg_restrict":                      "1",
	"kernel.yama.ptrace_scope":                   "1",
	"kernel.unprivileged_bpf_disabled":           "1",
	"net.core.bpf_jit_harden":                    "2",
	"net.ipv4.conf.all.rp_filter":                "1",
	"net.ipv4.conf.all.accept_redirects":         "0",
	"net.ipv4.conf.all.send_redirects":           "0",
	"net.ipv4.conf.all.accept_source_route":      "0",
	"net.ipv4.conf.all.log_martians":             "1",
	"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
	"net.ipv4.tcp_syncookies":                    "1",
	"net.ipv6.conf.all.accept_redirects":         "0",
	"net.ipv6.conf.all.accept_source_route":      "0",
	"fs.protected_hardlinks":                     "1",
	"fs.protected_symlinks":                      "1",
	"fs.suid_dumpable":                           "0",
}

func (sysctlCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var bad []string
	var evs []finding.Evidence
	for key, want := range sysctlBaseline {
		path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		got := strings.TrimSpace(string(b))
		if got != want {
			bad = append(bad, fmt.Sprintf("%s=%s (want %s)", key, got, want))
			evs = append(evs, evidence.Note(path, got))
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all baselined sysctls match"}
	}
	cmds := []string{}
	for _, line := range bad {
		k := strings.SplitN(line, "=", 2)[0]
		cmds = append(cmds, fmt.Sprintf("echo '%s = %s' >> /etc/sysctl.d/99-assessor.conf", k, sysctlBaseline[k]))
	}
	cmds = append(cmds, "sysctl --system")
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d sysctls drift from baseline", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Persist desired values in /etc/sysctl.d and reload.",
			Commands:    cmds,
		},
	}
}

func init() { engine.Register(sysctlCheck{}) }
