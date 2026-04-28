package ssh

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type bannerCheck struct{}

func (bannerCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "ssh.banner.set",
		Title:    "sshd Banner directive points to a non-empty file",
		Bucket:   "ssh",
		Severity: finding.SevLow,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (bannerCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/ssh/sshd_config"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no sshd_config"}
	}
	defer f.Close()
	got := parseSshdConfig(f)
	bv, ok := got["banner"]
	if !ok || bv.val == "" || strings.EqualFold(bv.val, "none") {
		return finding.Finding{
			Status:  finding.StatusWarn,
			Message: "no Banner configured for sshd",
			Remediation: finding.Remediation{
				Commands: []string{
					"echo 'Authorized access only.' > /etc/issue.net",
					"sed -i 's|^#\\?Banner.*|Banner /etc/issue.net|' /etc/ssh/sshd_config",
					"systemctl reload ssh",
				},
			},
		}
	}
	if st, err := os.Stat(bv.val); err != nil || st.Size() == 0 {
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "Banner points to missing or empty file: " + bv.val,
			Evidence: []finding.Evidence{evidence.Note(path, "Banner "+bv.val)},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "Banner points to " + bv.val}
}

type clientConfigCheck struct{}

func (clientConfigCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "ssh.client.config",
		Title:    "/etc/ssh/ssh_config has hardened client defaults",
		Bucket:   "ssh",
		Severity: finding.SevLow,
	}
}

func (clientConfigCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/ssh/ssh_config"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no ssh_config"}
	}
	defer f.Close()
	got := parseSshdConfig(f)
	var bad []string
	if v := got["hashknownhosts"].val; v != "" && !strings.EqualFold(v, "yes") {
		bad = append(bad, "HashKnownHosts="+v)
	}
	if v := got["stricthostkeychecking"].val; v == "no" {
		bad = append(bad, "StrictHostKeyChecking=no")
	}
	if v := got["forwardagent"].val; v == "yes" {
		bad = append(bad, "ForwardAgent=yes")
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "client config OK"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: strings.Join(bad, "; "),
		Evidence: []finding.Evidence{
			evidence.Note(path, strings.Join(bad, "\n")),
		},
	}
}

func init() {
	engine.Register(bannerCheck{})
	engine.Register(clientConfigCheck{})
}
