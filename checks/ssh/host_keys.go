package ssh

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type hostKeysCheck struct{}

func (hostKeysCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "ssh.host_keys.algorithms",
		Title:    "sshd host keys use strong algorithms and sizes",
		Bucket:   "ssh",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "workstation"},
	}
}

func (hostKeysCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	dir := "/etc/ssh"
	var bad []string
	var evs []finding.Evidence
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := filepath.Base(p)
		if !strings.HasPrefix(name, "ssh_host_") || !strings.HasSuffix(name, "_key") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		k, err := ssh.ParseRawPrivateKey(b)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: parse error %v", p, err))
			return nil
		}
		switch t := k.(type) {
		case *dsa.PrivateKey:
			bad = append(bad, fmt.Sprintf("%s: DSA host keys are deprecated", p))
			evs = append(evs, evidence.Note(p, "DSA"))
		case *rsa.PrivateKey:
			if t.N.BitLen() < 3072 {
				bad = append(bad, fmt.Sprintf("%s: RSA %d bits (want >= 3072)", p, t.N.BitLen()))
				evs = append(evs, evidence.Note(p, fmt.Sprintf("RSA %d", t.N.BitLen())))
			}
		case *ecdsa.PrivateKey:
			if t.Params().BitSize < 256 {
				bad = append(bad, fmt.Sprintf("%s: ECDSA %d bits", p, t.Params().BitSize))
				evs = append(evs, evidence.Note(p, fmt.Sprintf("ECDSA %d", t.Params().BitSize)))
			}
		}
		return nil
	})
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "host keys use modern algorithms"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Regenerate host keys using ed25519 (preferred) and RSA 4096.",
			Commands: []string{
				"rm /etc/ssh/ssh_host_dsa_* /etc/ssh/ssh_host_ecdsa_*",
				"ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''",
				"ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ''",
				"systemctl reload ssh",
			},
		},
	}
}

func init() { engine.Register(hostKeysCheck{}) }
