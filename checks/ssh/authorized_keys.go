package ssh

import (
	"bufio"
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

type authorizedKeysCheck struct{}

func (authorizedKeysCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "ssh.authorized_keys.perms",
		Title:    "User .ssh/authorized_keys files have safe permissions",
		Bucket:   "ssh",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (authorizedKeysCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	homes, err := userHomes()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var bad []string
	var evs []finding.Evidence
	for _, h := range homes {
		akPath := filepath.Join(h, ".ssh", "authorized_keys")
		st, err := os.Stat(akPath)
		if err != nil {
			continue
		}
		mode := st.Mode().Perm()
		if mode&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: %s (group/other readable)", akPath, mode))
			evs = append(evs, evidence.Note(akPath, mode.String()))
		}
		// Stat the .ssh dir too
		if dirSt, err := os.Stat(filepath.Join(h, ".ssh")); err == nil {
			if dirSt.Mode().Perm()&0o077 != 0 {
				bad = append(bad, fmt.Sprintf("%s/.ssh: %s", h, dirSt.Mode().Perm()))
			}
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "authorized_keys perms OK"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Restrict to 0700 on .ssh and 0600 on authorized_keys.",
			Commands:    []string{"chmod 700 ~/.ssh", "chmod 600 ~/.ssh/authorized_keys"},
		},
	}
}

func userHomes() ([]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		shell := fields[6]
		// Skip locked / nologin accounts.
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") || shell == "" {
			continue
		}
		home := fields[5]
		if home == "" || home == "/" || home == "/sbin" || home == "/var/empty" {
			continue
		}
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			out = append(out, home)
		}
	}
	return out, nil
}

func init() { engine.Register(authorizedKeysCheck{}) }
