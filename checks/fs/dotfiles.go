package fs

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

type dotfilesPermsCheck struct{}

func (dotfilesPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "fs.dotfiles.perms",
		Title:       "User credential dotfiles have safe perms",
		Bucket:      "fs",
		Severity:    finding.SevHigh,
		Description: "~/.ssh, ~/.gnupg, ~/.aws/credentials, ~/.kube/config, ~/.netrc, ~/.docker/config.json",
	}
}

var sensitivePaths = []struct {
	rel    string
	maxBit os.FileMode
}{
	{".ssh", 0o077},
	{".gnupg", 0o077},
	{".aws/credentials", 0o077},
	{".aws/config", 0o077},
	{".kube/config", 0o077},
	{".netrc", 0o077},
	{".docker/config.json", 0o077},
	{".azure/credentials", 0o077},
	{".config/gcloud", 0o077},
}

func (dotfilesPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	homes, err := loadHomes()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var bad []string
	var evs []finding.Evidence
	for _, h := range homes {
		for _, sp := range sensitivePaths {
			p := filepath.Join(h, sp.rel)
			st, err := os.Stat(p)
			if err != nil {
				continue
			}
			if st.Mode().Perm()&sp.maxBit != 0 {
				bad = append(bad, fmt.Sprintf("%s: %s", p, st.Mode().Perm()))
				evs = append(evs, evidence.Note(p, st.Mode().String()))
			}
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "credential dotfiles have safe perms"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d credential file(s) too permissive", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Restrict to 0700 (dirs) / 0600 (files).",
		},
	}
}

func loadHomes() ([]string, error) {
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
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		home := fields[5]
		if home == "" || home == "/" {
			continue
		}
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			out = append(out, home)
		}
	}
	return out, nil
}

type luksCheck struct{}

func (luksCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "fs.encryption.luks",
		Title:    "Block devices report at least one LUKS-encrypted volume",
		Bucket:   "fs",
		Severity: finding.SevMedium,
	}
}

func (luksCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	// /proc/swaps + /proc/mounts tell us what's used; we check via lsblk for FSTYPE crypto_LUKS.
	ev, err := evidence.Command("lsblk", "-o", "NAME,FSTYPE,MOUNTPOINTS")
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Err: err.Error()}
	}
	if strings.Contains(ev.Content, "crypto_LUKS") {
		return finding.Finding{Status: finding.StatusPass, Message: "LUKS volume(s) present", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "no LUKS volumes detected — confirm encryption is intentional",
		Evidence: []finding.Evidence{ev},
	}
}

func init() {
	engine.Register(dotfilesPermsCheck{})
	engine.Register(luksCheck{})
}
