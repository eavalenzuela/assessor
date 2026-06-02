package packages

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type reposSignedCheck struct{}

func (reposSignedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "packages.repos.signed",
		Title:       "Package repositories require signature verification",
		Bucket:      "packages",
		Severity:    finding.SevHigh,
		Description: "apt: no [trusted=yes]; dnf: gpgcheck=1 in every repo",
	}
}

func (reposSignedCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	switch facts.PackageManager {
	case "apt":
		return aptRepoSigning()
	case "dnf", "yum":
		return dnfRepoSigning()
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no supported package manager"}
}

func aptRepoSigning() finding.Finding {
	roots := []string{"/etc/apt/sources.list", "/etc/apt/sources.list.d"}
	var bad []string
	var evs []finding.Evidence
	check := func(p string) {
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		bb, ee := scanAptTrusted(string(b), p)
		bad = append(bad, bb...)
		evs = append(evs, ee...)
	}
	for _, r := range roots {
		st, err := os.Stat(r)
		if err != nil {
			continue
		}
		if st.IsDir() {
			filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".list") || strings.HasSuffix(p, ".sources")) {
					check(p)
				}
				return nil
			})
		} else {
			check(r)
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no [trusted=yes] in apt sources"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d apt source(s) bypass signature verification", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Remove `trusted=yes` and properly sign + key-trust the repo.",
		},
	}
}

func dnfRepoSigning() finding.Finding {
	var bad []string
	var evs []finding.Evidence
	filepath.WalkDir("/etc/yum.repos.d", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".repo") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		bb, ee := scanDnfGpgcheck(string(b), p)
		bad = append(bad, bb...)
		evs = append(evs, ee...)
		return nil
	})
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all dnf/yum repos have gpgcheck=1"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d dnf/yum repo(s) with gpgcheck=0", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Set gpgcheck=1 and import the repo's GPG key.",
		},
	}
}

// scanAptTrusted returns apt source lines that disable signature verification
// via `trusted=yes`, skipping blanks and #-comments. `path` labels evidence.
func scanAptTrusted(content, path string) (bad []string, evs []finding.Evidence) {
	for i, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "#") || lower == "" {
			continue
		}
		if strings.Contains(lower, "trusted=yes") {
			bad = append(bad, fmt.Sprintf("%s:%d %s", path, i+1, strings.TrimSpace(line)))
			evs = append(evs, evidence.FileLine(path, i+1, strings.TrimSpace(line)))
		}
	}
	return bad, evs
}

// scanDnfGpgcheck returns dnf/yum repo lines that set `gpgcheck=0` (whitespace
// around the `=` is tolerated). `path` labels evidence.
func scanDnfGpgcheck(content, path string) (bad []string, evs []finding.Evidence) {
	for i, line := range strings.Split(content, "\n") {
		low := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(line)), " ", "")
		if low == "gpgcheck=0" {
			bad = append(bad, fmt.Sprintf("%s:%d %s", path, i+1, strings.TrimSpace(line)))
			evs = append(evs, evidence.FileLine(path, i+1, strings.TrimSpace(line)))
		}
	}
	return bad, evs
}

func init() { engine.Register(reposSignedCheck{}) }
