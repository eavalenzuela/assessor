package auth

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

type uidZeroCheck struct{}

func (uidZeroCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.uid_zero.unique",
		Title:    "Only one account has UID 0",
		Bucket:   "auth",
		Severity: finding.SevCritical,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (uidZeroCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/passwd"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	defer f.Close()

	roots, evs := scanUIDZero(f, path)

	if len(roots) <= 1 {
		return finding.Finding{Status: finding.StatusPass, Message: fmt.Sprintf("UID 0: %v", roots)}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("multiple UID-0 accounts: %v", roots),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Change extra accounts to a non-zero UID, or remove them.",
		},
	}
}

type emptyPasswordCheck struct{}

func (emptyPasswordCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.shadow.empty_password",
		Title:    "No accounts with empty password fields",
		Bucket:   "auth",
		Severity: finding.SevCritical,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (emptyPasswordCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/shadow"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	defer f.Close()
	bad, evs := scanEmptyPasswords(f, path)
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no empty-password accounts"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("accounts with empty passwords: %v", bad),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Lock or set passwords for the listed accounts.",
			Commands:    []string{"passwd -l <user>"},
		},
	}
}

// scanUIDZero returns every account in a passwd stream whose UID field is "0",
// with file-line evidence. More than one such account means a hidden root-
// equivalent login. `path` only labels the evidence.
func scanUIDZero(r io.Reader, path string) (roots []string, evs []finding.Evidence) {
	s := bufio.NewScanner(r)
	lineNo := 0
	for s.Scan() {
		lineNo++
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "0" {
			roots = append(roots, fields[0])
			evs = append(evs, evidence.FileLine(path, lineNo, s.Text()))
		}
	}
	return roots, evs
}

// scanEmptyPasswords returns accounts in a shadow stream whose password hash
// field is empty (passwordless login). `path` only labels the evidence.
func scanEmptyPasswords(r io.Reader, path string) (bad []string, evs []finding.Evidence) {
	s := bufio.NewScanner(r)
	lineNo := 0
	for s.Scan() {
		lineNo++
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			bad = append(bad, fields[0])
			evs = append(evs, evidence.FileLine(path, lineNo, fields[0]+":<empty>"))
		}
	}
	return bad, evs
}

func init() {
	engine.Register(uidZeroCheck{})
	engine.Register(emptyPasswordCheck{})
}
