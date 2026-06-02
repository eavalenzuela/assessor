package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type pamPwqualityCheck struct{}

func (pamPwqualityCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.pam.pwquality",
		Title:    "pam_pwquality enforces minimum complexity",
		Bucket:   "auth",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (pamPwqualityCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	candidates := []string{"/etc/security/pwquality.conf"}
	matches, _ := filepath.Glob("/etc/security/pwquality.conf.d/*.conf")
	candidates = append(candidates, matches...)
	cfg := map[string]string{}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		b, _ := os.ReadFile(p)
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if ok {
				cfg[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		f.Close()
	}
	if len(cfg) == 0 {
		return finding.Finding{Status: finding.StatusFail, Message: "no pwquality settings found",
			Remediation: finding.Remediation{Description: "Install libpam-pwquality and configure minlen, dcredit, ucredit, ocredit, lcredit, retry."},
		}
	}
	bad := evaluatePwquality(cfg)
	ev := evidence.Note("pwquality.conf", fmt.Sprintf("%v", cfg))
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "pwquality OK", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusFail, Message: strings.Join(bad, "; "), Evidence: []finding.Evidence{ev}}
}

type pamFaillockCheck struct{}

func (pamFaillockCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.pam.faillock",
		Title:    "pam_faillock (or pam_tally2) enforces account lockout",
		Bucket:   "auth",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (pamFaillockCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	contents := concatPamFiles()
	if contents == "" {
		return finding.Finding{Status: finding.StatusError, Message: "no PAM files readable"}
	}
	if !hasLockoutModule(contents) {
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "no pam_faillock or pam_tally2 entries — accounts will not lock on repeated failure",
			Remediation: finding.Remediation{
				Description: "Add `auth required pam_faillock.so preauth ... silent deny=5 unlock_time=900` to /etc/pam.d/common-auth (Debian) or /etc/pam.d/system-auth (RHEL).",
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "lockout module configured"}
}

func concatPamFiles() string {
	var b strings.Builder
	filepath.WalkDir("/etc/pam.d", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		b.Write(data)
		b.WriteString("\n")
		return nil
	})
	return b.String()
}

type passwdGroupPermsCheck struct{}

func (passwdGroupPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.passwd.perms",
		Title:    "/etc/passwd and /etc/group are 0644 root:root",
		Bucket:   "auth",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (passwdGroupPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var bad []string
	var evs []finding.Evidence
	for _, p := range []string{"/etc/passwd", "/etc/group"} {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := st.Mode().Perm()
		if mode&0o022 != 0 {
			bad = append(bad, fmt.Sprintf("%s: %s (group/world writable)", p, mode))
			evs = append(evs, evidence.Note(p, mode.String()))
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "passwd/group perms OK"}
	}
	return finding.Finding{Status: finding.StatusFail, Message: strings.Join(bad, "; "), Evidence: evs}
}

type serviceShellsCheck struct{}

func (serviceShellsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.accounts.service_shells",
		Title:    "System (UID < 1000) accounts have nologin shells",
		Bucket:   "auth",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (serviceShellsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	defer f.Close()
	bad := scanServiceShells(f)
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all system accounts have nologin"}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: strings.Join(bad, "; "),
		Remediation: finding.Remediation{
			Commands: []string{"usermod -s /usr/sbin/nologin <user>"},
		},
	}
}

// evaluatePwquality checks parsed pwquality settings: minlen must be >= 14 and
// each character-class credit (d/u/o/l) must be negative, which forces at least
// one character of that class. Returns a list of violations (empty == OK).
func evaluatePwquality(cfg map[string]string) []string {
	var bad []string
	if v := cfg["minlen"]; v == "" || atoi(v) < 14 {
		bad = append(bad, fmt.Sprintf("minlen=%q (want >=14)", v))
	}
	for _, k := range []string{"dcredit", "ucredit", "ocredit", "lcredit"} {
		if v := cfg[k]; v == "" || atoi(v) >= 0 {
			bad = append(bad, fmt.Sprintf("%s=%q (want -1 to require this class)", k, v))
		}
	}
	return bad
}

// hasLockoutModule reports whether concatenated PAM config references an
// account-lockout module (pam_faillock or the legacy pam_tally2).
func hasLockoutModule(contents string) bool {
	return strings.Contains(contents, "pam_faillock.so") || strings.Contains(contents, "pam_tally2.so")
}

// scanServiceShells returns system accounts (0 < UID < 1000) that have an
// interactive login shell. The well-known maintenance accounts sync/shutdown/
// halt are exempt, as are accounts whose shell ends in nologin or false.
func scanServiceShells(r io.Reader) []string {
	var bad []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid := atoi(fields[2])
		if uid >= 1000 || uid == 0 {
			continue
		}
		shell := fields[6]
		if shell == "/bin/sync" || shell == "/sbin/shutdown" || shell == "/sbin/halt" {
			continue
		}
		if !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "false") {
			bad = append(bad, fmt.Sprintf("%s (uid=%d) shell=%s", fields[0], uid, shell))
		}
	}
	return bad
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			if c == '-' && n == 0 {
				continue
			}
			return -1
		}
		n = n*10 + int(c-'0')
	}
	if strings.HasPrefix(s, "-") {
		return -n
	}
	return n
}

func init() {
	engine.Register(pamPwqualityCheck{})
	engine.Register(pamFaillockCheck{})
	engine.Register(passwdGroupPermsCheck{})
	engine.Register(serviceShellsCheck{})
}
