package auth

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type loginDefsCheck struct{}

func (loginDefsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.login_defs.policy",
		Title:    "/etc/login.defs sets password aging and umask",
		Bucket:   "auth",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (loginDefsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/login.defs"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	defer f.Close()
	got := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			got[strings.ToUpper(fields[0])] = fields[1]
		}
	}

	type rule struct {
		key string
		max int
		min int
	}
	intRules := []rule{
		{"PASS_MAX_DAYS", 365, 0},
		{"PASS_MIN_DAYS", 30, 1},
		{"PASS_WARN_AGE", 30, 7},
	}
	var bad []string
	for _, r := range intRules {
		v, ok := got[r.key]
		if !ok {
			bad = append(bad, r.key+" unset")
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s=%s (not numeric)", r.key, v))
			continue
		}
		if r.max > 0 && n > r.max {
			bad = append(bad, fmt.Sprintf("%s=%d (>%d)", r.key, n, r.max))
		}
		if r.min > 0 && n < r.min {
			bad = append(bad, fmt.Sprintf("%s=%d (<%d)", r.key, n, r.min))
		}
	}
	if v, ok := got["UMASK"]; ok && v != "027" && v != "077" {
		bad = append(bad, fmt.Sprintf("UMASK=%s (want 027 or 077)", v))
	}
	if v, ok := got["ENCRYPT_METHOD"]; !ok || (v != "SHA512" && v != "YESCRYPT") {
		bad = append(bad, fmt.Sprintf("ENCRYPT_METHOD=%q (want SHA512 or YESCRYPT)", v))
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "login.defs policy OK"}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: strings.Join(bad, "; "),
		Evidence: []finding.Evidence{
			evidence.Note(path, fmt.Sprintf("%v", got)),
		},
	}
}

type sudoersNopasswdCheck struct{}

func (sudoersNopasswdCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.sudoers.nopasswd",
		Title:    "No NOPASSWD entries in /etc/sudoers and /etc/sudoers.d",
		Bucket:   "auth",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (sudoersNopasswdCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var paths []string
	if _, err := os.Stat("/etc/sudoers"); err == nil {
		paths = append(paths, "/etc/sudoers")
	}
	filepath.WalkDir("/etc/sudoers.d", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	var bad []string
	var evs []finding.Evidence
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		lineNo := 0
		for s.Scan() {
			lineNo++
			line := strings.TrimSpace(s.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(line, "NOPASSWD") {
				bad = append(bad, fmt.Sprintf("%s:%d %s", p, lineNo, line))
				evs = append(evs, evidence.FileLine(p, lineNo, line))
			}
		}
		f.Close()
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no NOPASSWD entries"}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d NOPASSWD entries — verify each is intended", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Remove NOPASSWD or scope tightly to a specific command.",
		},
	}
}

type shadowPermsCheck struct{}

func (shadowPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "auth.shadow.perms",
		Title:    "/etc/shadow has root:shadow 0640 (or stricter)",
		Bucket:   "auth",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (shadowPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	st, err := os.Stat("/etc/shadow")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	mode := st.Mode().Perm()
	ev := evidence.Note("/etc/shadow", mode.String())
	if mode&0o077 != 0 || mode&0o004 != 0 {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  fmt.Sprintf("/etc/shadow mode is %s (group/other readable)", mode),
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Commands: []string{"chmod 0640 /etc/shadow", "chown root:shadow /etc/shadow"},
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: fmt.Sprintf("/etc/shadow %s", mode), Evidence: []finding.Evidence{ev}}
}

func init() {
	engine.Register(loginDefsCheck{})
	engine.Register(sudoersNopasswdCheck{})
	engine.Register(shadowPermsCheck{})
}
