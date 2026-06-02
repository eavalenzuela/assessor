package forensic

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type passwdMtimeCheck struct{}

func (passwdMtimeCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "forensic.identity_files.recent_mod",
		Title:       "/etc/passwd, /etc/shadow, /etc/group modified recently",
		Bucket:      "forensic",
		Severity:    finding.SevMedium,
		Description: "Surfaces recent identity-file mutations — usually legitimate, worth a glance on incident triage",
	}
}

func (passwdMtimeCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	var hits []string
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers"} {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.ModTime().After(cutoff) {
			hits = append(hits, fmt.Sprintf("%s  %s", st.ModTime().Format("2006-01-02 15:04"), p))
		}
	}
	sort.Strings(hits)
	if len(hits) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no recent identity-file mutations"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: fmt.Sprintf("%d identity file(s) modified in last 7d", len(hits)),
		Evidence: []finding.Evidence{
			evidence.Note("stat", strings.Join(hits, "\n")),
		},
	}
}

type bashHistorySecretsCheck struct{}

func (bashHistorySecretsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "forensic.shell_history.secrets",
		Title:       "Shell history files do not contain obvious secrets",
		Bucket:      "forensic",
		Severity:    finding.SevMedium,
		Description: "Heuristic scan for tokens, passwords, AWS keys",
	}
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*\S+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}`),
}

func (bashHistorySecretsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	files := []string{"/root/.bash_history", "/root/.zsh_history"}
	if homes, err := historyHomes(); err == nil {
		for _, h := range homes {
			for _, name := range []string{".bash_history", ".zsh_history", ".python_history", ".psql_history", ".mysql_history"} {
				files = append(files, filepath.Join(h, name))
			}
		}
	}
	var hits []string
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		hits = append(hits, scanHistorySecrets(f, p)...)
		f.Close()
	}
	if len(hits) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no obvious secrets in shell histories"}
	}
	if len(hits) > 30 {
		hits = append(hits[:30], fmt.Sprintf("...[%d more]", len(hits)-30))
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: fmt.Sprintf("%d possible secret(s) in shell histories", len(hits)),
		Evidence: []finding.Evidence{
			// Don't echo matched lines — only the metadata. Reduces accidental disclosure
			// in the report itself.
			evidence.TrackedNote("shell history scan", strings.Join(hits, "\n")),
		},
		Remediation: finding.Remediation{
			Description: "Truncate the affected histories and rotate any disclosed credentials.",
		},
	}
}

// scanHistorySecrets scans a shell-history stream line-by-line against
// secretPatterns and returns "path:line (matches <regex>)" for each hit. Only
// metadata is returned — never the matched line — to avoid disclosing the
// secret in the report itself. `path` labels the output.
func scanHistorySecrets(r io.Reader, path string) []string {
	var hits []string
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := s.Text()
		for _, re := range secretPatterns {
			if re.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d (matches %s)", path, lineNo, re.String()))
				break
			}
		}
	}
	return hits
}

func historyHomes() ([]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	for _, home := range parseHistoryHomes(f) {
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			out = append(out, home)
		}
	}
	return out, nil
}

// parseHistoryHomes returns home directories of interactive accounts from a
// passwd stream, excluding nologin/false shells and the empty, "/", and "/root"
// homes (root is scanned separately). It does not stat the dirs.
func parseHistoryHomes(r io.Reader) []string {
	var out []string
	s := bufio.NewScanner(r)
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
		if home == "" || home == "/" || home == "/root" {
			continue
		}
		out = append(out, home)
	}
	return out
}

func init() {
	engine.Register(passwdMtimeCheck{})
	engine.Register(bashHistorySecretsCheck{})
}
