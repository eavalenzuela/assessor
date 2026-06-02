package logging

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type journaldPersistentCheck struct{}

func (journaldPersistentCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.journald.persistent",
		Title:    "journald is configured for persistent storage",
		Bucket:   "logging",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (journaldPersistentCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSystemd {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no systemd"}
	}
	if st, err := os.Stat("/var/log/journal"); err == nil && st.IsDir() {
		return finding.Finding{Status: finding.StatusPass, Message: "/var/log/journal exists",
			Evidence: []finding.Evidence{evidence.Note("/var/log/journal", "directory present")}}
	}
	val := journaldKey("Storage")
	ev := evidence.Note("journald.conf Storage", val)
	if val == "persistent" {
		return finding.Finding{Status: finding.StatusPass, Message: "Storage=persistent set", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  "journald not persistent (no /var/log/journal and Storage != persistent)",
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Commands: []string{
				"mkdir -p /var/log/journal",
				"systemd-tmpfiles --create --prefix /var/log/journal",
				"systemctl restart systemd-journald",
			},
		},
	}
}

func journaldKey(key string) string {
	for _, p := range []string{"/etc/systemd/journald.conf"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		if v := parseJournaldKey(f, key); v != "" {
			return v
		}
	}
	return ""
}

// parseJournaldKey returns the value of the given journald.conf key
// (case-insensitive key, value lower-cased), or "" if absent. Blanks and
// #-comments are skipped.
func parseJournaldKey(r io.Reader, key string) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func init() { engine.Register(journaldPersistentCheck{}) }
