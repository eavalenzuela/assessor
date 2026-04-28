package logging

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type logrotateCheck struct{}

func (logrotateCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.logrotate.config",
		Title:    "logrotate is installed and active",
		Bucket:   "logging",
		Severity: finding.SevLow,
	}
}

func (logrotateCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	if _, err := os.Stat("/etc/logrotate.conf"); err != nil {
		return finding.Finding{
			Status:  finding.StatusWarn,
			Message: "no /etc/logrotate.conf — logs may grow unbounded",
		}
	}
	count := 0
	filepath.WalkDir("/etc/logrotate.d", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			count++
		}
		return nil
	})
	ev := evidence.Note("/etc/logrotate.d", "drop-in count: "+itoa(count))
	if count == 0 {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "logrotate present but no drop-ins configured",
			Evidence: []finding.Evidence{ev},
		}
	}
	return finding.Finding{
		Status:   finding.StatusPass,
		Message:  itoa(count) + " logrotate drop-ins active",
		Evidence: []finding.Evidence{ev},
	}
}

type logPermsCheck struct{}

func (logPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "logging.files.perms",
		Title:    "Log files in /var/log are not world-readable",
		Bucket:   "logging",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (logPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var bad []string
	filepath.WalkDir("/var/log", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		st, err := os.Stat(p)
		if err != nil {
			return nil
		}
		// CIS suggests 640 for log files. Many distros default to 644 for /var/log/wtmp etc.
		if st.Mode().Perm()&0o007 != 0 {
			bad = append(bad, p+" "+st.Mode().Perm().String())
		}
		return nil
	})
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "log file perms OK"}
	}
	if len(bad) > 30 {
		bad = append(bad[:30], "...["+itoa(len(bad)-30)+" more]")
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: itoa(len(bad)) + " log file(s) world-readable",
		Evidence: []finding.Evidence{
			evidence.Note("/var/log walk", strings.Join(bad, "\n")),
		},
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func init() {
	engine.Register(logrotateCheck{})
	engine.Register(logPermsCheck{})
}
