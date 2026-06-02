package webdb

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

type pgHbaCheck struct{}

func (pgHbaCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "webdb.postgres.pg_hba_trust",
		Title:       "PostgreSQL pg_hba.conf has no `trust` entries for non-local connections",
		Bucket:      "webdb",
		Severity:    finding.SevCritical,
		Description: "`trust` auth allows passwordless logins; only acceptable for local-Unix peers",
	}
}

func (pgHbaCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var paths []string
	for _, base := range []string{"/etc/postgresql", "/var/lib/pgsql"} {
		filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Base(p) == "pg_hba.conf" {
				paths = append(paths, p)
			}
			return nil
		})
	}
	if len(paths) == 0 {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no pg_hba.conf found"}
	}
	var bad []string
	var evs []finding.Evidence
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		b, e := scanPgHbaTrust(f, p)
		f.Close()
		bad = append(bad, b...)
		evs = append(evs, e...)
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no risky `trust` entries"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d risky `trust` entries", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Replace `trust` with `scram-sha-256` (or `md5` if scram unavailable) and restart postgres.",
		},
	}
}

// scanPgHbaTrust scans one pg_hba.conf for risky `trust` auth: a `trust`
// method on any connection type other than `local` (Unix-socket peer) permits
// passwordless TCP logins. `path` is used only to label the returned evidence.
func scanPgHbaTrust(r io.Reader, path string) (bad []string, evs []finding.Evidence) {
	s := bufio.NewScanner(r)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		method := fields[len(fields)-1]
		typ := fields[0]
		if method == "trust" && typ != "local" {
			bad = append(bad, fmt.Sprintf("%s:%d %s", path, lineNo, line))
			evs = append(evs, evidence.FileLine(path, lineNo, line))
		}
	}
	return bad, evs
}

func init() { engine.Register(pgHbaCheck{}) }
