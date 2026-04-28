package webdb

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

type postgresListenCheck struct{}

func (postgresListenCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.postgres.listen_ssl",
		Title:    "PostgreSQL listen_addresses is restricted and ssl=on",
		Bucket:   "webdb",
		Severity: finding.SevHigh,
	}
}

func (postgresListenCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var paths []string
	for _, base := range []string{"/etc/postgresql", "/var/lib/pgsql"} {
		filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Base(p) == "postgresql.conf" {
				paths = append(paths, p)
			}
			return nil
		})
	}
	if len(paths) == 0 {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no postgresql.conf"}
	}
	var bad []string
	var evs []finding.Evidence
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		listen := pgValue(string(b), "listen_addresses")
		ssl := pgValue(string(b), "ssl")
		if listen == "*" {
			bad = append(bad, p+" listen_addresses='*'")
		}
		if ssl != "" && !strings.EqualFold(ssl, "on") {
			bad = append(bad, p+" ssl="+ssl)
		}
		ev, _ := evidence.File(p)
		evs = append(evs, ev)
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "postgres listen+ssl OK", Evidence: evs}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Set listen_addresses to a specific interface and ssl = on.",
		},
	}
}

// pgValue parses postgresql.conf style `key = value` (ignores comments + quotes).
func pgValue(contents, key string) string {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, "#"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		return strings.Trim(v, `'"`)
	}
	return ""
}

func init() { engine.Register(postgresListenCheck{}) }
