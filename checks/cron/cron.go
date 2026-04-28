package cron

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type cronPermsCheck struct{}

func (cronPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "cron.perms.world_writable",
		Title:    "/etc/cron* and /etc/crontab are not world-writable",
		Bucket:   "cron",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "workstation", "cis-l1"},
	}
}

func (cronPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	var bad []string
	var evs []finding.Evidence
	for _, r := range roots {
		filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			st, err := os.Stat(p)
			if err != nil {
				return nil
			}
			if st.Mode().Perm()&0o002 != 0 {
				bad = append(bad, fmt.Sprintf("%s (%s)", p, st.Mode().Perm()))
				evs = append(evs, evidence.Note(p, st.Mode().String()))
			}
			return nil
		})
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "cron perms OK"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d cron path(s) world-writable", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Restrict to root:root 0600 (file) / 0700 (dir).",
			Commands:    []string{"chmod o-w /etc/cron.d/*", "chown root:root /etc/cron.d/*"},
		},
	}
}

func init() { engine.Register(cronPermsCheck{}) }
