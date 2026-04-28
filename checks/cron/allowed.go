package cron

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type cronAllowedCheck struct{}

func (cronAllowedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "cron.access.restricted",
		Title:    "cron.allow / at.allow define an allowlist (not deny)",
		Bucket:   "cron",
		Severity: finding.SevLow,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (cronAllowedCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var present, missing []string
	for _, p := range []string{"/etc/cron.allow", "/etc/at.allow"} {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		} else {
			missing = append(missing, p)
		}
	}
	ev := evidence.Note("cron access files", "present="+strings.Join(present, ",")+" missing="+strings.Join(missing, ","))
	if len(missing) > 0 {
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "missing allow lists: " + strings.Join(missing, ", "),
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Create empty (or root-only) allow files to default-deny.",
				Commands: []string{
					"touch /etc/cron.allow /etc/at.allow",
					"chmod 600 /etc/cron.allow /etc/at.allow",
					"chown root:root /etc/cron.allow /etc/at.allow",
				},
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "allow lists present", Evidence: []finding.Evidence{ev}}
}

func init() { engine.Register(cronAllowedCheck{}) }
