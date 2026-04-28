package forensic

import (
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type ldPreloadCheck struct{}

func (ldPreloadCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "forensic.ld_preload.unexpected",
		Title:       "/etc/ld.so.preload is empty (or non-existent)",
		Bucket:      "forensic",
		Severity:    finding.SevHigh,
		Description: "Persistent library injection commonly indicates rootkit-style hooks",
	}
}

func (ldPreloadCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/ld.so.preload"
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusPass, Message: "no ld.so.preload"}
	}
	contents := strings.TrimSpace(string(b))
	if contents == "" {
		return finding.Finding{Status: finding.StatusPass, Message: "ld.so.preload is empty"}
	}
	ev, _ := evidence.File(path)
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "ld.so.preload has entries — verify each is legitimate",
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "If unexpected, investigate immediately — possible rootkit indicator.",
		},
	}
}

func init() { engine.Register(ldPreloadCheck{}) }
