package auth

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type staleAccountsCheck struct{}

func (staleAccountsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "auth.accounts.stale",
		Title:       "No interactive accounts unused for >180 days",
		Bucket:      "auth",
		Severity:    finding.SevLow,
		Description: "lastlog says **Never logged in** or last login >180d means the account is likely abandoned",
	}
}

func (staleAccountsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	out, err := exec.Command("lastlog", "-b", "180").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "lastlog unavailable", Err: err.Error()}
	}
	var stale []string
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			stale = append(stale, fields[0])
		}
	}
	if len(stale) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no stale interactive accounts"}
	}
	ev := evidence.Note("lastlog -b 180", string(out))
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d account(s) unused for >180 days — review if needed", len(stale)),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Lock or remove abandoned accounts.",
			Commands:    []string{"usermod -L <user>", "userdel -r <user>"},
		},
	}
}

func init() { engine.Register(staleAccountsCheck{}) }
