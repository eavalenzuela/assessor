package mac

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

type apparmorComplainCheck struct{}

func (apparmorComplainCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "mac.apparmor.complain_count",
		Title:    "AppArmor profiles in complain mode (not enforcing)",
		Bucket:   "mac",
		Severity: finding.SevMedium,
	}
}

func (apparmorComplainCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasAppArmor {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no AppArmor"}
	}
	if _, err := exec.LookPath("aa-status"); err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "aa-status not installed"}
	}
	out, err := exec.Command("aa-status").CombinedOutput()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	complain := countComplainProfiles(string(out))
	ev := evidence.Note("aa-status", string(out))
	if complain == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no profiles in complain mode", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d AppArmor profile(s) in complain mode", complain),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Move profiles to enforce: `aa-enforce /etc/apparmor.d/<profile>`",
		},
	}
}

// countComplainProfiles parses `aa-status` output for the "N profiles are in
// complain mode" line and returns N (0 if absent).
func countComplainProfiles(out string) int {
	var complain int
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "profiles are in complain mode") {
			fmt.Sscanf(l, "%d profiles are in complain mode", &complain)
		}
	}
	return complain
}

func init() { engine.Register(apparmorComplainCheck{}) }
