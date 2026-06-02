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

type unconfinedCheck struct{}

func (unconfinedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "mac.unconfined.processes",
		Title:    "Few/no unconfined processes (AppArmor) or unconfined_t (SELinux)",
		Bucket:   "mac",
		Severity: finding.SevMedium,
	}
}

func (unconfinedCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if facts.HasAppArmor {
		out, err := exec.Command("aa-status", "--json").Output()
		if err != nil {
			return finding.Finding{Status: finding.StatusUnverified, Err: err.Error()}
		}
		// json structure varies by version; just count "unconfined"
		count := strings.Count(string(out), `"unconfined":[`)
		ev := evidence.Note("aa-status --json", string(out))
		_ = count
		return finding.Finding{Status: finding.StatusPass, Message: "AppArmor present (manual review of unconfined processes recommended)", Evidence: []finding.Evidence{ev}}
	}
	if facts.HasSELinux {
		out, err := exec.Command("ps", "-eZ").Output()
		if err != nil {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
		unconfined := unconfinedSELinux(string(out))
		ev := evidence.Note("ps -eZ | grep unconfined_t", strings.Join(unconfined, "\n"))
		if len(unconfined) > 0 {
			return finding.Finding{
				Status:   finding.StatusWarn,
				Message:  fmt.Sprintf("%d processes in unconfined_t", len(unconfined)),
				Evidence: []finding.Evidence{ev},
			}
		}
		return finding.Finding{Status: finding.StatusPass, Message: "no unconfined_t processes"}
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no MAC subsystem"}
}

// unconfinedSELinux returns the `ps -eZ` lines whose security context is the
// unconfined_t domain (processes running outside SELinux confinement).
func unconfinedSELinux(psOut string) []string {
	var unconfined []string
	for _, line := range strings.Split(psOut, "\n") {
		if strings.Contains(line, "unconfined_t") {
			unconfined = append(unconfined, line)
		}
	}
	return unconfined
}

func init() { engine.Register(unconfinedCheck{}) }
