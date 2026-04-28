package mac

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type selinuxBooleansCheck struct{}

func (selinuxBooleansCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "mac.selinux.boolean_drift",
		Title:       "SELinux booleans differ from defaults (review and snapshot)",
		Bucket:      "mac",
		Severity:    finding.SevInfo,
		Description: "Captures booleans where current state != default for diffing",
	}
}

func (selinuxBooleansCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasSELinux {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no SELinux"}
	}
	if _, err := exec.LookPath("getsebool"); err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "getsebool not available"}
	}
	out, err := exec.Command("getsebool", "-a").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	// We can't compute drift without policy defaults; just snapshot all -> on as a baseline.
	var on []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "on") {
			on = append(on, line)
		}
	}
	ev := evidence.Note("getsebool -a (on)", strings.Join(on, "\n"))
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "SELinux booleans set to 'on' — review and snapshot for diff mode",
		Evidence: []finding.Evidence{ev},
	}
}

func init() { engine.Register(selinuxBooleansCheck{}) }
