package kernel

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type dmesgErrorsCheck struct{}

func (dmesgErrorsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "kernel.dmesg.recent_errors",
		Title:       "Recent dmesg shows no oom-killer or hardware errors",
		Bucket:      "kernel",
		Severity:    finding.SevMedium,
		Description: "OOM-kills and machine-check exceptions can mask attacks or precede outages",
	}
}

var dmesgPatterns = []string{
	"oom-kill", "Out of memory", "Killed process",
	"Machine check", "Hardware Error", "MCE",
	"general protection fault", "Call Trace:",
}

func (dmesgErrorsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	out, err := exec.Command("dmesg", "-l", "err,crit,alert,emerg", "-T").Output()
	if err != nil {
		// dmesg may need root or fail on systems with kernel.dmesg_restrict=1 — that's expected.
		return finding.Finding{Status: finding.StatusUnverified, Message: "dmesg unavailable: " + err.Error()}
	}
	var hits []string
	for _, line := range strings.Split(string(out), "\n") {
		for _, pat := range dmesgPatterns {
			if strings.Contains(line, pat) {
				hits = append(hits, line)
				break
			}
		}
	}
	ev := evidence.Note("dmesg -l err+", strings.Join(hits, "\n"))
	if len(hits) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no recent kernel errors"}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "kernel reporting errors — review",
		Evidence: []finding.Evidence{ev},
	}
}

func init() { engine.Register(dmesgErrorsCheck{}) }
