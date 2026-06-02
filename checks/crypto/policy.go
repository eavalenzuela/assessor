package crypto

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type cryptoPolicyCheck struct{}

func (cryptoPolicyCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "crypto.system.policy",
		Title:       "System-wide crypto policy is at DEFAULT or stricter",
		Bucket:      "crypto",
		Severity:    finding.SevMedium,
		Description: "RHEL crypto-policies / Debian update-crypto-policies",
	}
}

func (cryptoPolicyCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	if _, err := exec.LookPath("update-crypto-policies"); err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "update-crypto-policies not present"}
	}
	out, err := exec.Command("update-crypto-policies", "--show").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	policy := strings.TrimSpace(string(out))
	ev := evidence.Note("update-crypto-policies --show", policy)
	status, msg := classifyCryptoPolicy(policy)
	f := finding.Finding{Status: status, Message: msg, Evidence: []finding.Evidence{ev}}
	if status == finding.StatusFail {
		f.Remediation = finding.Remediation{Commands: []string{"update-crypto-policies --set DEFAULT"}}
	}
	return f
}

// classifyCryptoPolicy maps an update-crypto-policies value to a verdict:
// LEGACY fails (weak algorithms allowed), the known-good DEFAULT/FUTURE/FIPS
// pass, and anything else is a Warn (custom policy needing manual review).
func classifyCryptoPolicy(policy string) (finding.Status, string) {
	switch policy {
	case "LEGACY":
		return finding.StatusFail, "crypto policy = LEGACY (allows weak algorithms)"
	case "DEFAULT", "FUTURE", "FIPS":
		return finding.StatusPass, "policy=" + policy
	default:
		return finding.StatusWarn, "custom policy: " + policy
	}
}

func init() { engine.Register(cryptoPolicyCheck{}) }
