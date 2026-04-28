package ssh

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type rateLimitsCheck struct{}

func (rateLimitsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "ssh.sshd.rate_limits",
		Title:    "sshd MaxStartups and MaxSessions cap concurrent abuse",
		Bucket:   "ssh",
		Severity: finding.SevLow,
	}
}

func (rateLimitsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/ssh/sshd_config"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no sshd_config"}
	}
	defer f.Close()
	got := parseSshdConfig(f)
	var bad []string
	if v, ok := got["maxstartups"]; !ok {
		bad = append(bad, "MaxStartups not set (default 10:30:100 may allow flooding)")
	} else if !strings.Contains(v.val, ":") {
		bad = append(bad, fmt.Sprintf("MaxStartups=%s (want start:rate:full triple)", v.val))
	}
	if v, ok := got["maxsessions"]; !ok {
		bad = append(bad, "MaxSessions not set")
	} else if v.val == "0" || atoiSafe(v.val) > 10 {
		bad = append(bad, fmt.Sprintf("MaxSessions=%s (want 4-10)", v.val))
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "rate limits configured"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: strings.Join(bad, "; "),
		Evidence: []finding.Evidence{
			evidence.Note(path, fmt.Sprintf("MaxStartups=%v MaxSessions=%v", got["maxstartups"].val, got["maxsessions"].val)),
		},
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func init() { engine.Register(rateLimitsCheck{}) }
