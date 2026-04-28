package fs

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type swapEncryptedCheck struct{}

func (swapEncryptedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "fs.swap.encrypted",
		Title:       "Active swap is encrypted (or zswap-only)",
		Bucket:      "fs",
		Severity:    finding.SevMedium,
		Description: "Plaintext swap can leak in-memory keys to disk",
	}
}

func (swapEncryptedCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	b, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return finding.Finding{Status: finding.StatusPass, Message: "no swap configured"}
	}
	devices := []string{}
	for _, l := range lines[1:] {
		fields := strings.Fields(l)
		if len(fields) > 0 {
			devices = append(devices, fields[0])
		}
	}
	// Check each backing device for crypto_LUKS or dm-crypt.
	out, err := exec.Command("lsblk", "-o", "NAME,FSTYPE,TYPE,MOUNTPOINTS").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "lsblk unavailable", Err: err.Error()}
	}
	var bad []string
	for _, d := range devices {
		short := strings.TrimPrefix(d, "/dev/")
		// match lines mentioning the device
		encrypted := false
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, short) {
				continue
			}
			if strings.Contains(line, "crypt") || strings.Contains(line, "crypto_LUKS") {
				encrypted = true
				break
			}
		}
		if !encrypted {
			bad = append(bad, d)
		}
	}
	ev := evidence.Note("/proc/swaps + lsblk", strings.Join(devices, " "))
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all active swap is encrypted", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  "plaintext swap on: " + strings.Join(bad, ", "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Move swap onto a LUKS-backed volume, or disable swap and rely on zram/zswap.",
		},
	}
}

func init() { engine.Register(swapEncryptedCheck{}) }
