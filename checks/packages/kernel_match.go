package packages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type kernelMatchCheck struct{}

func (kernelMatchCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "packages.kernel.running_matches_installed",
		Title:       "Running kernel matches the newest installed kernel",
		Bucket:      "packages",
		Severity:    finding.SevMedium,
		Description: "If a newer kernel is installed but not booted, host is running pre-update code",
	}
}

func (kernelMatchCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	running := facts.Host.KernelRel
	if running == "" {
		b, err := os.ReadFile("/proc/sys/kernel/osrelease")
		if err != nil {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
		running = strings.TrimSpace(string(b))
	}
	installed := installedKernels(facts.PackageManager)
	if len(installed) == 0 {
		return finding.Finding{Status: finding.StatusUnverified, Message: "no installed kernel packages found"}
	}
	sort.Strings(installed)
	newest := installed[len(installed)-1]
	ev := evidence.Note("kernels", fmt.Sprintf("running=%s\ninstalled=\n  %s", running, strings.Join(installed, "\n  ")))
	if !strings.HasPrefix(newest, running) && !strings.HasPrefix(running, newest) {
		// substring match handles distro suffixes like 6.17.0-22-generic vs linux-image-6.17.0-22-generic
		if !strings.Contains(newest, running) {
			return finding.Finding{
				Status:   finding.StatusFail,
				Message:  "newer kernel installed but not running — reboot pending",
				Evidence: []finding.Evidence{ev},
				Remediation: finding.Remediation{
					Description: "Schedule a reboot to activate the newer kernel.",
				},
			}
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "running kernel is newest installed", Evidence: []finding.Evidence{ev}}
}

func installedKernels(mgr string) []string {
	switch mgr {
	case "apt":
		out, err := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version}\n", "linux-image-*").Output()
		if err != nil {
			return nil
		}
		var ks []string
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.Fields(l)
			if len(parts) >= 2 && strings.HasPrefix(parts[0], "linux-image-") {
				ks = append(ks, strings.TrimPrefix(parts[0], "linux-image-"))
			}
		}
		return ks
	case "dnf", "yum":
		out, err := exec.Command("rpm", "-q", "kernel", "--qf", "%{VERSION}-%{RELEASE}\n").Output()
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
	return nil
}

func init() { engine.Register(kernelMatchCheck{}) }
