package forensic

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type hiddenPidsCheck struct{}

func (hiddenPidsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "forensic.proc.hidden_pids",
		Title:       "PIDs in /proc are visible to ps",
		Bucket:      "forensic",
		Severity:    finding.SevHigh,
		Description: "Mismatch suggests a userspace rootkit hiding processes from ps/top",
	}
}

func (hiddenPidsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	procPids := map[int]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			procPids[pid] = true
		}
	}
	out, err := exec.Command("ps", "-eo", "pid", "--no-headers").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	psPids := parsePSPids(string(out))
	var hidden []int
	for _, pid := range pidsOnlyIn(procPids, psPids) {
		// PIDs can come and go between the two reads — re-check the PID still
		// exists to filter out short-lived processes that exited mid-scan.
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			hidden = append(hidden, pid)
		}
	}
	if len(hidden) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all /proc pids visible to ps"}
	}
	// Limit noise from race conditions; threshold of 3+ stable pids is suspicious.
	if len(hidden) < 3 {
		return finding.Finding{Status: finding.StatusPass, Message: fmt.Sprintf("%d short-lived PIDs not in ps (likely race)", len(hidden))}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: fmt.Sprintf("%d PIDs in /proc not visible to ps — possible rootkit", len(hidden)),
		Evidence: []finding.Evidence{
			evidence.Note("/proc \\ ps", fmt.Sprintf("%v", hidden)),
		},
		Remediation: finding.Remediation{
			Description: "Investigate each hidden PID with /proc/<pid>/cmdline, /proc/<pid>/exe, /proc/<pid>/maps.",
		},
	}
}

type unsignedModulesCheck struct{}

func (unsignedModulesCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "forensic.modules.unsigned",
		Title:    "Loaded kernel modules are signed",
		Bucket:   "forensic",
		Severity: finding.SevHigh,
	}
}

func (unsignedModulesCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	out, err := exec.Command("lsmod").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var unsigned []string
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		mod := fields[0]
		modinfo, err := exec.Command("modinfo", "-F", "sig_id", mod).Output()
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(modinfo)) == "" {
			unsigned = append(unsigned, mod)
		}
	}
	if len(unsigned) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all loaded modules signed"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: fmt.Sprintf("%d unsigned module(s)", len(unsigned)),
		Evidence: []finding.Evidence{
			evidence.Note("lsmod + modinfo", strings.Join(unsigned, "\n")),
		},
		Remediation: finding.Remediation{
			Description: "Rebuild affected DKMS modules with signing, or remove if not required.",
		},
	}
}

// parsePSPids parses whitespace-separated PIDs (from `ps -eo pid`) into a set,
// skipping non-numeric fields.
func parsePSPids(out string) map[int]bool {
	m := map[int]bool{}
	for _, f := range strings.Fields(out) {
		if n, err := strconv.Atoi(f); err == nil {
			m[n] = true
		}
	}
	return m
}

// pidsOnlyIn returns the PIDs present in `a` but not `b` — i.e. PIDs in /proc
// that ps did not report, the candidate set for process-hiding rootkits.
func pidsOnlyIn(a, b map[int]bool) []int {
	var out []int
	for pid := range a {
		if !b[pid] {
			out = append(out, pid)
		}
	}
	return out
}

func init() {
	engine.Register(hiddenPidsCheck{})
	engine.Register(unsignedModulesCheck{})
}
