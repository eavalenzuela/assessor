package kernel

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

type cmdlineCheck struct{}

func (cmdlineCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "kernel.cmdline.hardening",
		Title:    "Kernel command line includes hardening flags",
		Bucket:   "kernel",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "workstation"},
	}
}

var wantedCmdlineFlags = []string{
	"slab_nomerge", "init_on_alloc=1", "init_on_free=1",
	"page_alloc.shuffle=1", "vsyscall=none",
}

func (cmdlineCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	cmdline := strings.TrimSpace(string(b))
	var missing []string
	for _, f := range wantedCmdlineFlags {
		if !strings.Contains(cmdline, f) {
			missing = append(missing, f)
		}
	}
	ev := evidence.Note("/proc/cmdline", cmdline)
	if len(missing) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "all hardening flags present", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("missing hardening flags: %s", strings.Join(missing, ", ")),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Add the missing flags to GRUB_CMDLINE_LINUX in /etc/default/grub and rebuild.",
			Commands:    []string{"update-grub || grub2-mkconfig -o /boot/grub2/grub.cfg"},
		},
	}
}

type modulesSigCheck struct{}

func (modulesSigCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "kernel.modules.signed",
		Title:    "Kernel module signing is enforced",
		Bucket:   "kernel",
		Severity: finding.SevMedium,
		Profiles: []string{"server"},
	}
}

func (modulesSigCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	b, err := os.ReadFile("/sys/module/module/parameters/sig_enforce")
	if err != nil {
		return finding.Finding{Status: finding.StatusUnverified, Message: "kernel does not expose module signing state"}
	}
	val := strings.TrimSpace(string(b))
	ev := evidence.Note("/sys/module/module/parameters/sig_enforce", val)
	if val == "Y" {
		return finding.Finding{Status: finding.StatusPass, Message: "module signing enforced", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  "module signing is not enforced",
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Boot with module.sig_enforce=1 (requires a kernel built with module signing).",
		},
	}
}

func init() {
	engine.Register(cmdlineCheck{})
	engine.Register(modulesSigCheck{})
}
