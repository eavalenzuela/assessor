package kernel

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type bootPermsCheck struct{}

func (bootPermsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "kernel.boot.perms",
		Title:    "GRUB config and /boot are not world-readable",
		Bucket:   "kernel",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (bootPermsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	checks := []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI"}
	var bad []string
	var evs []finding.Evidence
	for _, p := range checks {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := st.Mode().Perm()
		if mode&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: %s", p, mode))
			evs = append(evs, evidence.Note(p, mode.String()))
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "boot files have safe perms"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Commands: []string{"chmod 600 /boot/grub*/grub.cfg", "chown root:root /boot/grub*/grub.cfg"},
		},
	}
}

type grubPasswordCheck struct{}

func (grubPasswordCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "kernel.boot.grub_password",
		Title:    "GRUB has a password set for editing menu entries",
		Bucket:   "kernel",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (grubPasswordCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/grub.d", "/boot/grub", "/boot/grub2"}
	for _, root := range roots {
		found := false
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			if strings.Contains(string(b), "password_pbkdf2") || strings.Contains(string(b), "password_") {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
		if found {
			return finding.Finding{Status: finding.StatusPass, Message: "GRUB password configured"}
		}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: "no GRUB password directives found",
		Remediation: finding.Remediation{
			Description: "Run grub-mkpasswd-pbkdf2 and add `password_pbkdf2 <user> <hash>` to /etc/grub.d/40_custom; then update-grub.",
		},
	}
}

type modulesBlocklistCheck struct{}

func (modulesBlocklistCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "kernel.modules.blocklist",
		Title:    "Legacy filesystem modules are not loaded",
		Bucket:   "kernel",
		Severity: finding.SevLow,
		Refs:     []finding.Reference{{Source: "CIS", ID: "1.1.1"}},
		Profiles: []string{"server", "cis-l1"},
	}
}

func (modulesBlocklistCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	out, err := exec.Command("lsmod").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			loaded[fields[0]] = true
		}
	}
	bad := []string{}
	for _, m := range []string{"cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "squashfs", "udf", "usb-storage", "dccp", "sctp", "tipc", "rds"} {
		if loaded[m] {
			bad = append(bad, m)
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no legacy modules loaded"}
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: "legacy modules loaded: " + strings.Join(bad, ", "),
		Evidence: []finding.Evidence{
			evidence.Note("lsmod", strings.Join(bad, "\n")),
		},
		Remediation: finding.Remediation{
			Description: "Add `install <mod> /bin/true` lines to /etc/modprobe.d/blocklist.conf.",
		},
	}
}

func init() {
	engine.Register(bootPermsCheck{})
	engine.Register(grubPasswordCheck{})
	engine.Register(modulesBlocklistCheck{})
}
