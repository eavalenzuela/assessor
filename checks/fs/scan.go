package fs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

// Common skip set — pseudo-filesystems, snapshots, container roots, etc.
var skipPaths = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
	"/var/lib/docker": true, "/var/lib/containers": true,
	"/snap": true, "/.snapshots": true,
}

func walkSystem(walkFn func(path string, d fs.DirEntry, info os.FileInfo)) {
	roots := []string{"/bin", "/sbin", "/usr", "/etc", "/opt", "/var", "/home", "/root", "/tmp"}
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsPermission(err) {
					return nil
				}
				return nil
			}
			if d.IsDir() && skipPaths[p] {
				return filepath.SkipDir
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			walkFn(p, d, info)
			return nil
		})
	}
}

type suidInventoryCheck struct{}

func (suidInventoryCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "fs.suid.inventory",
		Title:       "SUID/SGID file inventory",
		Bucket:      "fs",
		Severity:    finding.SevInfo,
		Description: "Catalog every SUID/SGID file for review and baseline diffing",
		Profiles:    []string{"server", "workstation"},
	}
}

func (suidInventoryCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var entries []string
	walkSystem(func(p string, d fs.DirEntry, info os.FileInfo) {
		if info.IsDir() {
			return
		}
		mode := info.Mode()
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			entries = append(entries, fmt.Sprintf("%s %s", mode, p))
		}
	})
	sort.Strings(entries)
	ev := evidence.Note("walk(/bin /sbin /usr /etc /opt /var /home /root /tmp)", strings.Join(entries, "\n"))
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d SUID/SGID file(s) — review against baseline", len(entries)),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Snapshot baseline and re-run with `assessor diff` to detect additions.",
		},
	}
}

type worldWritableCheck struct{}

func (worldWritableCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "fs.world_writable.files",
		Title:    "No world-writable files outside sticky-bit dirs",
		Bucket:   "fs",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (worldWritableCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var bad []string
	walkSystem(func(p string, d fs.DirEntry, info os.FileInfo) {
		if info.IsDir() {
			return
		}
		if info.Mode().Perm()&0o002 != 0 {
			bad = append(bad, fmt.Sprintf("%s %s", info.Mode().Perm(), p))
		}
	})
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no world-writable files"}
	}
	if len(bad) > 50 {
		bad = append(bad[:50], fmt.Sprintf("...[%d more truncated]", len(bad)-50))
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d world-writable file(s)", len(bad)),
		Evidence: []finding.Evidence{evidence.Note("walk", strings.Join(bad, "\n"))},
		Remediation: finding.Remediation{
			Description: "Remove the world-writable bit unless explicitly required.",
			Commands:    []string{"chmod o-w <path>"},
		},
	}
}

type unownedFilesCheck struct{}

func (unownedFilesCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "fs.unowned",
		Title:    "No files with no resolvable owner or group",
		Bucket:   "fs",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

func (unownedFilesCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	users, groups := loadUserGroupSets()
	var bad []string
	walkSystem(func(p string, d fs.DirEntry, info os.FileInfo) {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		if !users[st.Uid] || !groups[st.Gid] {
			bad = append(bad, fmt.Sprintf("uid=%d gid=%d %s", st.Uid, st.Gid, p))
		}
	})
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no orphaned files"}
	}
	if len(bad) > 50 {
		bad = append(bad[:50], fmt.Sprintf("...[%d more truncated]", len(bad)-50))
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d orphaned file(s)", len(bad)),
		Evidence: []finding.Evidence{evidence.Note("walk", strings.Join(bad, "\n"))},
		Remediation: finding.Remediation{
			Description: "Reassign ownership or remove. Often left over from removed users/groups.",
		},
	}
}

func loadUserGroupSets() (map[uint32]bool, map[uint32]bool) {
	users := map[uint32]bool{}
	groups := map[uint32]bool{}
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 {
				var uid uint32
				fmt.Sscanf(f[2], "%d", &uid)
				users[uid] = true
			}
		}
	}
	if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 {
				var gid uint32
				fmt.Sscanf(f[2], "%d", &gid)
				groups[gid] = true
			}
		}
	}
	return users, groups
}

func init() {
	engine.Register(suidInventoryCheck{})
	engine.Register(worldWritableCheck{})
	engine.Register(unownedFilesCheck{})
}
