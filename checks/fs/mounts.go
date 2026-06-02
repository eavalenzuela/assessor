package fs

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

type mountOptionsCheck struct{}

func (mountOptionsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "fs.mount.hardening",
		Title:    "Hardened mount options on sensitive paths",
		Bucket:   "fs",
		Severity: finding.SevMedium,
		Profiles: []string{"server", "cis-l1"},
	}
}

var mountExpect = map[string][]string{
	"/tmp":     {"nosuid", "nodev", "noexec"},
	"/var/tmp": {"nosuid", "nodev", "noexec"},
	"/dev/shm": {"nosuid", "nodev", "noexec"},
	"/home":    {"nosuid", "nodev"},
	"/boot":    {"nosuid", "nodev"},
}

func (mountOptionsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	mounts := parseMounts(string(b))
	bad, missingByPath := evaluateMounts(mounts)
	var evs []finding.Evidence
	for _, path := range missingByPath {
		evs = append(evs, evidence.Note("/proc/mounts", path+" "+strings.Join(mounts[path], ",")))
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "mount options OK"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Add the missing options to /etc/fstab and remount.",
			Commands:    []string{"mount -o remount,nosuid,nodev,noexec /tmp"},
		},
	}
}

// parseMounts parses /proc/mounts into mountpoint -> options. Field 1 is the
// mountpoint, field 3 the comma-separated options.
func parseMounts(content string) map[string][]string {
	mounts := map[string][]string{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mounts[fields[1]] = strings.Split(fields[3], ",")
	}
	return mounts
}

// evaluateMounts checks each sensitive path in mountExpect for its required
// hardening options. Returns human-readable "path missing x,y" lines plus the
// list of offending paths (for evidence). Paths not present are skipped.
func evaluateMounts(mounts map[string][]string) (bad []string, missingPaths []string) {
	for path, want := range mountExpect {
		opts, ok := mounts[path]
		if !ok {
			continue
		}
		set := map[string]bool{}
		for _, o := range opts {
			set[o] = true
		}
		var missing []string
		for _, w := range want {
			if !set[w] {
				missing = append(missing, w)
			}
		}
		if len(missing) > 0 {
			bad = append(bad, fmt.Sprintf("%s missing %s", path, strings.Join(missing, ",")))
			missingPaths = append(missingPaths, path)
		}
	}
	return bad, missingPaths
}

func init() { engine.Register(mountOptionsCheck{}) }
