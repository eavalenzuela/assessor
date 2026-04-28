package forensic

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type recentlyModifiedBinsCheck struct{}

func (recentlyModifiedBinsCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "forensic.bins.recently_modified",
		Title:       "System binaries modified in the last 7 days",
		Bucket:      "forensic",
		Severity:    finding.SevMedium,
		Description: "Surfaces binaries whose mtime moved recently — often legitimate (updates), but worth a glance",
	}
}

func (recentlyModifiedBinsCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	var hits []string
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().After(cutoff) {
				hits = append(hits, fmt.Sprintf("%s  %s", info.ModTime().Format("2006-01-02 15:04"), p))
			}
			return nil
		})
	}
	sort.Strings(hits)
	if len(hits) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no recently modified system binaries"}
	}
	if len(hits) > 100 {
		hits = append(hits[:100], fmt.Sprintf("...[%d more]", len(hits)-100))
	}
	return finding.Finding{
		Status:  finding.StatusWarn,
		Message: fmt.Sprintf("%d binary mtime(s) within last 7 days", len(hits)),
		Evidence: []finding.Evidence{
			evidence.Note("walk", strings.Join(hits, "\n")),
		},
		Remediation: finding.Remediation{
			Description: "Cross-check against your update history; investigate any without a corresponding upgrade.",
		},
	}
}

type pkgIntegrityCheck struct{}

func (pkgIntegrityCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "forensic.packages.integrity",
		Title:    "Package-tracked files match their installed checksums",
		Bucket:   "forensic",
		Severity: finding.SevHigh,
	}
}

func (pkgIntegrityCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	switch facts.PackageManager {
	case "apt":
		if _, err := os.Stat("/usr/bin/debsums"); err != nil {
			return finding.Finding{
				Status:  finding.StatusUnverified,
				Message: "debsums not installed; cannot verify package integrity",
				Remediation: finding.Remediation{
					Commands: []string{"apt install debsums"},
				},
			}
		}
		ev, err := evidence.Command("debsums", "-c")
		if err != nil && strings.TrimSpace(ev.Content) == "" {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
		if strings.TrimSpace(ev.Content) == "" {
			return finding.Finding{Status: finding.StatusPass, Message: "all package files match"}
		}
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "debsums detected modified files",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Reinstall the affected packages or investigate tampering.",
			},
		}
	case "dnf", "yum":
		ev, _ := evidence.Command("rpm", "-Va")
		// rpm -Va exits non-zero on any deviation; ignore the err.
		if strings.TrimSpace(ev.Content) == "" {
			return finding.Finding{Status: finding.StatusPass, Message: "rpm -Va clean"}
		}
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "rpm -Va reported deviations (some are expected for config files)",
			Evidence: []finding.Evidence{ev},
		}
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no supported integrity tool"}
}

func init() {
	engine.Register(recentlyModifiedBinsCheck{})
	engine.Register(pkgIntegrityCheck{})
}
