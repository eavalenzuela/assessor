package webdb

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type apacheModStatusCheck struct{}

func (apacheModStatusCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "webdb.apache.mod_status_exposure",
		Title:       "Apache mod_status / mod_info are not publicly accessible",
		Bucket:      "webdb",
		Severity:    finding.SevMedium,
		Description: "/server-status leaks process state and request URIs",
	}
}

func (apacheModStatusCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/apache2", "/etc/httpd"}
	var existing []string
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			existing = append(existing, r)
		}
	}
	if len(existing) == 0 {
		return finding.Finding{Status: finding.StatusSkipped, Message: "apache not installed"}
	}
	contents := concatConfigs(existing, []string{".conf"})
	if !strings.Contains(contents, "<Location /server-status>") && !strings.Contains(contents, "<Location /server-info>") {
		return finding.Finding{Status: finding.StatusPass, Message: "no server-status/server-info location blocks"}
	}
	// Find each block; check that it has a Require directive that's not "all granted".
	blockRE := regexp.MustCompile(`(?s)<Location\s+/server-(?:status|info)\s*>(.*?)</Location>`)
	bad := []string{}
	for _, m := range blockRE.FindAllStringSubmatch(contents, -1) {
		body := strings.ToLower(m[1])
		if strings.Contains(body, "require all granted") || (!strings.Contains(body, "require ") && !strings.Contains(body, "allow from")) {
			bad = append(bad, strings.TrimSpace(m[0]))
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "server-status access restricted"}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: "server-status / server-info location is unrestricted",
		Evidence: []finding.Evidence{
			evidence.Note("apache config", strings.Join(bad, "\n\n")),
		},
		Remediation: finding.Remediation{
			Description: "Limit with `Require ip 127.0.0.1` or remove the location block.",
		},
	}
}

func init() { engine.Register(apacheModStatusCheck{}) }
