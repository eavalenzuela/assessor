package webdb

import (
	"context"
	"os"
	"regexp"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type nginxDefaultVhostCheck struct{}

func (nginxDefaultVhostCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.nginx.default_vhost",
		Title:    "nginx defines an explicit default_server returning 444",
		Bucket:   "webdb",
		Severity: finding.SevLow,
	}
}

func (nginxDefaultVhostCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	if _, err := os.Stat("/etc/nginx/nginx.conf"); err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "nginx not installed"}
	}
	contents := concatConfigs([]string{"/etc/nginx"}, []string{".conf"})
	defServerRE := regexp.MustCompile(`(?i)listen\s+\S+\s+default_server`)
	if !defServerRE.MatchString(contents) {
		return finding.Finding{
			Status:  finding.StatusWarn,
			Message: "no default_server vhost — random Host: headers fall through to first vhost",
			Remediation: finding.Remediation{
				Description: "Add a catch-all server block with `listen 80 default_server; return 444;`.",
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "default_server vhost configured",
		Evidence: []finding.Evidence{evidence.Note("nginx config", "default_server present")}}
}

func init() { engine.Register(nginxDefaultVhostCheck{}) }
