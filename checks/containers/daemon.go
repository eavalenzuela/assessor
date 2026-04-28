package containers

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type dockerDaemonCheck struct{}

func (dockerDaemonCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "containers.docker.daemon",
		Title:       "Docker daemon.json includes hardening defaults",
		Bucket:      "containers",
		Severity:    finding.SevMedium,
		Description: "userns-remap, no-new-privileges, live-restore, log-driver",
	}
}

type dockerDaemonCfg struct {
	UsernsRemap     string                 `json:"userns-remap"`
	NoNewPrivileges bool                   `json:"no-new-privileges"`
	LiveRestore     bool                   `json:"live-restore"`
	LogDriver       string                 `json:"log-driver"`
	IcC             *bool                  `json:"icc,omitempty"`
	Other           map[string]interface{} `json:"-"`
}

func (dockerDaemonCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasDocker {
		return finding.Finding{Status: finding.StatusSkipped, Message: "docker not installed"}
	}
	const path = "/etc/docker/daemon.json"
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Finding{
			Status:  finding.StatusFail,
			Message: "no /etc/docker/daemon.json — running on insecure defaults",
			Remediation: finding.Remediation{
				Description: "Create daemon.json with userns-remap, no-new-privileges, live-restore.",
			},
		}
	}
	var cfg dockerDaemonCfg
	if err := json.Unmarshal(b, &cfg); err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var bad []string
	if cfg.UsernsRemap == "" {
		bad = append(bad, "userns-remap not set")
	}
	if !cfg.NoNewPrivileges {
		bad = append(bad, "no-new-privileges not enabled")
	}
	if !cfg.LiveRestore {
		bad = append(bad, "live-restore disabled")
	}
	ev, _ := evidence.File(path)
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "daemon.json hardened", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusWarn,
		Message:  strings.Join(bad, "; "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Commands: []string{`echo '{"userns-remap":"default","no-new-privileges":true,"live-restore":true}' > /etc/docker/daemon.json`, "systemctl restart docker"},
		},
	}
}

func init() { engine.Register(dockerDaemonCheck{}) }
