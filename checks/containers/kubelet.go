package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type kubeletCheck struct{}

func (kubeletCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "containers.k8s.kubelet",
		Title:       "kubelet has authentication and authorization configured",
		Bucket:      "containers",
		Severity:    finding.SevCritical,
		Description: "anonymous-auth must be false; authorization-mode must not be AlwaysAllow; read-only-port must be 0",
		Refs:        []finding.Reference{{Source: "CIS-K8s", ID: "4.2.1-4.2.4"}},
	}
}

type kubeletConfig struct {
	Authentication struct {
		Anonymous struct {
			Enabled bool `yaml:"enabled" json:"enabled"`
		} `yaml:"anonymous" json:"anonymous"`
	} `yaml:"authentication" json:"authentication"`
	Authorization struct {
		Mode string `yaml:"mode" json:"mode"`
	} `yaml:"authorization" json:"authorization"`
	ReadOnlyPort int `yaml:"readOnlyPort" json:"readOnlyPort"`
}

func (kubeletCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	candidates := []string{
		"/var/lib/kubelet/config.yaml",
		"/etc/kubernetes/kubelet/kubelet-config.yaml",
		"/etc/kubernetes/kubelet-config.yaml",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		// fallback: glob /etc/kubernetes for any kubelet*.yaml
		matches, _ := filepath.Glob("/etc/kubernetes/kubelet*.yaml")
		if len(matches) > 0 {
			path = matches[0]
		}
	}
	if path == "" {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no kubelet config found"}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var cfg kubeletConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		// try JSON
		if jerr := json.Unmarshal(b, &cfg); jerr != nil {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
	}
	var bad []string
	if cfg.Authentication.Anonymous.Enabled {
		bad = append(bad, "anonymous auth enabled")
	}
	if strings.EqualFold(cfg.Authorization.Mode, "AlwaysAllow") || cfg.Authorization.Mode == "" {
		bad = append(bad, fmt.Sprintf("authorization.mode=%q (want Webhook)", cfg.Authorization.Mode))
	}
	if cfg.ReadOnlyPort != 0 {
		bad = append(bad, fmt.Sprintf("readOnlyPort=%d (want 0)", cfg.ReadOnlyPort))
	}
	ev, _ := evidence.File(path)
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "kubelet hardened", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Set authentication.anonymous.enabled=false, authorization.mode=Webhook, readOnlyPort=0; restart kubelet.",
		},
	}
}

func init() { engine.Register(kubeletCheck{}) }
