package containers

import (
	"context"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type rootlessCheck struct{}

func (rootlessCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "containers.runtime.rootless",
		Title:       "Container runtime is configured rootless or with userns-remap",
		Bucket:      "containers",
		Severity:    finding.SevMedium,
		Description: "Reduces blast radius of a container escape",
	}
}

func (rootlessCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasDocker && !facts.HasPodman {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no docker/podman"}
	}
	if facts.HasPodman {
		// Podman defaults to rootless when run as a non-root user; rootful uses /run/podman/podman.sock.
		out, err := exec.Command("podman", "info", "--format", "{{.Host.Security.Rootless}}").Output()
		if err == nil && strings.TrimSpace(string(out)) == "true" {
			return finding.Finding{Status: finding.StatusPass, Message: "podman rootless"}
		}
	}
	if facts.HasDocker {
		out, err := exec.Command("docker", "info", "--format", "{{.SecurityOptions}}").Output()
		if err != nil {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
		s := string(out)
		ev := evidence.Note("docker info SecurityOptions", s)
		switch {
		case strings.Contains(s, "rootless"):
			return finding.Finding{Status: finding.StatusPass, Message: "docker rootless", Evidence: []finding.Evidence{ev}}
		case strings.Contains(s, "userns"):
			return finding.Finding{Status: finding.StatusPass, Message: "docker userns-remap active", Evidence: []finding.Evidence{ev}}
		}
		return finding.Finding{
			Status:   finding.StatusWarn,
			Message:  "docker daemon is rootful and not using userns-remap",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Add `\"userns-remap\": \"default\"` to /etc/docker/daemon.json or migrate to rootless.",
			},
		}
	}
	return finding.Finding{Status: finding.StatusUnverified, Message: "could not determine rootless status"}
}

func init() { engine.Register(rootlessCheck{}) }
