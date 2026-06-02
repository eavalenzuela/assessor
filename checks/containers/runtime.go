package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type privilegedCheck struct{}

func (privilegedCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "containers.privileged.running",
		Title:       "No running containers with --privileged or unrestricted capabilities",
		Bucket:      "containers",
		Severity:    finding.SevHigh,
		Description: "Privileged containers can break out of namespacing and disable mandatory security",
	}
}

type containerInspect struct {
	Name       string `json:"Name"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		CapAdd      []string `json:"CapAdd"`
		PidMode     string   `json:"PidMode"`
		NetworkMode string   `json:"NetworkMode"`
		IpcMode     string   `json:"IpcMode"`
		UsernsMode  string   `json:"UsernsMode"`
	} `json:"HostConfig"`
}

func (privilegedCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	if !facts.HasDocker && !facts.HasPodman {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no docker/podman"}
	}
	bin := "docker"
	if !facts.HasDocker {
		bin = "podman"
	}
	out, err := exec.Command(bin, "ps", "-q").Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no running containers"}
	}
	args := append([]string{"inspect"}, ids...)
	out, err = exec.Command(bin, args...).Output()
	if err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var inspects []containerInspect
	if err := json.Unmarshal(out, &inspects); err != nil {
		return finding.Finding{Status: finding.StatusError, Err: err.Error()}
	}
	var bad []string
	for _, c := range inspects {
		var issues []string
		if c.HostConfig.Privileged {
			issues = append(issues, "privileged")
		}
		if c.HostConfig.PidMode == "host" {
			issues = append(issues, "pid=host")
		}
		if c.HostConfig.NetworkMode == "host" {
			issues = append(issues, "net=host")
		}
		for _, cap := range c.HostConfig.CapAdd {
			if cap == "SYS_ADMIN" || cap == "ALL" {
				issues = append(issues, "cap_add="+cap)
			}
		}
		if len(issues) > 0 {
			bad = append(bad, fmt.Sprintf("%s: %s", strings.TrimPrefix(c.Name, "/"), strings.Join(issues, ",")))
		}
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: fmt.Sprintf("%d container(s) running, none privileged", len(inspects))}
	}
	return finding.Finding{
		Status:  finding.StatusFail,
		Message: strings.Join(bad, "; "),
		Evidence: []finding.Evidence{
			evidence.Note(bin+" inspect", strings.Join(bad, "\n")),
		},
		Remediation: finding.Remediation{
			Description: "Drop --privileged and tighten capabilities/network/PID namespaces.",
		},
	}
}

func init() { engine.Register(privilegedCheck{}) }
