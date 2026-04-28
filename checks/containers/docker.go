package containers

import (
	"context"
	"os"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type dockerSocketCheck struct{}

func (dockerSocketCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "containers.docker.socket_perms",
		Title:    "Docker daemon socket is not world-accessible",
		Bucket:   "containers",
		Severity: finding.SevHigh,
		Profiles: []string{"server", "workstation"},
	}
}

func (dockerSocketCheck) Run(ctx context.Context, facts sysfacts.Facts) finding.Finding {
	const path = "/var/run/docker.sock"
	st, err := os.Stat(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "docker socket not present"}
	}
	mode := st.Mode().Perm()
	ev := evidence.Note(path, mode.String())
	if mode&0o006 != 0 {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "docker socket is world-readable/writable",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Description: "Restrict to root:docker 0660.",
				Commands:    []string{"chmod 0660 /var/run/docker.sock", "chown root:docker /var/run/docker.sock"},
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "docker socket perms OK", Evidence: []finding.Evidence{ev}}
}

func init() { engine.Register(dockerSocketCheck{}) }
